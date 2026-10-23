from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
import re
import socket
import stat as stat_module
from pathlib import Path
from typing import Any, Callable, ContextManager, Dict, Iterator, Mapping, Sequence, Tuple
from urllib import error, request

from .filesystem import atomic_write_text, ensure_private_directory
from .network import PinnedPublicHTTPSHandler


THREAT_DELTA_VERSION = "osv-threat-delta-v1"
SUPPORTED_PREVIOUS_VERSIONS = frozenset((THREAT_DELTA_VERSION,))
OSV_ENDPOINT = "https://api.osv.dev/v1/querybatch"
MAX_LOCK_BYTES = 2_000_000
MAX_PACKAGES = 1_024
MAX_REQUEST_BYTES = 1_000_000
MAX_RESPONSE_BYTES = 8_000_000
MAX_REPORT_BYTES = 32_000_000
MAX_SUMMARY_CHARACTERS = 2_000
MAX_ALIASES = 64
MAX_FIX_VERSIONS = 64
_PACKAGE_RE = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)=="
    r"([A-Za-z0-9](?:[A-Za-z0-9.!+_-]*[A-Za-z0-9])?)\s+\\$"
)
_HASH_LINE_RE = re.compile(r"^\s+--hash=sha256:([0-9a-f]{64})(?:\s+\\)?$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_AUTHORITY = {
    "remediation_allowed": False,
    "installation_allowed": False,
    "quarantine_allowed": False,
    "deployment_allowed": False,
    "publication_allowed": False,
    "security_assurance_granted": False,
}
_BOUNDARY = (
    "OSV findings for the exact pinned lock at one observation time; not runtime exposure, "
    "vulnerability absence, exploitability, containment, or remediation authority"
)


@dataclass(frozen=True)
class LockedPackage:
    name: str
    version: str
    hashes: Tuple[str, ...]

    def as_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "version": self.version, "hashes": list(self.hashes)}


class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Any:
        raise error.HTTPError(req.full_url, code, "OSV redirects are denied", headers, fp)


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _canonical_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def _inside(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def _absolute_lexical_path(path: Path | str) -> Path:
    return Path(os.path.abspath(os.path.expanduser(str(path))))


def _assert_outside_git_worktrees(path: Path) -> None:
    lexical = _absolute_lexical_path(path)
    resolved = lexical.resolve(strict=False)
    for candidate in (lexical, resolved):
        for ancestor in (candidate, *candidate.parents):
            marker = ancestor / ".git"
            if marker.exists() or marker.is_symlink():
                raise ValueError(
                    "threat runtime state must remain outside every Git worktree"
                )


def _open_directory_no_symlinks(path: Path, *, create: bool) -> int:
    target = _absolute_lexical_path(path)
    required = ("O_DIRECTORY", "O_NOFOLLOW")
    missing = tuple(name for name in required if not hasattr(os, name))
    if missing:
        raise OSError(f"safe state access requires {', '.join(missing)}")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    descriptor = os.open(target.anchor, flags)
    try:
        for part in target.parts[1:]:
            try:
                next_descriptor = os.open(part, flags, dir_fd=descriptor)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(part, mode=0o700, dir_fd=descriptor)
                next_descriptor = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        if create:
            os.fchmod(descriptor, 0o700)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read_file_no_symlinks(path: Path, *, maximum: int, label: str) -> bytes:
    target = _absolute_lexical_path(path)
    parent_fd = _open_directory_no_symlinks(target.parent, create=False)
    file_fd = -1
    try:
        flags = os.O_RDONLY | os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        file_fd = os.open(target.name, flags, dir_fd=parent_fd)
        if not stat_module.S_ISREG(os.fstat(file_fd).st_mode):
            raise ValueError(f"{label} is not a regular file")
        with os.fdopen(file_fd, "rb") as handle:
            file_fd = -1
            raw = handle.read(maximum + 1)
        if len(raw) > maximum:
            raise ValueError(f"{label} exceeds the bounded size limit")
        return raw
    finally:
        if file_fd >= 0:
            os.close(file_fd)
        os.close(parent_fd)


def _strict_json_loads(raw: bytes, label: str) -> Any:
    def reject_duplicates(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"{label} contains duplicate key {key!r}")
            result[key] = value
        return result

    try:
        return json.loads(raw, object_pairs_hook=reject_duplicates)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"{label} is not valid UTF-8 JSON") from exc


@contextmanager
def _state_lock(state_dir: Path, *, exclusive: bool) -> Iterator[None]:
    directory_fd = _open_directory_no_symlinks(
        state_dir.resolve(strict=False), create=exclusive
    )
    lock_fd = -1
    try:
        flags = os.O_NOFOLLOW
        if exclusive:
            flags |= os.O_RDWR | os.O_CREAT
        else:
            flags |= os.O_RDONLY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        lock_fd = os.open(".threat-delta.lock", flags, 0o600, dir_fd=directory_fd)
        if exclusive:
            os.fchmod(lock_fd, 0o600)
        try:
            mode = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
            fcntl.flock(lock_fd, mode | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ValueError("threat runtime state is busy") from exc
        yield
    finally:
        if lock_fd >= 0:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)
        os.close(directory_fd)


def _exclusive_state_lock(state_dir: Path) -> ContextManager[None]:
    return _state_lock(state_dir, exclusive=True)


def _shared_state_lock(state_dir: Path) -> ContextManager[None]:
    return _state_lock(state_dir, exclusive=False)


def _normalized_timestamp(value: str, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty timestamp")
    candidate = value.strip()
    parsed_value = candidate[:-1] + "+00:00" if candidate.endswith("Z") else candidate
    try:
        parsed = datetime.fromisoformat(parsed_value)
    except ValueError as exc:
        raise ValueError(f"{label} must be ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_requirements_lock(path: Path) -> Tuple[Tuple[LockedPackage, ...], str]:
    raw = path.read_bytes()
    if len(raw) > MAX_LOCK_BYTES:
        raise ValueError("requirements lock exceeds the bounded size limit")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("requirements lock must be UTF-8") from exc

    packages: list[LockedPackage] = []
    pending: tuple[str, str, list[str]] | None = None
    seen: set[str] = set()
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        package_match = _PACKAGE_RE.fullmatch(line)
        hash_match = _HASH_LINE_RE.fullmatch(line)
        if pending is None and package_match:
            pending = (
                _canonical_name(package_match.group(1)),
                package_match.group(2),
                [],
            )
            continue
        if pending is not None and hash_match:
            name, version, hashes = pending
            digest = hash_match.group(1)
            if digest in hashes:
                raise ValueError(
                    f"requirements lock contains duplicate hash for package {name}"
                )
            hashes.append(digest)
            if not line.rstrip().endswith("\\"):
                if name in seen:
                    raise ValueError(
                        f"requirements lock contains duplicate package {name}"
                    )
                seen.add(name)
                packages.append(
                    LockedPackage(name=name, version=version, hashes=tuple(hashes))
                )
                pending = None
            continue
        raise ValueError(f"requirements lock line {line_number} is outside the bounded grammar")
    if pending is not None:
        raise ValueError("requirements lock ends before the package hash")
    if not packages:
        raise ValueError("requirements lock contains no packages")
    if len(packages) > MAX_PACKAGES:
        raise ValueError("requirements lock exceeds the bounded package limit")
    return tuple(sorted(packages, key=lambda item: item.name)), _sha256(raw)


def build_osv_request(packages: Sequence[LockedPackage]) -> bytes:
    body = _canonical_json(
        {
            "queries": [
                {
                    "package": {"ecosystem": "PyPI", "name": package.name},
                    "version": package.version,
                }
                for package in packages
            ]
        }
    )
    if len(body) > MAX_REQUEST_BYTES:
        raise ValueError("OSV request exceeds the bounded size limit")
    return body


def _default_opener(resolver: Callable[..., Any]) -> Any:
    return request.build_opener(
        request.ProxyHandler({}),
        _NoRedirect(),
        PinnedPublicHTTPSHandler(resolver, error_prefix="osv_endpoint"),
    )


def fetch_osv_batch(
    request_body: bytes,
    *,
    opener: Any | None = None,
    resolver: Callable[..., Any] = socket.getaddrinfo,
    timeout_seconds: float = 30.0,
) -> bytes:
    active_opener = opener or _default_opener(resolver)
    req = request.Request(
        OSV_ENDPOINT,
        data=request_body,
        method="POST",
        headers={
            "Accept": "application/json",
            "Accept-Encoding": "identity",
            "Content-Type": "application/json",
            "User-Agent": "osv-threat-delta/0.1.0",
        },
    )
    with active_opener.open(req, timeout=timeout_seconds) as response:
        status = getattr(response, "status", None)
        if status is None:
            status = response.getcode()
        if status != 200:
            raise ValueError(f"OSV returned HTTP {status}")
        if response.geturl() != OSV_ENDPOINT:
            raise ValueError("OSV response URL differs from the pinned endpoint")
        content_type = response.headers.get_content_type()
        if content_type != "application/json":
            raise ValueError("OSV response content type is not application/json")
        content_encoding = response.headers.get("Content-Encoding", "identity").lower()
        if content_encoding != "identity":
            raise ValueError("OSV response content encoding is not identity")
        content_length = response.headers.get("Content-Length")
        if content_length is not None:
            try:
                parsed_content_length = int(content_length)
            except ValueError as exc:
                raise ValueError("OSV response Content-Length is invalid") from exc
            if parsed_content_length < 0:
                raise ValueError("OSV response Content-Length is invalid")
            if parsed_content_length > MAX_RESPONSE_BYTES:
                raise ValueError("OSV response exceeds the bounded size limit")
        raw = response.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError("OSV response exceeds the bounded size limit")
    return raw


def _bounded_string(value: Any, label: str, *, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValueError(f"{label} must be a non-empty bounded string")
    return value


def _optional_timestamp(value: Any, label: str) -> str:
    if value in (None, ""):
        return ""
    return _normalized_timestamp(_bounded_string(value, label, maximum=64), label)


def _normalize_string_list(value: Any, label: str, *, maximum: int) -> Tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or len(value) > maximum:
        raise ValueError(f"{label} must be a bounded list")
    result = []
    for index, item in enumerate(value):
        text = _bounded_string(item, f"{label}[{index}]", maximum=256)
        if not _ID_RE.fullmatch(text):
            raise ValueError(f"{label}[{index}] has an invalid identifier")
        result.append(text)
    return tuple(sorted(set(result)))


def _fix_versions(vulnerability: Mapping[str, Any], package: LockedPackage) -> Tuple[str, ...]:
    fixes: set[str] = set()
    affected_rows = vulnerability.get("affected", [])
    if not isinstance(affected_rows, list) or len(affected_rows) > 256:
        raise ValueError("OSV affected must be a bounded list")
    for affected in affected_rows:
        if not isinstance(affected, Mapping):
            raise ValueError("OSV affected entry must be an object")
        package_row = affected.get("package", {})
        if not isinstance(package_row, Mapping):
            raise ValueError("OSV affected package must be an object")
        if package_row.get("ecosystem") != "PyPI":
            continue
        if _canonical_name(str(package_row.get("name", ""))) != package.name:
            continue
        ranges = affected.get("ranges", [])
        if not isinstance(ranges, list) or len(ranges) > 128:
            raise ValueError("OSV affected ranges must be a bounded list")
        for range_row in ranges:
            if not isinstance(range_row, Mapping):
                raise ValueError("OSV range entry must be an object")
            events = range_row.get("events", [])
            if not isinstance(events, list) or len(events) > 512:
                raise ValueError("OSV range events must be a bounded list")
            for event in events:
                if not isinstance(event, Mapping):
                    raise ValueError("OSV range event must be an object")
                fixed = event.get("fixed")
                if fixed is not None:
                    fixes.add(_bounded_string(fixed, "OSV fixed version", maximum=128))
                    if len(fixes) > MAX_FIX_VERSIONS:
                        raise ValueError("OSV fix versions exceed the bounded limit")
    return tuple(sorted(fixes))


def normalize_osv_response(raw: bytes, packages: Sequence[LockedPackage]) -> Tuple[Dict[str, Any], ...]:
    payload = _strict_json_loads(raw, "OSV response")
    if not isinstance(payload, Mapping):
        raise ValueError("OSV response must be an object")
    results = payload.get("results")
    if not isinstance(results, list) or len(results) != len(packages):
        raise ValueError("OSV result count differs from the lock package count")

    findings: list[Dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for package, result in zip(packages, results):
        if not isinstance(result, Mapping):
            raise ValueError("OSV result entry must be an object")
        vulnerabilities = result.get("vulns", [])
        if not isinstance(vulnerabilities, list) or len(vulnerabilities) > 512:
            raise ValueError("OSV vulnerabilities must be a bounded list")
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, Mapping):
                raise ValueError("OSV vulnerability must be an object")
            vulnerability_id = _bounded_string(vulnerability.get("id"), "OSV id", maximum=128)
            if not _ID_RE.fullmatch(vulnerability_id):
                raise ValueError("OSV id has an invalid identifier")
            key = (package.name, vulnerability_id)
            if key in seen:
                raise ValueError("OSV response contains a duplicate package finding")
            seen.add(key)
            summary = vulnerability.get("summary", "")
            if summary:
                summary = _bounded_string(summary, "OSV summary", maximum=MAX_SUMMARY_CHARACTERS)
            finding: Dict[str, Any] = {
                "package": package.name,
                "version": package.version,
                "id": vulnerability_id,
                "aliases": list(
                    _normalize_string_list(vulnerability.get("aliases"), "OSV aliases", maximum=MAX_ALIASES)
                ),
                "published": _optional_timestamp(vulnerability.get("published"), "OSV published"),
                "modified": _optional_timestamp(vulnerability.get("modified"), "OSV modified"),
                "withdrawn": _optional_timestamp(vulnerability.get("withdrawn"), "OSV withdrawn"),
                "summary": summary,
                "fix_versions": list(_fix_versions(vulnerability, package)),
                "malicious_package": vulnerability_id.startswith("MAL-"),
            }
            finding["finding_sha256"] = _sha256(_canonical_json(finding))
            findings.append(finding)
    return tuple(sorted(findings, key=lambda item: (item["package"], item["id"])))


def compare_reports(current_findings: Sequence[Mapping[str, Any]], previous: Mapping[str, Any] | None, lock_sha256: str) -> Dict[str, Any]:
    current = {
        (str(item["package"]), str(item["id"])): item
        for item in current_findings
        if not item.get("withdrawn")
    }
    if previous is None:
        new = sorted(f"{package}:{finding_id}" for package, finding_id in current)
        return {
            "baseline": "INITIAL_BASELINE",
            "new": new,
            "changed": [],
            "resolved": [],
            "notify": bool(new),
        }
    if previous.get("version") not in SUPPORTED_PREVIOUS_VERSIONS:
        raise ValueError("previous threat report has an unsupported version")
    previous_inventory = previous.get("inventory")
    if not isinstance(previous_inventory, Mapping):
        raise ValueError("previous threat report inventory is invalid")
    if previous_inventory.get("lock_sha256") != lock_sha256:
        new = sorted(f"{package}:{finding_id}" for package, finding_id in current)
        return {
            "baseline": "LOCK_CHANGED",
            "new": new,
            "changed": [],
            "resolved": [],
            "notify": True,
        }
    previous_findings = previous.get("findings")
    if not isinstance(previous_findings, list):
        raise ValueError("previous threat report findings are invalid")
    old = {
        (str(item["package"]), str(item["id"])): item
        for item in previous_findings
        if isinstance(item, Mapping) and not item.get("withdrawn")
    }
    new_keys = sorted(current.keys() - old.keys())
    resolved_keys = sorted(old.keys() - current.keys())
    changed_keys = sorted(
        key
        for key in current.keys() & old.keys()
        if current[key].get("finding_sha256") != old[key].get("finding_sha256")
    )
    render = lambda keys: [f"{package}:{finding_id}" for package, finding_id in keys]
    return {
        "baseline": "COMPARABLE",
        "new": render(new_keys),
        "changed": render(changed_keys),
        "resolved": render(resolved_keys),
        "notify": bool(new_keys or changed_keys or resolved_keys),
    }


def compile_report(
    *,
    packages: Sequence[LockedPackage],
    lock_path: Path,
    lock_sha256: str,
    raw_response: bytes,
    observed_at: str,
    previous: Mapping[str, Any] | None = None,
) -> Dict[str, Any]:
    findings = normalize_osv_response(raw_response, packages)
    active_count = sum(1 for item in findings if not item["withdrawn"])
    previous_report_sha256 = ""
    if previous is not None:
        previous_report_sha256 = str(previous.get("report_sha256", ""))
        if not _SHA256_RE.fullmatch(previous_report_sha256):
            raise ValueError("previous threat report hash is invalid")
    report: Dict[str, Any] = {
        "version": THREAT_DELTA_VERSION,
        "observed_at": _normalized_timestamp(observed_at, "observed_at"),
        "state": (
            "APPLICABLE_FINDINGS_REPORTED"
            if active_count
            else "NO_KNOWN_APPLICABLE_FINDINGS_AT_QUERY_TIME"
        ),
        "inventory": {
            "ecosystem": "PyPI",
            "lock_ref": lock_path.name,
            "lock_sha256": lock_sha256,
            "package_count": len(packages),
        },
        "source": {
            "provider": "OSV.dev",
            "endpoint": OSV_ENDPOINT,
            "response_sha256": _sha256(raw_response),
            "response_bytes": len(raw_response),
        },
        "result": {
            "finding_count": len(findings),
            "active_finding_count": active_count,
            "malicious_package_count": len(
                {
                    item["package"]
                    for item in findings
                    if item["malicious_package"] and not item["withdrawn"]
                }
            ),
        },
        "findings": list(findings),
        "delta": compare_reports(findings, previous, lock_sha256),
        "comparison": {
            "previous_report_sha256": previous_report_sha256,
        },
        "authority": dict(_AUTHORITY),
        "boundary": _BOUNDARY,
    }
    report["report_sha256"] = _sha256(_canonical_json(report))
    return report


def _load_previous(path: Path) -> Mapping[str, Any] | None:
    try:
        raw = _read_file_no_symlinks(
            path,
            maximum=MAX_REPORT_BYTES,
            label="previous threat report",
        )
    except FileNotFoundError:
        return None
    try:
        value = _strict_json_loads(raw, "previous threat report")
    except (OSError, ValueError) as exc:
        raise ValueError("previous threat report is unreadable") from exc
    if not isinstance(value, Mapping):
        raise ValueError("previous threat report must be an object")
    envelope_errors = _validate_report_envelope(value, allow_legacy=True)
    if envelope_errors:
        raise ValueError(f"previous threat report failed integrity: {', '.join(envelope_errors)}")
    return value


def _validate_report_envelope(
    report: Mapping[str, Any], *, allow_legacy: bool = False
) -> list[str]:
    errors: list[str] = []
    report_copy = dict(report)
    claimed_report_hash = report_copy.pop("report_sha256", "")
    if not isinstance(claimed_report_hash, str) or not _SHA256_RE.fullmatch(
        claimed_report_hash
    ):
        errors.append("report hash format is invalid")
    elif claimed_report_hash != _sha256(_canonical_json(report_copy)):
        errors.append("report hash mismatch")
    allowed_versions = (
        SUPPORTED_PREVIOUS_VERSIONS if allow_legacy else {THREAT_DELTA_VERSION}
    )
    if report.get("version") not in allowed_versions:
        errors.append("unsupported report version")
    if report.get("authority") != _AUTHORITY:
        errors.append("authority differs from the all-false contract")
    if report.get("boundary") != _BOUNDARY:
        errors.append("report boundary differs from the bounded contract")
    observed_at = report.get("observed_at")
    try:
        if _normalized_timestamp(observed_at, "observed_at") != observed_at:
            errors.append("observed_at is not canonical UTC")
    except (TypeError, ValueError):
        errors.append("observed_at is invalid")
    return errors


def scan_lock(
    *,
    root: Path,
    lock_path: Path,
    state_dir: Path,
    opener: Any | None = None,
    observed_at: str | None = None,
) -> Dict[str, Any]:
    root = root.resolve()
    lock_path = lock_path.resolve()
    lexical_state_dir = _absolute_lexical_path(state_dir)
    _assert_outside_git_worktrees(lexical_state_dir)
    state_dir = lexical_state_dir.resolve(strict=False)
    if not _inside(lock_path, root):
        raise ValueError("requirements lock must remain inside the repository")
    if _inside(state_dir, root):
        raise ValueError("threat runtime state must remain outside every Git worktree")
    packages, lock_sha256 = parse_requirements_lock(lock_path)
    output = ensure_private_directory(state_dir)
    with _exclusive_state_lock(output):
        previous_path = output / "current.json"
        previous = _load_previous(previous_path)
        request_body = build_osv_request(packages)
        raw_response = fetch_osv_batch(request_body, opener=opener)
        report = compile_report(
            packages=packages,
            lock_path=lock_path,
            lock_sha256=lock_sha256,
            raw_response=raw_response,
            observed_at=observed_at or datetime.now(timezone.utc).isoformat(),
            previous=previous,
        )
        raw_dir = ensure_private_directory(output / "raw")
        raw_path = raw_dir / f"{report['source']['response_sha256']}.json"
        if raw_path.is_symlink():
            raise ValueError("raw OSV response path must not be a symlink")
        if raw_path.exists():
            existing_raw = _read_file_no_symlinks(
                raw_path,
                maximum=MAX_RESPONSE_BYTES,
                label="raw OSV response",
            )
            if _sha256(existing_raw) != report["source"]["response_sha256"]:
                raise ValueError("existing raw OSV response hash mismatch")
        else:
            atomic_write_text(raw_path, raw_response.decode("utf-8"))
        if previous is not None:
            atomic_write_text(
                output / "previous.json",
                json.dumps(previous, indent=2, sort_keys=True) + "\n",
            )
        atomic_write_text(
            previous_path,
            json.dumps(report, indent=2, sort_keys=True) + "\n",
        )
        return report


def _validate_inventory(
    report: Mapping[str, Any],
    packages: Sequence[LockedPackage],
    lock_path: Path,
    lock_hash: str,
    *,
    label: str,
) -> None:
    expected = {
        "ecosystem": "PyPI",
        "lock_ref": lock_path.name,
        "lock_sha256": lock_hash,
        "package_count": len(packages),
    }
    if report.get("inventory") != expected:
        raise ValueError(f"{label} inventory differs from the current lock inventory")


def _normalized_findings_from_report(
    report: Mapping[str, Any],
    packages: Sequence[LockedPackage],
    raw_dir: Path,
    *,
    label: str,
) -> Tuple[Dict[str, Any], ...]:
    source = report.get("source")
    if not isinstance(source, Mapping):
        raise ValueError(f"{label} source metadata is invalid")
    response_hash = source.get("response_sha256")
    if not isinstance(response_hash, str) or not _SHA256_RE.fullmatch(response_hash):
        raise ValueError(f"{label} response hash is invalid")
    raw_path = raw_dir / f"{response_hash}.json"
    raw_response = _read_file_no_symlinks(
        raw_path,
        maximum=MAX_RESPONSE_BYTES,
        label=f"{label} raw OSV response",
    )
    if _sha256(raw_response) != response_hash:
        raise ValueError(f"{label} raw OSV response hash mismatch")
    expected_source = {
        "provider": "OSV.dev",
        "endpoint": OSV_ENDPOINT,
        "response_sha256": response_hash,
        "response_bytes": len(raw_response),
    }
    if source != expected_source:
        raise ValueError(f"{label} source metadata differs from the raw OSV response")
    findings = normalize_osv_response(raw_response, packages)
    if report.get("findings") != list(findings):
        raise ValueError(f"{label} findings differ from the normalized raw OSV response")
    return findings


def _load_bound_previous(
    report: Mapping[str, Any],
    *,
    previous_report_path: Path,
    raw_dir: Path,
    packages: Sequence[LockedPackage],
    lock_path: Path,
    lock_hash: str,
) -> Mapping[str, Any] | None:
    comparison = report.get("comparison")
    if not isinstance(comparison, Mapping) or set(comparison) != {
        "previous_report_sha256"
    }:
        raise ValueError("report comparison binding is invalid")
    previous_hash = comparison.get("previous_report_sha256")
    if previous_hash == "":
        return None
    if not isinstance(previous_hash, str) or not _SHA256_RE.fullmatch(previous_hash):
        raise ValueError("report predecessor hash is invalid")
    previous = _load_previous(previous_report_path)
    if previous is None or previous.get("report_sha256") != previous_hash:
        raise ValueError("bound previous threat report is missing or differs")
    previous_inventory = previous.get("inventory")
    if not isinstance(previous_inventory, Mapping):
        raise ValueError("previous threat report inventory is invalid")
    if previous_inventory.get("lock_sha256") == lock_hash:
        _validate_inventory(
            previous,
            packages,
            lock_path,
            lock_hash,
            label="previous threat report",
        )
        _normalized_findings_from_report(
            previous,
            packages,
            raw_dir,
            label="previous threat report",
        )
    return previous


def verify_report(
    *,
    report_path: Path,
    raw_dir: Path,
    lock_path: Path,
    previous_report_path: Path | None = None,
) -> Dict[str, Any]:
    errors: list[str] = []
    try:
        report_input = _absolute_lexical_path(report_path)
        state_dir = report_input.parent.resolve(strict=False)
        report_path = state_dir / report_input.name
        raw_input = _absolute_lexical_path(raw_dir)
        if raw_input.parent.resolve(strict=False) != state_dir:
            raise ValueError("raw OSV directory must share the report state directory")
        raw_dir = state_dir / raw_input.name
        previous_input = _absolute_lexical_path(
            previous_report_path or state_dir / "previous.json"
        )
        if previous_input.parent.resolve(strict=False) != state_dir:
            raise ValueError("previous report must share the report state directory")
        previous_report_path = _absolute_lexical_path(
            state_dir / previous_input.name
        )
        _assert_outside_git_worktrees(state_dir)
        report_raw = _read_file_no_symlinks(
            report_path,
            maximum=MAX_REPORT_BYTES,
            label="threat report",
        )
        report = _strict_json_loads(report_raw, "threat report")
        if not isinstance(report, Mapping):
            raise ValueError("report must be an object")
        envelope_errors = _validate_report_envelope(report)
        if envelope_errors:
            raise ValueError(", ".join(envelope_errors))
        with _shared_state_lock(state_dir):
            locked_report_raw = _read_file_no_symlinks(
                report_path,
                maximum=MAX_REPORT_BYTES,
                label="threat report",
            )
            if locked_report_raw != report_raw:
                raise ValueError("threat report changed while verification began")
            packages, lock_hash = parse_requirements_lock(lock_path)
            _validate_inventory(
                report,
                packages,
                lock_path,
                lock_hash,
                label="report",
            )
            findings = _normalized_findings_from_report(
                report,
                packages,
                raw_dir,
                label="report",
            )
            active_count = sum(1 for item in findings if not item["withdrawn"])
            expected_result = {
                "finding_count": len(findings),
                "active_finding_count": active_count,
                "malicious_package_count": len(
                    {
                        item["package"]
                        for item in findings
                        if item["malicious_package"] and not item["withdrawn"]
                    }
                ),
            }
            if report.get("result") != expected_result:
                raise ValueError("report result counts differ from normalized findings")
            expected_state = (
                "APPLICABLE_FINDINGS_REPORTED"
                if active_count
                else "NO_KNOWN_APPLICABLE_FINDINGS_AT_QUERY_TIME"
            )
            if report.get("state") != expected_state:
                raise ValueError("report state differs from normalized findings")
            previous = _load_bound_previous(
                report,
                previous_report_path=previous_report_path,
                raw_dir=raw_dir,
                packages=packages,
                lock_path=lock_path,
                lock_hash=lock_hash,
            )
            expected_delta = compare_reports(findings, previous, lock_hash)
            if report.get("delta") != expected_delta:
                raise ValueError("report delta differs from the bound predecessor")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        errors.append(str(exc))
    return {
        "version": "osv-threat-delta-audit-v1",
        "status": "PASS_BOUNDED" if not errors else "HOLD_INTEGRITY",
        "passed": not errors,
        "errors": errors,
        "authority": dict(_AUTHORITY),
    }


def summarize(report: Mapping[str, Any]) -> str:
    result = report["result"]
    delta = report["delta"]
    return "\n".join(
        (
            f"THREAT_DELTA: {report['state']}",
            f"packages={report['inventory']['package_count']} active_findings={result['active_finding_count']} "
            f"malicious_packages={result['malicious_package_count']}",
            f"baseline={delta['baseline']} new={len(delta['new'])} changed={len(delta['changed'])} "
            f"resolved={len(delta['resolved'])} notify={str(delta['notify']).lower()}",
            "authority=remediation_allowed=false installation_allowed=false quarantine_allowed=false "
            "deployment_allowed=false publication_allowed=false security_assurance_granted=false",
            f"boundary={report['boundary']}",
        )
    )
