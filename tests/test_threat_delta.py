from __future__ import annotations

from email.message import Message
import hashlib
import io
import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

import osv_threat_delta.core as threat_delta_module
from osv_threat_delta.core import (
    LockedPackage,
    OSV_ENDPOINT,
    build_osv_request,
    compare_reports,
    compile_report,
    fetch_osv_batch,
    normalize_osv_response,
    parse_requirements_lock,
    scan_lock,
    verify_report,
)
from osv_threat_delta.cli import main as threat_delta_main
from osv_threat_delta.network import resolve_public_https_addresses


def _lock_text() -> str:
    return (
        "# GENERATED FILE. DO NOT EDIT.\n\n"
        "demo_pkg==1.2.3 \\\n"
        f"    --hash=sha256:{'a' * 64} \\\n"
        f"    --hash=sha256:{'c' * 64}\n"
        "    # via demo-parent\n"
        "safe==2.0 \\\n"
        f"    --hash=sha256:{'b' * 64}\n"
    )


def _response(*, finding: bool = True) -> bytes:
    vulnerability = {
        "id": "GHSA-demo-1234-5678",
        "aliases": ["CVE-2026-1234"],
        "published": "2026-10-20T00:00:00Z",
        "modified": "2026-10-22T01:02:03Z",
        "summary": "Demo vulnerability",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "demo-pkg"},
                "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.2.4"}]}],
            }
        ],
    }
    return json.dumps(
        {"results": [{"vulns": [vulnerability] if finding else []}, {}]}
    ).encode()


def _report_hash(report: dict) -> str:
    payload = dict(report)
    payload.pop("report_sha256", None)
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


class FakeResponse:
    def __init__(self, body: bytes, *, url: str = OSV_ENDPOINT, status: int = 200):
        self.body = body
        self.url = url
        self.status = status
        self.headers = Message()
        self.headers["Content-Type"] = "application/json"
        self.headers["Content-Length"] = str(len(body))

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def getcode(self):
        return self.status

    def geturl(self):
        return self.url

    def read(self, size: int):
        return self.body[:size]


class FakeOpener:
    def __init__(self, response: FakeResponse):
        self.response = response
        self.request = None

    def open(self, req, timeout):
        self.request = req
        return self.response


class ThreatDeltaTests(unittest.TestCase):
    def _lock(self, root: Path) -> Path:
        path = root / "requirements.lock"
        path.write_text(_lock_text(), encoding="utf-8")
        return path

    def test_lock_parser_binds_versions_and_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = self._lock(Path(temporary))
            packages, digest = parse_requirements_lock(path)
        self.assertEqual(
            [(p.name, p.version) for p in packages],
            [("demo-pkg", "1.2.3"), ("safe", "2.0")],
        )
        self.assertEqual(packages[0].hashes, ("a" * 64, "c" * 64))
        self.assertEqual(digest, hashlib.sha256(_lock_text().encode()).hexdigest())

    def test_lock_parser_rejects_unhashed_or_unrecognized_content(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "requirements.lock"
            path.write_text("demo==1.0\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "bounded grammar"):
                parse_requirements_lock(path)

    def test_lock_parser_rejects_duplicate_hashes(self) -> None:
        duplicate = (
            "demo==1.0 \\\n"
            f"    --hash=sha256:{'a' * 64} \\\n"
            f"    --hash=sha256:{'a' * 64}\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "requirements.lock"
            path.write_text(duplicate, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate hash"):
                parse_requirements_lock(path)

    def test_dns_guard_rejects_mixed_public_and_private_answers(self) -> None:
        rows = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443)),
        ]

        def resolver(*args, **kwargs):
            return rows

        with self.assertRaisesRegex(ValueError, "nonpublic_dns"):
            resolve_public_https_addresses("api.osv.dev", 443, resolver=resolver)

    def test_dns_guard_returns_deduplicated_public_answers(self) -> None:
        rows = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:4860:4860::8888", 443, 0, 0)),
        ]

        def resolver(*args, **kwargs):
            return rows

        self.assertEqual(
            resolve_public_https_addresses("api.osv.dev", 443, resolver=resolver),
            ("8.8.8.8", "2001:4860:4860::8888"),
        )

    def test_request_is_exact_batch_without_free_form_text(self) -> None:
        body = json.loads(
            build_osv_request((LockedPackage("demo", "1.0", ("a" * 64,)),))
        )
        self.assertEqual(
            body,
            {"queries": [{"package": {"ecosystem": "PyPI", "name": "demo"}, "version": "1.0"}]},
        )

    def test_cli_scan_is_scheduler_safe_unless_ci_failure_is_requested(self) -> None:
        report = {"result": {"active_finding_count": 1}}
        base_args = [
            "scan",
            "--root",
            ".",
            "--state-dir",
            "/private/tmp/osv-threat-delta-cli-test",
            "--format",
            "json",
        ]
        with patch("osv_threat_delta.cli.scan_lock", return_value=report):
            with io.StringIO() as output, patch("sys.stdout", output):
                self.assertEqual(threat_delta_main(base_args), 0)
        with patch("osv_threat_delta.cli.scan_lock", return_value=report):
            with io.StringIO() as output, patch("sys.stdout", output):
                self.assertEqual(threat_delta_main([*base_args, "--fail-on-findings"]), 1)

    def test_transport_rejects_redirected_final_url(self) -> None:
        opener = FakeOpener(FakeResponse(b'{"results":[]}', url="https://example.com/result"))
        with self.assertRaisesRegex(ValueError, "pinned endpoint"):
            fetch_osv_batch(b"{}", opener=opener)

    def test_transport_rejects_encoded_response(self) -> None:
        response = FakeResponse(b'{"results":[]}')
        response.headers["Content-Encoding"] = "gzip"
        with self.assertRaisesRegex(ValueError, "content encoding"):
            fetch_osv_batch(b"{}", opener=FakeOpener(response))

    def test_response_normalization_extracts_fix_and_hashes_finding(self) -> None:
        packages = (
            LockedPackage("demo-pkg", "1.2.3", ("a" * 64,)),
            LockedPackage("safe", "2.0", ("b" * 64,)),
        )
        findings = normalize_osv_response(_response(), packages)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["fix_versions"], ["1.2.4"])
        self.assertRegex(findings[0]["finding_sha256"], r"^[0-9a-f]{64}$")

    def test_result_count_must_match_inventory(self) -> None:
        packages = (LockedPackage("demo", "1.0", ("a" * 64,)),)
        with self.assertRaisesRegex(ValueError, "result count"):
            normalize_osv_response(b'{"results":[]}', packages)

    def test_response_normalization_rejects_duplicate_json_keys(self) -> None:
        packages = (LockedPackage("demo", "1.0", ("a" * 64,)),)
        with self.assertRaisesRegex(ValueError, "duplicate key"):
            normalize_osv_response(
                b'{"results":[{}],"results":[{"vulns":[]}]}', packages
            )

    def test_cli_rejects_lock_outside_repository_for_verify(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "repository"
            root.mkdir()
            outside_lock = base / "requirements.lock"
            outside_lock.write_text(_lock_text(), encoding="utf-8")
            state_dir = base / "state"
            with io.StringIO() as output, patch("sys.stdout", output):
                result = threat_delta_main(
                    [
                        "verify",
                        "--root",
                        str(root),
                        "--lock",
                        str(outside_lock),
                        "--state-dir",
                        str(state_dir),
                    ]
                )
                self.assertIn("must remain inside", output.getvalue())
            self.assertEqual(result, 2)

    def test_comparison_reports_new_changed_and_resolved(self) -> None:
        current = [
            {"package": "a", "id": "CVE-1", "finding_sha256": "new", "withdrawn": ""},
            {"package": "b", "id": "CVE-2", "finding_sha256": "same", "withdrawn": ""},
        ]
        previous = {
            "version": "osv-threat-delta-v1",
            "inventory": {"lock_sha256": "lock"},
            "findings": [
                {"package": "a", "id": "CVE-1", "finding_sha256": "old", "withdrawn": ""},
                {"package": "b", "id": "CVE-2", "finding_sha256": "same", "withdrawn": ""},
                {"package": "c", "id": "CVE-3", "finding_sha256": "gone", "withdrawn": ""},
            ],
        }
        delta = compare_reports(current, previous, "lock")
        self.assertEqual(delta["changed"], ["a:CVE-1"])
        self.assertEqual(delta["resolved"], ["c:CVE-3"])
        self.assertTrue(delta["notify"])

    def test_lock_change_always_notifies_even_without_findings(self) -> None:
        previous = {
            "version": "osv-threat-delta-v1",
            "inventory": {"lock_sha256": "old-lock"},
            "findings": [],
        }
        delta = compare_reports([], previous, "new-lock")
        self.assertEqual(delta["baseline"], "LOCK_CHANGED")
        self.assertTrue(delta["notify"])

    def test_scan_writes_private_state_outside_repo_and_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as repository, tempfile.TemporaryDirectory() as state:
            root = Path(repository)
            lock = self._lock(root)
            opener = FakeOpener(FakeResponse(_response(finding=False)))
            report = scan_lock(
                root=root,
                lock_path=lock,
                state_dir=Path(state),
                opener=opener,
                observed_at="2026-10-23T12:00:00Z",
            )
            audit = verify_report(
                report_path=Path(state) / "current.json",
                raw_dir=Path(state) / "raw",
                lock_path=lock,
            )
            self.assertEqual(report["state"], "NO_KNOWN_APPLICABLE_FINDINGS_AT_QUERY_TIME")
            self.assertTrue(audit["passed"])
            self.assertFalse(report["authority"]["remediation_allowed"])

    def test_scan_rejects_runtime_state_inside_repository(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lock = self._lock(root)
            with self.assertRaisesRegex(ValueError, "outside every Git worktree"):
                scan_lock(root=root, lock_path=lock, state_dir=root / "state")

    def test_scan_rejects_runtime_state_inside_sibling_worktree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "source"
            root.mkdir()
            lock = self._lock(root)
            sibling = base / "other-worktree"
            sibling.mkdir()
            (sibling / ".git").mkdir()
            with self.assertRaisesRegex(ValueError, "outside every Git worktree"):
                scan_lock(
                    root=root,
                    lock_path=lock,
                    state_dir=sibling / "runtime",
                    opener=FakeOpener(FakeResponse(_response(finding=False))),
                )

    def test_scan_rejects_concurrent_state_owner_before_network(self) -> None:
        with tempfile.TemporaryDirectory() as repository, tempfile.TemporaryDirectory() as state:
            root = Path(repository)
            lock = self._lock(root)
            state_path = Path(state)

            class UnexpectedNetwork:
                def open(self, req, timeout):
                    raise AssertionError("network must not run while state is locked")

            with threat_delta_module._exclusive_state_lock(state_path):
                with self.assertRaisesRegex(ValueError, "state is busy"):
                    scan_lock(
                        root=root,
                        lock_path=lock,
                        state_dir=state_path,
                        opener=UnexpectedNetwork(),
                    )

    def test_scan_rejects_corrupted_previous_state_before_network(self) -> None:
        with tempfile.TemporaryDirectory() as repository, tempfile.TemporaryDirectory() as state:
            root = Path(repository)
            lock = self._lock(root)
            state_path = Path(state)
            scan_lock(
                root=root,
                lock_path=lock,
                state_dir=state_path,
                opener=FakeOpener(FakeResponse(_response(finding=False))),
                observed_at="2026-10-23T12:00:00Z",
            )
            current_path = state_path / "current.json"
            report = json.loads(current_path.read_text(encoding="utf-8"))
            report["state"] = "NO_FINDINGS_FOREVER"
            current_path.write_text(json.dumps(report), encoding="utf-8")

            class UnexpectedNetwork:
                def open(self, req, timeout):
                    raise AssertionError("network must not run for corrupt prior state")

            with self.assertRaisesRegex(ValueError, "previous threat report failed integrity"):
                scan_lock(
                    root=root,
                    lock_path=lock,
                    state_dir=state_path,
                    opener=UnexpectedNetwork(),
                    observed_at="2026-10-23T13:00:00Z",
                )

    def test_report_tampering_fails_verification(self) -> None:
        with tempfile.TemporaryDirectory() as repository, tempfile.TemporaryDirectory() as state:
            root = Path(repository)
            lock = self._lock(root)
            packages, lock_hash = parse_requirements_lock(lock)
            report = compile_report(
                packages=packages,
                lock_path=lock,
                lock_sha256=lock_hash,
                raw_response=_response(finding=False),
                observed_at="2026-10-23T12:00:00Z",
            )
            state_path = Path(state)
            raw_dir = state_path / "raw"
            raw_dir.mkdir()
            response_hash = report["source"]["response_sha256"]
            (raw_dir / f"{response_hash}.json").write_bytes(_response(finding=False))
            report["state"] = "NO_FINDINGS_FOREVER"
            report_path = state_path / "current.json"
            report_path.write_text(json.dumps(report), encoding="utf-8")
            audit = verify_report(report_path=report_path, raw_dir=raw_dir, lock_path=lock)
            self.assertFalse(audit["passed"])
            self.assertIn("report hash mismatch", audit["errors"])

    def test_rehashed_forged_findings_fail_raw_response_verification(self) -> None:
        with tempfile.TemporaryDirectory() as repository, tempfile.TemporaryDirectory() as state:
            root = Path(repository)
            lock = self._lock(root)
            state_path = Path(state)
            report = scan_lock(
                root=root,
                lock_path=lock,
                state_dir=state_path,
                opener=FakeOpener(FakeResponse(_response(finding=False))),
                observed_at="2026-10-23T12:00:00Z",
            )
            report["findings"] = [
                {
                    "package": "demo-pkg",
                    "version": "1.2.3",
                    "id": "GHSA-forged-0000-0000",
                    "aliases": [],
                    "published": "",
                    "modified": "",
                    "withdrawn": "",
                    "summary": "forged",
                    "fix_versions": [],
                    "malicious_package": False,
                    "finding_sha256": "0" * 64,
                }
            ]
            report["report_sha256"] = _report_hash(report)
            report_path = state_path / "current.json"
            report_path.write_text(json.dumps(report), encoding="utf-8")
            audit = verify_report(
                report_path=report_path,
                raw_dir=state_path / "raw",
                lock_path=lock,
            )
            self.assertFalse(audit["passed"])
            self.assertIn(
                "report findings differ from the normalized raw OSV response",
                audit["errors"],
            )

    def test_rehashed_false_silence_fails_predecessor_delta_verification(self) -> None:
        with tempfile.TemporaryDirectory() as repository, tempfile.TemporaryDirectory() as state:
            root = Path(repository)
            lock = self._lock(root)
            state_path = Path(state)
            scan_lock(
                root=root,
                lock_path=lock,
                state_dir=state_path,
                opener=FakeOpener(FakeResponse(_response(finding=False))),
                observed_at="2026-10-23T12:00:00Z",
            )
            report = scan_lock(
                root=root,
                lock_path=lock,
                state_dir=state_path,
                opener=FakeOpener(FakeResponse(_response(finding=True))),
                observed_at="2026-10-23T13:00:00Z",
            )
            audit = verify_report(
                report_path=state_path / "current.json",
                raw_dir=state_path / "raw",
                lock_path=lock,
                previous_report_path=state_path / "previous.json",
            )
            self.assertTrue(audit["passed"])
            report["delta"] = {
                "baseline": "COMPARABLE",
                "new": [],
                "changed": [],
                "resolved": [],
                "notify": False,
            }
            report["report_sha256"] = _report_hash(report)
            (state_path / "current.json").write_text(
                json.dumps(report), encoding="utf-8"
            )
            audit = verify_report(
                report_path=state_path / "current.json",
                raw_dir=state_path / "raw",
                lock_path=lock,
                previous_report_path=state_path / "previous.json",
            )
            self.assertFalse(audit["passed"])
            self.assertIn(
                "report delta differs from the bound predecessor",
                audit["errors"],
            )

    def test_invalid_response_hash_cannot_escape_raw_directory(self) -> None:
        with tempfile.TemporaryDirectory() as repository, tempfile.TemporaryDirectory() as state:
            root = Path(repository)
            lock = self._lock(root)
            state_path = Path(state)
            report = scan_lock(
                root=root,
                lock_path=lock,
                state_dir=state_path,
                opener=FakeOpener(FakeResponse(_response(finding=False))),
                observed_at="2026-10-23T12:00:00Z",
            )
            report["source"]["response_sha256"] = "../escape"
            report["report_sha256"] = _report_hash(report)
            (state_path / "current.json").write_text(
                json.dumps(report), encoding="utf-8"
            )
            audit = verify_report(
                report_path=state_path / "current.json",
                raw_dir=state_path / "raw",
                lock_path=lock,
            )
            self.assertFalse(audit["passed"])
            self.assertIn("report response hash is invalid", audit["errors"])

    def test_verifier_rejects_symlinked_raw_response(self) -> None:
        with tempfile.TemporaryDirectory() as repository, tempfile.TemporaryDirectory() as state:
            root = Path(repository)
            lock = self._lock(root)
            state_path = Path(state)
            report = scan_lock(
                root=root,
                lock_path=lock,
                state_dir=state_path,
                opener=FakeOpener(FakeResponse(_response(finding=False))),
                observed_at="2026-10-23T12:00:00Z",
            )
            response_hash = report["source"]["response_sha256"]
            raw_path = state_path / "raw" / f"{response_hash}.json"
            outside = state_path / "outside.json"
            outside.write_bytes(_response(finding=False))
            raw_path.unlink()
            raw_path.symlink_to(outside)
            audit = verify_report(
                report_path=state_path / "current.json",
                raw_dir=state_path / "raw",
                lock_path=lock,
            )
            self.assertFalse(audit["passed"])

    def test_verifier_rejects_oversized_report_before_parsing(self) -> None:
        with tempfile.TemporaryDirectory() as repository, tempfile.TemporaryDirectory() as state:
            root = Path(repository)
            lock = self._lock(root)
            state_path = Path(state)
            state_path.mkdir(exist_ok=True)
            (state_path / "raw").mkdir()
            report_path = state_path / "current.json"
            report_path.write_bytes(b"{" + b"x" * 128)
            with patch.object(threat_delta_module, "MAX_REPORT_BYTES", 64):
                audit = verify_report(
                    report_path=report_path,
                    raw_dir=state_path / "raw",
                    lock_path=lock,
                )
            self.assertFalse(audit["passed"])
            self.assertIn(
                "threat report exceeds the bounded size limit",
                audit["errors"],
            )


if __name__ == "__main__":
    unittest.main()
