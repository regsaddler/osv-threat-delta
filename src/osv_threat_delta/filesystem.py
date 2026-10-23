from __future__ import annotations

import os
from pathlib import Path
import secrets


def ensure_private_directory(path: str | Path, *, mode: int = 0o700) -> Path:
    """Create or tighten a directory without following the final path symlink."""

    target = Path(path)
    if mode & ~0o700 or not mode & 0o100:
        raise ValueError(
            "private directory mode must include owner execute and exclude group/other bits"
        )
    target.mkdir(parents=True, exist_ok=True, mode=mode)

    required_flags = ("O_DIRECTORY", "O_NOFOLLOW")
    missing = tuple(name for name in required_flags if not hasattr(os, name))
    if missing:
        raise OSError(f"private directories require {', '.join(missing)}")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    directory_fd = os.open(target, flags)
    try:
        os.fchmod(directory_fd, mode)
    finally:
        os.close(directory_fd)
    return target


def atomic_write_text(
    path: str | Path,
    text: str,
    *,
    encoding: str = "utf-8",
    mode: int = 0o600,
) -> None:
    """Atomically replace a file without following temporary-path symlinks."""
    target = Path(path)
    if not target.name or target.name in {".", ".."}:
        raise ValueError("atomic write target must name a file")

    target.parent.mkdir(parents=True, exist_ok=True)
    required_flags = ("O_DIRECTORY", "O_NOFOLLOW")
    missing = tuple(name for name in required_flags if not hasattr(os, name))
    if missing:
        raise OSError(f"safe atomic writes require {', '.join(missing)}")

    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        directory_flags |= os.O_CLOEXEC
    parent_fd = os.open(target.parent, directory_flags)
    temporary_name: str | None = None
    temporary_fd = -1
    try:
        create_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            create_flags |= os.O_CLOEXEC
        for _ in range(128):
            candidate = f".{target.name}.{secrets.token_hex(12)}.tmp"
            try:
                temporary_fd = os.open(
                    candidate,
                    create_flags,
                    mode,
                    dir_fd=parent_fd,
                )
            except FileExistsError:
                continue
            temporary_name = candidate
            break
        else:
            raise FileExistsError("could not allocate a unique atomic-write path")

        with os.fdopen(temporary_fd, "w", encoding=encoding) as handle:
            temporary_fd = -1
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(
            temporary_name,
            target.name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        temporary_name = None
    finally:
        if temporary_fd >= 0:
            os.close(temporary_fd)
        if temporary_name is not None:
            try:
                os.unlink(temporary_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
        os.close(parent_fd)
