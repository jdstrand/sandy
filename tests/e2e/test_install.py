"""End-to-end checks for the root-owned Makefile installation."""

from __future__ import annotations

import hashlib
import stat
from pathlib import Path

from tests.e2e.support import (
    INSTALL_DIR,
    REPO_ROOT,
    E2EContext,
    E2EFailure,
    assert_contains,
)

INSTALL_FILES = ("sandy", "debootstrap.sh", "oci.sh", "setup-container.sh")


def _file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _assert_installed_files(install_dir: Path) -> None:
    install_metadata = install_dir.stat()
    if not install_dir.is_dir() or install_dir.is_symlink():
        raise E2EFailure(f"Install path is not a regular directory: {install_dir}")
    if stat.S_IMODE(install_metadata.st_mode) != 0o755:
        raise E2EFailure(f"Install directory mode is not 0755: {install_dir}")
    if (install_metadata.st_uid, install_metadata.st_gid) != (0, 0):
        raise E2EFailure(f"Install directory is not owned by root: {install_dir}")

    for filename in INSTALL_FILES:
        source = REPO_ROOT / filename
        installed = install_dir / filename
        if not installed.is_file() or installed.is_symlink():
            raise E2EFailure(f"Missing regular installed file: {installed}")
        metadata = installed.stat()
        if stat.S_IMODE(metadata.st_mode) != 0o755:
            raise E2EFailure(f"Installed mode is not 0755: {installed}")
        if (metadata.st_uid, metadata.st_gid) != (0, 0):
            raise E2EFailure(f"Installed file is not owned by root: {installed}")
        if _file_digest(installed) != _file_digest(source):
            raise E2EFailure(f"Installed content differs from source: {installed}")


def test_main(context: E2EContext) -> None:
    """Exercise staged and direct installs."""
    context.claim_install_dir()

    with context.case("DESTDIR stages the install and accepts a trailing slash"):
        stage_root = context.root / "package-root"
        staged_install_dir = stage_root / INSTALL_DIR.relative_to("/")
        result = context.run(
            ["make", "install", f"DESTDIR={stage_root}/"],
            cwd=REPO_ROOT,
        )
        assert_contains(result, f"Installed sandy to {staged_install_dir}")
        assert_contains(
            result,
            "Granting sudo access to sandy is equivalent to granting "
            "unrestricted host root access",
        )
        _assert_installed_files(staged_install_dir)
        if INSTALL_DIR.exists() or INSTALL_DIR.is_symlink():
            raise E2EFailure("Staged install unexpectedly wrote to the live root")

    with context.case("DESTDIR=/ installs to the normal root"):
        result = context.run(
            ["make", "install", "DESTDIR=/"],
            cwd=REPO_ROOT,
        )
        assert_contains(result, f"Installed sandy to {INSTALL_DIR}")
        _assert_installed_files(INSTALL_DIR)

    with context.case("unset DESTDIR uses the documented default"):
        result = context.run(["make", "install"], cwd=REPO_ROOT)
        assert_contains(result, f"Installed sandy to {INSTALL_DIR}")
        _assert_installed_files(INSTALL_DIR)

        help_result = context.run(
            [str(INSTALL_DIR / "sandy"), "--help"],
            cwd=context.root,
        )
        assert_contains(help_result, "usage:")
