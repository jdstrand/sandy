"""Root-only managed-filesystem behavior against the real Linux VFS."""

from __future__ import annotations

import importlib.machinery
import importlib.util
from types import ModuleType

from tests.e2e.support import (
    PORT_LOCK,
    PORT_STATE,
    SANDY,
    E2EContext,
    E2EFailure,
)


def _load_sandy_module() -> ModuleType:
    """Load the extensionless Sandy implementation without running its CLI."""
    loader = importlib.machinery.SourceFileLoader(
        "sandy_e2e_filesystem",
        str(SANDY),
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    if spec is None:
        raise E2EFailure("Could not load the Sandy implementation")
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def test_main(context: E2EContext) -> None:
    """Exercise descriptor and symlink semantics that unit mocks cannot prove."""
    sandy = _load_sandy_module()

    with context.case(
        "machine-image and internal symlinks remain contained during write and removal"
    ):
        image_root = context.filesystem_image_root
        host_target = context.filesystem_host_target
        machine_link = context.filesystem_machine_link
        contained_target = image_root / host_target.relative_to("/")

        context.create_filesystem_fixture_directory(image_root)
        contained_target.mkdir(parents=True)
        context.create_filesystem_fixture_directory(host_target)
        host_keep = host_target / "keep"
        host_keep.write_text("host-decoy\n", encoding="utf-8")
        image_root.joinpath("etc").symlink_to(host_target)
        context.create_filesystem_fixture_symlink(machine_link, image_root)

        image_root.joinpath("control").symlink_to("/unsafe\x1b[31m")
        try:
            sandy._write(
                str(machine_link / "control" / "file"),
                "must-not-write\n",
            )
        except PermissionError as exc:
            if sandy._contains_control_character(str(exc)):
                raise E2EFailure(
                    "A rejected symlink target injected terminal controls"
                ) from exc
        else:
            raise E2EFailure("A control-bearing symlink target was accepted")

        contained_hosts = contained_target / "hosts"
        contained_hosts.symlink_to(host_keep)
        try:
            sandy._write(
                str(machine_link / "etc" / "hosts"),
                "must-not-escape\n",
                mode=0o644,
            )
        except PermissionError:
            pass
        else:
            raise E2EFailure("A final write symlink was unexpectedly followed")

        if host_keep.read_text(encoding="utf-8") != "host-decoy\n":
            raise E2EFailure("A final write symlink modified its host target")

        contained_hosts.unlink()
        sandy._write(
            str(machine_link / "etc" / "hosts"),
            "contained\n",
            mode=0o644,
        )
        if contained_hosts.read_text(encoding="utf-8") != "contained\n":
            raise E2EFailure("The contained image destination was not written")
        if host_target.joinpath("hosts").exists():
            raise E2EFailure("An image-internal absolute symlink escaped to the host")

        sandy._remove_managed_tree(str(machine_link))
        if machine_link.exists() or machine_link.is_symlink():
            raise E2EFailure("Machine-image symlink was not removed")
        if not image_root.is_dir():
            raise E2EFailure("Removing the image link deleted its external target")
        if host_keep.read_text(encoding="utf-8") != "host-decoy\n":
            raise E2EFailure("Removing the image link modified the host decoy")

        context.remove_filesystem_fixtures()
        context.assert_no_sandy_state()

    with context.case("regular-file bind mounts block recursive removal"):
        source_root = context.filesystem_host_target
        managed_root = context.filesystem_machine_link
        context.create_filesystem_fixture_directory(source_root)
        context.create_filesystem_fixture_directory(managed_root, mode=0o700)
        source_file = source_root / "source"
        mount_point = managed_root / "mounted-file"
        source_file.write_text("host-decoy\n", encoding="utf-8")
        mount_point.write_text("managed-placeholder\n", encoding="utf-8")

        context.mount_filesystem_file(source_file, mount_point)
        try:
            try:
                sandy._remove_managed_tree(str(managed_root))
            except PermissionError as exc:
                if str(exc) != "Refusing to cross a mount boundary":
                    raise E2EFailure(
                        f"Recursive removal failed for an unexpected reason: {exc}"
                    ) from exc
            else:
                raise E2EFailure("A regular-file bind mount was not rejected")

            if source_file.read_text(encoding="utf-8") != "host-decoy\n":
                raise E2EFailure("Recursive removal modified a bind-mounted source")
            if not managed_root.is_dir():
                raise E2EFailure("Recursive removal deleted the managed root")
        finally:
            context.unmount_filesystem_file(mount_point)

        if mount_point.read_text(encoding="utf-8") != "managed-placeholder\n":
            raise E2EFailure("Unbinding did not reveal the original managed file")

        context.remove_filesystem_fixtures()
        context.assert_no_sandy_state()

    with context.case("port state replacement retains one stable lock inode"):
        instance = sandy.Sandy.__new__(sandy.Sandy)
        instance.port_mappings = [("tcp", 48080, 80)]
        instance._update_port_mapping_state("e2e-lock-first", "10.200.1.10")
        first_state_stat = PORT_STATE.stat()
        first_lock_stat = PORT_LOCK.stat()

        instance.port_mappings = [("tcp", 48081, 81)]
        instance._update_port_mapping_state("e2e-lock-second", "10.200.1.11")
        second_state_stat = PORT_STATE.stat()
        second_lock_stat = PORT_LOCK.stat()

        if sandy._same_inode(first_state_stat, second_state_stat):
            raise E2EFailure("Atomic state persistence did not replace its inode")
        if not sandy._same_inode(first_lock_stat, second_lock_stat):
            raise E2EFailure("State persistence replaced the transaction lock inode")

        instance._clear_port_mapping_state()
        if PORT_STATE.exists():
            raise E2EFailure("Port state remained after locked clearing")
        instance._purge_cache()
        if not PORT_LOCK.is_file():
            raise E2EFailure("Cache purge removed the stable transaction lock")
        if not sandy._same_inode(first_lock_stat, PORT_LOCK.stat()):
            raise E2EFailure("Cache purge replaced the transaction lock inode")

        context.purge_cache()
        context.assert_no_sandy_state()
