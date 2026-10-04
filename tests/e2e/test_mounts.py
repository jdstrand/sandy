"""The workspace and shared directories: owner mapping, refusals, and mounts.

`up` mounts each directory in the running container. The owner of the host
directory maps to the container user, and no other id maps. These properties
need the real kernel (ID-mapped mounts, cgroupfs) and real systemd-nspawn, so
unit mocks cannot prove them. The module runs after test_lifecycle, which
leaves the main container running; it leaves that container running in the
same way (up --detach --persistent --network lenient).
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import stat
import time
from collections.abc import Iterable
from pathlib import Path

from tests.e2e.support import (
    MOUNTINFO,
    SLICE_CGROUP,
    SYSTEMD_MACHINES,
    CommandResult,
    E2EContext,
    E2EFailure,
    assert_contains,
    assert_not_contains,
    parse_mountinfo,
    up_temporary_directories,
)

# The exit status of an attach that the entry helper refuses.
ENTRY_FAILURE = 125
# strerror of EOVERFLOW: what container root gets when it creates a file.
OVERFLOW_MESSAGE = "Value too large for defined data type"
# The overflow id: the uid and gid of a file whose owner is not mapped.
OVERFLOW_ID = 65534
MOUNTS_PENDING = "mounts-pending"
OWNER_LINE = re.compile(r"([0-9]+):([0-9]+) (/\S+)")
SCOPE_GONE_TIMEOUT = 30
FILE_PREFIX = "e2e-mounts-"


def _parse_owners(text: str) -> dict[str, tuple[int, int]]:
    """Return path -> (uid, gid) for each line of `stat -c '%u:%g %n'` output."""
    owners = {}
    for line in text.replace("\r", "").splitlines():
        match = OWNER_LINE.fullmatch(line.strip())
        if match is not None:
            owners[match.group(3)] = (int(match.group(1)), int(match.group(2)))
    return owners


def _host_mounts_below(root: Path) -> list[str]:
    """Return the mount points of the host at or below root."""
    mounts = parse_mountinfo(MOUNTINFO.read_text(encoding="utf-8"))
    return [
        mount_point
        for mount_point, _ in mounts
        if mount_point == str(root) or mount_point.startswith(f"{root}/")
    ]


def _host_mount_count(path: Path) -> int:
    """Return the number of lines of the host mount table with this mount point."""
    target = os.path.realpath(path)
    mounts = parse_mountinfo(MOUNTINFO.read_text(encoding="utf-8"))
    return sum(1 for mount_point, _ in mounts if mount_point == target)


def _entries_of_root(directories: Iterable[Path]) -> list[Path]:
    """Return the entries below the directories that root owns, as user or group."""
    found = []
    for directory in directories:
        for current, names, files in os.walk(directory, followlinks=False):
            for name in (*names, *files):
                path = Path(current, name)
                entry = os.lstat(path)
                if entry.st_uid == 0 or entry.st_gid == 0:
                    found.append(path)
    return sorted(found)


def _remove_all(paths: Iterable[Path]) -> None:
    """Remove each path that exists; a directory with its contents."""
    for path in paths:
        try:
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path)
            else:
                path.unlink()
        except FileNotFoundError:
            pass


def _host_owner(path: Path) -> tuple[int, int]:
    entry = os.lstat(path)
    return entry.st_uid, entry.st_gid


def _host_file(
    context: E2EContext, path: Path, text: str = "", *, mode: int = 0o644
) -> Path:
    """Create a file of the host user on the host."""
    path.write_text(text, encoding="utf-8")
    os.chown(path, context.host_uid, context.host_gid)
    path.chmod(mode)
    return path


def _exec(
    context: E2EContext,
    command: str,
    *,
    user: str | None = None,
    expected: int | None = 0,
) -> CommandResult:
    return context.sandy(
        ["exec", "--", command],
        name=context.main_name,
        user=user or context.main_user,
        expected=expected,
    )


def _exec_fails(
    context: E2EContext, command: str, *, user: str | None = None
) -> CommandResult:
    """Run a command that must fail itself, not through a refused attach."""
    result = _exec(context, command, user=user, expected=None)
    if result.returncode in (0, ENTRY_FAILURE):
        raise E2EFailure(
            f"Expected the command to fail, got exit {result.returncode}: "
            f"{command}\n{result.output[-2000:]}"
        )
    return result


def _container_ids(context: E2EContext) -> tuple[int, int]:
    """Return the uid and gid of the container user, read in the container."""
    fields = _exec(context, "id -u; id -g").stdout.split()
    if len(fields) != 2 or not all(field.isdecimal() for field in fields):
        raise E2EFailure(f"Unexpected id output: {fields!r}")
    return int(fields[0]), int(fields[1])


def _container_owners(context: E2EContext, *paths: str) -> dict[str, tuple[int, int]]:
    """Return path -> (uid, gid) as the container user sees each path."""
    command = "stat -c '%u:%g %n' " + " ".join(shlex.quote(path) for path in paths)
    owners = _parse_owners(_exec(context, command).stdout)
    if set(owners) != set(paths):
        raise E2EFailure(f"stat answered for {sorted(owners)}, not for {paths}")
    return owners


def _start_main(context: E2EContext, *, workspace: str | None = None) -> CommandResult:
    """Start the main container as the lifecycle tests do."""
    result = context.sandy(
        ["up", "--detach", "--persistent", "--network", "lenient"],
        name=context.main_name,
        user=context.main_user,
        workspace=workspace,
    )
    context.wait_for_machine(context.main_name, running=True)
    return result


def _restart_main(
    context: E2EContext, *, workspace: str | None = None
) -> CommandResult:
    context.stop_container(context.main_name, context.main_user)
    return _start_main(context, workspace=workspace)


def _scope_loaded(context: E2EContext, name: str) -> bool:
    state = context.run(
        ["systemctl", "show", f"sandy-{name}.scope", "-p", "LoadState", "--value"]
    ).stdout.strip()
    return state != "not-found"


def _assert_not_started(context: E2EContext, name: str) -> None:
    """Fail unless the container has no machine, no image, and no scope."""
    if context.machine_running(name):
        raise E2EFailure(f"{name} is running")
    image = SYSTEMD_MACHINES / f"sandy.{name}"
    if image.exists() or image.is_symlink():
        raise E2EFailure(f"{image} exists")
    if _scope_loaded(context, name):
        raise E2EFailure(f"The scope of {name} exists")


def _wait_scope_gone(context: E2EContext, name: str) -> None:
    deadline = time.monotonic() + SCOPE_GONE_TIMEOUT
    while _scope_loaded(context, name):
        if time.monotonic() >= deadline:
            raise E2EFailure(f"The scope of {name} did not go")
        time.sleep(0.5)


def _check_owner_mapping(
    context: E2EContext,
    label: str,
    directory: Path,
    ids: tuple[int, int],
    created: list[Path],
) -> None:
    """The host owner and group are the container user's ids, and back again."""
    inside = f"/home/{context.main_user}/{label}"
    host = (context.host_uid, context.host_gid)
    seed = directory / f"{FILE_PREFIX}{label}-seed.txt"
    seed_dir = directory / f"{FILE_PREFIX}{label}-seed-dir"
    renamed = directory / f"{FILE_PREFIX}{label}-renamed.txt"
    made = directory / f"{FILE_PREFIX}{label}-made.txt"
    made_dir = directory / f"{FILE_PREFIX}{label}-made-dir"
    created.extend([seed, seed_dir, renamed, made, made_dir])

    _host_file(context, seed, "host\n")
    seed_dir.mkdir(mode=0o755)
    os.chown(seed_dir, *host)
    # The container user sees what the host user owns as its own.
    owners = _container_owners(
        context, f"{inside}/{seed.name}", f"{inside}/{seed_dir.name}"
    )
    if set(owners.values()) != {ids}:
        raise E2EFailure(f"{label}: the container sees {owners!r}, expected {ids}")
    # It can read, write, rename, and delete them.
    _exec(context, f"grep -Fx host {inside}/{seed.name}")
    _exec(context, f"echo more >> {inside}/{seed.name}")
    _exec(context, f"mv {inside}/{seed.name} {inside}/{renamed.name}")
    if renamed.read_text(encoding="utf-8") != "host\nmore\n":
        raise E2EFailure(f"{label}: the write or the rename did not reach the host")
    if _host_owner(renamed) != host:
        raise E2EFailure(
            f"{label}: a rename changed the owner to {_host_owner(renamed)}"
        )
    _exec(context, f"rm {inside}/{renamed.name} && rmdir {inside}/{seed_dir.name}")
    if renamed.exists() or seed_dir.exists():
        raise E2EFailure(f"{label}: the container did not delete the host's files")
    # What it creates belongs to the host user, in both uid and gid.
    _exec(
        context,
        f"echo made > {inside}/{made.name} && mkdir {inside}/{made_dir.name} "
        f"&& touch {inside}/{made_dir.name}/inner",
    )
    for path in (made, made_dir, made_dir / "inner"):
        if _host_owner(path) != host:
            raise E2EFailure(f"{label}: {path.name} belongs to {_host_owner(path)}")
    # The host user can edit and delete it.
    context.run_as_host_user(["tee", "-a", str(made)], input_text="edit\n")
    if made.read_text(encoding="utf-8") != "made\nedit\n":
        raise E2EFailure(f"{label}: the host user could not edit the file")
    context.run_as_host_user(["rm", "-r", "--", str(made_dir)])
    context.run_as_host_user(["rm", "--", str(made)])
    if made.exists() or made_dir.exists():
        raise E2EFailure(f"{label}: the host user could not delete the files")


def _assert_refused_before_start(
    context: E2EContext,
    name: str,
    result: CommandResult,
    message: str,
    temporary_before: set[Path],
) -> None:
    """Check an up that was refused before any host change."""
    assert_contains(result, message)
    assert_not_contains(result, "Starting")
    assert_not_contains(result, "Limits of")
    _assert_not_started(context, name)
    _assert_no_new_temporary_directories(temporary_before)


def _assert_no_new_temporary_directories(before: set[Path]) -> None:
    """Fail if an up left a directory that it made for its binds."""
    left = sorted(set(up_temporary_directories()) - before)
    if left:
        raise E2EFailure(f"up left temporary directories: {left}")


def test_main(context: E2EContext) -> None:
    """Prove the owner mapping, the refusals, and the mounts' own properties."""
    main = context.main_name
    user = context.main_user
    if context.machine_leader(main) is None:
        raise E2EFailure("The lifecycle tests must leave the main machine running")
    directories = (("workspace", context.workspace), ("shared", context.shared))
    host = (context.host_uid, context.host_gid)
    # Everything that the cases create in the host directories. The files are
    # removed at the end, so that later modules find the directories as before.
    created: list[Path] = []
    ids = _container_ids(context)
    try:
        with context.case("the workspace maps the host owner to the image user"):
            # Both directories: the host owner is the image user's own.
            for label, directory in directories:
                _check_owner_mapping(context, label, directory, ids, created)

        with context.case("files of host root are not mapped"):
            root_file = context.workspace / f"{FILE_PREFIX}root-file.txt"
            _host_file(context, root_file, "root\n")
            os.chown(root_file, 0, 0)
            created.append(root_file)
            inside = f"/home/{user}/workspace/{root_file.name}"
            owners = _container_owners(context, inside)
            if set(owners.values()) != {(OVERFLOW_ID, OVERFLOW_ID)}:
                raise E2EFailure(f"A file of root shows as {owners!r} in the container")
            denied = _exec_fails(context, f"echo x >> {inside}")
            assert_contains(denied, "Permission denied")
            if root_file.read_text(encoding="utf-8") != "root\n":
                raise E2EFailure("The container user changed a file of root")

        with context.case("container root cannot create files in the workspace"):
            # Earlier cases and modules made files of root on the host.
            root_before = set(_entries_of_root((context.workspace, context.shared)))
            for label, _ in directories:
                inside = f"/home/{user}/{label}"
                for command in (
                    f"touch {inside}/{FILE_PREFIX}root-new",
                    f"mkdir {inside}/{FILE_PREFIX}root-dir",
                ):
                    refused = _exec_fails(context, command, user="root")
                    assert_contains(refused, OVERFLOW_MESSAGE)
            # It cannot give a file of the host user to root either.
            victim = _host_file(context, context.workspace / f"{FILE_PREFIX}victim.txt")
            created.append(victim)
            _exec_fails(
                context, f"chown 0:0 /home/{user}/workspace/{victim.name}", user="root"
            )
            if _host_owner(victim) != host:
                raise E2EFailure(f"root changed the owner to {_host_owner(victim)}")
            appeared = set(_entries_of_root((context.workspace, context.shared)))
            if appeared - root_before:
                raise E2EFailure(
                    f"Files of root appeared on the host: {sorted(appeared - root_before)}"
                )

        with context.case(
            "container root can set the setuid bit only on files of the host user"
        ):
            # The documented residual risk: a setuid file of the host user.
            target = _host_file(context, context.workspace / f"{FILE_PREFIX}suid.txt")
            created.append(target)
            _exec(
                context,
                f"chmod 4755 /home/{user}/workspace/{target.name}",
                user="root",
            )
            entry = os.lstat(target)
            if (entry.st_uid, entry.st_gid) != host:
                raise E2EFailure(
                    f"The setuid file belongs to {entry.st_uid}:{entry.st_gid}"
                )
            if stat.S_IMODE(entry.st_mode) != 0o4755:
                raise E2EFailure(f"The mode is {stat.S_IMODE(entry.st_mode):o}")
            target.chmod(0o644)

        with context.case(
            "the mounts are nosuid, nodev, and ID-mapped, and only the container has them"
        ):
            inside_mounts = parse_mountinfo(
                _exec(context, "cat /proc/self/mountinfo").stdout
            )
            for label, _ in directories:
                mount_point = f"/home/{user}/{label}"
                options = [
                    found for point, found in inside_mounts if point == mount_point
                ]
                if len(options) != 1:
                    raise E2EFailure(f"{mount_point} is mounted {len(options)} times")
                missing = {"nosuid", "nodev", "idmapped"} - options[0]
                if missing:
                    raise E2EFailure(f"{mount_point} lacks {sorted(missing)}")
                # The image's own directory stays empty: nothing was mounted
                # in the host's mount namespace.
                image_directory = (
                    SYSTEMD_MACHINES / f"sandy.{main}" / "home" / user / label
                )
                if any(image_directory.iterdir()):
                    raise E2EFailure(f"{image_directory} holds files of the host")
            host_mounts = _host_mounts_below(context.root)
            if host_mounts:
                raise E2EFailure(
                    f"The host has mounts below the run root: {host_mounts}"
                )

        with context.case("mounts do not cross between the container and the host"):
            # The mount that sandy makes is private. Otherwise it would be a peer
            # of the host's mount: a mount of container root below the
            # directory would appear on the host, and a mount that the host
            # makes later would appear in the container. Both directories.
            for label, directory in directories:
                inside = f"/home/{user}/{label}"
                made = directory / "pm"
                late = directory / "late"
                for path in (made, late):
                    path.mkdir(mode=0o755)
                    os.chown(path, *host)
                # The container makes a mount; the host must not get it. Tracked
                # first, so that cleanup removes a mount that reached the host.
                context.track_scratch_mount(made)
                try:
                    _exec(
                        context,
                        f"mount -t tmpfs tmpfs {inside}/pm && "
                        f"touch {inside}/pm/from-container",
                        user="root",
                    )
                    seen = _exec(context, f"ls -A {inside}/pm")
                    if seen.stdout.split() != ["from-container"]:
                        raise E2EFailure(f"{label}: the container sees {seen.stdout!r}")
                    if _host_mount_count(made) != 0 or any(made.iterdir()):
                        raise E2EFailure(
                            f"{label}: a mount of container root reached the host"
                        )
                    context.forget_scratch_mount(made)
                finally:
                    if made in context.scratch_mounts:
                        context.unmount_scratch_filesystem(made)
                    _exec(context, f"umount {inside}/pm", user="root", expected=None)
                # The host makes a mount; the container must not get it.
                context.mount_scratch_filesystem("tmpfs", late)
                try:
                    (late / "inside-late.txt").write_text("late\n", encoding="utf-8")
                    listing = _exec(
                        context, f"test -d {inside}/late && ls -A {inside}/late | wc -l"
                    )
                    if listing.stdout.split() != ["0"]:
                        raise E2EFailure(
                            f"{label}: the container sees {listing.stdout!r} in late"
                        )
                finally:
                    context.unmount_scratch_filesystem(late)
                _remove_all([made, late])

        with context.case(
            "the mounts-pending marker refuses every attach, and down stops the container"
        ):
            marker = SLICE_CGROUP / f"sandy-{main}.scope" / MOUNTS_PENDING
            command_marker = context.workspace / f"{FILE_PREFIX}pending-ran.txt"
            created.append(command_marker)
            marker.mkdir()
            try:
                refused = _exec(
                    context,
                    f"touch /home/{user}/workspace/{command_marker.name}",
                    expected=ENTRY_FAILURE,
                )
                assert_contains(refused, "Container is still starting")
                assert_contains(refused, "sandy down")
                if command_marker.exists():
                    raise E2EFailure("The command ran although the marker existed")
                # The marker stays until the container stops, as when up was
                # killed before it removed the marker. down does not attach, so
                # it still stops the container, and the scope takes the marker.
                context.sandy(["down"], name=main, user=user)
                context.wait_for_machine(main, running=False)
                _wait_scope_gone(context, main)
            finally:
                try:
                    marker.rmdir()
                except FileNotFoundError:
                    pass
            # Start it again as test_lifecycle does; the later cases need it.
            _start_main(context)
            _exec(context, "true")

        with context.case(
            "a workspace that root owns is refused before any host change"
        ):
            name = context.mounts_name
            root_dir = context.root / "root-owned"
            group_root_dir = context.root / "group-root"
            root_dir.mkdir(mode=0o755)
            group_root_dir.mkdir(mode=0o755)
            os.chown(root_dir, 0, 0)
            # The owner is a regular user, but the group is root.
            os.chown(group_root_dir, context.host_uid, 0)
            slice_before = context.slice_artifacts()
            for workspace, shared, label in (
                (root_dir.name, None, "workspace"),
                (None, root_dir.name, "shared"),
                (group_root_dir.name, None, "workspace"),
                (None, group_root_dir.name, "shared"),
            ):
                temporary_before = set(up_temporary_directories())
                refused = context.sandy(
                    ["up", "--detach", "--network", "host"],
                    name=name,
                    user=user,
                    expected=1,
                    workspace=workspace,
                    shared=shared,
                )
                _assert_refused_before_start(
                    context,
                    name,
                    refused,
                    f"root owns the {label} directory",
                    temporary_before,
                )
            if context.slice_artifacts() != slice_before:
                raise E2EFailure("A refused up changed the state of sandy.slice")
            _remove_all([root_dir, group_root_dir])

        with context.case("a file system without ID-mapped mount support is refused"):
            name = context.mounts_name
            ramfs = context.root / "ramfs-workspace"
            ramfs.mkdir(mode=0o755)
            context.mount_scratch_filesystem("ramfs", ramfs)
            try:
                os.chown(ramfs, context.host_uid, context.host_gid)
                temporary_before = set(up_temporary_directories())
                refused = context.sandy(
                    ["up", "--detach", "--network", "host"],
                    name=name,
                    user=user,
                    expected=1,
                    workspace=ramfs.name,
                )
                _assert_refused_before_start(
                    context, name, refused, "mount_setattr failed", temporary_before
                )
                assert_contains(refused, "ID-mapped mounts need Linux 5.12")
            finally:
                context.unmount_scratch_filesystem(ramfs)
            _remove_all([ramfs])

        with context.case(
            "mounts below the workspace are not visible in the container"
        ):
            # The clone of the directory is not recursive, so a tmpfs and a bind
            # mount that exist on the host at the start show as the empty
            # directories below them. (The nspawn bind of earlier versions was
            # recursive.)
            tmpfs_dir = context.workspace / "sub"
            bind_dir = context.workspace / "bind-sub"
            bind_source = context.root / "bind-source"
            for directory in (tmpfs_dir, bind_dir, bind_source):
                directory.mkdir(mode=0o755)
                os.chown(directory, *host)
            _host_file(context, bind_source / "other-file.txt", "other\n")
            context.stop_container(main, user)
            context.mount_scratch_filesystem("tmpfs", tmpfs_dir)
            try:
                (tmpfs_dir / "inside-tmpfs.txt").write_text("tmpfs\n", encoding="utf-8")
                context.mount_scratch_bind(bind_source, bind_dir)
                try:
                    # The host sees what is mounted.
                    if (
                        not (tmpfs_dir / "inside-tmpfs.txt").is_file()
                        or not (bind_dir / "other-file.txt").is_file()
                    ):
                        raise E2EFailure("The host does not see its own mounts")
                    started = _start_main(context)
                    # up warns, and the warning names the real paths, sorted.
                    real = os.path.realpath(context.workspace)
                    listed = ", ".join(
                        f"'{path}'"
                        for path in sorted(
                            os.path.realpath(mount) for mount in (tmpfs_dir, bind_dir)
                        )
                    )
                    assert_contains(
                        started,
                        f"W: The workspace directory '{real}' has mounts below it: "
                        f"{listed}\n",
                    )
                    assert_contains(
                        started,
                        "   The container does not see these mounts\n",
                    )
                    for name in (tmpfs_dir.name, bind_dir.name):
                        path = f"/home/{user}/workspace/{name}"
                        listing = _exec(
                            context, f"test -d {path} && ls -A {path} | wc -l"
                        )
                        if listing.stdout.split() != ["0"]:
                            raise E2EFailure(
                                f"The container sees {listing.stdout!r} in {name}"
                            )
                finally:
                    context.unmount_scratch_filesystem(bind_dir)
            finally:
                context.unmount_scratch_filesystem(tmpfs_dir)
            _remove_all([tmpfs_dir, bind_dir, bind_source])

        with context.case("a linked workspace works and its real path is mounted"):
            target = context.root / "linked-target"
            link = context.root / "linked-workspace"
            target.mkdir(mode=0o755)
            os.chown(target, *host)
            link.symlink_to(target, target_is_directory=True)
            try:
                context.stop_container(main, user)
                started = _start_main(context, workspace=link.name)
                assert_contains(
                    started,
                    f"I: Mounting '{target.resolve()}' on '/home/{user}/workspace'",
                )
                _exec(context, f"echo linked > /home/{user}/workspace/linked.txt")
                if (target / "linked.txt").read_text(encoding="utf-8") != "linked\n":
                    raise E2EFailure("The file did not reach the link target")
                if _host_owner(target / "linked.txt") != host:
                    raise E2EFailure("The file in the link target has another owner")
                if (context.workspace / "linked.txt").exists():
                    raise E2EFailure("The file reached the normal workspace")
            finally:
                _restart_main(context)
                _remove_all([link, target])

        with context.case(
            "a mount target that is a link is refused and the container stops"
        ):
            home = SYSTEMD_MACHINES / f"sandy.{main}" / "home"
            for replaced in (home / user / "workspace", home / user):
                moved = replaced.with_name(f"{replaced.name}.orig")
                context.stop_container(main, user)
                os.rename(replaced, moved)
                os.symlink(moved.name, replaced)
                temporary_before = set(up_temporary_directories())
                try:
                    refused = context.sandy(
                        ["up", "--detach", "--persistent", "--network", "lenient"],
                        name=main,
                        user=user,
                        expected=1,
                    )
                    assert_contains(refused, "E: Could not mount")
                    assert_contains(refused, "openat2 failed")
                    assert_contains(refused, "Too many levels of symbolic links")
                    # The check of the targets in the image refuses the link
                    # before the start, so no container runs, and up leaves no
                    # directory that it made for its binds.
                    assert_not_contains(refused, "Starting")
                    context.wait_for_machine(main, running=False)
                    _wait_scope_gone(context, main)
                    _assert_no_new_temporary_directories(temporary_before)
                finally:
                    os.unlink(replaced)
                    os.rename(moved, replaced)
            _start_main(context)

        with context.case(
            "a mount target that becomes a link after the check is refused "
            "by the mount"
        ):
            # The link comes after the check of the targets in the image, so
            # only the mount, in the mount namespace of the container, can
            # refuse it.
            replaced = SYSTEMD_MACHINES / f"sandy.{main}" / "home" / user / "workspace"
            moved = replaced.with_name(f"{replaced.name}.orig")
            context.stop_container(main, user)
            temporary_before = set(up_temporary_directories())

            def make_the_link() -> None:
                os.rename(replaced, moved)
                os.symlink(moved.name, replaced)

            try:
                refused = context.up_with_a_change_while_it_waits(
                    main,
                    user,
                    ["up", "--detach", "--persistent", "--network", "lenient"],
                    make_the_link,
                )
                if refused.returncode != 1:
                    raise E2EFailure(
                        f"Expected exit 1, got {refused.returncode}:\n"
                        f"{refused.output}"
                    )
                assert_contains(refused, "Starting")
                assert_contains(refused, "E: Could not mount")
                assert_contains(refused, "openat2 failed")
                assert_contains(refused, "Too many levels of symbolic links")
                # The failed mount stops the container, and up removes the
                # directories that it made for its binds.
                context.wait_for_machine(main, running=False)
                _wait_scope_gone(context, main)
                _assert_no_new_temporary_directories(temporary_before)
            finally:
                if replaced.is_symlink():
                    os.unlink(replaced)
                if moved.exists():
                    os.rename(moved, replaced)
            _start_main(context)
    finally:
        _remove_all(created)
    _exec(context, "true")
