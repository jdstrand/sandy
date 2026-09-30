# sandy: start systemd-nspawn in its own unit

sandy is a Python script that starts systemd-nspawn development containers for
AI agents.

Goal: sandy starts systemd-nspawn outside the cgroup of the terminal that runs
sandy. Then an OOM kill in the terminal's scope, or a closed terminal, does not
end the container. Attached shells run inside the resource boundary of the
container, as `docker exec` and `podman exec` do.

Status: steps 1 and 2 of the implementation order are implemented. The
sections "Current layout", "Failure chain", and "Answers from the sandy code"
describe sandy before this change.

## Incident

A host ran out of memory, and no cgroup limit applied. A process in an
attached shell of a sandy container grew to about 40 GB, and the kernel OOM
killer killed it. The killed process was in the systemd scope of the terminal
emulator that ran sandy, not in the container's `machine-<name>.scope`.
systemd then stopped that terminal scope ("Failed with result 'oom-kill'").
The container's `machine-<name>.scope` ended at the same time, and the
container and all agent sessions in it were lost.

The console (`sandy -c <name> up`) and two attached shells
(`sandy -c <name> bash`) ran in tabs of one terminal emulator. The killed
process ran in one of the attached shells.

## Current layout (before this change)

- `/run/host/container-manager` contains `systemd-nspawn`.
- The killed process had a host UID in the container's UID range: it was
  container UID 1000 (`developer`). So it ran inside the container. It was not
  sandy.
- Console: PID 1 `(sd-stubinit)` (`--as-pid2`) and PID 4 `-bash`, both
  container UID 1000. Their cgroup is `0::/`, the container root, under
  `machine-<name>.scope` on the host.
- Attached shells:
  `su developer -s /bin/bash -c "script -qec 'cd <workdir> && exec bash --login' /dev/null"`,
  with PPID 0 and container UID 0 (entered from outside the container). Their
  cgroup is the scope of the host terminal:
  `0::/../../../user.slice/user-<uid>.slice/user@<uid>.service/app.slice/<terminal>.scope`.
- Cause in the code: `sandy -c <name> bash` (`run_bash` -> `_exec`) runs
  `nsenter -t <leader pid> -a -- su <user> -s /bin/bash -c "script -qec ... /dev/null"`.
  `nsenter -a` enters the cgroup namespace of the container, but it does not
  move the process into the cgroup of the container. sudo, sandy, nsenter, su,
  and script do not change the cgroup. So the shell stays in the cgroup of the
  terminal. The `../../../` prefix in the path above comes from this: the
  process is in the cgroup namespace of the container, but its cgroup is
  outside the namespace root.
- The memory of an attached shell is counted against the terminal's scope, not
  against `machine-<name>.scope`.
- Two attached shells in different windows or tabs of the terminal emulator
  share one scope. Inferred: one scope holds all windows and tabs of that
  terminal emulator. So separate tabs give no isolation.
- `machinectl shell` (and `systemd-run --machine=`) would put a shell in the
  cgroup of the container. Both need systemd and D-Bus inside the container,
  and sandy uses `--as-pid2`. `security-parity.md` ("Rejected approach:
  `systemd-run --machine=`") measured this and rejects it. This is why sandy
  uses nsenter. Other `machinectl` commands (`show -p Leader`, `poweroff`,
  `terminate`, `status`) do not need a bus in the container. sandy uses them
  today, and its ownership model depends on them.
- Attached processes are in the container's PID namespace. When the
  container's PID 1 ends, the kernel kills them too, whatever their cgroup.
- The heavy work (agent sessions, builds, scans) runs mostly in attached
  shells.

The nspawn supervisor was in the same terminal scope as the attached shells:
`/proc/<nspawn pid>/cgroup` showed the terminal's scope.

## Failure chain (steps 1 and 2 verified; steps 3 to 6 inferred)

1. `sandy -c <name> up` ran in tab 1. So sandy and the nspawn supervisor run in
   the terminal's scope. Only the container payload goes into
   `machine-<name>.scope`. Verified for the supervisor (see Current layout).
2. `sandy -c <name> bash` ran in tabs 2 and 3. The attached shells are also in
   the terminal's scope (see Current layout). So the supervisor and the heavy
   work shared one OOM domain.
3. A process in an attached shell grew to about 40 GB, and the host ran out of
   memory. The kernel killed that process.
4. After the kernel OOM kill, systemd stopped the terminal's scope
   (`OOMPolicy=stop` is the default; `DefaultOOMPolicy=stop` for both the
   system and the user manager on that host). This killed the terminal
   emulator, all tabs, all attached shells, and the supervisor.
5. With the supervisor gone, `machine-<name>.scope` ended. The kernel killed
   all processes in the container, including the console work in tab 1.
6. The state of tab 1 (idle) did not matter. It held the supervisor.

Conclusions:

- A supervisor in its own system unit (Requirement 1) would have saved the
  container. Only the terminals would have been lost.
- An attach in the container's unit (Requirement 5) would have kept the
  terminal emulator and the other tabs out of the OOM. With an optional memory
  limit on that unit (Requirement 4), the OOM would also have stayed in the
  container, and the host would not have run out of memory.
- A memory limit on the container unit alone would not have helped. The heavy
  process was not in that unit.

## Requirements

1. The nspawn supervisor runs in its own unit under the system manager. It must
   not depend on the terminal or on the user's `user@<uid>.service`.
2. The container survives these events: a stop of the terminal's scope, the
   close of the window or tab that started sandy, and an OOM kill of one
   process in the container.
3. Attach continues to work. The console becomes one more attach. `bash` and
   `exec` attach only to a running container (started by `up` or `up -d`).
   Lifecycle:
   - `up` (no `-d`): when the console exits, sandy stops the container, but
     only if no other attach exists. If other attaches exist, the container
     continues. Then the last attach to exit normally stops it.
   - `up -d`: sandy never stops the container automatically. Only `sandy down`
     (or `rm`) stops it.
   - Loss of a terminal ends only that terminal's attach. It never stops the
     container.
4. The default stays unlimited: `MemoryMax=` and `MemorySwapMax=` keep the
   value `infinity` (`max` in cgroupfs), as today. A later sandy option can set
   a memory limit on the container unit. With a limit, the kernel kills a
   process inside the unit before the host runs out of memory. The option would
   address item 2 of `security-parity.md` (see Related work).
5. Each attach (`sandy -c <name> bash` and `exec`) runs inside the container's
   unit, not in the terminal's scope. Its memory counts against the container
   unit, and against the limit when one is set. An OOM in one attach must not
   end the supervisor, other attaches, or the terminal emulator.
6. The image directory stays descriptor-anchored
   (`--directory=/proc/self/fd/<fd>`). The change must not replace the fd with
   a path.
7. When an attach ends, or its terminal goes away, sandy ends all processes of
   that attach. No orphaned attach processes stay in the container.
8. `up`, `up -d`, `bash`, and `exec` all have the same confinement as the
   container payload: the same seccomp filters and the same capability
   bounding set. This includes `-u root`. Step 1 (see Implementation order)
   delivers this before the console becomes an attach.
9. Resource defaults stay as today: `TasksMax=16384`, `MemoryMax=infinity`,
   `MemorySwapMax=infinity`, and no CPU quota.

## Tool facts (systemd 255, verified in the test VM unless noted)

- `OOMPolicy=` sets what systemd does after the kernel OOM killer (or
  systemd-oomd) kills a process of the unit. `continue`: log it, and the unit
  continues. `stop`: log it, and stop the unit. `kill`: set
  `memory.oom.group=1`, so the kernel kills all processes of the unit
  together. `OOMPolicy=continue` does not prevent the kill. The default is
  `DefaultOOMPolicy=` (`stop`), except `continue` for units with
  `Delegate=yes` (from the man page; not tested).
- Scope units accept `OOMPolicy=` from systemd 253 (systemd `NEWS`, "CHANGES
  WITH 253": "Scope units now support OOMPolicy="). On an older systemd,
  `systemd-run --scope -p OOMPolicy=...` is expected to fail. So sandy passes
  it only when `systemd-nspawn --version` reports 253 or later, and otherwise
  uses the default. An unknown version counts as 0.
- nspawn's stub PID 1 (`(sd-stubinit)`, with `--as-pid2`; source
  `src/nspawn/nspawn-stub-pid1.c` at v255) forks exactly one payload in its
  own session (PID 2 with `--user=root`; see the step 1 facts). It reaps all
  zombies in the container, including orphans of attaches. On
  `SIGRTMIN+3/4/5/6` (halt, poweroff, reboot, kexec) it sends SIGTERM, then
  SIGHUP, to the payload. It ignores SIGTERM and SIGHUP itself. It exits when
  the payload exits, and the container ends. It has no mode without a
  payload. It runs as the payload user; with sandy's `--user=root`, that is
  container root.
- Without `--as-pid2`, the payload is PID 1, and the kernel drops all signals
  sent to it from inside the container (also SIGKILL from container root).
  But the payload must then reap zombies and handle poweroff, which `sleep`
  does not do. Not used.
- The kernel sets a process name (`comm`) from the file name passed to
  `execve`, not from a symlink target. `comm` has at most 15 characters.
  Measured: exec of a symlink `sandy-keepalive -> /usr/bin/sleep` gives
  `comm=sandy-keepalive`, and `pgrep -x sleep` does not match it.
- sandy supports other base images through `SANDY_BOOTSTRAP_BASE` (examples
  in its help: `debian:bookworm`, `ubuntu:noble`). The default is Debian
  trixie (`debian:trixie-slim` for OCI, `debian:trixie` for debootstrap).
- Ubuntu 26.04 uses uutils (the Rust coreutils) by default:
  `/usr/bin/sleep -> ../lib/cargo/bin/coreutils/sleep` (package
  `coreutils-from-uutils`). A uutils utility refuses to run when `argv[0]`
  does not match its name. bash selects no behavior from `argv[0]`, except
  POSIX mode when the name is `sh`.
- With a `#!` script, the kernel execs the script file itself. So the script
  must be on a file system without `noexec`. A file that bash only reads (as
  `bash <file>`) has no such requirement.
- nspawn `--property=` sets properties on the machine scope that nspawn
  creates. It does not apply with `--keep-unit`.
- nspawn `--keep-unit` makes the unit that nspawn runs in the machine unit.
  nspawn then creates two subgroups in that unit: `payload` (the container,
  owned by the container's root UID with `--private-users`) and `supervisor`
  (nspawn, owned by host root). The unit's own cgroup is owned by host root.
- `systemd-run --scope` registers its own PID in a new system scope, then
  execs the command. So the command inherits the caller's file descriptors.
  A transient service (`systemd-run` without `--scope`) is started by PID 1
  and does not inherit them.
- A transient service whose main process exits with an error stays loaded as
  `failed`. Then `systemd-run --unit=<same name>` is refused until
  `reset-failed`, or unless the unit had `-G`/`--collect`. nspawn exits with
  status 1 or 255 on a normal stop. A scope does not have this problem.
- `su -c` puts the command in a new session. So a hangup of the terminal's pty
  does not reach the command.
- podman's runtimes (crun, runc) put an exec process in the container's cgroup.
  On `EBUSY`, they fall back to the cgroup of the container's init process
  (from `/proc/<init pid>/cgroup`). crun checks that this cgroup is below the
  container's cgroup, and retries up to 20 times. Sources: runc
  `libcontainer/process_linux.go` (`addIntoCgroupV2`, runc issue #2356); crun
  `src/libcrun/cgroup-setup.c` (`enter_cgroup_v2`). Read at runc 97f76a9 and
  crun 3c020c5.

## Test results (2026-09-29)

Environment: a disposable VM, Ubuntu noble cloud image, systemd
255.4-1ubuntu8.17, kernel 6.8.0-142-generic, 2 CPU, 4 GiB. Container: debootstrap `--variant=minbase` noble with user
`developer` (UID 1000). Options as in sandy before this change:
`--private-users=pick --as-pid2 --user=developer`; for the prototype, payload
`sleep infinity` and `--console=passive`. The prototype attach helper moves itself into a cgroup (`mkdir` of the leaf only),
then execs `nsenter -t <leader> -a -- su developer ...`. Tests 8 to 10 also
use debootstrap `--variant=minbase` root file systems for Ubuntu 26.04
(`resolute`, uutils `sleep`) and Debian trixie (GNU `sleep`). Tests 12 to 14
also use two more disposable VMs: Ubuntu jammy (systemd 249.11, kernel 5.15)
and Debian trixie (systemd 257.13, kernel 6.12).

1. **Unit layout (transient service, `--keep-unit`).**
   `sandy-t1.service/{payload,supervisor}`. `payload` is owned by UID
   161677312 (the container root). The unit's cgroup and `supervisor` are owned
   by host root. `OOMPolicy=continue`, `Delegate=yes`.
2. **The container can block a move into its cgroup root.** Container root
   moved its processes into a child cgroup and wrote `+memory` to the root's
   `cgroup.subtree_control`. Then a host write to `payload/cgroup.procs` failed
   with `EBUSY` (errno 16). A write to the child cgroup that the container made
   succeeded.
3. **Attach in a sibling cgroup (B2).** An attach in
   `sandy-t1.service/attach-a1` shows `0::/../attach-a1` in
   `/proc/self/cgroup` inside the container, with no host details. The
   container's cgroupfs does not show it. `systemctl stop` killed the attach
   processes and removed the whole cgroup tree.
4. **OOM in an attach under a unit limit.** `MemoryMax=1G`,
   `MemorySwapMax=0`, `tail /dev/zero` in `attach-hog`. Kernel:
   `constraint=CONSTRAINT_MEMCG, oom_memcg=/system.slice/sandy-t1.service,
   task_memcg=/system.slice/sandy-t1.service/attach-hog, task=tail`. Only
   `tail` died. The unit stayed `active`. The payload, the supervisor, and an
   idle attach survived. systemd logged "A process of this unit has been
   killed by the OOM killer." The empty `attach-hog` cgroup stayed until it
   was removed by hand.
5. **Loss of the terminal (sandy's chain: `su ... -c "script -qec '...'
   /dev/null"` under a pty, in a scope that acts as the terminal; then stop that
   scope).** The container survived. An idle interactive shell got EOF and
   exited. A busy foreground job (`sleep`) did not end: `su`, the inner
   `script`, and the job continued, with `su` re-parented to PID 1.
   `security-parity.md` ("PTY and signal behavior") already records this
   orphan behavior for SIGTERM on the current path. With B2 the orphans stay
   inside the container's unit, but nothing can reattach to them.
6. **Supervisor in a transient scope, fd-anchored.** A caller in a separate
   scope opened the image directory as an fd and ran
   `systemd-run --scope --unit=sandy-t1 -p Delegate=yes -p OOMPolicy=continue
   -p MemoryMax=1G -p MemorySwapMax=0 -- systemd-nspawn --keep-unit
   --console=passive --directory=/proc/self/fd/N ...` with `pass_fds`,
   `start_new_session=True`, and no tty. Then the caller exited.
   - The container started from the inherited fd.
   - The caller's scope ended. `sandy-t1.scope` stayed `active`. nspawn had
     PPID 1, its own session, and no tty.
   - Layout: `sandy-t1.scope/{payload,supervisor}`, the same as test 1.
   - All four properties were in effect on the scope.
   - OOM in a B2 attach: only `tail` died, and the scope stayed `active`.
   - `machinectl poweroff t1` removed the scope and its cgroup. No failed
     unit stayed.
   - The PID that `Popen` returns is the nspawn supervisor (`systemd-run
     --scope` execs).
7. **`sandy-keepalive` through a read-only bound symlink.** Host directory
   with only `sandy-keepalive -> /usr/bin/sleep`, bound with
   `--bind-ro=<dir>:/run/sandy`. Payload `/run/sandy/sandy-keepalive
   infinity`, `--user=root`, in the scope form of test 6.
   - PID 2: `comm=sandy-keepalive`, `exe=/usr/bin/sleep`, host UID 161677312
     (container root).
   - PID 2 maps `/usr/lib/x86_64-linux-gnu/libc.so.6` in the container's
     mount namespace, so it runs the container's own `sleep` and libc.
   - As `developer`: `kill -9 2` gave "Operation not permitted", and after
     `kill -9 -1` the container was still running.
   - As container root: `ln -sf ... /run/sandy/sandy-keepalive` gave
     "Read-only file system".
   - `machinectl poweroff` stopped the container, and the scope became
     inactive.
   - Rejected later: on Ubuntu 26.04 the same symlink fails with uutils
     ("Security violation: Requested utility `sandy-keepalive` does not match
     executable name"), exit status 1. Checked in an Ubuntu 26.04.1
     container.
8. **Symlink `sandy-keepalive -> /bin/bash` with the loop as a `-c` string**,
   on Ubuntu 26.04 and Debian trixie, scope form, `--user=root`.
   - PID 2: `comm=sandy-keepalive`, `exe=/usr/bin/bash`, container root. Child:
     `sleep infinity`, `comm=sleep`.
   - As `developer`: `kill -9 2` gave "Operation not permitted". After
     `kill -9 -1` the container was still running.
   - Killing the `sleep` child (`pkill -x sleep` as container root on 26.04;
     SIGKILL from the host on trixie, which has no `pkill` in minbase): a new
     `sleep` started, and the container continued.
   - Host directory removed while running: the container continued, and
     `/run/sandy` was empty in the container.
   - `machinectl poweroff`: scope inactive after 0.14 s (26.04) and 0.13 s
     (trixie).
   - Loop logic, outside nspawn: SIGTERM to the keepalive gave exit 0 with no
     `sleep` left. `sleep` not in `PATH` gave exit 127 after 7 ms (no spin).
     `sleep` with a bad argument gave exit 1.
9. **Script with a `#!/bin/bash` shebang, exec'd from the bind mount**, on
   Ubuntu 26.04.
   - Exec-capable bind source: works. PID 2 `comm=sandy-keepalive`,
     `cmdline=/bin/bash /run/sandy/sandy-keepalive`. The bind is `ro` in the
     container. Respawn and poweroff (0.14 s) work.
   - `noexec` bind source (tmpfs mounted `noexec`): the container does not
     start ("Container t9 failed with error code 1").
   - The script passes ShellCheck.
10. **Symlink `sandy-keepalive -> /bin/bash` reading `keepalive.sh` (the
    chosen design)**, `noexec` bind source, on Ubuntu 26.04 and Debian
    trixie.
    - PID 2: `comm=sandy-keepalive`, `cmdline=/run/sandy/sandy-keepalive
      /run/sandy/keepalive.sh`. Child: `sleep`.
    - PID 2 environment has no `BASH_ENV`. Keys: `PATH container TERM HOME
      USER LOGNAME container_uuid NOTIFY_SOCKET LANG container_host_version_id
      container_host_id`.
    - Bind source unmounted, and (26.04) host files deleted while running:
      the container continued. PID 2 kept an open fd on
      `keepalive.sh (deleted)`, and three kills of the child each started a
      new `sleep`.
    - `machinectl poweroff`: scope inactive after 0.14 s (26.04) and 0.22 s
      (trixie).
11. **`init.sh` under the payload's confinement** (systemd 255, trixie image).
    sandy's options: `--network-bridge`, `--private-users=pick`,
    `--ephemeral`, `--tmpfs=/tmp:mode=1777`, sandy's `--system-call-filter`
    value, and the `:idmap` bind of `/init.sh`. `init.sh` ran as a child of
    the payload, so it had the payload's exact filter and bounding set.
    - Payload child: `CapBnd=00000000fdecbfff` (includes `CAP_NET_ADMIN`, bit
      12), `Seccomp=2`, `Seccomp_filters=5`, `NoNewPrivs=0`. `init.sh` rc=0,
      `host0` 10.99.0.2/24, default route through 10.99.0.1, ping to the
      gateway OK.
    - Through `nsenter` (before this change): `CapBnd=000001ffffffffff`,
      `Seccomp=0`,
      `init.sh` rc=0.
    - `security-parity.md` reports `CapBnd=00000000fdecabff` (no
      `CAP_NET_ADMIN`). The difference is probably its network mode: with
      `--network-bridge` (a private network), nspawn keeps `CAP_NET_ADMIN`.
12. **`init.sh` under confinement on every supported systemd path**, with
    sandy's options for each version, both images, ephemeral and persistent
    (12 cases). Below 250: `--private-users=1000000:65536
    --private-users-ownership=auto`, and the `init.sh` copy `chown`ed to
    1000000, mode 0500, no `:idmap`. From 250: `--private-users=pick` and an
    `:idmap` bind of a host-root copy, mode 0500.
    - systemd 249, 255, and 257; trixie and 26.04; ephemeral and persistent:
      all pass. Each case: `CapBnd=00000000fdecbfff`, `Seccomp_filters=5`,
      `NoNewPrivs=0`, `init.sh` rc=0, address and default route set, ping OK.
13. **systemd 249: a bind target that is missing in the image.** With the
    userns options below 250, nspawn cannot create a missing bind mount point
    inside the image tree: "Failed to create mount point
    /var/lib/machines/<image>/init.sh: Value too large for defined data type"
    (`EOVERFLOW`). The userns options alone work, and the bind works when the
    image already has the target file. sandy binds `/init.sh` only when the
    image contains it (sandy writes it at build time only for a container
    with a network configuration), so sandy is not affected. The image tree stayed owned by UID 0 after
    `--private-users-ownership=auto`; the cause is probably an idmapped root
    mount on 249 (not verified).
14. **The keepalive (`/run/sandy` bind) on systemd 249, 255, and 257**, both
    images, ephemeral and persistent, scope form, `--user=root`, sandy's
    userns options for the version (12 cases). All pass: PID 2
    `comm=sandy-keepalive` with a `sleep` child, host directory deleted while
    running without effect, a killed `sleep` restarted, clean poweroff
    (0.10 to 0.43 s), scope inactive. `/run/sandy` does not exist in the
    image. nspawn mounts its own tmpfs on the container's `/run`
    (`/run rw,nosuid,nodev tmpfs`, verified on 249), so the mount point is
    created in that tmpfs and test 13 does not apply. In the container the
    bind is `ro`.

Tests 11 to 14 reproduced sandy's options by hand. They did not run sandy
itself.

Also observed: `machinectl terminate <name>` after a successful
`machinectl poweroff <name>` fails with "No machine '<name>' known" (rc=1).
So `_machine_poweroff` now runs `terminate` only when the machine or its
scope is still there 5 s after `poweroff`, and it discards the stderr of
`terminate`.

## Design

### Supervisor: transient scope

```
systemd-run --scope --quiet --unit=sandy-<name>.scope --slice=system.slice \
    --description="Sandy container <name> (attached|detached)" \
    --property=Delegate=yes [--property=OOMPolicy=continue] \
    --property=TasksMax=16384 \
    -- systemd-nspawn --keep-unit --console=passive --as-pid2 --user=root \
       --directory=/proc/self/fd/<fd> \
       --bind-ro=<private host dir>:/run/sandy ... \
       /run/sandy/sandy-keepalive /run/sandy/keepalive.sh
```

- Keep the resource defaults of the machined scope. Measured in the VM:

  | Unit | TasksMax | MemoryMax | MemorySwapMax | CPUQuotaPerSecUSec |
  |---|---|---|---|---|
  | machined scope (before this change) | 16384 | infinity | infinity | infinity |
  | `systemd-run --scope` | `DefaultTasksMax` (4584 in the VM) | infinity | infinity | infinity |

  machined sets `TasksMax=16384` on the scopes that it creates. A scope from
  `systemd-run` gets `DefaultTasksMax=`, which depends on the host. So sandy
  must set `-p TasksMax=16384` explicitly. The memory and CPU defaults already
  match.
- A later sandy option can add `-p MemoryMax=`, `-p MemorySwapMax=`, and other
  limits (Requirement 4). The default passes none.

- Start it through `_run_secure_subprocess_popen` with `pass_fds`,
  `start_new_session=True`, and stdin, stdout, and stderr on `/dev/null`, for
  both `up` and `up -d`.
- A scope, not a service, because only a scope keeps the descriptor-anchored
  `--directory` (Requirement 6). A scope also needs no `-G` or `reset-failed`.
- `OOMPolicy=continue` explicitly, although `Delegate=yes` makes it the
  default. Pass it only when `systemd-nspawn --version` reports 253 or later.
  Otherwise omit it and use the default (see Tool facts).
- `--console=passive` means no console. The payload must stay alive with no
  tty. `sandy up` starts the scope, then attaches. So the console becomes one
  more attach (Requirement 3).
- If a unit `sandy-<name>.scope` already exists, `up` fails closed.
- After the start, `up` treats "the scope ended before the container was
  ready" as an error and reports nspawn's exit status. This covers images
  that cannot run the keepalive.
- Ready means that the readiness probe, an attach as container root, runs.
  The entry helper refuses an attach until the payload exists
  (`security-parity.md` item 5), and the probe tries again every 0.5 s, for
  up to 60 s.
- Rejected: a transient service (loses the fd; needs `-G`), `machinectl start`
  or `systemd-nspawn@.service` (fixed `--boot` in `ExecStart=`, per-run
  options would need persistent `.nspawn` files and drop-ins, no fd passing),
  D-Bus `StartTransientUnit` from Python (no D-Bus in the standard library).

### Payload: `sandy-keepalive`

- PID 1 stays nspawn's stub init (`--as-pid2`). It reaps zombies and turns
  `machinectl poweroff` into SIGTERM and SIGHUP for PID 2. It exits when PID 2
  exits, so the container needs a PID 2 that does not exit.
- The repo has `sandy-keepalive.sh`, checked by ShellCheck like the other
  shell sources:

  ```bash
  #!/bin/bash
  # Keep the container's PID 2 alive until poweroff (SIGTERM or SIGHUP).
  trap 'kill "$!" 2>/dev/null; exit 0' TERM HUP
  while :; do
      sleep infinity &
      wait "$!"
      rc=$?
      # Restart sleep only if a signal killed it; fail closed otherwise.
      [ "$rc" -gt 128 ] || exit "$rc"
  done
  ```

- At `up`, sandy creates a private host directory with `mkdtemp` (as for the
  `init.sh` bind copy) and sets its mode to 0755. It holds exactly two
  entries:
  - `sandy-keepalive`: a symlink to `/bin/bash`.
  - `keepalive.sh`: a copy of `sandy-keepalive.sh`, mode 0644, written with
    the same safe-write pattern as the `init.sh` copy.
- sandy binds the directory read-only at `/run/sandy`. PID 2 is
  `/run/sandy/sandy-keepalive /run/sandy/keepalive.sh`, as container root
  (`--user=root`).
- How it works:
  - The kernel takes `comm` from the name passed to `execve`, so PID 2 shows
    as `sandy-keepalive` in `ps`, `pgrep`, and OOM logs.
  - The kernel resolves the symlink inside the container's mount namespace. So
    PID 2 runs the image's own bash with the image's own libc. The host
    directory holds no binary.
  - bash only reads `keepalive.sh`. So a `noexec` bind source (for example, a
    host `/tmp` mounted `noexec`) does not matter. The `init.sh` copy works in
    the same way (`/bin/sh /init.sh`).
  - The child is plain `sleep`, called by its own name. So GNU coreutils,
    uutils, and busybox all accept it.
- The loop:
  - Poweroff: the stub sends SIGTERM to PID 2 only (`kill_and_sigcont(pid,
    SIGTERM)`), not to its process group. bash is in `wait`. The bash manual:
    a trapped signal makes `wait` "return immediately with an exit status
    greater than 128, immediately after which the trap is executed". The trap
    ends `sleep` and runs `exit 0`, so the loop never reaches the status
    check. If the signal arrives outside `wait`, bash runs the trap after the
    current simple command, before the next `wait`. The following SIGHUP, the
    end of the PID namespace, and sandy's `machinectl terminate` are
    backstops.
  - A signal to the `sleep` child: no trap runs in bash, `wait` returns the
    child's status (above 128), and the loop starts a new `sleep`.
  - `sleep` missing or failing: the status is 127 or another value of 128 or
    less, so the keepalive exits. The container stops, and `up` reports the
    error. The loop never spins.
- Dependencies on the image: `/bin/bash` (also required by the entry helper,
  which runs `/bin/bash -c "script -qec ... /dev/null"`) and a `sleep` in
  `PATH`. The symlink and the
  script do not come from the image, because a persistent image can change.
  The binaries come from the image, as does every binary that the container
  runs.
- nspawn builds the payload environment itself (measured: `PATH`,
  `container`, `TERM`, `HOME`, `USER`, `LOGNAME`, `container_uuid`,
  `NOTIFY_SOCKET`, `LANG`, `container_host_version_id`, `container_host_id`).
  So the image cannot set `BASH_ENV` for PID 2, and the non-interactive bash
  reads no startup file.
- sandy removes the host directory once PID 2 has opened the script. After
  the container is ready, `up` waits up to 10 s until a descriptor of PID 2
  links to `/run/sandy/keepalive.sh` (read with `readlink` on the host
  `/proc/<pid>/fd`). From then on PID 2 does not need the directory: bash
  keeps its open fd on the deleted script, and the symlink was resolved at
  exec (tests 8 and 10). A ready container proves only that PID 2 exists.
  Measured with PID 2 held at its fork, before execve, on systemd 249, 255,
  and 257 with the Debian trixie and Ubuntu 26.04 images: without the wait,
  `up` removed the directory and returned, and the container stopped when
  PID 2 ran.
- Security: the payload runs as container root. With `--user=root`, the stub
  PID 1 also runs as container root for the container's whole life. Container root is an
  unprivileged host UID, limited by nspawn's bounding set and seccomp. The
  keepalive reads no input and uses no network. So this adds no new attack
  surface. The effect: UID 1000 cannot send it signals, so an accident such
  as `kill -9 -1` as `developer` does not stop the container. A `-u root`
  attach can still stop it, as before this change.
- The name has 15 characters, which is the `comm` limit. It is not
  `sandy-init`, because the process is not the init, and sandy already has
  `/init.sh`.
- Before this change, `up -d` ran the user's login shell as the payload, kept
  alive by nspawn's read-only console (from the man page; not tested). The
  keepalive replaced it.
- Rejected payloads:
  - `sleep` through a symlink named `sandy-keepalive` (test 7): works with GNU
    coreutils, but fails on Ubuntu 26.04. There `/usr/bin/sleep` is a uutils
    link (`../lib/cargo/bin/coreutils/sleep`), and it refuses to run under
    another name: "Security violation: Requested utility `sandy-keepalive`
    does not match executable name". Any rename through `argv[0]` fails in
    the same way.
  - Plain `sleep infinity`: works everywhere, but the process is named
    `sleep`, and `pkill sleep` as root stops the container.
  - A host `sleep` binary bind-mounted in: a dynamically linked host binary
    loads the container's libc, and can fail with symbol version errors.
  - A script with a `#!/bin/bash` shebang, exec'd from the bind mount
    (test 9): works, but the container does not start when the bind source
    is `noexec`.
  - bash with the loop as a `-c` string: works (test 8), but the loop is a
    quoted string in Python that ShellCheck cannot check.
  - A static binary: works with any image and sets its own name, but needs a
    compiler on the host and adds a compiled, architecture-specific artifact
    to a standard-library Python project.
  - `/init.sh` creates the files: `/init.sh` runs after the container starts
    (`_run_init_script` -> `_exec_as_root("/bin/sh /init.sh")`), so the
    payload would not exist yet. It also runs only when the network is
    configured and the image has `init.sh`. And files in the container's
    writable file system can be changed by container root.

### Lifecycle of `up`, `up -d`, and attaches

- sandy records whether `up` used `-d` in the scope's `Description=`
  ("Sandy container <name> (attached|detached)"). Only root can set it, and
  any other value means "do not stop" (see the step 2 decisions).
- When an attach (the console, `bash`, or `exec`) exits normally, its sandy
  process takes the lifecycle lock, with SIGHUP and SIGTERM blocked, and
  counts the attaches: the `attach-*` leaves whose `cgroup.events` show
  `populated 1`. It removes the empty leaves, for `-d` containers too. It
  counts populated leaves, not directories, because a sandy process killed
  with SIGKILL can leave an empty leaf. sandy runs `_machine_poweroff` only
  when the count is zero, no up-console marker exists, and the scope's
  description says "(attached)". `_machine_poweroff` also removes the port
  mappings. So the port-forwarding cleanup stays in one function, with a new
  trigger.
- The up-console marker closes a start race. Without `-d`, `up` holds
  the lifecycle lock while it starts the scope and creates the marker in the
  scope's cgroup. So no attach can exit, and stop the container, before the
  console starts. The console's own exit removes the marker before the count,
  and a console hangup removes it without a count.
- A new attach creates its leaf under the same lock, so a concurrent start
  and stop cannot both succeed.
- Loss of a terminal (SIGHUP or SIGTERM) runs only the attach cleanup
  (`cgroup.kill` and remove the leaf). It does not count or stop.
- A container started with `-d` is never stopped by an attach exit.
- **sandy killed with SIGKILL** (decision: parent-death signal). The entry
  helper (the host-side re-exec of sandy, in the attach leaf) sets
  `PR_SET_PDEATHSIG` to SIGTERM. When the sandy process that started it dies
  for any reason, including SIGKILL, the kernel sends the helper SIGTERM. The
  helper writes `1` to its leaf's `cgroup.kill`, which ends the whole attach
  and the helper, and the leaf becomes empty. Without this, an orphaned leaf
  stays populated, and for a container started without `-d` the "last attach
  out" rule would never fire.
  - `PR_SET_PDEATHSIG` fires when the **thread** that created the child exits,
    not the process. sandy starts no threads, so the main thread is the
    parent thread of every helper.
  - Accepted gap: if the helper itself also gets SIGKILL, the orphans stay
    until the container stops. `sandy down` removes them.
  - After a SIGKILL of sandy, no count runs for that attach. The empty leaf
    does not block a later count, but a container started without `-d` keeps
    running until another attach exits normally, or until `down`.
- **Container stopped without sandy** (decision: `up` removes stale rules).
  With no sandy process waiting for the container, a stop by the container
  itself (container root ends PID 2 or sends a poweroff signal to PID 1), a
  dead supervisor, or `machinectl terminate` outside sandy leaves the host
  DNAT rules and port state of `-p` mappings. Before this change, `up -d` had
  the same gap.
  - Effect: low for security. The rules forward host loopback ports to the
    container's bridge address. That address stays reserved, because IP
    allocation reads the `init.sh` files of existing machine directories. But
    the port state can block another container from the same host port until
    the next `up` of the same name, or `rm`. `down` of a stopped container
    does nothing.
  - Fix: `run_up` refuses a running container. After that check, before the
    network setup, `up` runs `_cleanup_port_mappings_for_container(<name>)`,
    the function that `rm` uses. It runs on every `up`, with or without `-p`,
    and removes only this name's Sandy-owned rules and state. It uses only the
    network that exists: it never creates the bridge or the firewall base.
    Before this change, `up` without `-p` removed only this name's port state
    (`remove_stale_port_state`).

### Attach: sibling cgroup in the container's unit (B2)

- sandy makes a random leaf name, and the entry helper creates only the leaf
  `<unit cgroup>/attach-<random>`. It fails if the unit's cgroup does not
  exist. The path comes from the validated container name
  (`/sys/fs/cgroup/system.slice/sandy-<name>.scope`, owned by host root), not
  from container data. The helper proves that this scope runs the machine
  from the Leader's host cgroup, which must be below the scope's `payload`.
- The entry helper moves itself into the leaf under the lifecycle lock,
  before its first fork and before any `setns`. The middle process and the
  session inherit the leaf.
- When the attach ends, or sandy gets SIGHUP or SIGTERM, sandy writes `1` to
  the leaf's `cgroup.kill` and removes the leaf (Requirement 7).
- Result: the attach counts against the container's unit (and its limit, if
  one is set), an OOM kills only one process, and the attach ends when the
  container stops. From the user's view this is the same as `podman exec`.

Differences from podman (internal only): the container's cgroupfs does not
show the attach, and `/proc/self/cgroup` shows `/../attach-<x>`.

Rejected alternatives:

- **B: move the attach into `payload`, as podman does.** A plain write fails
  if the container arranges it (test 2). The runc and crun fallback reads a
  cgroup path from `/proc/<init pid>/cgroup`, which the container controls,
  and the container then chooses where a host-started process goes. B also
  gives no limit that tools in the container can see: systemd can set the
  limit only on the unit, and `payload/memory.max` stays `max`.
- **A: one system scope for each attach.** It isolates the OOM, but the attach
  is outside the container's accounting and limit.
- **C: a slice for each container, with attach scopes in the slice.**
  `systemd-run` cannot create a slice unit. Properties need D-Bus or
  `systemctl set-property --runtime` drop-ins that sandy must remove. The
  attach is still outside the container's cgroup.

## Related work in `security-parity.md`

- **Item 1 (no seccomp on `exec` and `bash`).** The recommended fix replaces
  `nsenter` with a re-exec of sandy that enters the namespaces and applies the
  container's seccomp filters and capability bounding set. That re-exec is the
  correct place for the B2 cgroup move: it starts single-threaded, so it can
  move itself before `setns`, with no `preexec_fn`. Step 1 built it; step 2
  added the move.
  Correction to item 1: its "Exposure" section calls the gap "Limited",
  because interactive `up` is the common path. The goal is that `up`,
  `up -d`, `bash`, and `exec` all have the same confinement (Requirement 8).
  With this design every session is an attach, so the gap would apply to all
  sessions. `security-parity.md` item 1 now says this ("Exposure
  (corrected)").
- **Item 2 (no memory or CPU limits).** It recommended `--property=MemoryMax=`
  on nspawn's machine scope (its recommended fix now records the correction).
  With `--keep-unit` that option does not apply,
  and a limit on the machine scope would not cover attaches or the supervisor.
  With this design, a later option puts the limits on the `systemd-run --scope`
  unit. This change keeps the defaults unlimited, so it does not close item 2.
  The item's other points (validated CLI options, `size=` on the `/tmp`
  tmpfs) still apply.
- **"PTY and signal behavior".** It records the orphan behavior of test 5 and
  says to fix it separately. The `cgroup.kill` cleanup of each attach cgroup is
  that fix.

## Implementation order

**Step 1: equal confinement for every entry path** (`security-parity.md`
item 1). Replace `nsenter` in `_exec` and `_exec_as_root` with a re-exec of
sandy that enters the namespaces and applies the payload's seccomp filters and
capability bounding set, as item 1 describes. Test it against the layout before
step 2:
an attach must report the same `Seccomp`, `Seccomp_filters`, and `CapBnd` as
the payload. `security-parity.md` item 1 records the result (see Related
work).

Step 1 decisions:

- Small, targeted commits. Step 1 adds only the pinning it needs: a Leader
  pidfd and the Leader's `/proc/<pid>/ns/*` fds, opened once, with a pidfd
  liveness check after all fds are open. All `setns` calls use those fds.
- `NoNewPrivs=0`, as on `up`: install the filters before the uid change,
  while still namespaced root. `NoNewPrivs=1` on all paths
  (`--no-new-privileges=yes`) can be a later change.
  `security-parity.md` contradicted itself on this order; its item 1
  corrections now record the order as built.
- Remove `su`. The helper sets the uid, groups, and environment itself. The
  attach then matches the `up` payload more closely: no PAM session.
- Confine `init.sh` (`_exec_as_root`) too. Tests 11 and 12 show that it works
  under the payload's confinement on systemd 249, 255, and 257.
- Read `CapBnd` on the host side, from `/proc/<leader>/status`, before any
  `setns`. `security-parity.md` reads `/proc/1/status` inside the container.
  After `setns(mnt)`, `/proc` is the container's mount, and container root
  can change the container's mount table. So a read inside can be spoofed
  (inference, not tested). Read the filters with `PTRACE_SECCOMP_GET_FILTER`
  on the host, under the lifecycle lock, and revalidate the Leader through
  its pidfd after `PTRACE_DETACH`.
- `seccomp` and `setns` go through `syscall()`, because Python 3.10 has no
  `os.setns`. A table holds the syscall numbers for x86_64 and aarch64. Any
  other architecture fails closed.
- Fail closed on every error before `execv`. Never fall back to unconfined
  entry.
- The helper runs as `[sys.executable, "-I", <pinned sandy>, <internal
  mode>, ...]` through the existing subprocess wrappers. It starts
  single-threaded. It accepts only validated argv values and the expected
  inherited fds, so a manual call cannot do more than `nsenter` could before
  this change.

Helper flow as built (steps 1 and 2):

1. Parent (sandy, which starts no threads): validate the request, make the
   attach leaf name, keep the pty relay, and start the helper with 9
   validated argv values: machine, Leader PID, parent PID, attach leaf, user,
   home, working directory, kind (tty or sh), and command. The helper gets
   only stdin, stdout, stderr, and the pinned script descriptor; it refuses
   any other inherited descriptor.
2. Helper, on the host, before any `setns`: set the parent-death signal and
   check `getppid()`; take the lifecycle lock; open the Leader pidfd; check
   with `machinectl show -p Leader` that the PID is still the Leader; check
   that the Leader's cgroup is below the scope's `payload` (a Leader still in
   the scope's own cgroup means that the container is still starting);
   require the payload (container PID 2) among the Leader's children, or
   fail closed because the container is still starting (`security-parity.md`
   item 5); open the `/proc/<leader>/ns/*` fds; `PTRACE_SEIZE` and
   `PTRACE_INTERRUPT` the Leader (the stub PID 1) and `waitpid(__WALL)`; read
   the filters with `PTRACE_SECCOMP_GET_FILTER` for index 0, 1, and so on
   until `ENOENT` (any other errno fails, and a Leader with no filter fails);
   `PTRACE_DETACH` on every path, with any signal that the stop took off the
   queue; read `CapBnd` from the host's `/proc/<leader>/status`; confirm
   through the pidfd that the Leader is still alive; require the payload's
   filter count and `CapBnd` to equal the Leader's; join the attach leaf;
   release the lock.
3. The helper becomes a child subreaper and forks the middle process. The
   middle process calls `setns` on each pinned fd in the order `cgroup, ipc,
   uts, net, pid, mnt, user` (user last), becomes container root, forks the
   session (`CLONE_NEWPID` applies to children only), and exits at once. The
   session is reparented to the helper, which waits for it.
4. Session: `PR_CAPBSET_DROP` for each capability not in `CapBnd`, then a
   check with `PR_CAPBSET_READ`; install the filters oldest first (index
   order: index 0 is the oldest filter, measured on kernels 5.15, 6.8, and
   6.12) with `seccomp(SECCOMP_SET_MODE_FILTER)` while still namespaced root;
   read the container's `/etc/passwd` and `/etc/group`; `setgroups`,
   `setresgid`, `setresuid`; `chdir`; reset the signals; `execve` with the
   environment from `_container_environment`. For `bash` and `exec` (kind
   tty): `/bin/bash -c "script -qec '<cmd>' /dev/null"`, without `su`. For
   `_exec_as_root` and the readiness probe (kind sh): `/bin/sh -c <cmd>`.

Step 1 commits (each with unit tests, `make check`, and `make coverage`):

1. `ctypes` primitives: `ptrace`, `prctl`, `setns`, and `seccomp` wrappers,
   errno handling, the architecture table, and the `sock_fprog` layout. Unit
   tests mock `libc` and assert exact calls and errors.
2. Host-side extraction of the filters and `CapBnd`, under the lock, with
   pidfd revalidation. Unit tests: index order; `ENOENT` ends the list and
   other errnos fail; malformed `CapBnd`; the Leader exits during
   extraction; detach on every error path.
3. The internal helper mode: strict argv parsing, fork, `setns`, fork,
   confine, `execv`, exit status and signal propagation. Unit tests: call
   order, each fail-closed path, and rejection of a direct call without the
   expected fds.
4. Switch `_exec` (`bash` and `exec`, default user and `-u root`) and
   `_exec_as_root` to the helper, and remove `su`. Unit tests: exact argv and
   fds; no `nsenter` path remains.
5. Documentation: `security-parity.md` item 1 (the "Exposure" framing, the
   order contradiction, the host-side `CapBnd` read, `fdecbfff` with a
   private network, and the filter index order: its step 4 says "Index 0 is
   the most recent filter", but measurement shows that index 0 is the oldest)
   and the README (attach behavior, no PAM session).

Step 1 E2E tests (test VMs with systemd 249, 255, and 257; trixie and Ubuntu
26.04 images; with sandy itself):

1. `Seccomp`, `Seccomp_filters`, `CapBnd`, `CapEff`, and `NoNewPrivs` match
   field for field on `up`, `up -d` + `exec`, and `bash`, for the default
   user and for `-u root`.
2. A syscall probe (a Python program that runs with python3 in the
   container) gives the same allow and deny result on every path. At least these are
   denied everywhere: `add_key`, `request_key`, `keyctl`, `perf_event_open`,
   `bpf`, `iopl`, `ioperm`, `clock_adjtime`, `quotactl`, `uselib`. Landlock
   stays allowed on every path.
3. 150 runs of an attach with no `SIGSYS` (covers CPython running after the
   filter install).
4. The attach environment is the allow-list of `_container_environment`.
5. Extraction failure (for example, the Leader exits during the attach)
   refuses the command.
6. `init.sh` runs through the helper with real sandy, and the network comes
   up.

Step 1 facts that differ from the plan above or that step 2 needs (all
measured in the test VMs):

- Filter index order: index 0 is the oldest filter (kernels 5.15, 6.8, 6.12).
  Install in index order. `security-parity.md` said the opposite.
- The helper design as built (`sandy`: `_entry_helper_main`,
  `_run_confined_entry`, `_enter_namespaces_and_fork`, `_confine_and_exec`):
  the helper is a child subreaper. The middle process empties `sys.meta_path`
  and `sys.path`, joins the namespaces, calls `setresuid(0)` in the container
  user namespace (host uid 0 in the host PID namespace could signal any host
  root process), forks the session, and exits at once. The helper finds the
  session in its host `/proc` children list and waits for it. Orphans inside
  the container go to the container's PID 1, not to the helper.
- For the B2 cgroup move in step 2: the helper, the middle process, and the
  session are the processes to place. As built, the helper joins the leaf
  under the lifecycle lock, before its first fork, so the middle process and
  the session inherit it.
- Helper argv in step 1: machine, Leader PID, user, home, workdir, kind (tty
  or sh), command. Step 2 adds sandy's PID and the attach leaf (see the step
  2 decisions). uid, gid, and groups are resolved in the session from the
  container's `/etc/passwd` and `/etc/group` after the filters are installed,
  with nspawn's rules: root gets no supplementary groups; other users get the
  groups that list them as members.
- The pinned script must be a regular file that only its owner can write (any
  owner; decided by the user).
- The lifecycle lock exists: one global `sandy.__cache/lifecycle.lock`,
  exclusive, with a bounded wait of 10 seconds. Step 2's attach counting and
  leaf creation reuse it. Most holders are short. Two hold it longer: a stop
  through `_machine_poweroff` (up to two 5 s waits), and `up` without `-d`
  until the up-console marker exists (up to 5 s). A waiter gives up
  after 10 s.
- Container PIDs: with `--user=developer`, PIDs 2 and 3 are `getent passwd` and
  `getent initgroups`, and the payload is PID 4. With `--user=root` the
  payload is PID 2. The stub init runs as the payload user. So the keepalive
  (`--user=root`) is PID 2; tests should still identify it by name.
- `init.sh` now runs with the payload's bounding set and needs
  `CAP_NET_ADMIN`.
- The time namespace is not joined; it was the host's in every measured case.
- Exit status: SIGKILL of the session is passed on as SIGKILL (a container
  stop gives -9 to the caller).
- `nsenter` is gone from sandy. The E2E harness still uses `nsenter` and
  `setpriv` for its own fixtures.

**Step 2: this change**, on top of step 1:

1. The supervisor scope: `TasksMax=16384`, and `OOMPolicy=continue` only on
   systemd 253 or later.
2. The `sandy-keepalive` payload.
3. The B2 attach cgroup, placed by the step 1 entry process before `setns`,
   with `cgroup.kill` cleanup.
4. `up` as start plus attach, the `-d` record, the lifecycle rules, and the
   parent-death signal in the entry helper.
5. The stop path, including the `machinectl terminate` failure after
   `poweroff`, and the stale-rule cleanup at the start of `up`.

A run with an Ubuntu 26.04 OCI image on systemd 255 passed the keepalive,
respawn, attach, and network checks. With `sleep` hidden, `up` failed in
0.7 s with exit status 127 and left no machine, scope, or keepalive directory.

Step 2 decisions that differ from the plan above:

- The `-d` record is the scope's `Description=` ("Sandy container <name>
  (detached|attached)"), not a state file. It is bound to the running
  instance, needs no cleanup, and only root can set it. Any other value
  means "do not stop".
- The attach leaf name is random, made by sandy, and passed to the helper
  in argv with sandy's PID (9 request values after the script path and the
  mode). The helper sets the parent-death signal, then requires `getppid()`
  to equal that PID.
- The helper joins the leaf, so the helper, middle process, and session
  are all in it. sandy removes the leaf after the helper exits. On SIGHUP
  or SIGTERM the helper writes `cgroup.kill`; only if that write fails does
  it forward the signal to the session. The count of populated leaves also
  removes empty ones; this is safe because leaves are created and joined
  under the lifecycle lock.
- The helper proves the scope from the Leader's host cgroup, which must be
  below `/system.slice/sandy-<name>.scope/payload`. A container started by
  an earlier sandy fails this check; `bash` and `exec` refuse it.
- `init.sh` now runs in the main thread after readiness, before the
  console attach (not in a thread during the console).
- `up` runs `_cleanup_port_mappings_for_container` after CLI validation;
  the old `remove_stale_port_state` path is removed.
- The stop waits up to 5 s for the machine and the scope to go away, then
  runs `terminate` and waits again.

Step 2 follow-up: nftables port rules carry a comment and are removed by
comment and handle; an up-console marker closes the start race of `up`;
E2E tests cover stale rules for both firewall backends, with iptables hidden
in a private mount namespace for the nftables backend.

Remaining accepted gaps: SIGKILL of both sandy and its helper leaves the
attach running until the container stops; Ctrl-C during `up`'s start stops
the container (user accepted); SIGKILL of `up` after its start leaves the
up-console marker, so no attach exit stops that container.

Also known, not yet decided: before the console attach, `up` has no SIGHUP
or SIGTERM handler (only the attach installs one). If the terminal closes
during the start, sandy ends without its cleanup: the up-console marker
stays, and so do the temporary keepalive and `init.sh` directories. Only
SIGINT (Ctrl-C) runs the stop of a failed start.

Reasons for this order: step 2 makes the console an attach, so without step 1
first the main session would lose its seccomp filter. Step 1 also builds the
single-threaded entry process that step 2 needs for the cgroup move. Step 1
can be tested alone. Step 2's E2E tests then cover confined attaches. The cost:
step 1 is the larger and more difficult part, and the incident fix waits for
it.

Each step adds unit tests as `AGENTS.md` requires.

## E2E tests for step 2

In test VMs with systemd 249, 255, and 257, with sandy itself. Run the tests
with at least two images: the default (Debian trixie) and Ubuntu 26.04
(`SANDY_BOOTSTRAP_BASE`, uutils).

1. `sandy up` in the scope form. The console becomes an attach. sandy passes
   only the image fd; the `init.sh` copy is a host path in `--bind-ro`. The
   console gets the attach environment allow-list, not nspawn's payload
   environment, so it has no `container=` variable.
2. The keepalive: PID 2 has `comm=sandy-keepalive`, runs as container root,
   has no `BASH_ENV`, and UID 1000 cannot send it signals. A killed `sleep`
   child is restarted. The host directory (mode 0755, two entries) is removed
   after PID 2 has opened the script. `up` works when the host temporary
   directory is `noexec`. An image without `sleep` in `PATH` makes `up` fail
   with a clear error, and the keepalive does not spin. The `noexec` and
   missing-`sleep` cases were checked by hand; the E2E suite does not cover
   them.
3. `sandy -c <name> bash` and `exec` through the B2 path.
4. Attach cleanup after the attach ends, after SIGHUP (close the pty), and
   after SIGTERM. No orphans stay. After a SIGKILL of sandy, an empty leaf
   stays until the next count or until the scope stops.
5. Stop the terminal's scope, and close the terminal. The container survives.
6. Lifecycle: `up` console exit with no other attach stops the container.
   With another attach, the container continues, and the last attach to exit
   normally stops it. `up -d` is never stopped by an attach exit. Two attaches that
   exit at the same time stop the container exactly once.
7. The unit has `TasksMax=16384`, `MemoryMax=infinity`, and
   `MemorySwapMax=infinity` by default. With a test-only limit set, an OOM in
   an attach kills only that process.
8. Two containers at the same time. Unit names do not collide.
9. `sandy down` and `sandy rm`, including the `machinectl terminate` failure
   after `poweroff`. The port-forwarding rules are removed.
10. `sandy up` when a unit `sandy-<name>.scope` already exists: fail closed.
11. On systemd older than 253 (systemd 249): `up` works
    without `OOMPolicy=`. The keepalive bind and the `init.sh` bind work with
    the userns options below 250 (tests 12 and 14 by hand; here with sandy).
12. SIGKILL of the sandy process of an attach: the helper gets its
    parent-death signal, ends the attach with `cgroup.kill`, and the leaf
    becomes empty. The empty leaf does not block a later count, but no count
    runs for the killed attach: a container started without `-d` keeps
    running until another attach exits normally, or until `down`.
13. Stale port rules, with the iptables and nftables backends: stop a
    container with `-p` mappings without sandy (container root ends PID 2).
    The rules and state stay. A following `up` of the same name removes them
    before it sets up new ones. Also: `up` with different `-p` values, `up`
    with no `-p`, repeated cleanup, and no effect on another running
    container's rules.

Open questions:

- A later change: CLI options for `MemoryMax=`, `MemorySwapMax=`, `TasksMax=`,
  and `CPUQuota=`. Defaults stay as today.
- A later change: `NoNewPrivs=1` on all paths.
- A later change: `rm --network` without a bridge. `run_rm` constructs
  `SandyNet()` before the running-container check and the confirmation. With
  no bridge (for example, after a reboot), this creates the bridge and the
  firewall base and sets `net.ipv4.ip_forward=1`. `cleanup()` then removes the
  bridge and the firewall, but `ip_forward` stays 1. A declined prompt or a
  running container leaves the new bridge and firewall in place. Fix: use
  `SandyNet(create=False)` there. Sandy does not save its rules for a reboot,
  and only Sandy removes the bridge, so no rules can remain without the
  bridge; `cleanup()` keeps its early return. With this change:
  - Update the README sentence and the `_cleanup_port_mappings_for_container`
    docstring that say `rm --network` removes remaining iptables rules.
  - Update the E2E case "up with host networking builds no network". It
    deletes only the bridge. It must also remove the Sandy firewall state, as
    a reboot does. Otherwise the `rm --network` at the end of `test_nftables`
    leaves the nft tables.
  - Update the E2E cleanup (`E2EContext.cleanup`). It runs
    `rm --network --force` also when Sandy firewall state remains without the
    bridge, and it relies on `rm --network` to build the bridge first.

## Safety

- Do not make the host run out of memory.
- The change applies at the next start of a container.

## Answers from the sandy code (before this change)

This section records how sandy worked before this change. For the current
behavior, see Design.

- **How does sandy start nspawn?** `run_up` builds `systemd-nspawn
  --directory=/proc/self/fd/<fd> --machine=<name> --tmpfs=/tmp:mode=1777
  --as-pid2 --timezone=bind --user=<user> ...`. The interactive path runs it
  under a pty from sandy (`_run_container_interactive`), in the cgroup of
  sandy. The `--detach` path uses `_run_secure_subprocess_popen` with
  `start_new_session=True`. That prevents SIGHUP from the terminal, but nspawn
  stays in the terminal's cgroup. The code has the comment "XXX: probably
  should create a systemd unit for this". No `--keep-unit`, `--property=`, or
  `--slice=` is used.
- **How does sandy attach shells?** See Current layout. `exec` uses the same
  `_exec` path. `_exec_as_root` uses `nsenter -t <pid> -a -- sh -c <command>`,
  also in the caller's cgroup.
- **How does it stop and clean up a container?** `_machine_poweroff` removes
  the port mappings, then runs `machinectl poweroff <name>`, then
  `machinectl terminate <name>`. The cleanup after an interactive `up` runs in
  the sandy process. If sandy is killed, the port-forwarding cleanup after exit
  does not occur.
- **What does sandy do on SIGHUP?** sandy installs a handler only for
  SIGWINCH. SIGHUP has the default action, which ends sandy. In the current
  interactive path, nspawn is sandy's child on sandy's pty. The effect of
  sandy's end on nspawn was not tested. The new design removes this
  question: the supervisor has no tty, has its own session, and continues when
  sandy exits (test 6).
