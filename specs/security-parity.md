# Security Parity Gaps

Confinement properties that Sandy lacked compared with Docker, and that the
separate security audits (not in this repository) do not cover, because no
audit finding touches these code paths. Item 1 is fixed; items 2 to 4 are
open.

The comparison target is Docker with default options. Docker is not a
production sandbox for hostile code either. It is used here only as a widely
understood baseline.

Scope: Sandy's own confinement configuration. Sandy's root-side code defects,
network policy, supply chain, and cleanup behavior are covered by the separate
security audits.


## Test Environment

All measurements in this document come from disposable Incus virtual machines.
The virtual machines were deleted after each test.

* Host: Ubuntu 24.04 (noble), kernel 6.8.0-136-generic, x86_64, 2 vCPU,
  4 GiB RAM.
* systemd 255 (255.4-1ubuntu8.16), which supplies `systemd-nspawn`.
* Container root filesystem: Debian trixie, `debootstrap --variant=minbase`.
* Sandy's runtime argument shape was reproduced from an earlier, unmerged
  revision of `run_up`, including `--as-pid2`, `--volatile=overlay`,
  `--private-users=pick`, `--tmpfs=/tmp:mode=1777`, and the
  `--system-call-filter` value. The current `run_up` passes `--ephemeral`
  instead of `--volatile=overlay` (and neither with `--persistent`). It also
  passes `--keep-unit`, `--console=passive`, `--user=root`, and the keepalive
  payload, inside a `systemd-run --scope` wrapper (see
  `sandy-nspawn-scope-brief.md`).
* Syscall behavior was measured with a static C probe that calls each syscall
  with invalid arguments and records `errno`. `EPERM` indicates a seccomp
  denial. Other error codes indicate the syscall reached the kernel.
* Where a count such as "150 runs" appears, each run was a separate process
  against the same live container, and the recorded value is the exact contents
  of `/proc/self/status` for the final process after `exec`.

Note: the quoted `--system-call-filter` value in `run_up` was checked and is
correct. systemd removes the quotes. The landlock syscalls are permitted with
the argument as written, and denied without it. The argument needs no change,
although the reference section below proposes adding a deny argument beside it.

Seccomp policies were resolved exactly, not sampled. The five live seccomp
programs were read from a running container with `PTRACE_SECCOMP_GET_FILTER`
and the classic BPF was interpreted offline against a synthetic
`struct seccomp_data` for every syscall number. No syscall was executed to
determine policy.


## 1. The syscall filter is absent on the `exec` and `bash` paths

### Status

Fixed by step 1 of `sandy-nspawn-scope-brief.md` (in this directory).
The `up` console, `exec`, `bash`, `-u root`, `init.sh`, and the readiness
probe now enter through a confined helper instead of `nsenter`. Measured on systemd 249, 255, and 257
(kernels 5.15, 6.8, and 6.12) with Debian trixie and Ubuntu 26.04 images. The
sections below record the original finding, the implemented fix, the
measurements, and the corrections to earlier text of this item.

### Observation (before the fix)

`sandy up` starts the payload as a child of `systemd-nspawn`, so the payload
inherits the seccomp filter. `sandy exec` and `sandy bash` used `nsenter`
(in `Sandy._exec`, and `Sandy._exec_as_root` for `init.sh`). Seccomp filters
are per process and are inherited only across fork and exec. `nsenter` starts
from an unfiltered host root process, so the entered process received no
filter and the full capability bounding set.

### Evidence

Same container, same unprivileged agent uid, both paths:

```
                     sandy 'up'   sandy 'exec'
Seccomp:             2            0
Seccomp_filters:     5            0
```

Ten syscalls are denied on the `up` path and reach the kernel on the `exec`
path:

```
add_key          request_key      keyctl           perf_event_open
bpf              iopl             ioperm           clock_adjtime
quotactl         uselib
```

`keyctl`, `add_key`, `request_key`, `perf_event_open`, and `bpf` are all denied
by Docker's default seccomp profile. Each has kernel privilege escalation
history.

### Docker comparison

`docker exec` re-applies the container's seccomp profile, AppArmor profile, and
capability set to the new process. Sandy cannot do this with `nsenter`.

### Exposure (corrected)

This item first called the gap "Limited", because interactive `up` was the
common path. That framing is wrong for two reasons. First, the heavy work
(agent sessions, builds, scans) runs mostly in attached shells. Second, step 2
of `sandy-nspawn-scope-brief.md` makes the `up` console one more attach. Every
session then uses the entry path, so all paths must have the same confinement.

### Rejected approach: `systemd-run --machine=`

Tested and does not work with Sandy's design.

```
--as-pid2 (Sandy today):
  systemd-run --machine=NAME   rc=1  Failed to connect to bus: No such file...
  machinectl shell NAME        rc=1  There is no system bus in container NAME

same image with --boot and dbus installed:
  systemd-run --machine=NAME   rc=0  CapBnd: 00000000fdecabff | Seccomp: 2
  machinectl shell NAME        rc=0  Connected to machine NAME.
```

Both tools ask the systemd instance inside the container to start a unit, over
the container's private D-Bus. `--as-pid2` runs a minimal stub init, so there is
no systemd and no bus inside. When systemd does run inside, the mechanism works
correctly and inherits the confinement, because that systemd is a descendant of
the filtered PID 1.

Adopting it requires replacing `--as-pid2` with `--boot`. That converts Sandy
from an application container into a full machine, adds systemd, D-Bus, and
logind inside the container, requires every image to supply an init, and changes
the lifecycle. This is not recommended.

### Implemented fix: a confined entry helper

Sandy re-executes itself as an internal helper:
`[python, -I, /proc/self/fd/<n>, __sandy-entry-helper, ...]`, started through
the existing subprocess wrappers with the running `sandy` script passed as a
pinned descriptor. The helper starts single-threaded, which `fork` and
`setns(CLONE_NEWUSER)` need. It accepts only validated argv values, runs only as
root, and refuses to run with descriptors other than 0, 1, 2, and the script.
The script must be a regular file that only its owner can write; the parent
already runs it as root, so the helper gets the same trust.

1. Host side, under the global lifecycle lock (`sandy.__cache/lifecycle.lock`,
   held briefly by the helper, with a bounded wait of 10 seconds; a helper
   that waits longer exits with status 125. Other holders keep the lock for
   seconds: `up` without `-d` until its console-pending marker exists, and
   the stop after the last attach):
   * Pin the Leader (the container's PID 1, `(sd-stubinit)`) with a pidfd, and
     confirm with `machinectl` that it is still the machine's Leader.
   * Open `/proc/<pid>/ns/{cgroup,ipc,uts,net,pid,mnt,user}` through a
     `/proc/<pid>` directory descriptor.
   * `PTRACE_SEIZE` and `PTRACE_INTERRUPT` (not `PTRACE_ATTACH`, which queues
     a SIGSTOP), `waitpid(__WALL)`, then `PTRACE_SECCOMP_GET_FILTER` for index
     0, 1, and so on until `ENOENT`; any other errno fails. `PTRACE_DETACH`
     gives back a signal that a signal-delivery-stop took off the queue.
   * Read `CapBnd` from the host's `/proc/<pid>/status`, before any `setns`.
     After `setns(mnt)`, `/proc` is the container's mount, which container
     root controls.
   * Check through the pidfd that the Leader did not exit.
   * Read the Leader's host cgroup and require it below
     `/system.slice/sandy-<name>.scope/payload`, then create and join the
     attach leaf `attach-<random>` (step 2 of the scope brief).
2. The helper becomes a child subreaper and forks the middle process. The
   middle process empties `sys.meta_path` and `sys.path`, joins the namespaces
   (user last; see below), calls `setgroups([])`, `setresgid(0, 0, 0)`, and
   `setresuid(0, 0, 0)` (container root), forks the session, and exits.
3. The session is the first process in the container's PID namespace. It drops
   each capability that is not in `CapBnd` and reads the set back, installs the
   filters in index order while still namespaced root, reads the container's
   `/etc/passwd` and `/etc/group`, sets groups, gid, and uid, changes
   directory, restores default signal state, and calls `execve`.
4. The helper finds the session in its host `/proc` children list and waits
   for it. On SIGHUP or SIGTERM it ends the whole attach through the leaf's
   `cgroup.kill`; only if that write fails does it forward the signal to the
   session. It ignores SIGINT and SIGQUIT while it waits (as `system(3)`
   does), and passes on the exit status or the terminating signal.

Every helper error before `execve` exits with status 125. Errors that sandy
finds before it starts the helper exit with status 1. There is no fallback to
the unconfined path.

Account data follows nspawn, as measured: `root` gets no supplementary groups;
other users get exactly the groups that list them as members. The files are
read at attach time, as `su` did, and only after the filters are in place.
Malformed entries fail closed. The working directory is the workspace when it
exists, otherwise `/`, where the `nsenter` path started (measured on
util-linux 2.37, 2.39, and 2.41).

### Why the middle process changes uid and blocks imports

The middle process stays in the host PID namespace (`setns(CLONE_NEWPID)`
applies only to children) and has the container's mounts. `setns` into a user
namespace does not change the uid. Measured on all three systemd versions,
with code that repeats the middle process's steps:

```
middle process state             kill(host root, 0)  PTRACE_SEIZE  module planted by container root
host uid 0                       ok                  EPERM         imported; it SIGKILLed a host root process
container root                   EPERM               EPERM         imported; its kill gave EPERM
container root, imports blocked  EPERM               EPERM         ImportError
```

The result was the same with `ptrace_scope` 1 and 0. The real middle process
imports nothing after `setns` (checked with strace); the import block makes a
later change fail closed. The middle process exits right after its fork, so it
exists for only a short time. Container processes cannot address it: it has no
PID in the container, and the session's parent PID inside the container is 0.

`nsenter`, as used before the fix, left a waiting parent with host uid 0 in
the host PID namespace. It is C and reads no files after `setns`.

### Namespace entry order

Enter the user namespace **last**. Entering it first fails:

```
setns 1073741824 (CLONE_NEWNET): Operation not permitted
```

The other namespaces are owned by the host user namespace. Joining the
container user namespace first gives up the host `CAP_SYS_ADMIN` that the
remaining `setns` calls still need. `util-linux` `nsenter` documents this and
uses two passes: every namespace except user, then user; it retries with user
first only if the first pass fails. The working order is:

```
cgroup, ipc, uts, net, pid, mnt, user
```

### Measured result

E2E (`tests/e2e/test_confinement.py`, with sandy itself), passing on systemd
249, 255, and 257:

* `exec`, `bash`, and `-u root` match the payload's `Seccomp`,
  `Seccomp_filters`, `CapBnd`, and `NoNewPrivs`. `CapEff` is 0 for the default
  user and equals `CapBnd` for `-u root`, as for a root payload.
* The session's seccomp programs are byte-for-byte equal to the payload's and
  the Leader's.
* On confined paths, the denied syscalls give EPERM; unconfined, they reach the
  kernel. Landlock stays allowed. Exception: on kernel 5.15 with
  `unprivileged_bpf_disabled=2`, an unprivileged `bpf()` returns EPERM before
  it checks its arguments, so the probe cannot see a seccomp denial for `bpf`
  there. The byte comparison still covers it. On all three kernels, root in a
  user namespace cannot create a BPF map even without seccomp.
* 150 confined runs complete; no SIGSYS.
* When another tracer holds the Leader, extraction fails and `exec` refuses the
  command (status 125).
* `init.sh` runs through the helper and configures the container address.

Also measured in step 1, when the `up` payload still ran as the user: Uid,
Gid, and Groups of the attach equal the `up` payload's for developer and root,
with and without group memberships (24 cases).

### Corrections to earlier text of this item

* **Filter index order.** Step 4 of the earlier fix said "Index 0 is the most
  recent filter, so replay the list in reverse". That is wrong. Measured on
  kernels 5.15, 6.8, and 6.12 (install a 1-instruction filter, then a
  2-instruction filter, read index 0): index 0 is the oldest filter. Index
  order is installation order. The first implementation followed the earlier
  text and installed the filters in reverse; only the byte comparison found it,
  because the status fields and the filter count still matched.
* **Step order.** The earlier text recommended installing seccomp before the
  uid change ("Step order and NoNewPrivs") and also said "Install seccomp last,
  after the uid change" (implementation notes). The fix installs the filters
  before the uid change, while namespaced root, so `NoNewPrivs` stays 0 as on
  the `up` path. `--no-new-privileges=yes` on all paths can be a later change.
* **CapBnd source.** The earlier text read `CapBnd` from `/proc/1/status`
  inside the container. After `setns(mnt)`, that `/proc` is the container's
  mount. The fix reads it on the host, before any `setns`.
* **CapBnd value.** The earlier text measured `0x00000000fdecabff` (25
  capabilities), without a private network namespace. With a private network
  namespace (`--private-network` or sandy's bridge), the measured value is
  `0x00000000fdecbfff` (27), which adds `CAP_NET_BIND_SERVICE` and
  `CAP_NET_ADMIN`. The
  helper copies whatever the Leader has, so the attach matches in every
  network mode.
* **Payload PID.** The payload is not always PID 2. With
  `--user=developer`, nspawn runs `getent passwd` and `getent initgroups` as
  container PIDs 2 and 3, and the payload is PID 4. With `--user=root` the
  payload is PID 2. The stub init runs as the payload user. Sandy now passes
  `--user=root` for the keepalive payload, so its payload is PID 2.
* **`su` removed.** Attached sessions have no PAM session. The helper sets the
  uid, groups, and environment itself.
* Line references such as `sandy:5595` in this item referred to an earlier
  revision. The text above names functions instead.

### PTY and signal behavior

* PTY: for the console, `exec`, and `bash` (kind tty), the session runs the
  command through `script -qec`, which allocates a terminal from the
  container's devpts instance. `init.sh` and the readiness probe (kind sh) run
  `/bin/sh -c` without a terminal. Before it starts the helper, sandy's pty
  child closes every descriptor except 0, 1, 2, and the pinned script.
* Signals (step 2, as built): the helper, the middle process, and the session
  run in their own cgroup `attach-<random>` in the container's scope. On
  SIGHUP or SIGTERM the helper writes `1` to that cgroup's `cgroup.kill`, which
  ends every process of the attach, the helper included. The helper sets
  `PR_SET_PDEATHSIG` to SIGTERM, so the same happens when the sandy process
  that started it exits, SIGKILL included. After a normal exit, sandy kills
  what the session left behind and removes the cgroup. Accepted gap: if the
  helper and sandy both get SIGKILL, the attach keeps running until the
  container stops.

### Residual risk

* CPython runs between the filter install and `execve`. No SIGSYS occurred in
  150 runs on each of the three kernels. If Sandy later adopts a stricter
  filter, measure this again.
* The middle process runs briefly in the host PID namespace with the
  container's mounts, as container root and with imports blocked.
* The helper does not join the time namespace. The host, Leader, payload, and
  attach had the same time namespace in every measured case, because nspawn
  does not create one. A later nspawn that does would make attaches differ.
* Attached sessions run in the container's scope (step 2), so their memory
  and tasks count against the container, not against the terminal.

### Alternative 1: a static helper binary (not chosen)

Keep `nsenter` and pass the extracted filters to a small static helper on an
inherited descriptor. Three implementations were built and measured, 150 runs
each, against the same reference:

```
                            correct    stripped size   source lines
C                           150/150         743 KB          89
Rust                        150/150        1355 KB         122
Go (runtime.LockOSThread)   150/150        1401 KB         107
Go (without LockOSThread)   142/150        1401 KB         107
```

All three produce a result identical to the in-process fix. Go without
`runtime.LockOSThread()` failed 8 times in 150. Six runs kept the full
capability bounding set. Two runs were completely unconfined, with `CapBnd`
full, `NoNewPrivs` 0, and `Seccomp` 0. Every failing run exited 0.

`PR_CAPBSET_DROP`, `PR_SET_NO_NEW_PRIVS`, and `seccomp()` without `TSYNC` are
per-thread operations. The Go scheduler can move a goroutine to a different
operating system thread, so without an explicit lock the state is applied to one
thread and `execve` runs on another. All syscalls report success. This is why
`runc`, which is written in Go, performs its namespace and privilege setup in a
C constructor that runs before the Go runtime starts.

If a helper binary is chosen, use Rust. It has no runtime threads, so that
failure cannot occur by omission, and it removes the one parsing surface, which
is the length-prefixed filter payload read from the descriptor. Build it with
`-C target-feature=+crt-static -C panic=abort`. C is acceptable and has the
lightest build dependency. Go is not recommended for this specific job.

The helper must live outside the container image and be bind mounted read only,
the same way `run_up` binds `/init.sh`. An image that Sandy does not
control must not be able to replace it. That requirement, plus the descriptor
protocol and the added build artifact, is why the in-process fix is preferred.

### Alternative 2: a resident supervisor (not chosen)

Run a small filtered supervisor as the container payload at `up` time, and have
`exec` ask it to fork a new session. Seccomp, capabilities, and any LSM profile
are then inherited by construction, with no ptrace and no replay. This is the
design Docker uses. It needs a resident helper, a control socket, and pseudo
terminal plumbing, so it has more moving parts than either option above. Not
measured.

## 2. No memory or CPU limits

### Observation

Sandy passes no `--property=` option to `systemd-nspawn`, sets no memory or
CPU limit on its scope, and sets no explicit size on the `/tmp` tmpfs. There is
no equivalent of `--memory`, `--cpus`, or `--pids-limit`.

### Evidence

Measured on the machine scope of a running container, and inside it, with the
arguments of the earlier revision (`--volatile=overlay`; see Test
Environment):

```
MemoryMax=infinity   MemoryHigh=infinity   CPUQuotaPerSecUSec=infinity
TasksMax=16384

Filesystem   Size    Mounted on
overlay      973.7M  /       (25 percent of host RAM)
tmpfs        1.9G    /tmp    (50 percent of host RAM)
```

Host RAM was 3894 MB.

`TasksMax=16384` came from machined's default for the machine scope. Sandy now
sets `TasksMax=16384` on its own scope, `sandy-<name>.scope`, to match, and no
option changes it. Process count is therefore bounded, but generously.

With `--volatile=overlay`, both writable file systems were tmpfs backed by host
RAM, so the container could consume about 75 percent of host RAM by writing
files alone. Sandy now passes `--ephemeral` instead (or neither option with
`--persistent`). Then only `/tmp` is a tmpfs (by default 50 percent of host
RAM), and the root file system is an ephemeral snapshot or copy of the image
on host disk (from the `systemd-nspawn` man page; not measured). Anonymous
memory is not limited at all.

### Docker comparison

Docker's defaults are also unlimited. Docker exposes `--memory`, `--cpus`, and
`--pids-limit`, and operators use them. Sandy exposes no control.

### Impact

An agent that loops, builds in a cycle, or writes large logs can degrade or
stop the host. This needs no exploit and no hostile intent.

### Recommended fix

Correction (step 2 of `sandy-nspawn-scope-brief.md`): nspawn now runs with
`--keep-unit` in the transient scope `sandy-<name>.scope`, so nspawn's
`--property=` options do not apply. Put the limits on that scope instead,
through `systemd-run --property=MemoryMax=` and the like. The scope holds the
supervisor, the container, and every attached session, so one limit covers
all of them. Step 2 keeps the defaults of the machined scope
(`TasksMax=16384`, no memory or CPU limit), so this item stays open.

Set an explicit `size=` on the `/tmp` tmpfs. Expose the values as validated
CLI options with conservative defaults.


## 3. No LSM confinement

### Observation

Sandy applies no AppArmor profile and no SELinux label. No option or code path
sets either; the source mentions SELinux only in a comment about extended
attributes.

### Evidence

```
container PID 1 profile   : unconfined
up path (nspawn child)    : unconfined
exec path (nsenter)       : unconfined
```

AppArmor was enabled on the host during the test. The `exec` row was measured
on the `nsenter` path, before item 1's fix. The entry helper writes no LSM
attribute, so that path is probably still unconfined (not measured).

### Docker comparison

Docker applies the `docker-default` AppArmor profile, or the SELinux
`container_t` type, to every container. That layer still holds when the
namespace layer fails. It blocks writes to `/proc/sys` and `/sys`, mount
operations, and cross-container ptrace.

### Recommended fix

Ship an AppArmor profile and apply it. Verified working from an `nsenter`
process:

```
printf 'exec sandy-test' > /proc/self/attr/exec
exec /bin/sh -c 'cat /proc/self/attr/current'
  -> sandy-test (enforce)
```

The same write belongs in step 3 of the item 1 helper (the session, before
`execve`), so that attached sessions carry the profile. No extra tooling is
needed beyond a loaded profile.

If this is out of scope, state that in `README.md` instead of leaving it
unstated.


## 4. No capability reduction

### Observation

`systemd-nspawn` 255 supports `--capability=`, `--drop-capability=`,
`--ambient-capability=`, and `--no-new-privileges=`. Sandy uses none of them, so
the payload keeps the nspawn default set.

### Evidence

```
Sandy, no private network   CapBnd 0x00000000fdecabff   25 capabilities
Sandy, bridge (default)     CapBnd 0x00000000fdecbfff   27 capabilities
Docker default              CapBnd 0x00000000a80425fb   14 capabilities
NoNewPrivs on the 'up' path: 0
```

Both Sandy sets include `SYS_ADMIN`, `SYS_PTRACE`, `SYS_BOOT`, `SYS_RESOURCE`,
`DAC_READ_SEARCH`, `LINUX_IMMUTABLE`, and `AUDIT_CONTROL`. Docker's default set
contains none of those.

The agent's own effective set is 0, because it runs as uid 1000. The bounding
set limits anything that later reaches container root, which is the case the
bounding set exists for.

`NoNewPrivs=0` means a setuid root binary inside the image can still elevate to
container root.

### Measured fix

```
--drop-capability=CAP_SYS_ADMIN,CAP_SYS_PTRACE,CAP_SYS_BOOT,CAP_SYS_MODULE,
  CAP_SYS_RAWIO,CAP_SYS_TIME,CAP_SYS_TTY_CONFIG,CAP_SYS_PACCT,CAP_SYS_RESOURCE,
  CAP_AUDIT_CONTROL,CAP_AUDIT_WRITE,CAP_MAC_ADMIN,CAP_MAC_OVERRIDE,
  CAP_LINUX_IMMUTABLE,CAP_IPC_OWNER,CAP_NET_ADMIN,CAP_NET_RAW,
  CAP_DAC_READ_SEARCH,CAP_LEASE,CAP_NET_BROADCAST,CAP_MKNOD,CAP_SETFCAP
--no-new-privileges=yes
```

Result:

```
CapBnd 0x00000000008401fb   10 capabilities   NoNewPrivs 1
retained: CHOWN DAC_OVERRIDE FOWNER FSETID KILL SETGID SETPCAP SETUID
          SYS_CHROOT SYS_NICE
```

Four fewer than Docker's default. This was measured without a private network
namespace. With the default bridge, nspawn's set also has
`CAP_NET_BIND_SERVICE`, which is not in the drop list, so 11 capabilities stay
(computed, not measured). A workload of bash login shell, python3, a
50 MB write to the `/tmp` tmpfs, `cp -a`, `tar -czf`, and a setuid `mount`
attempt produced identical output and exit code 0 with and without the drop
list.

### Implementation notes

* Correction after item 1's fix: `init.sh` no longer keeps full
  capabilities. `_run_init_script` calls `_exec_as_root("/bin/sh /init.sh")`,
  which now runs through the confined entry helper with the payload's bounding
  set. `init.sh` configures `host0` with `ip`, so a runtime set without
  `CAP_NET_ADMIN` would break network setup. Before item 1's fix, `init.sh`
  ran through `nsenter` with `CapEff=0x000001ffffffffff`, and this bullet said
  that dropping `CAP_NET_ADMIN` was safe for that reason.
* The build stage and the runtime stage may need different sets. The build
  (the nspawn call in `_new_machine_from_scratch`) runs `setup-container.sh`
  as root and installs packages. Apply the tight set only to the runtime
  nspawn call in `run_up`. The build stage with a drop list was not tested.

### Effect on the `-u root` maintenance path

`-u root` exists so an operator can do work the image does not already cover:
install a package, run `ping`, debug with `strace`. The drop list must not
break that. Measured as container root, in a container with a private network
namespace, which is what `--network lenient` produces:

| Task | nspawn defaults | drop list above | drop list keeping NET_RAW and SYS_PTRACE |
| --- | --- | --- | --- |
| `apt-get update` and install | ok | ok | ok |
| raw socket, which `ping` needs | ok | **fails** | ok |
| `strace` | ok | **fails** | ok |

Two corrections to earlier assumptions.

First, `apt` does not need `CAP_SETFCAP` or `CAP_MKNOD` for ordinary packages.
Installation succeeded under the full drop list. A package that sets a file
capability or creates a device node may still need them, and that case was not
exercised, so do not remove them from the build stage on this evidence alone.

Second, `ping` never works under `--network host`, with any capability policy.
Measured: raw socket creation returns `EPERM` even with the complete nspawn
default set. The container network namespace is then the host one, which is
owned by the initial user namespace, so container root holds `CAP_NET_RAW` only
in its own user namespace and the check fails. With `--network lenient` the
namespace is created for the container and the capability applies. This is
worth stating in `README.md`; it looks like a Sandy defect and is not one.

Recommendation: keep `CAP_NET_RAW` and `CAP_SYS_PTRACE` in the runtime bounding
set. Also keep `CAP_NET_ADMIN` while `init.sh` configures `host0` through the
entry helper (see the implementation notes; the table above was measured when
`init.sh` still ran through `nsenter`). Drop the other nineteen. The agent runs as an unprivileged uid with
`CapEff` 0, so the bounding set matters only if something reaches container
root, and the valuable removals are `SYS_ADMIN`, `SYS_BOOT`, `SYS_MODULE`,
`SYS_RAWIO`, `SYS_TIME`, and the `MAC_` pair. Note the trade: keeping
`CAP_NET_RAW` matches Docker's default set, while keeping `CAP_SYS_PTRACE` is
more permissive than Docker. The justification is the maintenance path, and it
should be recorded as a deliberate choice.

### Open question: a carve-out for `-u root`

Not decided. Recorded here so the decision is made deliberately rather than by
default. Either option can be adopted later without reworking item 1.

**Option A, one set for the container.** Tune the drop list until ordinary
maintenance works, as recommended above, and give `-u root` no special
treatment. Simple, one policy to explain and to test.

**Option B, two sets.** Start the container with the wider maintenance set as
the ceiling, then drop further to the tighter runtime set inside the confining
step of item 1 whenever the target user is not root. `-u root` keeps the
container set.

Option B is implementable. An earlier note in this document said it was not;
that was wrong. A bounding set can always be narrowed by
`PR_CAPBSET_DROP` after the container starts, and the confining step already
calls it. What cannot be done is widening it for one `exec`, so the ceiling
must be the maintenance set.

Option B changes what the item 1 test asserts. Today the E2E test requires
every attach, for the default user and for `-u root`, to match the payload,
which runs as container root. Under option B the test would need an expected
`CapBnd` for each user.

Arguments for a carve-out:

* It removes the tail wagging the dog. Under option A the operator's debugging
  needs set the agent's bounding set. `CAP_SYS_PTRACE` is being kept for
  `strace`, not because the agent should have it available.
* It cannot be reached from inside the container. `sandy -u root` runs on the
  host under sudo, so a process in the container cannot invoke it. Widening
  root's set does not widen anything the agent can use directly.
* It leaves room for maintenance tasks not yet tested, such as a package that
  sets file capabilities or creates a device node, or mounting a filesystem to
  debug, without loosening the agent's runtime policy to match.

Arguments against:

* The container bounding set is the ceiling for everything in the container,
  including anything that reaches container root by other means. Option B
  raises that ceiling, so the carve-out is not free even though the agent
  cannot invoke it.
* Two policies mean two sets to document, test, and keep in step. Option A has
  one.
* The measured gap is currently small. Keeping `CAP_NET_RAW` and
  `CAP_SYS_PTRACE` was enough for every maintenance task tested. If that stays
  true, option B buys little.

What would force the decision: a maintenance task that needs a capability we
are unwilling to leave in the runtime set. `CAP_SYS_ADMIN`, needed for
mounting, is the likely candidate. Until such a case appears, option A is the
smaller change.

Note that the proposed nested user namespace block (see "Blocking nested user
namespaces") could not be carved out under either option. It is a property of
the user namespace, so it would cover every process in the container,
including container root. An operator who needs nested namespaces would need
the proposed `--allow-inner-sandboxing` flag.

- [ ] **Decide between option A and option B for `-u root`.** Not urgent.
      Revisit when the runtime drop list is implemented, or sooner if a
      maintenance task needs a capability that should not stay in the runtime
      set.
* Items 1 and 4 touch the same code. The `nsenter` path lost the bounding set
  for the same reason it lost seccomp. `nsenter` has no capability option, so
  the item 1 fix mirrors `CapBnd` as well: the helper reads it in step 1 and
  drops to it in step 3. Measured with the item 1 fix in place (without a
  private network namespace): `CapBnd` on the `exec` path drops from
  `0x000001ffffffffff` to `0x00000000fdecabff`, which matches the `up` path
  exactly.


## Reference: the InfluxDB 3 Core systemd unit

InfluxData ships a hardened systemd unit with `influxdb3-core`. It is a useful
in-house reference for what the same organization already considers a
reasonable confinement baseline. Measured from package `influxdb3-core`
version 3.11.0-1 on Ubuntu 24.04, read with `systemctl cat influxdb3-core`.

The two things are not equivalent. The unit confines one known daemon with a
narrow and stable syscall profile. Sandy confines an arbitrary development
container that must run compilers, package managers, and language runtimes.
Sandy cannot be as tight. The comparison is useful only where a control costs
no generality.

### Syscall policy compared

Both policies were resolved to concrete syscall names and compared on the
373 entries of the x86_64 syscall table. Sandy's set was obtained by extracting
the five live seccomp programs from a running container with
`PTRACE_SECCOMP_GET_FILTER` and interpreting the classic BPF offline, so no
syscall was executed.

```
  sandy  (nspawn container filter)  allows 311   denies  62
  influx (influxdb3-core.service)   allows 295   denies  78

  denied by influx, allowed by sandy: 23
  denied by sandy, allowed by influx:  7
  denied by both:                     55
```

Sandy's 62 denials are all `EPERM` except six `ENOSYS`. The unit sets
`SystemCallErrorNumber=EPERM` explicitly.

The 23 that only the unit denies are mostly things a development container
legitimately needs: `chroot`, `mount`, `umount2`, `pivot_root`, `ptrace`,
`seccomp`, the `fsopen` and `move_mount` family, and the three `landlock`
calls that Sandy allows on purpose with the landlock allowance in `run_up`.
Sandy should keep allowing those.

Three of the 23 are different, and they are the actionable finding.

### Actionable: adopt the unit's abused-syscall denials

The unit contains this:

```
# Disallow often abused unprivileged syscalls from @system-service:
# io_uring_setup - create an io_uring instance
# keyctl - use kernel keyrings
# userfaultfd - page faults to fd (often disabled in vm.unprivileged_userfaultfd)
SystemCallFilter=~io_uring_setup keyctl userfaultfd
```

Sandy denies `keyctl`, because nspawn denies it by default. Sandy **allows**
`io_uring_setup` and `userfaultfd`. Both are reachable by an unprivileged
agent, and both have a long kernel exploitation history. The same reasoning the
unit already states applies to Sandy, and the change is one argument:

```
--system-call-filter=~io_uring_setup userfaultfd
```

Add it alongside the existing allow argument in `run_up`. Neither call is
needed by normal development work. Verify with the syscall probe on both entry
paths.

### Observation for the unit itself

The unit denies `keyctl` but permits `add_key` and `request_key`, because
`@system-service` includes them. Sandy denies all three. The kernel keyring
attack surface is reached through all three calls, and Docker's default profile
blocks all three together. Consider:

```
SystemCallFilter=~io_uring_setup keyctl add_key request_key userfaultfd
```

This is a note about the unit, not about Sandy.

### Directives the unit has and Sandy does not

Mapped to the items above:

| Control | influxdb3-core unit | Sandy | Item |
| --- | --- | --- | --- |
| `NoNewPrivileges=true` | yes | no (`NoNewPrivs` 0) | 4 |
| `CapabilityBoundingSet=` (empty) | yes | no, 25 or 27 capabilities retained (see item 4) | 4 |
| `AmbientCapabilities=` (empty) | yes | not set | 4 |
| `RestrictSUIDSGID=true` | yes | no | 4 |
| `RestrictNamespaces=true` | yes | not applicable, Sandy needs namespaces | - |
| `RestrictAddressFamilies=` | AF_INET, AF_INET6, AF_UNIX | not set | - |
| `LockPersonality=true` | yes | no | - |
| `ProtectSystem=strict` | yes | no; the root is writable, and `--ephemeral` discards the changes at stop | - |
| `ProtectProc=invisible` | yes | not set | - |
| `SystemCallErrorNumber=EPERM` | yes | nspawn default is EPERM | - |
| `SystemCallArchitectures=native` | yes | not set | - |
| Memory or CPU limit | **no**, only `LimitNOFILE=65536` | no | 2 |
| LSM profile | no | no | 3 |

`systemd-analyze security influxdb3-core.service` reports an overall exposure
level of 2.6, "OK".

Two honest points about this table:

* `CapabilityBoundingSet=` empty is possible for a daemon that needs no
  privilege. A development container cannot use an empty set. The measured drop
  list in item 4 is the equivalent that a container can accept.
* The unit sets **no** memory, task, or CPU limit either. Item 2 is therefore
  not something the reference solves. It remains open in both places.

The unit also documents a commented `IPAddressDeny` block with RFC1918,
link-local, loopback, and the IPv6 equivalents. Sandy blocks RFC1918 and
link-local, plus `fe80::/10` and `fc00::/7` (`SandyNet.PRIVATE_NETWORKS` and
`IPV6_PRIVATE_NETWORKS`), and rejects all other forwarded IPv6 from the
bridge. The two projects reached a similar network policy independently.

## Nested Agent Sandboxes

The AI agents that Sandy exists to contain carry their own sandboxes. Those
sandboxes need the same kernel primitives that an outer container restricts.
Sandy already makes one accommodation for this: the landlock allowance in
`run_up` exists so that Codex can sandbox itself.

This section records which agent sandboxes still work inside Sandy. Sandy is
better than Docker here, so this is a compatibility record, not a parity gap.

### What each agent uses on Linux

Measured from the installed binaries, not from documentation.

| Agent | Linux mechanism | macOS |
| --- | --- | --- |
| Claude Code 2.1.220 | bubblewrap and seccomp | seatbelt |
| Codex | landlock and seccomp, also bubblewrap | seatbelt |
| Gemini CLI | bubblewrap, or podman/docker through `GEMINI_SANDBOX` | seatbelt |
| Copilot CLI | minimal on Linux, one bubblewrap reference | seatbelt |

Claude Code's bubblewrap arguments include `--unshare-user`, `--unshare-pid`,
`--unshare-net`, `--ro-bind`, `--proc`, `--dev`, `--tmpfs`,
`--die-with-parent`, `--new-session`, and `--cap-drop`. Bubblewrap is therefore
the common Linux mechanism, not a special case.

### Results

Measured with `kernel.apparmor_restrict_unprivileged_userns=0` so that each
layer's own policy is visible. With that sysctl at 1, which is the Ubuntu 24.04
default, every user namespace row fails everywhere, including on a bare host.

| Primitive | host | sandy `up` | sandy `exec` | docker default | docker seccomp off | plus apparmor off | docker privileged |
| --- | --- | --- | --- | --- | --- | --- | --- |
| landlock create and restrict_self | ok | ok | ok | ok | ok | ok | ok |
| nested seccomp filter | ok | ok | ok | ok | ok | ok | ok |
| `unshare(CLONE_NEWUSER)` | ok | ok | ok | fail | ok | ok | ok |
| `unshare` NS, PID, NET | ok | ok | ok | fail | ok | ok | ok |
| bubblewrap, Claude Code shape | ok | fail | fail | fail | fail | fail | ok |

Codex works. Landlock and nested seccomp succeed on both Sandy entry paths.
The landlock allowance in `run_up` is load-bearing: without it, landlock
returns `EPERM`.

Bubblewrap does not work. Claude Code and Gemini CLI therefore fall back to
their permission-prompt model inside Sandy.

### Two sequential blockers for bubblewrap

**Blocker 1, the user namespace mapping step.** Measured in a live Sandy
container on a host with the AppArmor restriction enabled:

```
kernel.apparmor_restrict_unprivileged_userns = 1
unshare(CLONE_NEWUSER)                 -> ok, CapEff becomes full in the new ns
self-write /proc/self/setgroups        -> EACCES
self-write /proc/self/gid_map          -> EPERM
self-write /proc/self/uid_map          -> EPERM
parent-write of the child's setgroups  -> ok
parent-write of the child's gid_map    -> ok
parent-write of the child's uid_map    -> ok
bwrap 0.11.0                           -> "setting up uid map: Permission denied"
```

Every step bubblewrap needs succeeds when the parent process performs the
mapping. The child then has the correct uid and full capabilities in its new
namespace. Only the self-write path is refused, and that is the path bubblewrap
uses.

Sandy is not the cause. The measurement above was taken on the `exec` path
before item 1's fix, when it had zero seccomp filters and the full capability
bounding set, and it still failed. Sandy's filter also permits `unshare`, `mount`, `pivot_root`, and
`umount2`, confirmed by the offline decode described in the reference section.

The cause is the host AppArmor policy. AppArmor is not namespaced, so it applies
to processes inside the container. The mechanism was measured directly:

```
profile before unshare  : unconfined
unshare(CLONE_NEWUSER)  : ok
profile after unshare   : unprivileged_userns (enforce)
CapEff after unshare    : 000001ffffffffff
```

Creating a user namespace transitions the process from `unconfined` into the
`unprivileged_userns` profile. The capability set still reads as full, because
AppArmor mediates capability *use* rather than capability possession. The
in-namespace privileged operations that bubblewrap performs are then refused,
while the parent-side writes succeed because the parent never transitioned.

Two Ubuntu sysctls control this:

```
kernel.apparmor_restrict_unprivileged_userns       1
kernel.apparmor_restrict_unprivileged_unconfined   0
```

The behavior also depends on whether the `unprivileged_userns` profile is
loaded. That profile ships in the `apparmor` package:

```
dpkg -S /etc/apparmor.d/unprivileged_userns
  -> apparmor: /etc/apparmor.d/unprivileged_userns
```

The kernel restriction and the profile are independent. The Ubuntu 24.04 image
used for testing has the AppArmor kernel module enabled but does not install
the `apparmor` package, so the profile is absent until it is installed. No
service restart is needed; the profiles load on package install.

All three states were reproduced in a disposable VM inside a Sandy-shaped
container:

| `apparmor` package | `userns` sysctl | Result |
| --- | --- | --- |
| not installed, so no profile | 1 | `unshare(CLONE_NEWUSER)` denied outright |
| installed, profile loaded | 1 | `unshare` succeeds, profile transition, map writes refused |
| either | 0 | mapping succeeds, blocker 2 is reached |

The second row is the normal distribution state and the one that matches a real
host. The first row is a deployment trap worth knowing: with the restriction
enabled and the profile missing, unprivileged user namespaces are refused
outright rather than confined.

The second row reproduces the live environment exactly, including the same
errno values and the same `bwrap: setting up uid map: Permission denied`.

Sandy is fully excluded by a control test: with the same policy and the same
sysctls, bubblewrap fails identically for an unprivileged user on the bare VM
host, outside any container. The kernel audit records are the same in both
places:

```
apparmor="AUDIT"  operation="userns_create" class="namespace"
  info="Userns create - transitioning profile" profile="unconfined"
  comm="bwrap" requested="userns_create" target="unprivileged_userns"
apparmor="DENIED" operation="capable" class="cap"
  profile="unprivileged_userns" comm="bwrap" capability=8 capname="setpcap"
apparmor="DENIED" operation="open" class="file"
  info="Failed name lookup - disconnected path" error=-13
  profile="unprivileged_userns" name="proc/<pid>/uid_map"
  requested_mask="wr" denied_mask="wr"
```

To read these on a host, clear the ring buffer with `dmesg -C`, reproduce the
failure, then run `dmesg | grep -i apparmor` or
`journalctl -k --since -2min | grep -i apparmor`.

`ps` does not show this. The Sandy process tree, including `systemd-nspawn` and
the stub init, always reads `unconfined`, for two reasons.

First, the transition is gated on `CAP_SYS_ADMIN`, not on the user id.
Measured:

| Creator of the user namespace | Resulting profile |
| --- | --- |
| root, with `CAP_SYS_ADMIN` | `unconfined` |
| root, with `CAP_SYS_ADMIN` dropped | `unprivileged_userns (enforce)` |
| unprivileged uid | `unprivileged_userns (enforce)` |

Sandy and `systemd-nspawn` run as root with `CAP_SYS_ADMIN`, so they are
exempt. The agent user inside the container is not.

Second, the transition applies only to the process that creates the namespace,
from the moment it creates it. A failing `bwrap` exits within milliseconds, so
`ps` cannot catch it. To observe the profile directly, create a user namespace
that persists:

```
unshare -U sleep 30 &
cat /proc/$(pgrep -P $! sleep)/attr/current
  -> unprivileged_userns (enforce)
```

**Blocker 2, masked `/proc`.** With the sysctl at 0 the mapping step succeeds
and bubblewrap fails later:

```
bwrap: Can't mount proc on /newroot/proc: Operation not permitted
```

nspawn covers the container procfs with read-only bind mounts on `/proc/sys`,
`/proc/acpi`, `/proc/bus`, `/proc/fs`, `/proc/irq`, `/proc/scsi`, `/proc/kmsg`,
and `/proc/sys/kernel/random/boot_id`. The kernel requires a fully visible
procfs before a process in a non-initial user namespace may mount a new one.

Isolated by testing inside a Sandy-shaped container with the AppArmor
restriction off:

```
bwrap --unshare-user --ro-bind / / /bin/true                      -> ok
bwrap --unshare-user --unshare-pid --ro-bind / / --proc /proc ... -> FAIL
```

This blocker is Sandy's, and it is the only part of the chain Sandy controls.
It also shows the shape of a workaround: a nested sandbox that does not need a
private procfs works inside Sandy today, once AppArmor permits the mapping.
Claude Code's invocation does pass `--proc`, so it is affected.

### Docker comparison

Docker hits three blockers in sequence. Its default seccomp profile denies
`unshare`. With `seccomp=unconfined`, the `docker-default` AppArmor profile
denies the `mount --make-rslave` that bubblewrap performs first, reported as
`Failed to make / slave: Permission denied`. With AppArmor also unconfined, it
reaches the same `/proc` masking failure Sandy has. Only `--privileged` works.

Sandy reaches blocker 2 with no options at all, so it is one layer closer to
supporting a nested sandbox than Docker with two `--security-opt` overrides.

### Why this matters, and why it matters less than it looks

The two sandboxes defend different things. Sandy protects the host from the
container. The agent's own sandbox protects assets inside the container from
the agent: workspace files outside the project directory, and credentials such
as `~/.claude/.credentials.json`.

Losing bubblewrap does not weaken the host boundary. It removes a second, inner
boundary that limits what a prompt-injected agent can reach within the
container. That is a real but secondary loss.

### Blocking nested user namespaces

Sandy permits nested user namespaces today. Unprivileged user namespaces are the
most common Linux privilege escalation vector. Sandy's outer user namespace
bounds the result of an escape, because container root maps to an unused host
uid, but it does not stop a kernel defect reached through a nested namespace.

Two mechanisms were compared. Both were measured in a Sandy-shaped container
with the host AppArmor restriction disabled, so that only the Sandy-side control
was active.

| Control | `unshare(2)` | `clone(2)` | `clone3(2)` | bubblewrap |
| --- | --- | --- | --- | --- |
| `--system-call-filter=~unshare` | blocked, EPERM | allowed | allowed | **allowed** |
| `user.max_user_namespaces=0` | blocked, ENOSPC | blocked, ENOSPC | blocked, ENOSPC | blocked |

The syscall filter does not work. Bubblewrap creates its namespaces with
`clone`, not `unshare`, so `~unshare` blocks the `unshare(1)` command and lets
every real sandbox through.

A more precise rule is not available either. seccomp can inspect the `clone`
flags argument, but not the `clone3` flags, because `clone3` passes them inside
a structure behind a pointer and seccomp cannot dereference pointers. Measured
with a hand-written filter that denies `clone` when the flags contain
`CLONE_NEWUSER`:

```
clone(2)  with CLONE_NEWUSER -> Operation not permitted
clone3(2) with CLONE_NEWUSER -> ALLOWED  <== bypass
```

Docker handles this by making `clone3` return `ENOSYS`, so glibc falls back to
`clone`. Sandy cannot copy that. nspawn's `--system-call-filter` accepts syscall
names, `@` groups, and numbers only. It offers no argument inspection and no
choice of error number, and
a `clone3` that returns `EPERM` rather than `ENOSYS` breaks `pthread_create` on
current glibc instead of triggering the fallback.

`user.max_user_namespaces` is a per-user-namespace ucount limit checked inside
`create_user_ns()`, so it covers all three entry paths. It is the only complete
mechanism available to Sandy. Set it by joining only the container user
namespace, which keeps the host mount namespace so that `/proc/sys` stays
writable:

```
nsenter --user=/proc/<leader>/ns/user -- \
    sh -c 'echo 0 > /proc/sys/user/max_user_namespaces'
```

Measured: the container value changes from 2147483647 to 0, nested `unshare`
and `clone` are refused, and the host value is unchanged. Normal container work
is unaffected.

The resulting error is self-documenting for bubblewrap:

```
bwrap: Creating new namespace failed: nesting depth or
       /proc/sys/user/max_*_namespaces exceeded (ENOSPC)
```

`unshare(1)` reports the same condition less clearly, as "No space left on
device". Document that.

**Caveat.** The write happens after the container starts, so there is a short
window in which a payload could create a namespace first. Exploiting it requires
a hostile image, which the separate security audit already covers, but the
window should be documented rather than ignored.

### Proposed default and escape hatch

Default: set `user.max_user_namespaces=0`. On any host with the distribution
default for AppArmor, the inner sandboxes already fail to start, so this costs
close to nothing today and closes a real attack surface.

Do not ship `~unshare`. It does not deliver the property, and its presence
suggests that it does.

Escape hatch: a single `up` flag, `--allow-inner-sandboxing`. It must do all
three of the following, because any subset leaves the user with a flag they were
told to set and an inner sandbox that still fails for an invisible reason.

1. Skip the ucount write.
2. Unmask `/proc` in the container, so that a nested `--proc` mount is allowed.
3. Print a warning naming `kernel.apparmor_restrict_unprivileged_userns`. Sandy
   cannot and must not change that host setting. Without the user relaxing it
   themselves, the inner sandbox still does not start.

Sandy is deliberately chatty, so point 3 matches its existing style. The user
learns exactly what was relaxed and what remains their decision.

### Related defect: subordinate id ranges do not exist

```
/etc/subuid          developer:100000:65536
/etc/subgid          developer:100000:65536
container uid_map    0 1550581760 65536
```

The image grants the agent user subordinate ids 100000 to 165535, but the
container user namespace maps only 0 to 65535. That range does not exist inside
the container. Any tool that depends on it, including rootless podman,
`newuidmap`, and `newgidmap`, cannot work and fails in a confusing way.
`newuidmap` is not installed, which currently hides the problem.

Bubblewrap is also absent from the image. `setup-container.sh` never installs
it, so the question does not arise until someone installs it by hand.

### Checklist

- [ ] **Add regression coverage for the landlock allowance.** This is the one
      nested-sandbox feature that works today, and it depends on a single
      argument in `run_up`. Partly done: the E2E test calls
      `landlock_create_ruleset` with invalid arguments on each entry path and
      compares the errno with an unconfined baseline. Still open: an E2E case
      that calls
      `landlock_create_ruleset`, `landlock_add_rule`, and
      `landlock_restrict_self` as the agent user and requires success on the
      `up` path and on the `exec` path. Add a unit test that asserts the exact
      `--system-call-filter` value, not only its prefix. Assert failure when
      the argument is removed, so the test proves the argument is the cause.
- [ ] **Decide the position on the host AppArmor restriction.** Blocker 1 is
      confirmed and is not Sandy's to fix. Relaxing it with
      `sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` weakens the
      host for every process, not only Sandy's container, so the default should
      stay as the distribution ships it. Record the decision and state in
      `README.md` that agent-internal bubblewrap sandboxes do not start under
      the distribution default.
- [ ] **Block nested user namespaces by default.** Write
      `user.max_user_namespaces=0` into the container user namespace after the
      machine is registered and verified, joining only the user namespace
      (the entry helper's `setns` code can do this; sandy no longer uses
      `nsenter`). Do not use `--system-call-filter=~unshare`; it does not
      block bubblewrap. Add a test that asserts nested `unshare`, `clone`, and
      `clone3` are all refused.
- [ ] **Add the `--allow-inner-sandboxing` flag.** One flag that skips the
      ucount write, unmasks `/proc`, and prints a warning naming
      `kernel.apparmor_restrict_unprivileged_userns`. Validate it like every
      other CLI value. Add tests for both states, including the warning text.
- [ ] **Record the inner-sandbox policy.** With the default above, Sandy is the
      only sandbox unless the flag is given. Disable the inner sandboxes
      explicitly in `setup-container.sh`, for example `GEMINI_SANDBOX=false` and
      the Claude Code sandbox setting, so a failure is a stated choice and not a
      runtime surprise. Keep the Codex landlock sandbox enabled, because it
      works and needs no user namespace.
- [ ] **TODO: add or update a sandboxing section in `README.md`.** Partly
      done: the README sections "Attached sessions" and "Container scope and
      session lifecycle" state the entry-path parity, `TasksMax=16384`, and
      that there is no memory or CPU limit. It should also state the other
      confinement properties (LSM, `NoNewPrivs`, landlock), that agent-internal
      sandboxes do not run by default, what `--allow-inner-sandboxing` changes,
      and that the host AppArmor setting remains the user's decision. Cover the
      confusing `unshare(1)` error text, "No space left on device", and the
      fact that `ping` cannot work under `--network host` with any capability
      policy. State what `-u root` can and cannot do. Keep it consistent with
      the existing Security section, which already states that sudo access to
      Sandy is host-root-equivalent.
- [ ] **Fix or remove the subordinate id ranges.** Either delete the
      `/etc/subuid` and `/etc/subgid` entries in `setup-container.sh` or set
      them to a range inside 0 to 65535.
- [ ] **Decide whether to install bubblewrap in the image.** Install it only if
      the inner sandbox is meant to be supported. Otherwise document that it is
      absent on purpose.
- [ ] **Audit the rest of `/proc/sys` before shipping the unmask.** The unmask
      in `--allow-inner-sandboxing` was checked against three paths only:
      `/proc/sys/kernel/hostname`, `/proc/sys/vm/drop_caches`, and
      `/proc/kmsg`. All three stayed refused, with the denial moving from the
      read-only mount to the kernel capability check, which is against the
      initial user namespace for sysctls that are not namespaced. Namespaced
      sysctls behave differently. `/proc/sys/net` in particular belongs to the
      container network namespace. Check the whole tree before the flag ships.

## Reference: bubblewrap as an alternative engine

Bubblewrap keeps appearing in this document as the mechanism the agents use for
their own sandboxes. It is worth comparing directly, and worth asking whether
Sandy should use it instead of `systemd-nspawn`.

### Default confinement compared

Measured with the same 36-call syscall probe and the same `/proc/self/status`
fields, as an unprivileged uid inside each engine. Bubblewrap was run as root,
because that is how Sandy would invoke it.

| Property | Sandy on nspawn | bubblewrap, no extra flags | bubblewrap, tuned |
| --- | --- | --- | --- |
| seccomp filters | 5 | **0** | 0, caller must supply BPF |
| syscalls denied in the probe | 22 | 12 | 12 |
| `CapBnd` | `0xfdecabff`, 25 caps (no private network) | `0x1ffffffffff`, all 41 | `0x0` with `--cap-drop ALL` |
| `NoNewPrivs` | 0 | **1** | 1 |
| nested user namespaces | allowed | allowed | blocked by `--disable-userns` |
| `/proc` masked paths | 8 | 3 | 3 |

The ten syscalls that nspawn denies and bubblewrap does not are exactly the ten
from item 1: `add_key`, `request_key`, `keyctl`, `perf_event_open`, `bpf`,
`iopl`, `ioperm`, `clock_adjtime`, `quotactl`, and `uselib`. They come from
nspawn's built-in filter, which bubblewrap has no equivalent of.

The comparison splits cleanly. Out of the box nspawn is much stronger on system
call surface and bubblewrap has none at all. Tuned, bubblewrap reaches an empty
capability bounding set with one flag, which nspawn cannot do as easily, and it
sets `NO_NEW_PRIVS` by default where nspawn does not.

Two bubblewrap features are directly relevant to work proposed above:

* `--disable-userns` blocks nested user namespaces and reports the same
  `ENOSPC`, because it is implemented as the same ucount limit this document
  proposes for Sandy. Bubblewrap ships it as a first-class flag; nspawn has no
  equivalent.
* `--cap-drop ALL` produces `CapBnd` of `0x0`, which is the empty bounding set
  the InfluxDB unit achieves with `CapabilityBoundingSet=`.

### Should Sandy replace nspawn with bubblewrap

No. The two are not the same kind of tool. Bubblewrap is a sandbox primitive
that builds one filesystem view, runs one process tree, and exits. Sandy is a
container manager. The following are all things Sandy needs and bubblewrap does
not provide.

* **Lifecycle.** `up --detach`, `exec`, `bash`, `down`, `list`, and `status`
  need a persistent, addressable machine. Bubblewrap has no concept of one.
* **Entering a running sandbox.** Bubblewrap offers no way in. Sandy's entry
  helper needs a registered machine: it finds and checks the Leader through
  `machinectl`. Without one, Sandy would need another way to verify what it
  enters.
* **Identity verification.** Sandy's ownership model depends on `machinectl`:
  the Leader PID from `machinectl`, a pidfd pin of that process, and a Leader
  cgroup below `sandy-<name>.scope/payload`. All of that would have to be
  reinvented.
* **Idmapped mounts.** Bubblewrap has no `--idmap`. Sandy's `--bind=...:idmap`
  workspace handling would have to change to a different ownership model.
* **A default syscall policy.** Sandy would have to author and maintain one.
  That is a living artifact, and the measured `clone3` limitation means it
  still could not express the nested user namespace rule precisely.
* **Resource control.** Neither engine provides it, so item 2 stays open either
  way. Sandy starts the engine in its own `systemd-run` scope, so limits go on
  that unit, for either engine.

Bubblewrap's headline advantage, running without root, is also unavailable to
Sandy. Bridge creation, NAT and firewall rules, `/var/lib/machines`, and image
builds all require root regardless of the sandbox engine.

### A complementary use, not a replacement

Sandy could provide the inner boundary itself rather than depending on each
agent's. That idea is developed in the next section. Note that it does not
require bubblewrap and does not conflict with the nested user namespace default,
because Landlock needs no namespace at all.

## Going Further: a Sandy-provided inner boundary

Items 1 to 4 close gaps against Docker. This section goes past parity. It is a
proposal, not a finding, and it is not required by any item above.

### The gap it addresses

Sandy's boundary protects the host. It does nothing inside the container. An
agent that is prompt-injected today can read every credential in the container,
including `~/.ssh`, `~/.aws`, `~/.config/gh`, and the credential files of other
agents, and can write anywhere in the mounted workspace, including outside the
project directory when the workspace root is broad.

That inner boundary is exactly what the vendor sandboxes provide, and the
nested agent sandboxes section shows that they cannot start under Sandy.

### Mechanism: Landlock, not bubblewrap

An earlier draft of this document said such a boundary needs a nested user
namespace and therefore conflicts with the `user.max_user_namespaces=0`
default. That was wrong. Bubblewrap needs a user namespace because it is
designed for unprivileged callers who have no other way to obtain one. Landlock
needs none.

Measured in a live Sandy container, as the unprivileged agent user, with no
privilege and no namespace created:

```
read  secret/creds : Permission denied
write secret/      : Permission denied
read  work/file    : data
write work/        : ok
run   /bin/true    : ok
namespaces used    : user:[4026534174]   <- unchanged, none created
re-run the helper  : Permission denied   <- inherited, cannot be dropped
```

The ruleset is applied by the process to itself, survives `execv`, and cannot
be removed by anything downstream.

### Where it hooks

Item 1's helper has a confining step (`_confine_and_exec`) that runs
immediately before `execve` on every entry path, after the capability and
seccomp work and before the shell starts. Adding a Landlock ruleset there is a
few syscalls in code that exists anyway:

1. `landlock_create_ruleset` with the handled access rights.
2. `landlock_add_rule` for each permitted path hierarchy.
3. `PR_SET_NO_NEW_PRIVS`. The helper does not set it today (`NoNewPrivs`
   stays 0). After the uid change the session has no capabilities, so
   `landlock_restrict_self` needs it. Set it here, or restrict before the uid
   change.
4. `landlock_restrict_self`.
5. `execv`.

Sandy already permits those three syscalls with the landlock allowance in
`run_up` for Codex, so the syscall policy needs no change.

### What it would enforce

Read and write on the workspace and the agent's home. Read and execute on the
system directories. Nothing else. In particular, deny `~/.ssh`, `~/.aws`,
`~/.config/gh`, and every path outside the shared directories, so that a
compromised session cannot exfiltrate credentials belonging to tools it was not
invited to use and cannot write outside the shared workspace.

### The limitation, which is significant

The vendor sandboxes wrap each **tool call**, meaning the individual commands
the agent runs. Sandy's confining step wraps the **whole session**. That
difference is not a detail. It is how Claude Code denies a shell command access
to `~/.claude/.credentials.json` while the agent itself still reads that file
to authenticate. Sandy cannot make that distinction from outside the agent.

So this proposal delivers cross-tool credential isolation and workspace
scoping. It does not deliver the property that an agent cannot read its own
secrets. It is a useful subset of what the vendor sandboxes do, not a
replacement for them.

### Cost

Sandy would own a filesystem policy: which paths are readable and which are
writable. Every path in it needs the same validation discipline as the rest of
the code, and the policy has to track whatever the agents legitimately need.
That configuration surface is the main argument for leaving this to the vendors
if their sandboxes can be made to start.

- [ ] **Decide whether to build a Sandy-provided inner boundary.** Not urgent
      and not required by items 1 to 4. Item 1 has landed; its confining step
      (`_confine_and_exec`) is the only place it can hook. Weigh it against simply
      making the vendor sandboxes work through `--allow-inner-sandboxing`.

## Candidate Additions

These are proposals, not part of the four agreed items.

### 5. No test asserts any of these properties

Item 1 now has E2E and unit coverage (`tests/e2e/test_confinement.py`, and the
entry helper tests in `tests/test_sandy.py`). For item 2, the E2E suite checks
today's scope values (`TasksMax=16384`, no memory or CPU limit;
`tests/e2e/test_scope.py`), and unit tests check the exact `systemd-run`
`--property=` arguments. Nothing detects a regression in items 3 and 4. The
unit test `test_detached_host_command_has_security_flags` still asserts only
that some nspawn argument starts with `--system-call-filter=`. It does not
check the value, and it cannot check the effect.

Every property in this document is measured by reading `/proc/<pid>/status` or
by calling a syscall and checking `errno`. Both are cheap and deterministic in
an E2E context. Proposed coverage:

* E2E: assert `Seccomp`, `Seccomp_filters`, `CapBnd`, and `NoNewPrivs` of a
  process started by `up`, and of the same fields for a process started by
  `exec` against a detached container. Assert the two agree.
* E2E: assert that a named set of syscalls is denied on both paths.
* E2E: assert the scope reports the configured `MemoryMax` and `TasksMax`, and
  that the tmpfs sizes match the configured values.
* Unit: assert the exact `--drop-capability`, `--no-new-privileges`, and
  `--property` arguments in the constructed command, not only their prefixes.
* E2E: assert that landlock still works for the agent user on both paths. See
  the first checklist item in the nested agent sandboxes section. That argument
  is already shipped and already load-bearing, so its test is due now rather
  than as part of this proposal.

Status: the first two bullets are done for item 1. The third is done for
today's default scope values only. The fourth is done for the scope's
`--property=` arguments. The fifth is partly done (see the landlock checklist
item above).

Without this, a later systemd version or a refactor can silently remove the
confinement, as the `nsenter` path did before item 1's fix.

### 6. The README does not state the confinement model

`README.md` now states the entry-path parity ("Attached sessions"),
`TasksMax=16384`, and that there is no memory or CPU limit ("Container scope
and session lifecycle"). It does not state the other kernel-level confinement
properties: no LSM profile, `NoNewPrivs` 0, and the landlock allowance.

Proposed: add a short table to the Security section that lists each property,
its state, and whether it differs between entry paths. Update it when items 2 to
4 land. If any item is deliberately out of scope, record that decision there.


## Residual Risk After All Items

These remain and are shared with Docker. They are recorded so they are not
mistaken for gaps introduced by the items above.

* The kernel is shared. Neither tool is a virtual machine boundary.
* `unshare` is permitted on both paths. Measured `ALLOWED` in every
  configuration tested. An agent can create nested user namespaces, which
  widens the reachable kernel attack surface. Docker's default profile permits
  it as well.
* `ptrace` and `process_vm_readv` are permitted within the container. The agent
  runs as an unprivileged uid, so it can only reach its own processes. This
  matches Docker.
* `--network host` disables the network isolation completely. This is an
  explicit opt-in and is documented.
