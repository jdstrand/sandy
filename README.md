# sandy

`sandy` is a CLI for building and operating development containers on top of
`systemd-nspawn`. The project focuses on reproducible environments for AI agent
work.

Disclaimer: While `sandy` was written with security in mind, it is a side
project intended to explore AI sandboxing using `systemd-nspawn`, should be
considered experimental and should not be used on production systems. Because
it is experimental, it may change incompatibly at any time.

`sandy` originally started as a python reimplementation of the CLI for a docker
wrapper written by Trevor Hilton (@hiltontj).


## Features

- Container lifecycle management
- OCI or `debootstrap` based bootstrapping
- Uses ephemeral containers (read-only) by default with opt-in writable root
- Workspace sharing
- Host (wide-open) or bridged (`sandybr0`) networking (private with lenient
  egress with optional port forwarding)


## Requirements

- Linux host with `systemd-nspawn`, `nsenter`, `ip`, ...
- Either `debootstrap` **or** the combination of `skopeo` and `umoci` for image
  creation
- Firewall tooling: `iptables` or `nftables` as a fallback for NAT rules with
  bridged networking
- Root privileges
- Directory layout: currently manages root filesystems in `/var/lib/machines`
  (all prefixed with `sandy.`


### Getting Started

1. Install required packages on the host (example for Debian/Ubuntu):
   ```bash
   sudo apt-get update
   sudo apt-get install -y systemd-container debootstrap iptables skopeo umoci
   ```
   Install only the tools you intend to use (eg, `sandy auto-detects OCI vs.
   `debootstrap` support)
2. When run from the checked out directory, `sandy` will look for the
   `debootstrap.sh`, `oci.sh` and `setup-container.sh` helper scripts. If
   copying `sandy` to another directory, put these scripts next to `sandy`
   (also see the `SANDY_...` environment variables from `--help`)
3. Ensure `/var/lib/machines` exists as described above.
4. Run `sandy` as root (`sudo /path/to/sandy ...`). By default it mounts the
   `workspace` subdirectory for the developer user.


## Usage

### Quick start

```bash
# share files with the container
$ mkdir workspace && cp ... ./workspace

# create the 'ai-dev' container and use it
$ sudo sandy up -b
I: Using OCI method to create 'debian:trixie-slim' container
I: Pulling 'debian:trixie-slim'
...

developer@ai-dev:~/workspace$ claude|codex|copilot|gemini|...
...
developer@ai-dev:~/workspace$ exit
Container ai-dev exited successfully.

# use an existing container
# Tip: use --persistent after building containers to login to any AI account(s)
$ sudo sandy up --persistent
...
$ developer@ai-dev:~/workspace$ claude
... login then /quit ...
$ developer@ai-dev:~/workspace$ exit

# afterward, omit --persistent
$ sudo sandy up
Running: sudo ~/code/dev/sandy/sandy up
I: Mounting '/home/jamie/code/workspace' on '/home/developer/workspace'
I: Bind mounting /init.sh as read-only
I: Starting 'ai-dev'
...
developer@ai-dev:~/workspace$
...
$ developer@ai-dev:~/workspace$ exit

# create a chat session with an AI agent
$ mkdir workspace/chat && cd workspace
$ sudo sandy -c chat -w chat up -b --persistent  # once, create 'chat'
$ developer@ai-dev:~/workspace$ claude
... <login> /quit ...
$ developer@ai-dev:~/workspace$ exit
$ sudo sandy -c chat -w chat up -d               # if needed, start detached
$ sudo sandy -c chat -w chat exec claude         # run a command
```

The general invocation is:
```bash
$ sudo /path/to/sandy [GLOBAL OPTIONS] [COMMAND] [COMMAND OPTIONS]
```


### Global options
- `-w, --workspace PATH` - relative workspace to bind-mount inside the
  container (validated to prevent traversal; default: `workspace`).
- `-c, --container NAME` - container identifier (RFC-compliant hostname;
  default: `ai-dev`).
- `-u, --user USERNAME` - in-container user (POSIX-compliant name; default:
  `developer`).


### Commands
- `up` - Build and start the container. Key flags:
  - `--build` to create a container
  - `--detach` leaves the container running in the background
  - `--persistent` keeps the instance running across CLI exits
  - `--network {host,lenient}` chooses host networking or an isolated bridge
    (default `lenient`).
  - `--port proto:host:container` forwards 127.0.0.1 traffic (e.g., `--port
    tcp:8080:80`). Multiple flags allowed.
- `down` - Stop the container
- `rm` - Remove containers, cache, or network artifacts. Accepts `--all`,
  `--force`, `--cache`, `--network`.
- `bash` - Launch an interactive shell inside the container (default when no
  command is supplied).
- `exec` - Execute a specific command (`./sandy exec -- cargo test`).
- `status` - Show `machinectl status` for the container.
- `list` - Enumerate managed containers and their paths under
  `/var/lib/machines`.


### Networking and Port Forwarding

When `--network lenient` (default), `sandy` creates `sandybr0`, enables IP
forwarding, and creates firewall rules to block RFC1918/ULA ranges while
allowing loopback-published services via port mappings. Host networking
(`--network host`) skips bridge configuration entirely.


## Security

Container technologies (eg, `docker`, `podman`, `incus`, etc) typically require
`root` access for various aspects of setting up containers. For usability, most
of these tools create a root-running service that exposes a socket that is used
by a corresponding client tool where the socket is guarded by group membership
such that if the user invoking the client tool is in the group, then the user
can run any commands supported by the root-running service. While this provides
user convenience, it typically means that any users with this group membership
effectively have `root` on the host (due to mounting volumes in the container,
etc).

Like other container technologies, `sandy` also requires `root` to setup up
networking, root filesystems, invoking `systemd-nspawn`, etc. Unlike the other
container technologies, `sandy` does not provide a root running service and
instead is expected to be called with `sudo` (or similar) and for transparency,
`sandy` is fairly chatty with its output.

Users may find it convenient to install `sandy` to a root-owned directory and
adjust `sudoers` accordingly. The install target copies `sandy` and its helper
scripts to `/usr/local/lib/sandy` by default:

```bash
$ git clone https://github.com/jdstrand/sandy.git
$ cd sandy
$ sudo make install
```

After copying the files, `make install` prints a narrowly scoped example that
may be appropriate for sudoers, but it never updates sudoers. Review any policy
change with `visudo`; for example, a site may choose:

```
%sudo	ALL=(root:root) /usr/local/lib/sandy/sandy
```

Set `INSTALL_DIR` to choose another absolute installation directory. Packagers
can set an absolute `DESTDIR`, which is prepended as a staging root. A
`DESTDIR` of `/` is equivalent to leaving it empty, and trailing slashes are
accepted.

This limits the suggested policy entry to running the installed `sandy`
executable as `root`. Sites can apply stricter policy or choose a different
administrative group as appropriate.

As mentioned above, `sandy` was written with security in mind with the goal of
creating a strong sandbox for AI agents, but it should be understood there may
be bugs, unimplemented functionality or holes in the sandbox setup that allow
escape. As a side-project, the project's scope is for experimentation, not as a
general-purpose production sandboxing tool.


## Tests

The unit tests use Python's standard `unittest` framework and mock all
privileged container, filesystem, PTY, and firewall operations. They can be run
as an unprivileged user without installing `sandy`'s runtime tools.

```bash
make install-tools
make check
```

`make install-tools` requires Python 3.10 or newer. It creates `.venv-test` and
installs the pinned Python QA dependencies. If `language-checker` is unavailable,
the inclusivity check prints a warning and is skipped. The individual checks
are also available:

```bash
make format-check
make type-check
make test
make inclusivity-check
```

Use `make format` to apply Black formatting. Branch coverage is measured with
`make coverage`; the checked-in configuration enforces a minimum combined
branch and statement coverage of 95%.

If `language-checker` is not on `PATH`, provide its executable path explicitly:

```bash
make check LANGUAGE_CHECKER=/path/to/language-checker
```


## End to End (e2e) Tests

The end-to-end suite exercises the real root-only container, cache,
`systemd-nspawn`, mount, network, firewall, and cleanup paths. Run it only in a
disposable Linux VM. It creates and removes `/var/lib/machines/sandy.*`,
`sandybr0`, Sandy firewall rules and caches, and temporarily changes
`net.ipv4.ip_forward`. The runner refuses to start if it detects pre-existing
Sandy machine, bridge, or firewall state.

Ubuntu 24.04 (Noble) is the minimum tested guest. The VM must support nested
`systemd-nspawn` containers and user namespaces, have outbound DNS, HTTP, and
HTTPS access, and expose the normal kernel networking and firewall interfaces.
The tested VM had 4 vCPUs, 8 GiB of RAM, and a 40 GiB disk; allow at least 20
GiB of free disk space for uncached builds.

Install the host-side test requirements:

```bash
sudo apt-get update
sudo apt-get install -y \
    acl ca-certificates curl debootstrap iproute2 iptables make nftables \
    python3 skopeo systemd-container uidmap umoci util-linux
```

From a clean checkout in the disposable VM, run:

```bash
sudo env SANDY_E2E=1 make e2e
```

The opt-in variable and root check are intentional safety guards. The fast
suite uses Sandy's normal default bootstrap method and base image with a
minimal setup script. It covers cache misses, cache reuse, cache invalidation,
lifecycle operations, mounts, networking, firewall rules, port forwarding and
cleanup. Lifecycle and network tests reuse the cache created by the cache
tests.

To run the fast suite and then smoke-test one uncached build with Sandy's
complete default `setup-container.sh`, run:

```bash
sudo env SANDY_E2E=1 make e2e-full
```

The additional full build may take 10–20 minutes depending on network and
package caches because the default setup installs and compiles complete
development toolchains.
