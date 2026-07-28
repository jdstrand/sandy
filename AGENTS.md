# Sandy Agent Guidance

## Project and Threat Model

`sandy` is an experimental, security-sensitive Python 3.10 CLI for building
and operating `systemd-nspawn` development containers. It runs as root and
manages host filesystems, processes, network interfaces, firewall rules, and
container state. A defect can damage the host or weaken the container boundary.

Work from the repository root. Preserve the security model in `README.md`,
keep changes narrow, and preserve unrelated user changes. Do not represent
Sandy as a production-grade sandbox.

The extensionless Python executable `sandy` is the main implementation. Bash
helpers are in the repository root; unit and E2E tests are under `tests/`.

## Task Scope and Autonomy

* For review, explanation, diagnosis, or planning, inspect and report without
  modifying files.
* For change, build, or fix requests, make in-scope local changes and run
  relevant non-destructive checks without asking first.
* Make routine decisions independently. Ask only when materially different
  interpretations would produce different outcomes.
* Require explicit authorization for root commands, destructive actions,
  external writes, production dependencies, or material scope expansion.
* Deliver the requested scope completely without silently narrowing, widening,
  or transforming it.

## Mandatory Security Requirements

These requirements take priority over convenience. Obtain explicit direction
before weakening one.

### Trust, Privilege, and Lifecycle

Treat CLI arguments, environment variables, command output, persisted data,
filesystem metadata, and existing host network or firewall state as untrusted.

* Parse and validate CLI values before privileged setup. Use strict allow-lists
  with explicit type, length, format, and range limits.
* Reject ambiguous or malformed values rather than repairing them; validate
  again at each trust boundary and when loading persisted data.
* Require root before constructing objects or mutating host state. Run
  safe-directory checks before host changes.
* Fail closed on malformed security-sensitive state. Validate before mutation
  and clean up before removal.
* Keep cleanup scoped, idempotent, and safe after partial failure. Remove only
  resources proven to be owned by Sandy.
* Preserve confirmations and opt-in guards for destructive or host-wide work.

### Host Command Execution

Use `_run_secure_subprocess`, `_run_secure_subprocess_popen`, or
`_run_secure_subprocess_pty` for host commands from Python.

* Pass argument lists and keep `shell=False`. Never use `shell=True`,
  `os.system`, `eval`, `exec`, or host-shell command strings.
* Validate user-derived arguments before command execution. Call
  `subprocess.run` or `subprocess.Popen` only inside the wrappers and their
  focused tests.
* Arbitrary in-container commands are intentional. Preserve the host/container
  boundary and never expand those commands in a host shell.
* In Bash, quote expansions, use `--` where supported, validate values before
  use, and avoid `eval` or dynamically constructed shell programs.

### Filesystem and Deletion Safety

Use `_verify_safe_dir`, `_rmtree`, `_mkdir`, and `_write` for managed host
paths.

* Never derive a host path directly from unvalidated CLI or environment input.
* Reject traversal, unexpected absolute paths, symlinks, ownership changes,
  unsafe permissions, inode mismatches, and non-directory components.
* Never delete the managed root or anything outside the expected
  `/var/lib/machines/sandy.*` scope.
* Verify the exact target immediately before destructive operations and account
  for symlink and time-of-check/time-of-use races.
* Use restrictive file permissions and unpredictable temporary names. Clean up
  exact paths only, without broad globs, unresolved variables, or unchecked
  recursive deletion.

### Networking and Firewall State

Preserve equivalent documented isolation for iptables and nftables.

* Preserve rule order, established-connection handling, private-network
  blocking, IPv6 handling, and loopback-only port publication.
* Validate addresses, CIDRs, protocols, ports, interfaces, object names, and
  command output before use.
* Make intentional fallbacks explicit, documented, and tested; never silently
  degrade isolation.
* Remove only Sandy-owned rules, chains, tables, interfaces, and forwarding
  state.
* When shared policy changes, test setup, reuse, conflicts, partial failure,
  and cleanup for both backends.

### Persistent State, Logging, and Secrets

* On every load, discard unknown, derived, or invalid state fields. Preserve
  locking and atomic updates.
* Sanitize untrusted terminal and log output with the existing sanitizer.
* Do not log control characters, credentials, tokens, private keys, or
  unnecessary host details.
* Do not hardcode secrets, deserialize with `pickle`, or dynamically import
  code selected by external input.

## Code Conventions

* Follow PEP 8 and Black formatting.
* Production Python and shell source outside `tests/` must contain ASCII only.
  Tests may use non-ASCII text only when required to test that behavior.
* Add useful Python 3.10-compatible argument and return annotations to new or
  modified functions.
* Keep functions focused and security decisions explicit. Prefer existing
  helpers over duplicated validation or command construction.
* Avoid unrelated formatting, typing, dependency, or refactoring churn.
* Keep the Python runtime standard-library-only unless the task justifies a
  production dependency. Pin development dependencies in
  `requirements-test.txt`.
* Bash changes must pass ShellCheck. Comments should explain security
  assumptions or non-obvious reasons.

## Test Strategy

Unit tests must run unprivileged without Sandy runtime tools.

* Exercise pure logic directly with real data structures and safe temporary
  directories.
* Mock privileged host mutations, external programs, PTYs, networking,
  firewalls, and timing.
* Mock `subprocess.run` or `subprocess.Popen` directly only in wrapper tests;
  elsewhere, mock Sandy's wrapper boundary.
* Assert exact arguments, ordering, rollback, cleanup, and error paths. Cover
  malformed input, boundaries, partial failure, conflicts, and repeated
  cleanup.
* Add a regression test for each bug fix.
* Maintain the configured 95 percent combined branch and statement coverage;
  do not add low-value tests solely to reach 100 percent.

## Development and Validation

The Makefile is the source of truth. Run commands from the repository root and
set up tools with `make install-tools`.

Run a focused unit test with:

```bash
.venv-test/bin/python -W error -m unittest -v \
    tests.test_sandy.ClassName.test_name
```

Run the smallest validation set that covers the change:

* Documentation or instructions only: `git diff --check` and ASCII validation.
* Python: focused tests, then `make check`.
* Shell: `make shell-check` plus relevant tests.
* Security-sensitive control flow: `make coverage`.
* E2E: only when explicitly required and inside a verified disposable VM.

Report checks that fail or cannot run. Repeat checks only after a failure or
material uncertainty. Do not delete an existing virtual environment, install
host packages, or weaken checks merely to obtain a passing result.

## End-to-End Test Safety

E2E tests perform real root-only host and container operations.

* Never run them on a normal development host or shared system.
* Run them only in a verified disposable Linux VM satisfying `README.md`.
* Require root and `SANDY_E2E=1`; never bypass or weaken these guards.
* Confirm the VM has no pre-existing Sandy machines, bridge, firewall state, or
  caches.
* Use `sudo env SANDY_E2E=1 make e2e`. Use `e2e-full` only when complete
  provisioning behavior needs verification.

## Communication and Handoff

* Report progress only for material findings or changes in direction.
* Lead the final response with the outcome, checks, gaps, risks, and
  assumptions; omit filler and repeated summaries.
* Match deliverable length to the task. Update tests, `--help`, and `README.md`
  when user-visible behavior or security assumptions change.
* Do not modify sudoers, install files as root, or run destructive cleanup as
  ordinary verification.
