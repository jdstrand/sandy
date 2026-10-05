#!/usr/bin/env python3

"""Unit tests for the extensionless ``sandy`` CLI script."""

import argparse
import errno
import importlib.machinery
import importlib.util
import io
import json
import os
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from collections.abc import Callable, Iterator, Mapping
from contextlib import (
    ExitStack,
    closing,
    contextmanager,
    redirect_stderr,
    redirect_stdout,
)
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import ANY, MagicMock, call, mock_open, patch

PROJECT_DIR = Path(__file__).resolve().parents[1]
SANDY_PATH = PROJECT_DIR / "sandy"


def _load_sandy_module():
    """Load this repository's sandy script without executing its main guard."""
    loader = importlib.machinery.SourceFileLoader(
        "sandy_under_test",
        str(SANDY_PATH),
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    if spec is None:
        raise RuntimeError("Could not create an import specification for sandy")
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


sandy = _load_sandy_module()
# A supervisor pinned by up, for tests that mock the checks that use it.
PINNED_SUPERVISOR = sandy.PinnedSupervisor(pidfd=-1, pid=4242)
# The stop of a supervisor whose pin or marker failed: up removed its ports,
# and the stop runs under the lifecycle lock, so it is short.
LOCKED_STOP = {
    "remove_ports": False,
    "term_timeout": sandy.CONTAINER_POWEROFF_TIMEOUT / 2,
    "kill_timeout": sandy.CONTAINER_POWEROFF_TIMEOUT / 2,
}
# The stop after the last session runs under the lifecycle lock: it waits
# for the port mapping lock, and then stops, each for a short time.
LAST_ATTACH_STOP = {
    "port_lock_timeout": sandy.PORT_MAPPINGS_LOCK_TIMEOUT,
    "stop_timeout": sandy.CONTAINER_POWEROFF_TIMEOUT,
}


def make_sandy():
    """Create a Sandy instance without privileged constructor side effects."""
    instance = sandy.Sandy.__new__(sandy.Sandy)
    instance.container = "ai-dev"
    instance.workspace = "workspace"
    instance.shared = None
    instance.user = "developer"
    instance.user_home = "/home/developer"
    instance.script_dir = str(PROJECT_DIR)
    instance.has_debootstrap = True
    instance.has_skopeo = True
    instance.has_umoci = True
    instance.systemd_version = 255
    instance.network = None
    instance.port_mappings = []
    instance.cn_debootstrap = str(PROJECT_DIR / "debootstrap.sh")
    instance.cn_oci = str(PROJECT_DIR / "oci.sh")
    instance.cn_keepalive = str(PROJECT_DIR / "sandy-keepalive.sh")
    instance.cn_setup_container = str(PROJECT_DIR / "setup-container.sh")
    instance.bootstrap_method = "OCI"
    instance.bootstrap_script = instance.cn_oci
    instance.base_image = "debian:trixie-slim"
    return instance


def make_network():
    """Create a SandyNet instance without probing or changing host networking."""
    instance = sandy.SandyNet.__new__(sandy.SandyNet)
    instance.bridge_name = "sandybr0"
    instance.network = "10.200.1.0"
    instance.network_cidr = "10.200.1.0/24"
    instance.gateway = "10.200.1.1"
    instance.configured = True
    instance.has_iptables = True
    instance.has_ip6tables = True
    instance.has_nft = True
    instance.firewall_backend = "iptables"
    return instance


@contextmanager
def captured_output():
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        yield stdout, stderr


@contextmanager
def state_file_handle(raw_state):
    handle = io.StringIO(raw_state)
    yield handle


def run_with_fifo_release(
    target: Callable[[], object], fifos: list[Path], timeout: float = 5.0
) -> tuple[object, BaseException | None, bool]:
    """Run target in a thread; return its result, its exception, and blocked.

    A blocking open of a FIFO for reading waits for a writer. When the thread
    still runs after timeout, open each FIFO for writing without blocking, so
    that the open returns, and report blocked. The test then fails at once,
    with no hang.
    """
    outcome: dict[str, object] = {}

    def run() -> None:
        try:
            outcome["result"] = target()
        except BaseException as exc:  # the test checks each exception
            outcome["exception"] = exc

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(timeout)
    blocked = worker.is_alive()
    if blocked:
        for fifo in fifos:
            try:
                writer = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
            except OSError:
                continue
            os.close(writer)
        worker.join(timeout)
    exception = outcome.get("exception")
    if not isinstance(exception, BaseException):
        exception = None
    return outcome.get("result"), exception, blocked


class CliSmokeTests(unittest.TestCase):
    def test_executable_help_smoke(self):
        result = subprocess.run(
            [str(SANDY_PATH), "--help"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
            shell=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Sandy CLI", result.stdout)
        for command in ("up", "down", "rm", "bash", "exec", "status", "list"):
            with self.subTest(command=command):
                self.assertIn(command, result.stdout)

    def test_executable_rejects_invalid_network_before_privileged_setup(self):
        result = subprocess.run(
            [str(SANDY_PATH), "up", "--network", "untrusted"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
            shell=False,
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("invalid choice", result.stderr)


class ValidationTests(unittest.TestCase):
    def assert_table(self, validator, cases):
        for value, expected in cases:
            with self.subTest(value=value):
                self.assertEqual(validator(value), expected)

    def test_container_names(self):
        self.assert_table(
            sandy._validate_container_name,
            [
                ("a", True),
                ("ai-dev", True),
                ("a" * 63, True),
                ("", False),
                ("a" * 64, False),
                ("-bad", False),
                ("bad-", False),
                ("Bad", False),
                ("bad_name", False),
                ("bad;name", False),
                ("bad\nname", False),
                # re.match with "$" accepted a trailing newline.
                ("ai-dev\n", False),
            ],
        )

    def test_usernames(self):
        self.assert_table(
            sandy._validate_username,
            [
                ("developer", True),
                ("_", True),
                ("user-name_2", True),
                ("a" * 32, True),
                ("", False),
                ("a" * 33, False),
                ("-root", False),
                ("Root", False),
                ("user$", False),
                ("user;id", False),
                ("user\nname", False),
                ("developer\n", False),
            ],
        )

    def test_workspace_paths(self):
        self.assert_table(
            sandy._validate_workspace_path,
            [
                ("workspace", True),
                ("nested/workspace", True),
                ("./workspace", True),
                (".", True),
                ("name..with-dots", True),
                ("a" * 4096, True),
                ("", False),
                (None, False),
                ("/absolute", False),
                ("../secret", False),
                ("workspace/../secret", False),
                ("workspace/../../secret", False),
                ("bad\x00path", False),
                ("bad\npath", False),
                ("a" * 4097, False),
            ],
        )

    def test_environment_values(self):
        self.assert_table(
            lambda value: sandy._validate_env_var(
                value,
                {"oci", "debootstrap"},
                16,
            ),
            [
                ("oci", True),
                ("debootstrap", True),
                ("", False),
                ("OCI", False),
                ("other", False),
                ("oci\n", False),
                ("a" * 17, False),
            ],
        )
        self.assertFalse(sandy._validate_env_var("value\nwith-newline"))

    def test_container_environment_is_an_explicit_allow_list(self):
        with patch.dict(
            sandy.os.environ,
            {
                "TERM": "xterm-kitty",
                "SANDY_TEST_HOST_SECRET": "must-not-cross",
            },
            clear=True,
        ):
            environment = sandy._container_environment(
                "developer",
                "/home/developer",
            )

        self.assertEqual(
            environment,
            {
                "HOME": "/home/developer",
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "LOGNAME": "developer",
                "PATH": sandy.CONTAINER_PATH,
                "SHELL": "/bin/bash",
                "SYSTEMD_COLORS": "0",
                "TERM": "xterm-kitty",
                "USER": "developer",
            },
        )
        self.assertNotIn("SANDY_TEST_HOST_SECRET", environment)

    def test_container_environment_validates_identity_and_terminal(self):
        with patch.dict(sandy.os.environ, {}, clear=True):
            root_environment = sandy._container_environment("root", "/root")
        self.assertEqual(root_environment["TERM"], sandy.DEFAULT_CONTAINER_TERM)

        for terminal_type in ("xterm-256color", "xterm-ghostty"):
            with self.subTest(terminal_type=terminal_type):
                with patch.dict(
                    sandy.os.environ,
                    {"TERM": terminal_type},
                    clear=True,
                ):
                    environment = sandy._container_environment("root", "/root")
                self.assertEqual(environment["TERM"], terminal_type)

        invalid_identities = (
            ("Bad", "/home/Bad"),
            ("developer", "/root"),
            ("root", "/home/root"),
        )
        for user, user_home in invalid_identities:
            with self.subTest(user=user, user_home=user_home):
                with self.assertRaises(ValueError):
                    sandy._container_environment(user, user_home)

        for terminal_type in ("bad term", "bad\nterm", "-bad", "x" * 65):
            with self.subTest(terminal_type=terminal_type):
                with patch.dict(
                    sandy.os.environ,
                    {"TERM": terminal_type},
                    clear=True,
                ):
                    with self.assertRaisesRegex(ValueError, "Invalid TERM"):
                        sandy._container_environment("root", "/root")

    def test_container_exit_status_normalization(self):
        cases = (
            (0, 0),
            (23, 23),
            (-15, 143),
            (-999, 255),
            (256, 1),
            (None, 1),
            (True, 1),
        )
        for status, expected in cases:
            with self.subTest(status=status):
                self.assertEqual(sandy._container_exit_code(status), expected)

        sandy._raise_for_container_status(0)
        with self.assertRaises(SystemExit) as raised:
            sandy._raise_for_container_status(-15)
        self.assertEqual(raised.exception.code, 143)

    def test_image_names(self):
        self.assert_table(
            sandy._validate_image_name,
            [
                ("debian:trixie-slim", True),
                ("ubuntu.noble", True),
                ("a" * 128, True),
                ("", False),
                ("Debian:latest", False),
                ("registry.example/debian:latest", False),
                ("debian latest", False),
                ("a" * 129, False),
                ("debian:trixie-slim\n", False),
            ],
        )

    def test_network_cidrs(self):
        self.assert_table(
            sandy._validate_network_cidr,
            [
                ("10.20.0.0/16", True),
                ("192.168.1.0/24", True),
                ("fd00::/64", True),
                ("8.8.8.0/24", False),
                ("10.20.0.1/16", False),
                ("not-a-cidr", False),
            ],
        )

    def test_ip_addresses(self):
        self.assert_table(
            sandy._validate_ip_address,
            [
                ("10.20.0.10", True),
                ("192.168.1.1", True),
                ("fd00::1", True),
                ("8.8.8.8", False),
                ("not-an-ip", False),
            ],
        )

    def test_port_mappings(self):
        self.assert_table(
            sandy._validate_port_mapping,
            [
                ("tcp:1:65535", ("tcp", 1, 65535)),
                ("udp:8080:80", ("udp", 8080, 80)),
                ("", None),
                (None, None),
                ("sctp:1:2", None),
                ("tcp:0:80", None),
                ("tcp:65536:80", None),
                ("tcp:80:0", None),
                ("tcp:eighty:80", None),
                ("tcp:80", None),
                ("tcp:1:2:3", None),
            ],
        )

    def test_strip_control_characters(self):
        message = "safe\nforged\rline\tvalue\x00\x7f"
        self.assertEqual(
            sandy._strip_control_characters(message), "safeforgedlinevalue"
        )
        self.assertEqual(sandy._strip_control_characters(123), "123")

    def test_terminal_safe_repr_preserves_escaped_identity(self):
        represented = sandy._terminal_safe_repr("unsafe\x1b[31m\\literal")

        self.assertEqual(represented, "'unsafe\\x1b[31m\\\\literal'")
        self.assertFalse(sandy._contains_control_character(represented))


class SubprocessWrapperTests(unittest.TestCase):
    def test_command_argument_validation(self):
        for command in ([], [""], ["ok", 2], None):
            with self.subTest(command=command):
                with self.assertRaises(ValueError):
                    sandy._validate_command_args(command)

        sandy._validate_command_args(["echo", "safe"])

    def test_run_wrapper_forces_shell_false(self):
        completed = subprocess.CompletedProcess(["true"], 0)
        with patch.object(sandy.subprocess, "run", return_value=completed) as run:
            result = sandy._run_secure_subprocess(["true"], check=True)

        self.assertIs(result, completed)
        run.assert_called_once_with(["true"], check=True, shell=False)

    def test_run_wrapper_preserves_called_process_error_output(self):
        error = subprocess.CalledProcessError(
            2,
            ["tool"],
            output="ordinary output",
            stderr="bad\nforged",
        )
        with patch.object(sandy.subprocess, "run", side_effect=error):
            with self.assertRaises(subprocess.CalledProcessError) as raised:
                sandy._run_secure_subprocess(["tool"])

        self.assertEqual(raised.exception.stderr, "bad\nforged")
        self.assertEqual(raised.exception.stdout, "ordinary output")

    def test_popen_wrapper_forces_shell_false(self):
        process = MagicMock()
        with patch.object(sandy.subprocess, "Popen", return_value=process) as popen:
            result = sandy._run_secure_subprocess_popen(["tool"], stdin=None)

        self.assertIs(result, process)
        popen.assert_called_once_with(["tool"], stdin=None, shell=False)

    def test_subprocess_wrappers_validate_explicit_inherited_fds(self):
        completed = subprocess.CompletedProcess(["true"], 0)
        descriptor = os.open(SANDY_PATH, os.O_RDONLY)
        try:
            with patch.object(sandy.subprocess, "run", return_value=completed) as run:
                result = sandy._run_secure_subprocess(
                    ["true"],
                    pass_fds=[descriptor],
                )
            self.assertIs(result, completed)
            run.assert_called_once_with(
                ["true"],
                pass_fds=(descriptor,),
                shell=False,
            )

            with self.assertRaisesRegex(
                ValueError,
                "Inherited file descriptors require close_fds=True",
            ):
                sandy._run_secure_subprocess(
                    ["true"],
                    close_fds=False,
                    pass_fds=(descriptor,),
                )
        finally:
            os.close(descriptor)

        with self.assertRaises(OSError):
            sandy._run_secure_subprocess(["true"], pass_fds=(descriptor,))

        for pass_fds in ((-1,), (True,), (0, 0), object()):
            with self.subTest(pass_fds=pass_fds):
                with self.assertRaises(ValueError):
                    sandy._validate_inherited_fds(pass_fds)

    def test_subprocess_wrappers_reject_shell_execution(self):
        for wrapper in (
            sandy._run_secure_subprocess,
            sandy._run_secure_subprocess_popen,
        ):
            with self.subTest(wrapper=wrapper.__name__):
                with self.assertRaisesRegex(
                    ValueError,
                    "Shell execution is not permitted",
                ):
                    wrapper(["tool"], shell=True)

    def test_subprocess_wrappers_validate_before_execution(self):
        cases = (
            (sandy._run_secure_subprocess, "run"),
            (sandy._run_secure_subprocess_popen, "Popen"),
        )
        for wrapper, subprocess_method in cases:
            with self.subTest(wrapper=wrapper.__name__):
                with patch.object(sandy.subprocess, subprocess_method) as execute:
                    with self.assertRaisesRegex(
                        ValueError,
                        "Invalid command arguments",
                    ):
                        wrapper(["tool", ""])
                execute.assert_not_called()

    def test_pty_wrapper_rejects_missing_callbacks(self):
        callback = lambda _fd: b""
        with self.assertRaises(ValueError):
            sandy._run_secure_subprocess_pty(
                ["tool"],
                environment={"PATH": sandy.CONTAINER_PATH},
                master_read=None,
                stdin_read=callback,
            )
        with self.assertRaises(ValueError):
            sandy._run_secure_subprocess_pty(
                ["tool"],
                environment={"PATH": sandy.CONTAINER_PATH},
                master_read=callback,
                stdin_read=None,
            )

    def test_pty_wrapper_validates_explicit_environment_before_fork(self):
        callback = lambda _fd: b""
        with patch.object(sandy.pty, "fork") as fork:
            with self.assertRaisesRegex(ValueError, "environment is required"):
                sandy._run_secure_subprocess_pty(
                    ["tool"],
                    master_read=callback,
                    stdin_read=callback,
                    environment=None,
                )
        fork.assert_not_called()

        invalid_environments = (
            {"BAD-KEY": "value"},
            {"KEY": "bad\nvalue"},
            {"KEY": "x" * 4097},
            {f"KEY{index}": "value" for index in range(65)},
        )
        for environment in invalid_environments:
            with self.subTest(environment_size=len(environment)):
                with patch.object(sandy.pty, "fork") as fork:
                    with self.assertRaises(ValueError):
                        sandy._run_secure_subprocess_pty(
                            ["tool"],
                            master_read=callback,
                            stdin_read=callback,
                            environment=environment,
                        )
                fork.assert_not_called()

    def test_pty_wrapper_marks_only_explicit_fds_inheritable_in_child(self):
        # Mocks: the fork (this process takes the child branch), the
        # descriptor cleanup, and the exec, so this process keeps its
        # descriptors. The child closes the others before exec.
        descriptor = os.open(SANDY_PATH, os.O_RDONLY)
        manager = MagicMock()
        manager.execvpe.side_effect = RuntimeError("exec called")
        try:
            with patch.object(sandy.pty, "fork", return_value=(0, 10)):
                with patch.object(sandy, "_close_inherited_fds", manager.close):
                    with patch.object(
                        sandy.os, "set_inheritable", manager.set_inheritable
                    ):
                        with patch.object(sandy.os, "execvpe", manager.execvpe):
                            with self.assertRaisesRegex(RuntimeError, "exec called"):
                                sandy._run_secure_subprocess_pty(
                                    ["tool"],
                                    environment={"PATH": sandy.CONTAINER_PATH},
                                    master_read=MagicMock(),
                                    stdin_read=MagicMock(),
                                    pass_fds=(descriptor,),
                                )
            self.assertEqual(
                manager.mock_calls,
                [
                    call.close((descriptor,)),
                    call.set_inheritable(descriptor, True),
                    call.execvpe("tool", ["tool"], {"PATH": sandy.CONTAINER_PATH}),
                ],
            )
        finally:
            os.close(descriptor)

    def test_close_inherited_fds_keeps_standard_streams_and_passed_fds(self):
        # Mocks: the descriptor list and close, so that this process keeps
        # its descriptors.
        with patch.object(sandy, "_open_fds", return_value={0, 1, 2, 3, 5, 7, 9}):
            with patch.object(sandy.os, "close") as close:
                sandy._close_inherited_fds((5, 9))
        self.assertEqual(close.call_args_list, [call(3), call(7)])

        with patch.object(sandy, "_open_fds", return_value={0, 1, 2, 4}):
            with patch.object(
                sandy.os, "close", side_effect=OSError(errno.EIO, "close failed")
            ):
                with self.assertRaises(OSError):
                    sandy._close_inherited_fds(())

    def test_close_inherited_fds_in_a_real_child(self):
        # No mocks: a new interpreter inherits two descriptors without
        # close-on-exec, keeps one, and reports what stays open.
        script = (
            "import importlib.machinery, importlib.util, json, sys\n"
            "loader = importlib.machinery.SourceFileLoader('sandy_child', sys.argv[1])\n"
            "spec = importlib.util.spec_from_loader(loader.name, loader)\n"
            "module = importlib.util.module_from_spec(spec)\n"
            "loader.exec_module(module)\n"
            "module._close_inherited_fds((int(sys.argv[2]),))\n"
            "print(json.dumps(sorted(module._open_fds())))\n"
        )
        kept = os.open(SANDY_PATH, os.O_RDONLY)
        extra = os.open(SANDY_PATH, os.O_RDONLY)
        try:
            result = subprocess.run(
                [sys.executable, "-I", "-c", script, str(SANDY_PATH), str(kept)],
                pass_fds=(kept, extra),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
                shell=False,
            )
        finally:
            os.close(kept)
            os.close(extra)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), [0, 1, 2, kept])

    def test_pty_child_gets_no_inherited_descriptor(self):
        # Regression test for the pty path giving inherited descriptors to the
        # entry helper. No mocks: a new interpreter inherits a descriptor
        # without close-on-exec and runs a command through the real PTY
        # wrapper. The command reports the targets of its own descriptors.
        command = (
            "import json, os\n"
            "fd_dir = '/proc/self/fd'\n"
            "targets = []\n"
            "for name in os.listdir(fd_dir):\n"
            "    try:\n"
            "        targets.append(os.readlink(os.path.join(fd_dir, name)))\n"
            "    except OSError:\n"
            "        pass\n"
            "print('FDS=' + json.dumps(targets))\n"
        )
        runner = (
            "import importlib.machinery, importlib.util, os, sys\n"
            "loader = importlib.machinery.SourceFileLoader('sandy_child', sys.argv[1])\n"
            "spec = importlib.util.spec_from_loader(loader.name, loader)\n"
            "module = importlib.util.module_from_spec(spec)\n"
            "loader.exec_module(module)\n"
            "sys.exit(module._run_secure_subprocess_pty(\n"
            "    [sys.executable, '-I', '-c', sys.argv[2]],\n"
            "    environment={'PATH': '/usr/bin:/bin'},\n"
            "    master_read=lambda fd: os.read(fd, 1024),\n"
            "    stdin_read=lambda fd: b'',\n"
            "))\n"
        )
        with tempfile.NamedTemporaryFile(prefix="sandy-inherited-") as marker:
            descriptor = os.open(marker.name, os.O_RDONLY)
            try:
                result = subprocess.run(
                    [sys.executable, "-I", "-c", runner, str(SANDY_PATH), command],
                    pass_fds=(descriptor,),
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    check=False,
                    timeout=60,
                    shell=False,
                )
            finally:
                os.close(descriptor)
            lines = result.stdout.decode("utf-8", "replace").splitlines()
            reports = [line[4:] for line in lines if line.startswith("FDS=")]
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(len(reports), 1, lines)
            targets = json.loads(reports[0])
            self.assertTrue(targets)
            self.assertNotIn(marker.name, targets)


class PtyProcessTests(unittest.TestCase):
    def test_parent_pty_relays_io_resize_and_exit_status(self):
        stdin_read = MagicMock(return_value=b"input")
        master_read = MagicMock(side_effect=[b"output", b""])
        old_handler = object()

        def ioctl(_fd, request, argument):
            if request == 0x80045430:
                argument[0] = 7
            return 0

        def install_signal(_signal_number, handler):
            if callable(handler):
                handler(sandy.signal.SIGWINCH, None)
            return old_handler

        def listdir(path):
            if path == "/proc":
                return ["not-a-pid", "456", "789"]
            if path == "/proc/456/fd":
                return ["0"]
            if path == "/proc/789/fd":
                raise PermissionError("denied")
            return []

        select_results = [
            InterruptedError(),
            ([sys.stdin.fileno()], [], []),
            ([10], [], []),
            ([10], [], []),
        ]
        with ExitStack() as stack:
            stack.enter_context(patch.object(sandy.pty, "fork", return_value=(123, 10)))
            stack.enter_context(
                patch.object(
                    sandy.os,
                    "get_terminal_size",
                    return_value=os.terminal_size((120, 40)),
                )
            )
            stack.enter_context(patch.object(sandy.fcntl, "ioctl", side_effect=ioctl))
            stack.enter_context(
                patch.object(
                    sandy.termios,
                    "tcgetattr",
                    return_value=["settings"],
                )
            )
            setraw = stack.enter_context(patch.object(sandy.tty, "setraw"))
            signal_call = stack.enter_context(
                patch.object(
                    sandy.signal,
                    "signal",
                    side_effect=install_signal,
                )
            )
            stack.enter_context(
                patch.object(
                    sandy.select,
                    "select",
                    side_effect=select_results,
                )
            )
            stack.enter_context(patch.object(sandy.os, "listdir", side_effect=listdir))
            stack.enter_context(
                patch.object(
                    sandy.os,
                    "readlink",
                    return_value="/dev/pts/7",
                )
            )
            kill = stack.enter_context(patch.object(sandy.os, "kill"))
            write = stack.enter_context(patch.object(sandy.os, "write"))
            restore_terminal = stack.enter_context(
                patch.object(sandy.termios, "tcsetattr")
            )
            close = stack.enter_context(patch.object(sandy.os, "close"))
            stack.enter_context(
                patch.object(
                    sandy.os,
                    "waitpid",
                    return_value=(123, 3 << 8),
                )
            )
            result = sandy._run_secure_subprocess_pty(
                ["tool"],
                environment={"PATH": sandy.CONTAINER_PATH},
                master_read=master_read,
                stdin_read=stdin_read,
            )

        self.assertEqual(result, 3)
        setraw.assert_called_once()
        kill.assert_called_once_with(456, sandy.signal.SIGWINCH)
        self.assertIn(call(10, b"input"), write.call_args_list)
        self.assertIn(call(sys.stdout.fileno(), b"output"), write.call_args_list)
        restore_terminal.assert_called_once()
        close.assert_called_once_with(10)
        self.assertEqual(signal_call.call_count, 2)

    def test_parent_pty_handles_non_terminal_and_signal_exit(self):
        master_read = MagicMock(return_value=b"")
        worker = object()
        main = object()

        def ioctl(_fd, request, _argument):
            if request == 0x80045430:
                raise OSError("no PTY peer")
            return 0

        with patch.object(sandy.pty, "fork", return_value=(123, 10)):
            with patch.object(
                sandy.os,
                "get_terminal_size",
                side_effect=OSError,
            ):
                with patch.object(sandy.fcntl, "ioctl", side_effect=ioctl):
                    with patch.object(
                        sandy.termios,
                        "tcgetattr",
                        side_effect=sandy.termios.error,
                    ):
                        with patch.object(
                            sandy.threading,
                            "current_thread",
                            return_value=worker,
                        ):
                            with patch.object(
                                sandy.threading,
                                "main_thread",
                                return_value=main,
                            ):
                                with patch.object(
                                    sandy.select,
                                    "select",
                                    return_value=([10], [], []),
                                ):
                                    with patch.object(sandy.os, "close"):
                                        with patch.object(
                                            sandy.os,
                                            "waitpid",
                                            return_value=(
                                                123,
                                                sandy.signal.SIGTERM,
                                            ),
                                        ):
                                            result = sandy._run_secure_subprocess_pty(
                                                ["tool"],
                                                environment={
                                                    "PATH": sandy.CONTAINER_PATH
                                                },
                                                master_read=master_read,
                                                stdin_read=MagicMock(),
                                            )
        self.assertEqual(result, -sandy.signal.SIGTERM)

    def test_parent_pty_handles_master_read_error_and_unknown_status(self):
        with patch.object(sandy.pty, "fork", return_value=(123, 10)):
            with patch.object(
                sandy.os,
                "get_terminal_size",
                return_value=os.terminal_size((80, 24)),
            ):
                with patch.object(sandy.fcntl, "ioctl", return_value=0):
                    with patch.object(
                        sandy.termios,
                        "tcgetattr",
                        side_effect=sandy.termios.error,
                    ):
                        with patch.object(
                            sandy.select,
                            "select",
                            return_value=([10], [], []),
                        ):
                            with patch.object(sandy.os, "close"):
                                with patch.object(
                                    sandy.os,
                                    "waitpid",
                                    return_value=(123, 0),
                                ):
                                    with patch.object(
                                        sandy.os,
                                        "WIFEXITED",
                                        return_value=False,
                                    ):
                                        with patch.object(
                                            sandy.os,
                                            "WIFSIGNALED",
                                            return_value=False,
                                        ):
                                            result = sandy._run_secure_subprocess_pty(
                                                ["tool"],
                                                environment={
                                                    "PATH": sandy.CONTAINER_PATH
                                                },
                                                master_read=MagicMock(
                                                    side_effect=OSError
                                                ),
                                                stdin_read=MagicMock(),
                                            )
        self.assertEqual(result, -1)

    def test_child_pty_reports_exec_failure_safely(self):
        executable = "missing\n\x1b[31m"
        with ExitStack() as stack:
            stack.enter_context(patch.object(sandy.pty, "fork", return_value=(0, 10)))
            # This process takes the child branch; keep its descriptors.
            stack.enter_context(patch.object(sandy, "_close_inherited_fds"))
            stack.enter_context(
                patch.object(
                    sandy.os,
                    "execvpe",
                    side_effect=OSError("missing\nforged"),
                )
            )
            child_exit = stack.enter_context(
                patch.object(
                    sandy.os,
                    "_exit",
                    side_effect=RuntimeError("child exited"),
                )
            )
            _, stderr = stack.enter_context(captured_output())
            with self.assertRaisesRegex(RuntimeError, "child exited"):
                sandy._run_secure_subprocess_pty(
                    [executable],
                    environment={"PATH": sandy.CONTAINER_PATH},
                    master_read=MagicMock(),
                    stdin_read=MagicMock(),
                )
        child_exit.assert_called_once_with(1)
        output = stderr.getvalue()
        diagnostic = output.rstrip("\n")
        self.assertFalse(sandy._contains_control_character(diagnostic))
        self.assertNotIn(executable, output)
        self.assertNotIn("missing\nforged", output)
        self.assertIn("missing\\n\\x1b[31m", output)
        self.assertIn("missing\\nforged", output)

    def test_child_pty_executes_with_only_the_explicit_environment(self):
        environment = {
            "PATH": sandy.CONTAINER_PATH,
            "TERM": "xterm-256color",
        }
        with patch.object(sandy.pty, "fork", return_value=(0, 10)):
            # This process takes the child branch; keep its descriptors.
            with patch.object(sandy, "_close_inherited_fds"):
                with patch.object(
                    sandy.os,
                    "execvpe",
                    side_effect=RuntimeError("exec called"),
                ) as explicit_exec:
                    with self.assertRaisesRegex(RuntimeError, "exec called"):
                        sandy._run_secure_subprocess_pty(
                            ["tool", "argument"],
                            master_read=MagicMock(),
                            stdin_read=MagicMock(),
                            environment=environment,
                        )

        explicit_exec.assert_called_once_with(
            "tool",
            ["tool", "argument"],
            environment,
        )


class ParserTests(unittest.TestCase):
    def parse(self, *arguments):
        with patch.object(sys, "argv", ["sandy", *arguments]):
            return sandy.parse_args_custom()

    def test_up_resource_limit_options_follow_docker_run(self):
        args = self.parse(
            "up", "--pids-limit", "-1", "--tmp-size", "512m", "--oom-score-adj", "-500"
        )
        self.assertEqual(
            (args.pids_limit, args.tmp_size, args.oom_score_adj), (-1, 512 * MIB, -500)
        )
        args = self.parse(
            "up", "--tmp-size=1G", "--pids-limit=4096", "--oom-score-adj=1000"
        )
        self.assertEqual(
            (args.pids_limit, args.tmp_size, args.oom_score_adj), (4096, GIB, 1000)
        )
        args = self.parse("up")
        self.assertEqual(
            (args.pids_limit, args.tmp_size, args.oom_score_adj), (None, None, None)
        )

    def test_up_resource_limit_options_reject_bad_or_repeated_values(self):
        for arguments in (
            ("--tmp-size", "5 g"),
            ("--tmp-size", "1k"),
            ("--pids-limit", "0"),
            ("--oom-score-adj", "-1000"),
            ("--oom-score-adj", "1001"),
            ("--pids-limit", "1", "--pids-limit", "2"),
            ("--oom-score-adj", "1", "--oom-score-adj", "2"),
            # A container has no CPU, memory, or swap option of its own.
            ("--cpus", "1"),
            ("-m", "1g"),
            ("--memory-swap", "1g"),
        ):
            with self.subTest(arguments=arguments):
                with captured_output(), self.assertRaises(SystemExit) as raised:
                    self.parse("up", *arguments)
                self.assertEqual(raised.exception.code, 2)

    def test_update_options_follow_docker_update(self):
        args = self.parse("-c", "box", "update", "--pids-limit", "512")
        self.assertEqual(
            (args.command, args.container, args.shared_limits, args.pids_limit),
            ("update", "box", False, 512),
        )
        # update --shared does not change the global -s/--shared directory.
        args = self.parse(
            "-s",
            "dir",
            "update",
            "--shared",
            "--cpuset-cpus",
            "4-7,9",
            "-m",
            "24g",
            "--pids-limit",
            "-1",
        )
        self.assertEqual(
            (
                args.shared,
                args.shared_limits,
                args.cpuset_cpus,
                args.memory,
                args.pids_limit,
                args.reset,
            ),
            ("dir", True, (4, 5, 6, 7, 9), 24 * GIB, -1, False),
        )
        args = self.parse("update", "--shared", "--reset")
        self.assertEqual(
            (args.shared, args.shared_limits, args.reset), (None, True, True)
        )
        args = self.parse("update")
        self.assertEqual(
            (
                args.shared_limits,
                args.cpuset_cpus,
                args.memory,
                args.pids_limit,
                args.reset,
            ),
            (False, None, None, None, False),
        )
        self.assertFalse(hasattr(args, "tmp_size"))
        for arguments in (
            ("--tmp-size", "1g"),
            ("--oom-score-adj", "1"),
            # No abbreviations: --cpus is a prefix of --cpuset-cpus.
            ("--cpus", "1"),
            ("--cpu", "1"),
            ("--mem", "1g"),
            ("--memory-swap", "1g"),
            ("-m", "63m"),
            ("-m", "1g", "-m", "2g"),
            ("--cpuset-cpus", "x"),
            ("--cpuset-cpus", "1", "--cpuset-cpus", "2"),
            ("--pids-limit", "0"),
        ):
            with self.subTest(arguments=arguments):
                with captured_output(), self.assertRaises(SystemExit) as raised:
                    self.parse("update", *arguments)
                self.assertEqual(raised.exception.code, 2)

    def test_no_command_defaults(self):
        args = self.parse()
        self.assertIsNone(args.command)
        self.assertIsNone(args.workspace)
        self.assertEqual(args.user, "developer")

    def test_up_options(self):
        args = self.parse(
            "-w",
            "project",
            "-s",
            "shared",
            "-c",
            "test-box",
            "-u",
            "tester",
            "up",
            "--build",
            "--detach",
            "--persistent",
            "--network",
            "host",
            "--port",
            "tcp:8080:80",
            "-p",
            "udp:5353:53",
        )

        self.assertEqual(args.command, "up")
        self.assertEqual(args.workspace, "project")
        self.assertEqual(args.shared, "shared")
        self.assertEqual(args.container, "test-box")
        self.assertEqual(args.user, "tester")
        self.assertTrue(args.build)
        self.assertTrue(args.detach)
        self.assertTrue(args.persistent)
        self.assertEqual(args.network, "host")
        self.assertEqual(args.ports, ["tcp:8080:80", "udp:5353:53"])

    def test_up_defaults(self):
        args = self.parse("up")
        self.assertFalse(args.build)
        self.assertFalse(args.detach)
        self.assertFalse(args.persistent)
        self.assertEqual(args.network, "lenient")
        self.assertIsNone(args.ports)

    def test_exec_preserves_remainder(self):
        args = self.parse(
            "-w",
            "project",
            "exec",
            "--",
            "python3",
            "-c",
            "print('ok')",
        )
        self.assertEqual(args.command, "exec")
        self.assertEqual(
            args.exec_command,
            ["--", "python3", "-c", "print('ok')"],
        )

    def test_bash_preserves_remainder(self):
        args = self.parse("bash", "-c", "printf safe")
        self.assertEqual(args.command, "bash")
        self.assertEqual(args.bash_args, ["-c", "printf safe"])

    def test_down_options(self):
        args = self.parse("down", "--force", "--purge")
        self.assertEqual(args.command, "down")
        self.assertTrue(args.force)
        self.assertTrue(args.purge)

    def test_rm_options(self):
        cases = (
            (("--all", "--force"), (True, True, False, False)),
            (("--cache",), (False, False, True, False)),
            (("--network",), (False, False, False, True)),
        )
        for options, expected in cases:
            with self.subTest(options=options):
                args = self.parse("rm", *options)
                actual = (args.all, args.force, args.cache, args.network)
                self.assertEqual(args.command, "rm")
                self.assertEqual(actual, expected)

    def test_subcommand_names_are_valid_global_option_values(self):
        cases = [
            (("-w", "exec", "status"), "exec", "status"),
            (("--workspace=up", "list"), "up", "list"),
            (("-sexec", "status"), None, "status"),
            (("-c", "list", "status"), None, "status"),
        ]
        for arguments, workspace, command in cases:
            with self.subTest(arguments=arguments):
                args = self.parse(*arguments)
                self.assertEqual(args.command, command)
                if workspace is not None:
                    self.assertEqual(args.workspace, workspace)

    def test_duplicate_store_once_options_fail(self):
        with captured_output() as (_, stderr):
            with self.assertRaises(SystemExit) as raised:
                self.parse("-w", "one", "--workspace", "two", "status")
        self.assertEqual(raised.exception.code, 2)
        self.assertIn("can only be specified once", stderr.getvalue())

    def test_invalid_network_choice_fails(self):
        with captured_output() as (_, stderr):
            with self.assertRaises(SystemExit) as raised:
                self.parse("up", "--network", "bad")
        self.assertEqual(raised.exception.code, 2)
        self.assertIn("invalid choice", stderr.getvalue())

    def test_all_simple_subcommands(self):
        for command in ("down", "rm", "status", "list"):
            with self.subTest(command=command):
                self.assertEqual(self.parse(command).command, command)


class MainDispatchTests(unittest.TestCase):
    def make_args(self, command, **overrides):
        values = {
            "workspace": None,
            "shared": None,
            "container": None,
            "user": "developer",
            "command": command,
        }
        values.update(overrides)
        return argparse.Namespace(**values)

    def run_main(self, args, instance=None):
        instance = instance or MagicMock()
        instance.container = "ai-dev"
        instance.user = "developer"
        with patch.object(sandy, "parse_args_custom", return_value=args):
            with patch.object(sandy, "_require_root"):
                with patch.object(sandy, "_verify_safe_dir"):
                    with patch.object(sandy, "Sandy", return_value=instance):
                        sandy.main()
        return instance

    def test_a_query_that_does_not_answer_ends_the_command(self):
        instance = MagicMock()
        instance.run_status.side_effect = subprocess.TimeoutExpired(
            ["machinectl", "show", "ai-dev", "-p", "Leader", "--value"],
            sandy.QUERY_COMMAND_TIMEOUT,
        )
        with captured_output() as (stdout, _):
            with self.assertRaises(SystemExit) as exited:
                self.run_main(self.make_args("status"), instance)
        self.assertEqual(exited.exception.code, 1)
        self.assertEqual(
            stdout.getvalue(), "E: 'machinectl' did not answer in 3 seconds\n"
        )

    def test_a_failed_machine_query_ends_the_command(self):
        # Mocks: the command, which raises the error of a failed query.
        instance = MagicMock()
        instance.run_rm.side_effect = sandy._MachineQueryError(
            "ai-dev", "Failed to connect to bus: Connection refused"
        )
        args = self.make_args("rm", all=False, cache=False, network=False)
        with captured_output() as (stdout, _):
            with self.assertRaises(SystemExit) as exited:
                self.run_main(args, instance)
        self.assertEqual(exited.exception.code, 1)
        self.assertEqual(
            stdout.getvalue(),
            "E: Could not query machine 'ai-dev': "
            "'Failed to connect to bus: Connection refused'\n",
        )

    def test_root_and_safe_directory_checks_precede_construction(self):
        args = self.make_args("status")
        instance = MagicMock(container="ai-dev", user="developer")
        events = []

        def parse_arguments():
            events.append("parse")
            return args

        def verify_directory(path):
            events.append(("verify", path))

        def require_root():
            events.append("root")

        def create_instance():
            events.append("construct")
            return instance

        with patch.object(
            sandy,
            "parse_args_custom",
            side_effect=parse_arguments,
        ):
            with patch.object(sandy, "_require_root", side_effect=require_root):
                with patch.object(
                    sandy,
                    "_verify_safe_dir",
                    side_effect=verify_directory,
                ) as verify:
                    with patch.object(
                        sandy,
                        "Sandy",
                        side_effect=create_instance,
                    ):
                        sandy.main()

        self.assertEqual(
            events[:4],
            ["parse", "root", ("verify", sandy.SYSTEMD_MACHINES), "construct"],
        )
        verify.assert_called_once_with(sandy.SYSTEMD_MACHINES)

    def test_non_root_exits_before_safe_directory_verification(self):
        args = self.make_args("status")
        with patch.object(sandy, "parse_args_custom", return_value=args):
            with patch.object(sandy.os, "getuid", return_value=1000):
                with patch.object(sandy, "_verify_safe_dir") as verify:
                    with patch.object(sandy, "Sandy") as constructor:
                        with captured_output() as (stdout, _):
                            with self.assertRaises(SystemExit) as raised:
                                sandy.main()

        self.assertEqual(raised.exception.code, 1)
        self.assertIn("Must run as root", stdout.getvalue())
        verify.assert_not_called()
        constructor.assert_not_called()

    def test_parser_exits_before_privileged_checks(self):
        cases = (
            (["sandy", "--help"], 0),
            (["sandy", "up", "--network", "untrusted"], 2),
        )

        for argv, expected_code in cases:
            with self.subTest(argv=argv):
                with patch.object(sys, "argv", argv):
                    with patch.object(sandy, "_require_root") as require_root:
                        with patch.object(sandy, "_verify_safe_dir") as verify:
                            with patch.object(sandy, "Sandy") as constructor:
                                with captured_output():
                                    with self.assertRaises(SystemExit) as raised:
                                        sandy.main()

                self.assertEqual(raised.exception.code, expected_code)
                require_root.assert_not_called()
                verify.assert_not_called()
                constructor.assert_not_called()

    def test_validated_globals_are_applied(self):
        args = self.make_args(
            "status",
            workspace="project",
            shared="shared",
            container="test-box",
            user="root",
        )
        instance = self.run_main(args)

        self.assertEqual(instance.workspace, "project")
        self.assertEqual(instance.shared, "shared")
        self.assertEqual(instance.container, "test-box")
        self.assertEqual(instance.user, "root")
        self.assertEqual(instance.user_home, "/root")
        instance.run_status.assert_called_once_with()

    def test_custom_user_updates_derived_home(self):
        args = self.make_args("status", user="tester")
        instance = self.run_main(args)

        self.assertEqual(instance.user, "tester")
        self.assertEqual(instance.user_home, "/home/tester")
        instance.run_status.assert_called_once_with()

    def test_invalid_globals_exit_before_dispatch(self):
        cases = [
            {"workspace": "../secret"},
            {"shared": "/absolute"},
            {"container": "Bad_Name"},
            {"user": "Root"},
        ]
        for overrides in cases:
            with self.subTest(overrides=overrides):
                args = self.make_args("status", **overrides)
                instance = MagicMock(container="ai-dev", user="developer")
                with captured_output():
                    with self.assertRaises(SystemExit) as raised:
                        self.run_main(args, instance)
                self.assertEqual(raised.exception.code, 1)
                instance.run_status.assert_not_called()

    def test_command_dispatch(self):
        cases = {
            "up": ("run_up", {}),
            "down": ("run_down", {}),
            "bash": ("run_bash", {}),
            "exec": ("run_exec", {}),
            "status": ("run_status", {}),
            "list": ("run_list", {}),
            "update": ("run_update", {}),
        }
        for command, (method_name, extra) in cases.items():
            with self.subTest(command=command):
                args = self.make_args(command, **extra)
                instance = self.run_main(args)
                method = getattr(instance, method_name)
                if command in {"status", "list"}:
                    method.assert_called_once_with()
                else:
                    method.assert_called_once_with(args)

    def test_rm_dispatches_option_values(self):
        args = self.make_args(
            "rm",
            all=True,
            cache=True,
            network=False,
            force=True,
        )
        instance = self.run_main(args)
        instance.run_rm.assert_called_once_with(
            args,
            all=True,
            cache=True,
            network=False,
        )

    def test_no_command_opens_login_shell(self):
        args = self.make_args(None)
        instance = MagicMock()
        instance._exec.return_value = 0
        instance = self.run_main(args, instance)
        instance._exec.assert_called_once_with(None, login_shell=True)

    def test_no_command_propagates_login_shell_failure(self):
        args = self.make_args(None)
        instance = MagicMock()
        instance._exec.return_value = 19
        with self.assertRaises(SystemExit) as raised:
            self.run_main(args, instance)
        self.assertEqual(raised.exception.code, 19)

    def test_invalid_terminal_is_rejected_before_privileged_checks(self):
        args = self.make_args("exec")
        with patch.dict(sandy.os.environ, {"TERM": "bad\nterm"}, clear=True):
            with patch.object(sandy, "parse_args_custom", return_value=args):
                with patch.object(sandy, "_require_root") as require_root:
                    with patch.object(sandy, "_verify_safe_dir") as verify:
                        with patch.object(sandy, "Sandy") as constructor:
                            with captured_output() as (stdout, _):
                                with self.assertRaises(SystemExit) as raised:
                                    sandy.main()

        self.assertEqual(raised.exception.code, 1)
        self.assertIn("Invalid TERM", stdout.getvalue())
        require_root.assert_not_called()
        verify.assert_not_called()
        constructor.assert_not_called()


class FilesystemSafetyTests(unittest.TestCase):
    def safe_stat(
        self,
        *,
        uid=0,
        gid=0,
        mode=stat.S_IFDIR | 0o755,
        ino=1,
        dev=1,
        nlink=1,
    ):
        return SimpleNamespace(
            st_uid=uid,
            st_gid=gid,
            st_mode=mode,
            st_dev=dev,
            st_ino=ino,
            st_nlink=nlink,
        )

    @contextmanager
    def opened_parent(self, directory, basename="state"):
        def open_parent(_path):
            return (
                os.open(directory, sandy.DIRECTORY_OPEN_FLAGS),
                basename,
            )

        with patch.object(sandy, "_open_verified_parent", side_effect=open_parent):
            yield

    def test_managed_paths_are_normalized_and_scoped(self):
        with patch.object(sandy, "SYSTEMD_MACHINES", "/safe"):
            self.assertEqual(
                sandy._managed_path_components(
                    "/safe",
                    allow_managed_root=True,
                ),
                ("safe",),
            )
            self.assertEqual(
                sandy._managed_path_components(
                    "/safe/sandy.container/etc",
                    allow_managed_root=False,
                ),
                ("safe", "sandy.container", "etc"),
            )

            invalid_paths = (
                ("/safe", False),
                ("/unsafe/sandy.container", True),
                ("/safe/container", True),
                ("/safe/sandy.", True),
                ("/safe/sandy.container/../other", True),
                ("/safe//sandy.container", True),
                ("safe/sandy.container", True),
                ("", True),
                ("/safe/sandy.container\n", True),
                ("/safe/sandy.container\x1b", True),
                ("/safe/sandy.container\t", True),
                (f"/safe/sandy.container{chr(0x85)}", True),
            )
            for path, allow_managed_root in invalid_paths:
                with self.subTest(path=path):
                    with self.assertRaises(ValueError):
                        sandy._managed_path_components(
                            path,
                            allow_managed_root=allow_managed_root,
                        )

    def test_container_name_from_machine_path_validates_top_level_name(self):
        with patch.object(sandy, "SYSTEMD_MACHINES", "/safe"):
            self.assertEqual(
                sandy._container_name_from_machine_path("/safe/sandy.container"),
                "container",
            )

            invalid_paths = (
                "/safe",
                "/safe/sandy.__cache",
                "/safe/sandy.bad_name",
                "/safe/sandy.container/sandy.nested",
            )
            for path in invalid_paths:
                with self.subTest(path=path):
                    with self.assertRaises(ValueError):
                        sandy._container_name_from_machine_path(path)

    def test_verify_safe_dir_uses_no_follow_descriptor_walk(self):
        with patch.object(sandy, "SYSTEMD_MACHINES", "/safe"):
            with patch.object(sandy.os, "open", side_effect=[10, 11, 12]) as open_fd:
                with patch.object(
                    sandy.os,
                    "fstat",
                    side_effect=[
                        self.safe_stat(ino=1),
                        self.safe_stat(ino=2),
                        self.safe_stat(ino=3),
                    ],
                ):
                    with patch.object(sandy.os, "close") as close:
                        sandy._verify_safe_dir("/safe/sandy.container")

        self.assertEqual(
            open_fd.call_args_list,
            [
                call("/", sandy.DIRECTORY_OPEN_FLAGS),
                call("safe", sandy.DIRECTORY_OPEN_FLAGS, dir_fd=10),
                call("sandy.container", sandy.DIRECTORY_OPEN_FLAGS, dir_fd=11),
            ],
        )
        self.assertEqual(close.call_args_list, [call(10), call(11), call(12)])

    def test_owned_directory_rejects_wrong_type_owner_and_permissions(self):
        cases = [
            self.safe_stat(mode=stat.S_IFREG | 0o644),
            self.safe_stat(uid=1000),
            self.safe_stat(gid=1000),
            self.safe_stat(mode=stat.S_IFDIR | 0o775),
            self.safe_stat(mode=stat.S_IFDIR | 0o757),
        ]
        for unsafe in cases:
            with self.subTest(unsafe=unsafe):
                with self.assertRaises(PermissionError):
                    sandy._verify_owned_directory(unsafe, "unsafe")

        sandy._verify_owned_directory(self.safe_stat(), "safe")

    def test_owned_symlink_and_target_validation_fail_closed(self):
        safe_link = self.safe_stat(mode=stat.S_IFLNK | 0o777)
        sandy._verify_owned_symlink(safe_link, "safe")

        unsafe_links = (
            self.safe_stat(mode=stat.S_IFREG | 0o644),
            self.safe_stat(mode=stat.S_IFLNK | 0o777, uid=1000),
            self.safe_stat(mode=stat.S_IFLNK | 0o777, gid=1000),
        )
        for unsafe_link in unsafe_links:
            with self.subTest(unsafe_link=unsafe_link):
                with self.assertRaises(PermissionError) as raised:
                    sandy._verify_owned_symlink(
                        unsafe_link,
                        "unsafe\x1b[31m",
                    )
                message = str(raised.exception)
                self.assertIn("\\x1b", message)
                self.assertFalse(sandy._contains_control_character(message))

        with tempfile.TemporaryDirectory() as temp_dir:
            parent = Path(temp_dir)
            (parent / "link").symlink_to("target")
            parent_fd = os.open(parent, sandy.DIRECTORY_OPEN_FLAGS)
            try:
                with patch.object(sandy, "_verify_owned_symlink"):
                    for target in (
                        "\n",
                        "\t",
                        "\x1b[31m",
                        "\x7f",
                        chr(0x85),
                    ):
                        with self.subTest(target=repr(target)):
                            with patch.object(
                                sandy.os,
                                "readlink",
                                return_value=target,
                            ):
                                with self.assertRaises(PermissionError) as raised:
                                    sandy._read_verified_symlink(
                                        parent_fd,
                                        "link",
                                    )
                        self.assertFalse(
                            sandy._contains_control_character(str(raised.exception))
                        )
            finally:
                os.close(parent_fd)

    def test_managed_regular_file_helpers_are_no_follow_and_inode_stable(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            parent = Path(temp_dir)
            lock_path = parent / "port_mappings.lock"

            with self.opened_parent(parent, lock_path.name):
                first = sandy._open_stable_lock_file("/managed/lock")
            try:
                first_stat = os.fstat(first.fileno())
            finally:
                first.close()

            with self.opened_parent(parent, lock_path.name):
                second = sandy._open_stable_lock_file("/managed/lock")
            try:
                second_stat = os.fstat(second.fileno())
            finally:
                second.close()

            self.assertTrue(sandy._same_inode(first_stat, second_stat))
            self.assertEqual(stat.S_IMODE(lock_path.stat().st_mode), 0o600)

            with self.opened_parent(parent, lock_path.name):
                with patch.object(sandy, "_same_inode", return_value=False):
                    with self.assertRaises(PermissionError):
                        sandy._open_stable_lock_file("/managed/lock")

            state_path = parent / "port_mappings.json"
            state_path.write_text("{}\n", encoding="utf-8")
            state_path.chmod(0o600)
            with self.opened_parent(parent, state_path.name):
                state = sandy._open_existing_managed_text_file("/managed/state")
            self.assertIsNotNone(state)
            try:
                self.assertEqual(state.read(), "{}\n")
            finally:
                state.close()

            state_path.chmod(0o644)
            with self.opened_parent(parent, state_path.name):
                with self.assertRaises(PermissionError):
                    sandy._open_existing_managed_text_file("/managed/state")

            state_path.unlink()
            with self.opened_parent(parent, state_path.name):
                self.assertIsNone(
                    sandy._open_existing_managed_text_file("/managed/state")
                )

    def test_managed_regular_file_validation_escapes_labels(self):
        cases = (
            self.safe_stat(uid=os.geteuid(), gid=os.getegid()),
            self.safe_stat(
                mode=stat.S_IFREG | 0o600,
                uid=os.geteuid() + 1,
                gid=os.getegid(),
            ),
            self.safe_stat(
                mode=stat.S_IFREG | 0o600,
                uid=os.geteuid(),
                gid=os.getegid() + 1,
            ),
            self.safe_stat(
                mode=stat.S_IFREG | 0o600,
                uid=os.geteuid(),
                gid=os.getegid(),
                nlink=2,
            ),
            self.safe_stat(
                mode=stat.S_IFREG | 0o640,
                uid=os.geteuid(),
                gid=os.getegid(),
            ),
        )
        for unsafe in cases:
            with self.subTest(unsafe=unsafe):
                with self.assertRaises(PermissionError) as raised:
                    sandy._verify_owned_regular_file(
                        unsafe,
                        "unsafe\x1b[31m",
                        expected_mode=0o600,
                    )
                message = str(raised.exception)
                self.assertIn("\\x1b", message)
                self.assertFalse(sandy._contains_control_character(message))

        sandy._verify_owned_regular_file(
            self.safe_stat(
                mode=stat.S_IFREG | 0o600,
                uid=os.geteuid(),
                gid=os.getegid(),
            ),
            "safe",
            expected_mode=0o600,
        )

    def test_host_directory_resolution_rejects_invalid_and_linked_paths(self):
        invalid_paths = (
            "",
            "relative",
            "/tmp/../tmp",
            "/tmp\n",
            "/tmp\x1b",
            f"/tmp{chr(0x85)}",
        )
        for path in invalid_paths:
            with self.subTest(path=path):
                with self.assertRaises(ValueError):
                    sandy._open_verified_host_directory(path)

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "target"
            target.mkdir()
            (root / "link").symlink_to(target, target_is_directory=True)
            with patch.object(sandy, "_verify_owned_directory"):
                with self.assertRaises(PermissionError):
                    sandy._open_verified_host_directory(str(root / "link"))

        safe = self.safe_stat()
        with patch.object(
            sandy.os, "open", side_effect=[10, OSError(errno.EACCES, "")]
        ):
            with patch.object(sandy.os, "fstat", return_value=safe):
                with patch.object(sandy.os, "close") as close:
                    with patch.object(sandy, "_verify_owned_directory"):
                        with self.assertRaises(OSError):
                            sandy._open_verified_host_directory("/target")
        close.assert_called_once_with(10)

        with patch.object(sandy.os, "open", side_effect=[10, 11]):
            with patch.object(sandy.os, "fstat", return_value=safe):
                with patch.object(sandy.os, "close") as close:
                    with patch.object(
                        sandy,
                        "_verify_owned_directory",
                        side_effect=[None, PermissionError("unsafe")],
                    ):
                        with self.assertRaises(PermissionError):
                            sandy._open_verified_host_directory("/target")
        self.assertEqual(close.call_args_list, [call(11), call(10)])

    def test_verified_directory_resolution_closes_error_paths(self):
        safe = self.safe_stat()

        with patch.object(sandy, "SYSTEMD_MACHINES", "/safe"):
            with patch.object(sandy.os, "open", side_effect=[10, 11]):
                with patch.object(sandy.os, "fstat", return_value=safe):
                    with patch.object(sandy.os, "close") as close:
                        with patch.object(sandy, "_verify_owned_directory"):
                            directory_fd = sandy._open_verified_dir("/safe")
                            self.assertEqual(directory_fd, 11)
                            sandy.os.close(directory_fd)
        self.assertEqual(close.call_args_list, [call(10), call(11)])

        with patch.object(sandy, "SYSTEMD_MACHINES", "/safe"):
            with patch.object(
                sandy.os,
                "open",
                side_effect=[10, OSError(errno.EACCES, "unsafe")],
            ):
                with patch.object(sandy.os, "fstat", return_value=safe):
                    with patch.object(sandy.os, "close") as close:
                        with patch.object(sandy, "_verify_owned_directory"):
                            with self.assertRaises(OSError):
                                sandy._open_verified_dir("/safe")
        close.assert_called_once_with(10)

        with patch.object(sandy, "SYSTEMD_MACHINES", "/safe"):
            with patch.object(sandy.os, "open", side_effect=[10, 11]):
                with patch.object(sandy.os, "fstat", return_value=safe):
                    with patch.object(sandy.os, "close") as close:
                        with patch.object(
                            sandy,
                            "_verify_owned_directory",
                            side_effect=[None, PermissionError("unsafe")],
                        ):
                            with self.assertRaises(PermissionError):
                                sandy._open_verified_dir("/safe")
        self.assertEqual(close.call_args_list, [call(11), call(10)])

        with patch.object(sandy, "SYSTEMD_MACHINES", "/safe"):
            with patch.object(
                sandy.os,
                "open",
                side_effect=[10, 11, FileNotFoundError()],
            ):
                with patch.object(sandy.os, "fstat", return_value=safe):
                    with patch.object(sandy.os, "close") as close:
                        with patch.object(sandy, "_verify_owned_directory"):
                            with self.assertRaises(FileNotFoundError):
                                sandy._open_verified_dir(
                                    "/safe/sandy.container",
                                )
        self.assertEqual(close.call_args_list, [call(10), call(11)])

        with patch.object(sandy, "SYSTEMD_MACHINES", "/safe"):
            with patch.object(sandy.os, "open", side_effect=[10, 11, 12]):
                with patch.object(sandy.os, "fstat", return_value=safe):
                    with patch.object(sandy.os, "close") as close:
                        with patch.object(
                            sandy,
                            "_verify_owned_directory",
                            side_effect=[None, None, PermissionError("unsafe")],
                        ):
                            with self.assertRaises(PermissionError):
                                sandy._open_verified_dir(
                                    "/safe/sandy.container",
                                )
        self.assertEqual(close.call_args_list, [call(10), call(12), call(11)])

    def test_verified_directory_rejects_direct_host_root_image(self):
        root_stat = self.safe_stat(ino=1, dev=1)
        safe_stat = self.safe_stat(ino=2, dev=1)

        with patch.object(sandy, "SYSTEMD_MACHINES", "/safe"):
            with patch.object(sandy.os, "open", side_effect=[10, 11, 12]):
                with patch.object(
                    sandy.os,
                    "fstat",
                    side_effect=[root_stat, safe_stat, root_stat],
                ):
                    with patch.object(sandy.os, "close") as close:
                        with self.assertRaisesRegex(PermissionError, "host root"):
                            sandy._open_verified_dir("/safe/sandy.root")
        self.assertEqual(close.call_args_list, [call(10), call(12), call(11)])

    def test_verify_safe_dir_rejects_symlink_components_and_closes_fds(self):
        safe = self.safe_stat()
        for error_number in (errno.ELOOP, errno.ENOTDIR):
            with self.subTest(error_number=error_number):
                with patch.object(sandy, "SYSTEMD_MACHINES", "/safe"):
                    with patch.object(
                        sandy.os,
                        "open",
                        side_effect=[10, OSError(error_number, "unsafe")],
                    ):
                        with patch.object(sandy.os, "fstat", return_value=safe):
                            with patch.object(sandy.os, "close") as close:
                                with self.assertRaises(PermissionError):
                                    sandy._verify_safe_dir(
                                        "/safe/sandy.container",
                                    )
                close.assert_called_once_with(10)

    def test_remove_managed_tree_never_removes_managed_root(self):
        with patch.object(sandy, "SYSTEMD_MACHINES", "/safe"):
            with self.assertRaises(ValueError):
                sandy._remove_managed_tree("/safe")

    def test_remove_managed_tree_is_descriptor_anchored_and_does_not_follow_symlinks(
        self,
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            parent = root / "managed"
            target = parent / "sandy.test"
            external = root / "external"
            (target / "nested").mkdir(parents=True)
            external.mkdir()
            (target / "file").write_text("managed", encoding="utf-8")
            (target / "nested" / "file").write_text("nested", encoding="utf-8")
            (external / "keep").write_text("external", encoding="utf-8")
            (target / "link").symlink_to(external, target_is_directory=True)

            with self.opened_parent(parent, target.name):
                with patch.object(sandy, "_verify_owned_directory"):
                    sandy._remove_managed_tree("/managed/sandy.test")

            self.assertFalse(target.exists())
            self.assertEqual(
                (external / "keep").read_text(encoding="utf-8"),
                "external",
            )

    def test_remove_managed_tree_unlinks_top_level_image_symlink_without_following(
        self,
    ):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            parent = root / "managed"
            external = root / "external"
            parent.mkdir()
            external.mkdir()
            (external / "keep").write_text("external", encoding="utf-8")
            (parent / "sandy.test").symlink_to(
                external,
                target_is_directory=True,
            )

            with patch.object(sandy, "SYSTEMD_MACHINES", "/managed"):
                with self.opened_parent(parent, "sandy.test"):
                    with patch.object(sandy, "_verify_owned_symlink"):
                        sandy._remove_managed_tree("/managed/sandy.test")

            self.assertFalse((parent / "sandy.test").exists())
            self.assertEqual(
                (external / "keep").read_text(encoding="utf-8"),
                "external",
            )

    def test_remove_managed_tree_rejects_nested_and_cache_symlink_targets(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            parent = root / "managed"
            external = root / "external"
            parent.mkdir()
            external.mkdir()
            (parent / "nested").symlink_to(external, target_is_directory=True)

            with patch.object(sandy, "SYSTEMD_MACHINES", "/managed"):
                with self.opened_parent(parent, "nested"):
                    with self.assertRaises(PermissionError):
                        sandy._remove_managed_tree("/managed/sandy.test/nested")

            self.assertTrue((parent / "nested").is_symlink())
            self.assertTrue(external.is_dir())

            (parent / "nested").unlink()
            (parent / "sandy.__cache").symlink_to(
                external,
                target_is_directory=True,
            )
            with patch.object(sandy, "SYSTEMD_MACHINES", "/managed"):
                with self.opened_parent(parent, "sandy.__cache"):
                    with self.assertRaises(PermissionError):
                        sandy._remove_managed_tree("/managed/sandy.__cache")

            self.assertTrue((parent / "sandy.__cache").is_symlink())

    def test_remove_managed_tree_revalidates_image_link_and_rejects_regular_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            parent = Path(temp_dir)
            external = parent / "external"
            external.mkdir()
            (parent / "sandy.test").symlink_to(
                external,
                target_is_directory=True,
            )

            mismatched = self.safe_stat(mode=stat.S_IFLNK | 0o777, ino=999)
            with patch.object(sandy, "SYSTEMD_MACHINES", "/managed"):
                with self.opened_parent(parent, "sandy.test"):
                    with patch.object(
                        sandy,
                        "_read_verified_symlink",
                        return_value=(str(external), mismatched),
                    ):
                        with self.assertRaises(PermissionError):
                            sandy._remove_managed_tree("/managed/sandy.test")
            self.assertTrue((parent / "sandy.test").is_symlink())

            (parent / "sandy.test").unlink()
            (parent / "sandy.test").write_text("keep", encoding="utf-8")
            with self.opened_parent(parent, "sandy.test"):
                with self.assertRaises(PermissionError):
                    sandy._remove_managed_tree("/managed/sandy.test")
            self.assertEqual(
                (parent / "sandy.test").read_text(encoding="utf-8"),
                "keep",
            )

    def test_remove_managed_tree_uses_open_parent_after_path_replacement(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            parent = root / "managed"
            moved_parent = root / "moved"
            target = parent / "sandy.test"
            target.mkdir(parents=True)
            (target / "old").write_text("old", encoding="utf-8")

            def replace_parent(_path):
                parent_fd = os.open(parent, sandy.DIRECTORY_OPEN_FLAGS)
                parent.rename(moved_parent)
                parent.mkdir()
                replacement = parent / "sandy.test"
                replacement.mkdir()
                (replacement / "keep").write_text("new", encoding="utf-8")
                return parent_fd, "sandy.test"

            with patch.object(
                sandy,
                "_open_verified_parent",
                side_effect=replace_parent,
            ):
                with patch.object(sandy, "_verify_owned_directory"):
                    sandy._remove_managed_tree("/managed/sandy.test")

            self.assertFalse((moved_parent / "sandy.test").exists())
            self.assertEqual(
                (parent / "sandy.test" / "keep").read_text(encoding="utf-8"),
                "new",
            )

    def test_mount_id_metadata_is_strictly_validated(self):
        with patch("builtins.open", mock_open(read_data="mnt_id:\t123\n")):
            self.assertEqual(sandy._fd_mount_id(10), 123)

        invalid_metadata = (
            "",
            "mnt_id:\tabc\n",
            "mnt_id:\t0\n",
            "mnt_id:\t1\nmnt_id:\t2\n",
            f"mnt_id:\t{'1' * 21}\n",
        )
        for metadata in invalid_metadata:
            with self.subTest(metadata=metadata):
                with patch("builtins.open", mock_open(read_data=metadata)):
                    with self.assertRaises(PermissionError):
                        sandy._fd_mount_id(10)

        for invalid_fd in (-1, True, None):
            with self.subTest(invalid_fd=invalid_fd):
                with self.assertRaises(ValueError):
                    sandy._fd_mount_id(invalid_fd)

    def test_image_and_internal_symlinks_are_contained_by_image_root(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            managed = root / "machines"
            image = root / "external-image"
            real_etc = image / "real-etc"
            host_target = root / "real-etc"
            managed.mkdir()
            real_etc.mkdir(parents=True)
            host_target.mkdir()
            (host_target / "keep").write_text("host", encoding="utf-8")
            (image / "etc").symlink_to("/real-etc", target_is_directory=True)
            (managed / "sandy.test").symlink_to(
                image,
                target_is_directory=True,
            )

            path = managed / "sandy.test" / "etc" / "hosts"
            with patch.object(sandy, "SYSTEMD_MACHINES", str(managed)):
                with patch.object(sandy, "_verify_owned_directory"):
                    with patch.object(sandy, "_verify_owned_symlink"):
                        sandy._write(str(path), "contained", mode=0o644)

            self.assertEqual(
                (real_etc / "hosts").read_text(encoding="utf-8"),
                "contained",
            )
            self.assertEqual(
                (host_target / "keep").read_text(encoding="utf-8"),
                "host",
            )
            self.assertFalse((host_target / "hosts").exists())

    def test_relative_machine_image_symlink_and_ancestor_policy(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            managed = root / "machines"
            image = root / "image"
            managed.mkdir()
            image.mkdir()
            (managed / "sandy.relative").symlink_to(
                "../image",
                target_is_directory=True,
            )

            with patch.object(sandy, "SYSTEMD_MACHINES", str(managed)):
                with patch.object(sandy, "_verify_owned_directory"):
                    with patch.object(sandy, "_verify_owned_symlink"):
                        sandy._verify_safe_dir(
                            str(managed / "sandy.relative"),
                        )

            (managed / "sandy.ancestor").symlink_to(
                "..",
                target_is_directory=True,
            )
            with patch.object(sandy, "SYSTEMD_MACHINES", str(managed)):
                with patch.object(sandy, "_verify_owned_directory"):
                    with patch.object(sandy, "_verify_owned_symlink"):
                        with self.assertRaises(PermissionError):
                            sandy._verify_safe_dir(
                                str(managed / "sandy.ancestor"),
                            )

            managed_fd = os.open(managed, sandy.DIRECTORY_OPEN_FLAGS)
            duplicate_fd = os.dup(managed_fd)
            try:
                with patch.object(
                    sandy,
                    "_read_verified_symlink",
                    return_value=("/different", self.safe_stat()),
                ):
                    with patch.object(
                        sandy,
                        "_open_verified_host_directory",
                        return_value=duplicate_fd,
                    ):
                        with self.assertRaises(PermissionError):
                            sandy._open_machine_image_symlink(
                                managed_fd,
                                "sandy.same",
                            )
            finally:
                os.close(managed_fd)

    def test_relative_image_symlink_cannot_escape_image_root(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            managed = root / "machines"
            image = managed / "sandy.test"
            contained = image / "outside"
            external = root / "outside"
            contained.mkdir(parents=True)
            external.mkdir()
            (external / "keep").write_text("external", encoding="utf-8")
            (image / "escape").symlink_to(
                "../outside",
                target_is_directory=True,
            )

            path = image / "escape" / "state"
            with patch.object(sandy, "SYSTEMD_MACHINES", str(managed)):
                with patch.object(sandy, "_verify_owned_directory"):
                    with patch.object(sandy, "_verify_owned_symlink"):
                        sandy._write(str(path), "contained")

            self.assertEqual(
                (contained / "state").read_text(encoding="utf-8"),
                "contained",
            )
            self.assertEqual(
                (external / "keep").read_text(encoding="utf-8"),
                "external",
            )
            self.assertFalse((external / "state").exists())

    def test_image_symlink_component_normalization(self):
        self.assertEqual(
            sandy._image_symlink_components(
                ("usr", "lib"),
                "../share/./zoneinfo",
                ("UTC",),
            ),
            ("usr", "share", "zoneinfo", "UTC"),
        )
        self.assertEqual(
            sandy._image_symlink_components(
                ("ignored",),
                "/etc",
                ("hosts",),
            ),
            ("etc", "hosts"),
        )

    def test_image_symlink_resolution_limit_boundary(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            image = Path(temp_dir)
            (image / "target").mkdir()

            for prefix, count in (("accepted", 8), ("rejected", 9)):
                for index in range(count):
                    destination = (
                        f"{prefix}-{index + 1}" if index + 1 < count else "target"
                    )
                    (image / f"{prefix}-{index}").symlink_to(
                        destination,
                        target_is_directory=True,
                    )

            image_fd = os.open(image, sandy.DIRECTORY_OPEN_FLAGS)
            try:
                with patch.object(sandy, "_verify_owned_directory"):
                    with patch.object(sandy, "_verify_owned_symlink"):
                        accepted_fd = sandy._open_image_directory(
                            image_fd,
                            ("accepted-0",),
                        )
                        os.close(accepted_fd)

                        with self.assertRaisesRegex(
                            PermissionError,
                            "Too many symlinks",
                        ):
                            sandy._open_image_directory(
                                image_fd,
                                ("rejected-0",),
                            )
            finally:
                os.close(image_fd)

    def test_image_symlink_loops_and_unsafe_targets_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            managed = root / "machines"
            image = managed / "sandy.test"
            image.mkdir(parents=True)
            (image / "first").symlink_to("second", target_is_directory=True)
            (image / "second").symlink_to("first", target_is_directory=True)

            with patch.object(sandy, "SYSTEMD_MACHINES", str(managed)):
                with patch.object(sandy, "_verify_owned_directory"):
                    with patch.object(sandy, "_verify_owned_symlink"):
                        with self.assertRaises(PermissionError):
                            sandy._verify_safe_dir(str(image / "first"))

            (managed / "sandy.root").symlink_to("/", target_is_directory=True)
            with patch.object(sandy, "SYSTEMD_MACHINES", str(managed)):
                with patch.object(sandy, "_verify_owned_directory"):
                    with patch.object(sandy, "_verify_owned_symlink"):
                        with self.assertRaises(PermissionError):
                            sandy._verify_safe_dir(
                                str(managed / "sandy.root"),
                            )

            (managed / "sandy.__cache").symlink_to(
                root,
                target_is_directory=True,
            )
            with patch.object(sandy, "SYSTEMD_MACHINES", str(managed)):
                with patch.object(sandy, "_verify_owned_directory"):
                    with self.assertRaises(PermissionError):
                        sandy._verify_safe_dir(
                            str(managed / "sandy.__cache"),
                        )

    def test_image_directory_resolution_rejects_mount_boundaries(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            image = Path(temp_dir)
            (image / "etc").mkdir()
            image_fd = os.open(image, sandy.DIRECTORY_OPEN_FLAGS)
            try:
                with patch.object(sandy, "_verify_owned_directory"):
                    with patch.object(
                        sandy,
                        "_fd_mount_id",
                        side_effect=[1, 2],
                    ):
                        with self.assertRaises(PermissionError):
                            sandy._open_image_directory(image_fd, ("etc",))
            finally:
                os.close(image_fd)

        with tempfile.TemporaryDirectory() as temp_dir:
            image = Path(temp_dir)
            (image / "etc").mkdir()
            image_fd = os.open(image, sandy.DIRECTORY_OPEN_FLAGS)
            root_stat = os.fstat(image_fd)
            different_device = SimpleNamespace(
                st_uid=root_stat.st_uid,
                st_gid=root_stat.st_gid,
                st_mode=stat.S_IFDIR | 0o755,
                st_dev=root_stat.st_dev + 1,
                st_ino=root_stat.st_ino + 1,
            )
            try:
                with patch.object(
                    sandy.os,
                    "fstat",
                    side_effect=[root_stat, different_device],
                ):
                    with patch.object(sandy, "_verify_owned_directory"):
                        with patch.object(sandy, "_fd_mount_id", return_value=1):
                            with self.assertRaises(PermissionError):
                                sandy._open_image_directory(image_fd, ("etc",))
            finally:
                os.close(image_fd)

        with tempfile.TemporaryDirectory() as temp_dir:
            image_fd = os.open(temp_dir, sandy.DIRECTORY_OPEN_FLAGS)
            try:
                with self.assertRaises(FileNotFoundError):
                    sandy._open_image_directory(image_fd, ("missing",))
            finally:
                os.close(image_fd)

    def test_image_file_resolution_uses_pinned_root_and_rejects_final_symlink(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            image = root / "image"
            external = root / "external"
            image.mkdir()
            external.write_text("host", encoding="utf-8")
            init_script = image / "init.sh"
            init_script.write_text("#!/bin/sh\n", encoding="utf-8")
            init_script.chmod(0o644)

            image_fd = os.open(image, sandy.DIRECTORY_OPEN_FLAGS)
            try:
                file_fd = sandy._open_image_file(image_fd, ("init.sh",))
                try:
                    self.assertEqual(os.read(file_fd, 64), b"#!/bin/sh\n")
                finally:
                    os.close(file_fd)

                init_script.unlink()
                init_script.symlink_to(external)
                with self.assertRaises(PermissionError):
                    sandy._open_image_file(image_fd, ("init.sh",))
            finally:
                os.close(image_fd)

        with tempfile.TemporaryDirectory() as temp_dir:
            image = Path(temp_dir)
            group_writable = image / "init.sh"
            group_writable.write_text("#!/bin/sh\n", encoding="utf-8")
            group_writable.chmod(0o664)
            image_fd = os.open(image, sandy.DIRECTORY_OPEN_FLAGS)
            try:
                with self.assertRaises(PermissionError):
                    sandy._open_image_file(image_fd, ("init.sh",))
            finally:
                os.close(image_fd)

    def test_image_file_resolution_rejects_a_fifo_without_blocking(self):
        # Root in a container can put a FIFO at an image path. A blocking
        # open of a FIFO waits for a writer, so the open must not block, and
        # the file check must refuse the FIFO. Nothing is mocked: the FIFO,
        # the open, and the check are real.
        with tempfile.TemporaryDirectory() as temp_dir:
            image = Path(temp_dir)
            fifo = image / "init.sh"
            os.mkfifo(fifo, 0o644)
            image_fd = os.open(image, sandy.DIRECTORY_OPEN_FLAGS)
            try:
                result, exception, blocked = run_with_fifo_release(
                    lambda: sandy._open_image_file(image_fd, ("init.sh",)), [fifo]
                )
            finally:
                os.close(image_fd)
        if isinstance(result, int):
            os.close(result)
        self.assertFalse(blocked, "the open of the FIFO blocked")
        self.assertIsInstance(exception, PermissionError)
        self.assertEqual(str(exception), "Image file 'init.sh' is not a regular file")

    def test_image_file_resolution_rejects_mount_boundaries(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            image = Path(temp_dir)
            init_script = image / "init.sh"
            init_script.write_text("#!/bin/sh\n", encoding="utf-8")
            init_script.chmod(0o644)
            image_fd = os.open(image, sandy.DIRECTORY_OPEN_FLAGS)
            try:
                with patch.object(
                    sandy,
                    "_fd_mount_id",
                    side_effect=[1, 2],
                ):
                    with self.assertRaisesRegex(PermissionError, "mount boundary"):
                        sandy._open_image_file(image_fd, ("init.sh",))
            finally:
                os.close(image_fd)

    def test_image_file_resolution_rejects_device_boundaries(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            image = Path(temp_dir)
            init_script = image / "init.sh"
            init_script.write_text("#!/bin/sh\n", encoding="utf-8")
            init_script.chmod(0o644)
            image_fd = os.open(image, sandy.DIRECTORY_OPEN_FLAGS)
            root_stat = os.fstat(image_fd)
            different_device = self.safe_stat(
                uid=os.geteuid(),
                gid=os.getegid(),
                mode=stat.S_IFREG | 0o644,
                ino=root_stat.st_ino + 1,
                dev=root_stat.st_dev + 1,
            )
            try:
                with patch.object(
                    sandy.os,
                    "fstat",
                    side_effect=[root_stat, different_device],
                ):
                    with patch.object(sandy, "_fd_mount_id", return_value=1):
                        with self.assertRaisesRegex(
                            PermissionError,
                            "filesystem boundary",
                        ):
                            sandy._open_image_file(image_fd, ("init.sh",))
            finally:
                os.close(image_fd)

    def test_init_bind_copy_uses_private_regular_file_and_exact_cleanup(self):
        with tempfile.NamedTemporaryFile() as source:
            source.write(b'CONTAINER_IP="10.200.1.10"\n')
            source.flush()
            init_fd = os.open(source.name, sandy.READ_FILE_OPEN_FLAGS)
            try:
                temporary_dir, bind_path = sandy._create_init_bind_copy(init_fd)
            finally:
                os.close(init_fd)

        try:
            directory_stat = os.stat(temporary_dir)
            file_stat = os.stat(bind_path)
            self.assertTrue(stat.S_ISDIR(directory_stat.st_mode))
            self.assertEqual(stat.S_IMODE(directory_stat.st_mode) & 0o077, 0)
            self.assertTrue(stat.S_ISREG(file_stat.st_mode))
            self.assertEqual(stat.S_IMODE(file_stat.st_mode), 0o500)
            self.assertEqual(
                Path(bind_path).read_text(), 'CONTAINER_IP="10.200.1.10"\n'
            )
        finally:
            sandy._remove_init_bind_copy(temporary_dir)
        self.assertFalse(Path(temporary_dir).exists())

    def test_init_bind_copy_rejects_oversized_source_and_bad_cleanup_target(self):
        with tempfile.NamedTemporaryFile() as source:
            source.write(b"x" * (sandy.INIT_SCRIPT_MAX_BYTES + 1))
            source.flush()
            init_fd = os.open(source.name, sandy.READ_FILE_OPEN_FLAGS)
            try:
                with self.assertRaisesRegex(PermissionError, "too large"):
                    sandy._create_init_bind_copy(init_fd)
            finally:
                os.close(init_fd)

        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaisesRegex(PermissionError, "unexpected"):
                sandy._remove_init_bind_copy(temp_dir)

    def test_init_bind_copy_can_target_fixed_user_namespace_owner(self):
        with tempfile.NamedTemporaryFile() as source:
            source.write(b'CONTAINER_IP="10.200.1.10"\n')
            source.flush()
            init_fd = os.open(source.name, sandy.READ_FILE_OPEN_FLAGS)
            try:
                with patch.object(sandy.os, "fchown") as fchown:
                    temporary_dir, bind_path = sandy._create_init_bind_copy(
                        init_fd,
                        12345,
                        12345,
                    )
            finally:
                os.close(init_fd)

        try:
            self.assertEqual(stat.S_IMODE(os.stat(bind_path).st_mode), 0o500)
            fchown.assert_called_once()
            self.assertEqual(fchown.call_args.args[1:], (12345, 12345))
        finally:
            sandy._remove_init_bind_copy(temporary_dir)

    def test_remove_managed_tree_refuses_target_and_nested_mount_boundaries(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            parent = Path(temp_dir)
            target = parent / "sandy.test"
            (target / "nested").mkdir(parents=True)

            with self.opened_parent(parent, target.name):
                with patch.object(sandy, "_verify_owned_directory"):
                    with patch.object(
                        sandy,
                        "_fd_mount_id",
                        side_effect=[1, 2],
                    ):
                        with self.assertRaises(PermissionError):
                            sandy._remove_managed_tree("/managed/sandy.test")
            self.assertTrue((target / "nested").is_dir())

    def test_recursive_removal_revalidates_devices_and_inodes(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "nested").mkdir()
            root_fd = os.open(root, sandy.DIRECTORY_OPEN_FLAGS)
            root_stat = os.fstat(root_fd)
            try:
                with self.assertRaises(PermissionError):
                    sandy._remove_directory_contents(
                        root_fd,
                        root_stat.st_dev + 1,
                        sandy._fd_mount_id(root_fd),
                    )
            finally:
                os.close(root_fd)
            self.assertTrue((root / "nested").is_dir())

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "nested").mkdir()
            root_fd = os.open(root, sandy.DIRECTORY_OPEN_FLAGS)
            try:
                with patch.object(sandy, "_same_inode", return_value=False):
                    with self.assertRaises(PermissionError):
                        sandy._remove_directory_contents(
                            root_fd,
                            os.fstat(root_fd).st_dev,
                            sandy._fd_mount_id(root_fd),
                        )
            finally:
                os.close(root_fd)
            self.assertTrue((root / "nested").is_dir())

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "nested").mkdir()
            root_fd = os.open(root, sandy.DIRECTORY_OPEN_FLAGS)
            try:
                with patch.object(
                    sandy,
                    "_same_inode",
                    side_effect=[True, False],
                ):
                    with self.assertRaises(PermissionError):
                        sandy._remove_directory_contents(
                            root_fd,
                            os.fstat(root_fd).st_dev,
                            sandy._fd_mount_id(root_fd),
                        )
            finally:
                os.close(root_fd)
            self.assertTrue((root / "nested").is_dir())

    def test_recursive_removal_revalidates_non_directory_mount_and_inode(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            entry = root / "mounted-file"
            entry.write_text("keep", encoding="utf-8")
            root_fd = os.open(root, sandy.DIRECTORY_OPEN_FLAGS)
            try:
                with patch.object(sandy, "_fd_mount_id", return_value=2):
                    with self.assertRaisesRegex(
                        PermissionError,
                        "mount boundary",
                    ):
                        sandy._remove_directory_contents(
                            root_fd,
                            os.fstat(root_fd).st_dev,
                            1,
                        )
            finally:
                os.close(root_fd)
            self.assertEqual(entry.read_text(encoding="utf-8"), "keep")

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            entry = root / "changed-file"
            entry.write_text("keep", encoding="utf-8")
            root_fd = os.open(root, sandy.DIRECTORY_OPEN_FLAGS)
            try:
                with patch.object(sandy, "_same_inode", return_value=False):
                    with self.assertRaisesRegex(
                        PermissionError,
                        "Entry changed",
                    ):
                        sandy._remove_directory_contents(
                            root_fd,
                            os.fstat(root_fd).st_dev,
                            sandy._fd_mount_id(root_fd),
                        )
            finally:
                os.close(root_fd)
            self.assertEqual(entry.read_text(encoding="utf-8"), "keep")

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            entry = root / "replaced-file"
            entry.write_text("keep", encoding="utf-8")
            root_fd = os.open(root, sandy.DIRECTORY_OPEN_FLAGS)
            try:
                with patch.object(
                    sandy,
                    "_same_inode",
                    side_effect=[True, False],
                ):
                    with self.assertRaisesRegex(
                        PermissionError,
                        "Entry changed",
                    ):
                        sandy._remove_directory_contents(
                            root_fd,
                            os.fstat(root_fd).st_dev,
                            sandy._fd_mount_id(root_fd),
                        )
            finally:
                os.close(root_fd)
            self.assertEqual(entry.read_text(encoding="utf-8"), "keep")

    def test_remove_managed_tree_revalidates_target_before_and_after_recursion(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            parent = Path(temp_dir)
            target = parent / "sandy.test"
            target.mkdir()

            with self.opened_parent(parent, target.name):
                with patch.object(sandy, "_verify_owned_directory"):
                    with patch.object(sandy, "_same_inode", return_value=False):
                        with self.assertRaises(PermissionError):
                            sandy._remove_managed_tree("/managed/sandy.test")
            self.assertTrue(target.is_dir())

            (target / "nested").mkdir()
            with self.opened_parent(parent, target.name):
                with patch.object(sandy, "_verify_owned_directory"):
                    with patch.object(
                        sandy,
                        "_same_inode",
                        side_effect=[True, False],
                    ):
                        with self.assertRaises(PermissionError):
                            sandy._remove_managed_tree("/managed/sandy.test")
            self.assertTrue(target.is_dir())

            with self.opened_parent(parent, target.name):
                with patch.object(sandy, "_verify_owned_directory"):
                    with patch.object(
                        sandy,
                        "_fd_mount_id",
                        side_effect=[1, 1, 2],
                    ):
                        with self.assertRaises(PermissionError):
                            sandy._remove_managed_tree("/managed/sandy.test")
            self.assertTrue((target / "nested").is_dir())

    def test_mkdir_uses_parent_descriptor_and_cleans_failed_verification(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            parent = Path(temp_dir)
            with self.opened_parent(parent, "sandy.test"):
                with patch.object(sandy, "_verify_owned_directory"):
                    sandy._mkdir("/managed/sandy.test")
            self.assertTrue((parent / "sandy.test").is_dir())
            self.assertEqual(
                stat.S_IMODE((parent / "sandy.test").stat().st_mode),
                0o700,
            )

            with self.opened_parent(parent, "sandy.failed"):
                with patch.object(
                    sandy,
                    "_verify_owned_directory",
                    side_effect=PermissionError("unsafe"),
                ):
                    with self.assertRaises(PermissionError):
                        sandy._mkdir("/managed/sandy.failed")
            self.assertFalse((parent / "sandy.failed").exists())

    def test_write_atomically_replaces_regular_file_and_sets_mode(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            parent = Path(temp_dir)
            destination = parent / "state"
            destination.write_text("old", encoding="utf-8")

            with self.opened_parent(parent):
                sandy._write("/managed/state", "safe content", mode=0o640)

            self.assertEqual(destination.read_text(encoding="utf-8"), "safe content")
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o640)
            self.assertEqual(list(parent.glob(".sandy-*.tmp")), [])

    def test_write_rejects_invalid_inputs_and_destination_owner(self):
        with self.assertRaises(ValueError):
            sandy._write("/managed/state", b"bytes")

        for mode in (True, -1, 0o1000, "0600"):
            with self.subTest(mode=mode):
                with self.assertRaises(ValueError):
                    sandy._write("/managed/state", "content", mode=mode)

        with tempfile.TemporaryDirectory() as temp_dir:
            parent = Path(temp_dir)
            destination = parent / "state"
            destination.write_text("old", encoding="utf-8")
            with self.opened_parent(parent):
                with patch.object(
                    sandy.os,
                    "geteuid",
                    return_value=os.geteuid() + 1,
                ):
                    with self.assertRaises(PermissionError):
                        sandy._write("/managed/state", "unsafe")
            self.assertEqual(destination.read_text(encoding="utf-8"), "old")

    def test_write_fails_closed_on_temporary_file_collisions(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            parent = Path(temp_dir)
            collision = parent / ".sandy-collision.tmp"
            collision.write_text("keep", encoding="utf-8")

            with self.opened_parent(parent):
                with patch.object(
                    sandy.secrets,
                    "token_hex",
                    return_value="collision",
                ):
                    with self.assertRaises(FileExistsError):
                        sandy._write("/managed/state", "content")

            self.assertEqual(collision.read_text(encoding="utf-8"), "keep")
            self.assertFalse((parent / "state").exists())

    def test_write_rejects_invalid_temporary_inode_and_zero_progress(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            parent = Path(temp_dir)
            invalid_temporary = self.safe_stat(
                mode=stat.S_IFREG | 0o600,
                uid=os.geteuid() + 1,
            )

            with self.opened_parent(parent):
                with patch.object(
                    sandy.os,
                    "fstat",
                    return_value=invalid_temporary,
                ):
                    with self.assertRaises(PermissionError):
                        sandy._write("/managed/state", "content")
            self.assertEqual(list(parent.iterdir()), [])

            with self.opened_parent(parent):
                with patch.object(sandy.os, "write", return_value=0):
                    with self.assertRaises(OSError):
                        sandy._write("/managed/state", "content")
            self.assertEqual(list(parent.iterdir()), [])

    def test_write_detects_post_replace_inode_mismatch(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            parent = Path(temp_dir)
            with self.opened_parent(parent):
                with patch.object(sandy, "_same_inode", return_value=False):
                    with self.assertRaises(PermissionError):
                        sandy._write("/managed/state", "content")

            self.assertEqual(
                (parent / "state").read_text(encoding="utf-8"),
                "content",
            )
            self.assertEqual(list(parent.glob(".sandy-*.tmp")), [])

    def test_write_rejects_absolute_relative_and_magic_symlinks(self):
        link_targets = ("absolute", "relative", "magic")
        for link_type in link_targets:
            with self.subTest(link_type=link_type):
                with tempfile.TemporaryDirectory() as temp_dir:
                    root = Path(temp_dir)
                    parent = root / "managed"
                    external = root / "external"
                    parent.mkdir()
                    external.write_text("keep", encoding="utf-8")

                    magic_fd = None
                    if link_type == "absolute":
                        link_target = str(external)
                    elif link_type == "relative":
                        link_target = "../external"
                    else:
                        magic_fd = os.open(external, os.O_RDONLY)
                        link_target = f"/proc/self/fd/{magic_fd}"
                    try:
                        (parent / "state").symlink_to(link_target)
                        with self.opened_parent(parent):
                            with self.assertRaises(PermissionError):
                                sandy._write("/managed/state", "unsafe")
                    finally:
                        if magic_fd is not None:
                            os.close(magic_fd)

                    self.assertEqual(
                        external.read_text(encoding="utf-8"),
                        "keep",
                    )
                    self.assertTrue((parent / "state").is_symlink())

    def test_write_rejects_hard_link_destination(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            parent = Path(temp_dir)
            external = parent / "external"
            destination = parent / "state"
            external.write_text("keep", encoding="utf-8")
            os.link(external, destination)

            with self.opened_parent(parent):
                with self.assertRaises(PermissionError):
                    sandy._write("/managed/state", "unsafe")

            self.assertEqual(external.read_text(encoding="utf-8"), "keep")
            self.assertEqual(destination.read_text(encoding="utf-8"), "keep")

    def test_write_uses_open_parent_after_path_replacement(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            parent = root / "managed"
            moved_parent = root / "moved"
            parent.mkdir()

            def replace_parent(_path):
                parent_fd = os.open(parent, sandy.DIRECTORY_OPEN_FLAGS)
                parent.rename(moved_parent)
                parent.mkdir()
                return parent_fd, "state"

            with patch.object(
                sandy,
                "_open_verified_parent",
                side_effect=replace_parent,
            ):
                sandy._write("/managed/state", "anchored")

            self.assertEqual(
                (moved_parent / "state").read_text(encoding="utf-8"),
                "anchored",
            )
            self.assertFalse((parent / "state").exists())

    def test_write_cleans_temporary_file_after_interruption(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            parent = Path(temp_dir)
            with self.opened_parent(parent):
                with patch.object(
                    sandy.os,
                    "write",
                    side_effect=OSError("interrupted"),
                ):
                    with self.assertRaises(OSError):
                        sandy._write("/managed/state", "content")

            self.assertFalse((parent / "state").exists())
            self.assertEqual(list(parent.iterdir()), [])

    def test_write_cleans_temporary_file_after_failed_rename(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            parent = Path(temp_dir)
            destination = parent / "state"
            destination.write_text("old", encoding="utf-8")

            with self.opened_parent(parent):
                with patch.object(
                    sandy.os,
                    "replace",
                    side_effect=OSError("rename failed"),
                ):
                    with self.assertRaises(OSError):
                        sandy._write("/managed/state", "new")

            self.assertEqual(destination.read_text(encoding="utf-8"), "old")
            self.assertEqual(list(parent.glob(".sandy-*.tmp")), [])


class GuestFileTests(unittest.TestCase):
    def setUp(self):
        # The address lock is in the cache directory of the host. Mock: the
        # lock, a MagicMock context manager. The test of two builds uses the
        # real lock on a temporary file.
        self.real_addresses_lock = sandy._addresses_lock
        patcher = patch.object(sandy, "_addresses_lock")
        self.addresses_lock = patcher.start()
        self.addCleanup(patcher.stop)

    def test_create_guest_files_without_network(self):
        writes = []

        def record_write(path, content, mode=0o600):
            writes.append((path, content, mode))

        def exists(path):
            if path == sandy.SYSTEMD_MACHINES:
                return True
            return False

        with patch.object(sandy, "_write", side_effect=record_write):
            with patch.object(sandy.os.path, "exists", side_effect=exists):
                with captured_output():
                    sandy._create_guest_files("/machine", "test-box")

        self.assertEqual(
            writes[0],
            (
                "/machine/etc/hosts",
                "127.0.0.1 localhost test-box\n",
                0o644,
            ),
        )
        self.assertEqual(writes[1], ("/machine/etc/localtime", "", 0o644))
        self.assertEqual(len(writes), 2)

    def test_create_guest_files_builds_network_init_script(self):
        writes = []

        def record_write(path, content, mode=0o600):
            writes.append((path, content, mode))

        def exists(path):
            return path == sandy.SYSTEMD_MACHINES

        with patch.object(sandy, "_write", side_effect=record_write):
            with patch.object(sandy.os.path, "exists", side_effect=exists):
                with patch.object(sandy.glob, "glob", return_value=[]):
                    with captured_output():
                        sandy._create_guest_files(
                            "/machine",
                            "test-box",
                            "10.20.30.0/24",
                            "10.20.30.1",
                        )

        init_path, init_content, init_mode = writes[-1]
        self.assertEqual(init_path, "/machine/init.sh")
        self.assertEqual(init_mode, 0o755)
        self.assertIn('CONTAINER_IP="10.20.30.10"', init_content)
        self.assertIn('NETWORK_PREFIX="24"', init_content)
        self.assertIn('GATEWAY_IP="10.20.30.1"', init_content)
        self.assertIn("MAX_RETRIES=10", init_content)
        self.assertIn("rm -f -- /etc/resolv.conf", init_content)
        self.assertIn("nameserver 1.1.1.1", init_content)

    def test_create_guest_files_skips_invalid_network_init(self):
        for cidr, gateway in [
            ("8.8.8.0/24", "8.8.8.1"),
            ("10.0.0.0/24", "8.8.8.1"),
        ]:
            with self.subTest(cidr=cidr, gateway=gateway):
                with patch.object(sandy, "_write") as write:
                    with patch.object(sandy.os.path, "exists", return_value=False):
                        with captured_output():
                            sandy._create_guest_files(
                                "/machine",
                                "test-box",
                                cidr,
                                gateway,
                            )
                self.assertEqual(write.call_count, 2)

    def test_create_guest_files_skips_an_allocated_ip(self):
        writes = []

        def record_write(path, content, mode=0o600):
            writes.append((path, content, mode))

        def exists(path):
            return path == sandy.SYSTEMD_MACHINES

        with patch.object(sandy, "_write", side_effect=record_write):
            with patch.object(sandy.os.path, "exists", side_effect=exists):
                with patch.object(
                    sandy.glob,
                    "glob",
                    return_value=["/var/lib/machines/sandy.old"],
                ):
                    with patch.object(
                        sandy,
                        "_read_machine_container_ip",
                        return_value="10.20.30.10",
                    ) as read_address:
                        with captured_output():
                            sandy._create_guest_files(
                                "/machine",
                                "test-box",
                                "10.20.30.0/24",
                                "10.20.30.1",
                            )

        read_address.assert_called_once_with("/var/lib/machines/sandy.old")
        self.assertIn('CONTAINER_IP="10.20.30.11"', writes[-1][1])

    def test_create_guest_files_copies_utc_or_preserves_localtime(self):
        for localtime_exists, expected_writes in ((False, 2), (True, 1)):
            with self.subTest(localtime_exists=localtime_exists):

                def exists(path):
                    if path == "/machine/etc/localtime":
                        return localtime_exists
                    return path == "/usr/share/zoneinfo/UTC"

                with patch.object(sandy.os.path, "exists", side_effect=exists):
                    with patch(
                        "builtins.open",
                        mock_open(read_data="UTC data"),
                    ):
                        with patch.object(sandy, "_write") as write:
                            with captured_output():
                                sandy._create_guest_files(
                                    "/machine",
                                    "test-box",
                                )
                self.assertEqual(write.call_count, expected_writes)
                if not localtime_exists:
                    self.assertEqual(write.call_args.args[1], "UTC data")

    def test_create_guest_files_handles_parse_and_scan_errors(self):
        with patch.object(sandy, "_write") as write:
            with patch.object(sandy.os.path, "exists", return_value=True):
                with patch.object(
                    sandy,
                    "_validate_network_cidr",
                    return_value=True,
                ):
                    with patch.object(
                        sandy.ipaddress,
                        "ip_network",
                        side_effect=ValueError("invalid\nforged"),
                    ):
                        with captured_output() as (stdout, _):
                            sandy._create_guest_files(
                                "/machine",
                                "test-box",
                                "10.20.30.0/24",
                                "10.20.30.1",
                            )
        self.assertEqual(write.call_count, 1)
        self.assertNotIn("invalid\nforged", stdout.getvalue())
        self.assertIn("invalid\\nforged", stdout.getvalue())

        directories = [
            "/var/lib/machines/sandy.__cache",
            "/var/lib/machines/sandy.missing",
            "/var/lib/machines/sandy.unreadable",
            "/var/lib/machines/sandy.malformed",
        ]

        def read_address(path):
            if path.endswith("sandy.unreadable"):
                raise OSError("unreadable\nforged")
            if path.endswith("sandy.malformed"):
                raise ValueError("malformed")
            return None

        with patch.object(sandy.os.path, "exists", return_value=True):
            with patch.object(sandy.glob, "glob", return_value=directories):
                with patch.object(
                    sandy,
                    "_read_machine_container_ip",
                    side_effect=read_address,
                ) as read:
                    with patch.object(sandy, "_write") as write:
                        with captured_output() as (stdout, _):
                            sandy._create_guest_files(
                                "/machine",
                                "test-box",
                                "10.20.30.0/24",
                                "10.20.30.1",
                            )
        # The cache is not an image. An image with no /init.sh reserves no
        # address, with no warning; an error gives one warning line.
        self.assertEqual(read.call_args_list, [call(path) for path in directories[1:]])
        self.assertIn('CONTAINER_IP="10.20.30.10"', write.call_args.args[1])
        output = stdout.getvalue()
        self.assertIn(
            "W: Did not reserve the address in "
            "'/var/lib/machines/sandy.unreadable/init.sh': 'unreadable\\nforged'\n",
            output,
        )
        self.assertIn(
            "W: Did not reserve the address in "
            "'/var/lib/machines/sandy.malformed/init.sh': 'malformed'\n",
            output,
        )
        self.assertNotIn("unreadable\nforged", output)
        self.assertNotIn("sandy.missing", output)

    def test_create_guest_files_reports_exhausted_address_pool(self):
        directories = [
            f"/var/lib/machines/sandy.container-{number}" for number in range(10, 254)
        ]

        def read_address(path):
            number = int(path.rsplit("-", 1)[1])
            return f"10.20.30.{number}"

        with patch.object(sandy.os.path, "exists", return_value=True):
            with patch.object(sandy.glob, "glob", return_value=directories):
                with patch.object(
                    sandy,
                    "_read_machine_container_ip",
                    side_effect=read_address,
                ):
                    with patch.object(sandy, "_write") as write:
                        with captured_output() as (stdout, _):
                            sandy._create_guest_files(
                                "/machine",
                                "test-box",
                                "10.20.30.0/24",
                                "10.20.30.1",
                            )
        self.assertEqual(write.call_count, 1)
        self.assertIn("No available IP addresses", stdout.getvalue())

    def allocate_beside_images(
        self, prepare: Callable[[Path, Path], list[Path]]
    ) -> tuple[str, str, bool, str]:
        """Allocate an address beside real images made by prepare.

        prepare gets the machines directory and a directory outside it, and
        returns the FIFOs that it made. Return the new /init.sh, the output,
        whether the scan blocked, and the machines directory. Mocks:
        SYSTEMD_MACHINES is a temporary directory, _open_verified_dir opens
        an image there with no ownership check (the test user owns it, not
        root), and _write records the guest files. The glob, the opens of
        the image files, and the reads are real.
        """
        writes: list[tuple[str, str, int]] = []

        def record_write(path: str, content: str, mode: int = 0o600) -> None:
            writes.append((path, content, mode))

        def open_machine(path: str) -> int:
            return os.open(path, sandy.DIRECTORY_OPEN_FLAGS)

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            machines = root / "machines"
            outside = root / "outside"
            new_image = root / "new"
            for directory in (machines, outside, new_image / "etc"):
                directory.mkdir(parents=True)
            (new_image / "etc" / "localtime").write_text("", encoding="utf-8")
            fifos = prepare(machines, outside)
            with patch.object(sandy, "SYSTEMD_MACHINES", str(machines)):
                with patch.object(
                    sandy, "_open_verified_dir", side_effect=open_machine
                ):
                    with patch.object(sandy, "_write", side_effect=record_write):
                        with captured_output() as (stdout, _):
                            _, exception, blocked = run_with_fifo_release(
                                lambda: sandy._create_guest_files(
                                    str(new_image),
                                    "new",
                                    "10.20.30.0/24",
                                    "10.20.30.1",
                                ),
                                fifos,
                            )
        if exception is not None:
            raise exception
        init_scripts = [
            content for path, content, _ in writes if path.endswith("/init.sh")
        ]
        self.assertEqual(len(init_scripts), 1)
        return init_scripts[0], stdout.getvalue(), blocked, str(machines)

    def test_address_scan_reserves_the_address_of_a_safe_init_script(self):
        def prepare(machines: Path, _outside: Path) -> list[Path]:
            # The address of another network reserves nothing here.
            for name, address in (("old", "10.20.30.10"), ("other", "10.99.0.11")):
                image = machines / f"sandy.{name}"
                image.mkdir()
                init_script = image / "init.sh"
                init_script.write_text(f'CONTAINER_IP="{address}"\n', encoding="utf-8")
                init_script.chmod(0o644)
            # An image of a host-network container has no /init.sh.
            (machines / "sandy.host").mkdir()
            return []

        init_script, output, blocked, _ = self.allocate_beside_images(prepare)
        self.assertFalse(blocked)
        self.assertIn('CONTAINER_IP="10.20.30.11"', init_script)
        self.assertNotIn("W:", output)

    def test_address_scan_does_not_follow_an_init_script_link(self):
        # Root in a container controls its image. Before the fix, the scan
        # followed a link at /init.sh with host semantics: here it reserved
        # the address in a file outside the image.
        def prepare(machines: Path, outside: Path) -> list[Path]:
            target = outside / "init.sh"
            target.write_text('CONTAINER_IP="10.20.30.10"\n', encoding="utf-8")
            target.chmod(0o644)
            image = machines / "sandy.linked"
            image.mkdir()
            (image / "init.sh").symlink_to(target)
            return []

        init_script, output, blocked, machines = self.allocate_beside_images(prepare)
        self.assertFalse(blocked)
        self.assertIn('CONTAINER_IP="10.20.30.10"', init_script)
        self.assertIn(
            f"W: Did not reserve the address in '{machines}/sandy.linked/init.sh': "
            "\"Unsafe image file path component 'init.sh'\"\n",
            output,
        )

    def test_address_scan_reads_at_most_the_init_script_limit(self):
        # Before the fix, the scan read the whole file. A link to /dev/zero,
        # or a large file, then used memory with no limit.
        def prepare(machines: Path, _outside: Path) -> list[Path]:
            image = machines / "sandy.large"
            image.mkdir()
            init_script = image / "init.sh"
            init_script.write_text(
                'CONTAINER_IP="10.20.30.10"\n' + "#" * sandy.INIT_SCRIPT_MAX_BYTES,
                encoding="utf-8",
            )
            init_script.chmod(0o644)
            return []

        init_script, output, blocked, machines = self.allocate_beside_images(prepare)
        self.assertFalse(blocked)
        self.assertIn('CONTAINER_IP="10.20.30.10"', init_script)
        self.assertIn(
            f"W: Did not reserve the address in '{machines}/sandy.large/init.sh': "
            "'Container init script is too large'\n",
            output,
        )

    def test_address_scan_does_not_block_on_a_fifo(self):
        # Before the fix, the open of a FIFO at /init.sh waited for a writer,
        # and up blocked for good.
        def prepare(machines: Path, _outside: Path) -> list[Path]:
            image = machines / "sandy.fifo"
            image.mkdir()
            fifo = image / "init.sh"
            os.mkfifo(fifo, 0o644)
            return [fifo]

        init_script, output, blocked, machines = self.allocate_beside_images(prepare)
        self.assertFalse(blocked, "the scan blocked in the open of a FIFO")
        self.assertIn('CONTAINER_IP="10.20.30.10"', init_script)
        self.assertIn(
            f"W: Did not reserve the address in '{machines}/sandy.fifo/init.sh': "
            "\"Image file 'init.sh' is not a regular file\"\n",
            output,
        )

    def test_read_machine_container_ip_closes_its_descriptors(self):
        # Mock: _open_verified_dir opens the temporary image with no
        # ownership check. Each path must close each descriptor it opened.
        def open_machine(path: str) -> int:
            return os.open(path, sandy.DIRECTORY_OPEN_FLAGS)

        def open_descriptors() -> int:
            return len(os.listdir("/proc/self/fd"))

        with tempfile.TemporaryDirectory() as temp_dir:
            image = Path(temp_dir)
            init_script = image / "init.sh"
            cases = (
                ('CONTAINER_IP="10.20.30.10"\n', "10.20.30.10", None),
                ("no address\n", None, None),
                ("#" * (sandy.INIT_SCRIPT_MAX_BYTES + 1), None, "too large"),
                (None, None, None),
            )
            with patch.object(sandy, "_open_verified_dir", side_effect=open_machine):
                for content, expected, error in cases:
                    with self.subTest(expected=expected, error=error):
                        if content is None:
                            init_script.unlink()
                        else:
                            init_script.write_text(content, encoding="utf-8")
                            init_script.chmod(0o644)
                        before = open_descriptors()
                        if error is None:
                            self.assertEqual(
                                sandy._read_machine_container_ip(temp_dir), expected
                            )
                        else:
                            with self.assertRaisesRegex(PermissionError, error):
                                sandy._read_machine_container_ip(temp_dir)
                        self.assertEqual(open_descriptors(), before)

    def test_address_scan_holds_the_lock_until_its_init_script_exists(self):
        # Mocks: the lock, the scan, and the writes, which record events.
        # The scan, the choice, and the write of /init.sh are one step under
        # the lock; the messages come after the release.
        events: list[str] = []
        lock = self.addresses_lock.return_value
        lock.__enter__.side_effect = lambda *_: events.append("lock")
        lock.__exit__.side_effect = lambda *_: events.append(
            f"unlock, output: {stdout.getvalue()!r}"
        )

        def read_address(path: str) -> str | None:
            events.append(f"scan {Path(path).name}")
            raise OSError("unreadable")

        def record_write(path: str, _content: str, mode: int = 0o600) -> None:
            events.append(f"write {path}")

        def exists(path: str) -> bool:
            return path == sandy.SYSTEMD_MACHINES

        with patch.object(sandy.os.path, "exists", side_effect=exists):
            with patch.object(
                sandy.glob, "glob", return_value=["/var/lib/machines/sandy.old"]
            ):
                with patch.object(
                    sandy, "_read_machine_container_ip", side_effect=read_address
                ):
                    with patch.object(sandy, "_write", side_effect=record_write):
                        with captured_output() as (stdout, _):
                            sandy._create_guest_files(
                                "/machine", "test-box", "10.20.30.0/24", "10.20.30.1"
                            )
        self.assertEqual(
            events,
            [
                "write /machine/etc/hosts",
                "write /machine/etc/localtime",
                "lock",
                "scan sandy.old",
                "write /machine/init.sh",
                "unlock, output: 'I: Creating /etc/hosts with:\\n127.0.0.1 "
                "localhost test-box\\n\\nI: Creating empty /etc/localtime in guest\\n'",
            ],
        )
        output = stdout.getvalue()
        self.assertLess(
            output.index("W: Did not reserve the address in "),
            output.index("I: Creating /init.sh with:"),
        )

    def test_two_builds_of_different_names_get_different_addresses(self):
        # Regression test: no lock covered the scan and the write of /init.sh,
        # so two builds of different names could both find .10 free. Build a
        # waits in the lock before its write; build b must wait for the lock,
        # then find the address of a. Mocks: SYSTEMD_MACHINES (a temporary
        # directory), _open_verified_dir (no ownership check),
        # _open_stable_lock_file (a temporary lock file), and _write (it
        # writes the file; a waits first). The flock and the scan are real.
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            machines = root / "machines"
            (machines / "sandy.__cache").mkdir(parents=True)
            lock_file = root / "addresses.lock"
            images = {}
            for name in ("a", "b"):
                images[name] = machines / f"sandy.{name}"
                (images[name] / "etc").mkdir(parents=True)
                (images[name] / "etc" / "localtime").write_text("", encoding="utf-8")
            a_in_lock = threading.Event()
            a_may_write = threading.Event()

            def open_lock(path: str) -> io.TextIOWrapper:
                self.assertEqual(
                    path,
                    os.path.join(str(machines), "sandy.__cache", "addresses.lock"),
                )
                return open(lock_file, "a+", encoding="utf-8")

            def open_machine(path: str) -> int:
                return os.open(path, sandy.DIRECTORY_OPEN_FLAGS)

            def write(path: str, content: str, mode: int = 0o600) -> None:
                if path == str(images["a"] / "init.sh"):
                    a_in_lock.set()
                    a_may_write.wait(10)
                Path(path).write_text(content, encoding="utf-8")
                os.chmod(path, mode)

            errors: list[BaseException] = []

            def build(name: str) -> None:
                try:
                    sandy._create_guest_files(
                        str(images[name]), name, "10.20.30.0/24", "10.20.30.1"
                    )
                except BaseException as exc:  # the test reports each error
                    errors.append(exc)

            builds = {
                name: threading.Thread(target=build, args=(name,), daemon=True)
                for name in images
            }
            with patch.object(sandy, "_addresses_lock", self.real_addresses_lock):
                with patch.object(sandy, "SYSTEMD_MACHINES", str(machines)):
                    with patch.object(
                        sandy, "_open_stable_lock_file", side_effect=open_lock
                    ):
                        with patch.object(
                            sandy, "_open_verified_dir", side_effect=open_machine
                        ):
                            with patch.object(sandy, "_write", side_effect=write):
                                with captured_output():
                                    builds["a"].start()
                                    self.assertTrue(a_in_lock.wait(10))
                                    builds["b"].start()
                                    builds["b"].join(1.0)
                                    b_did_not_wait = not builds["b"].is_alive()
                                    a_may_write.set()
                                    for thread in builds.values():
                                        thread.join(10)
            addresses = {
                name: (image / "init.sh").read_text(encoding="utf-8")
                for name, image in images.items()
            }
        self.assertEqual(errors, [])
        self.assertFalse(b_did_not_wait, "build b did not wait for the address lock")
        self.assertIn('CONTAINER_IP="10.20.30.10"', addresses["a"])
        self.assertIn('CONTAINER_IP="10.20.30.11"', addresses["b"])

    def test_addresses_lock_holds_an_exclusive_flock_on_its_stable_file(self):
        # Mocks: the stable lock file and flock, which record their calls.
        handle = MagicMock()
        handle.fileno.return_value = 9
        with patch.object(
            sandy, "_open_stable_lock_file", return_value=handle
        ) as opened, patch.object(sandy.fcntl, "flock") as flock:
            with self.real_addresses_lock():
                self.assertEqual(flock.call_args_list, [call(9, sandy.fcntl.LOCK_EX)])
                handle.close.assert_not_called()
        opened.assert_called_once_with(
            os.path.join(sandy.SYSTEMD_MACHINES, "sandy.__cache", "addresses.lock")
        )
        self.assertEqual(
            flock.call_args_list,
            [call(9, sandy.fcntl.LOCK_EX), call(9, sandy.fcntl.LOCK_UN)],
        )
        handle.close.assert_called_once_with()

        # An error of the flock closes the file; an error of the unlock does
        # not hide the result of the step.
        handle.reset_mock()
        with patch.object(
            sandy, "_open_stable_lock_file", return_value=handle
        ), patch.object(sandy.fcntl, "flock", side_effect=OSError(errno.EINTR, "x")):
            with self.assertRaises(OSError):
                with self.real_addresses_lock():
                    self.fail("the step ran without the lock")
        handle.close.assert_called_once_with()
        handle.reset_mock()
        with patch.object(
            sandy, "_open_stable_lock_file", return_value=handle
        ), patch.object(
            sandy.fcntl, "flock", side_effect=[None, OSError(errno.EBADF, "x")]
        ):
            with self.real_addresses_lock():
                pass
        handle.close.assert_called_once_with()


class SandyInitializationTests(unittest.TestCase):
    def test_constructor_rejects_non_root_before_host_changes(self):
        with patch.object(sandy.os, "getuid", return_value=1000):
            with patch.object(sandy.shutil, "which", return_value=None):
                with captured_output() as (stdout, _):
                    with self.assertRaises(SystemExit) as raised:
                        sandy.Sandy()
        self.assertEqual(raised.exception.code, 1)
        self.assertIn("Must run as root", stdout.getvalue())

    def test_constructor_sets_safe_defaults_with_checks_mocked(self):
        with patch.object(sandy.os, "getuid", return_value=0):
            with patch.object(sandy.shutil, "which", return_value="/usr/bin/tool"):
                with patch.object(sandy, "_check_systemd_version", return_value=255):
                    with patch.object(sandy.Sandy, "_check_required_scripts"):
                        with patch.object(sandy.Sandy, "_check_required_tools"):
                            with patch.object(sandy.Sandy, "_set_bootstrap_method"):
                                instance = sandy.Sandy()

        self.assertEqual(instance.container, "ai-dev")
        self.assertEqual(instance.workspace, "workspace")
        self.assertEqual(instance.user_home, "/home/developer")
        self.assertEqual(instance.systemd_version, 255)
        self.assertEqual(instance.port_mappings, [])
        self.assertIsNone(instance.network)

    def test_required_tools_reports_missing_programs(self):
        instance = make_sandy()
        instance.systemd_version = 249
        with patch.object(sandy.shutil, "which", return_value=None):
            with captured_output() as (stdout, _):
                with self.assertRaises(SystemExit):
                    instance._check_required_tools()
        self.assertIn("Missing required tools", stdout.getvalue())
        self.assertIn("systemd-nspawn", stdout.getvalue())
        # The workspace mounts need no ACL tools on any systemd version.
        self.assertNotIn("setfacl", stdout.getvalue())
        self.assertNotIn("setpriv", stdout.getvalue())
        self.assertNotIn("nsenter", stdout.getvalue())

    def test_required_tools_reports_each_missing_systemd_tool(self):
        # Mocks: the tool lookup. up starts the container's scope with
        # systemd-run and queries it with systemctl.
        for missing in ("systemctl", "systemd-run"):
            with self.subTest(missing=missing):
                instance = make_sandy()
                with patch.object(
                    sandy.shutil,
                    "which",
                    side_effect=lambda name: (
                        None if name == missing else f"/usr/bin/{name}"
                    ),
                ):
                    with captured_output() as (stdout, _):
                        with self.assertRaises(SystemExit) as exited:
                            instance._check_required_tools()
                self.assertEqual(exited.exception.code, 1)
                self.assertEqual(
                    stdout.getvalue(), f"E: Missing required tools: {missing}\n"
                )

    def test_required_tools_accepts_debootstrap_and_warns_without_firewall(self):
        instance = make_sandy()
        instance.has_skopeo = False
        instance.has_umoci = False

        def which(name):
            if name in {"iptables", "nft"}:
                return None
            return f"/usr/bin/{name}"

        with patch.object(sandy.shutil, "which", side_effect=which):
            with captured_output() as (stdout, _):
                instance._check_required_tools()
        self.assertIn("network isolation will be disabled", stdout.getvalue())

    def test_required_tools_rejects_missing_bootstrap_toolchain(self):
        instance = make_sandy()
        instance.has_debootstrap = False
        instance.has_skopeo = False
        instance.has_umoci = False
        with patch.object(
            sandy.shutil,
            "which",
            return_value="/usr/bin/tool",
        ):
            with captured_output() as (stdout, _):
                with self.assertRaises(SystemExit):
                    instance._check_required_tools()
        self.assertIn("Need either", stdout.getvalue())

    def test_required_scripts_are_resolved(self):
        instance = make_sandy()
        with patch.object(sandy.os.path, "exists", return_value=True):
            instance._check_required_scripts()
        self.assertEqual(instance.cn_debootstrap, str(PROJECT_DIR / "debootstrap.sh"))
        self.assertEqual(instance.cn_oci, str(PROJECT_DIR / "oci.sh"))
        self.assertEqual(
            instance.cn_setup_container,
            str(PROJECT_DIR / "setup-container.sh"),
        )

    def test_missing_required_script_exits(self):
        instance = make_sandy()
        for exists_values, expected in (
            ([False], "debootstrap.sh"),
            ([True, False], "oci.sh"),
            ([True, True, False], "sandy-keepalive.sh"),
            ([True, True, True, False], "setup-container.sh"),
        ):
            with self.subTest(expected=expected):
                with patch.object(
                    sandy.os.path,
                    "exists",
                    side_effect=exists_values,
                ):
                    with captured_output() as (stdout, _):
                        with self.assertRaises(SystemExit):
                            instance._check_required_scripts()
                self.assertIn(expected, stdout.getvalue())

    def test_bootstrap_selection(self):
        cases = [
            ("oci", True, True, True, "OCI", "debian:trixie-slim"),
            ("debootstrap", True, False, False, "debootstrap", "debian:trixie"),
            ("", True, True, True, "OCI", "debian:trixie-slim"),
            ("", True, False, False, "debootstrap", "debian:trixie"),
        ]
        for method, deb, skopeo, umoci, expected_method, image in cases:
            with self.subTest(method=method, skopeo=skopeo):
                instance = make_sandy()
                instance.has_debootstrap = deb
                instance.has_skopeo = skopeo
                instance.has_umoci = umoci
                environment = {"SANDY_BOOTSTRAP": method}
                with patch.dict(sandy.os.environ, environment, clear=True):
                    instance._set_bootstrap_method()
                self.assertEqual(instance.bootstrap_method, expected_method)
                self.assertEqual(instance.base_image, image)

    def test_bootstrap_override_is_validated(self):
        instance = make_sandy()
        environment = {
            "SANDY_BOOTSTRAP": "oci",
            "SANDY_BOOTSTRAP_BASE": "ubuntu:noble",
        }
        with patch.dict(sandy.os.environ, environment, clear=True):
            instance._set_bootstrap_method()
        self.assertEqual(instance.base_image, "ubuntu:noble")

        with patch.dict(
            sandy.os.environ,
            {"SANDY_BOOTSTRAP": "oci\n"},
            clear=True,
        ):
            with captured_output():
                with self.assertRaises(SystemExit):
                    instance._set_bootstrap_method()

    def test_unavailable_requested_bootstrap_exits(self):
        instance = make_sandy()
        instance.has_skopeo = False
        with patch.dict(sandy.os.environ, {"SANDY_BOOTSTRAP": "oci"}, clear=True):
            with captured_output():
                with self.assertRaises(SystemExit):
                    instance._set_bootstrap_method()

        instance = make_sandy()
        instance.has_debootstrap = False
        with patch.dict(
            sandy.os.environ,
            {"SANDY_BOOTSTRAP": "debootstrap"},
            clear=True,
        ):
            with captured_output():
                with self.assertRaises(SystemExit):
                    instance._set_bootstrap_method()

    def test_invalid_base_image_exits(self):
        instance = make_sandy()
        with patch.dict(
            sandy.os.environ,
            {
                "SANDY_BOOTSTRAP": "oci",
                "SANDY_BOOTSTRAP_BASE": "Bad/Image",
            },
            clear=True,
        ):
            with captured_output():
                with self.assertRaises(SystemExit):
                    instance._set_bootstrap_method()

    def test_confirmation(self):
        instance = make_sandy()
        cases = [("y", True), ("YES", True), ("n", False), ("", False)]
        for response, expected in cases:
            with self.subTest(response=response):
                with patch("builtins.input", return_value=response):
                    self.assertEqual(instance._confirm("Continue"), expected)

        with patch("builtins.input", side_effect=EOFError):
            with captured_output():
                self.assertFalse(instance._confirm("Continue"))


class SystemUtilityTests(unittest.TestCase):
    def test_systemd_version_parsing(self):
        result = subprocess.CompletedProcess(
            ["systemd-nspawn", "--version"],
            0,
            stdout="systemd 255 (255.4)\n+PAM\n",
        )
        with patch.object(sandy, "_run_secure_subprocess", return_value=result):
            self.assertEqual(sandy._check_systemd_version(), 255)

    def test_systemd_version_fallback(self):
        with patch.object(
            sandy,
            "_run_secure_subprocess",
            side_effect=subprocess.CalledProcessError(1, ["systemd-nspawn"]),
        ):
            with captured_output() as (stdout, _):
                self.assertEqual(sandy._check_systemd_version(), 0)
        self.assertIn("assuming older version", stdout.getvalue())

    def test_machine_and_cache_paths_are_scoped(self):
        instance = make_sandy()
        with patch.object(sandy, "SYSTEMD_MACHINES", "/machines"):
            self.assertEqual(
                instance._get_machine_dir(),
                "/machines/sandy.ai-dev",
            )
            with patch.object(sandy.os.path, "exists", return_value=False):
                self.assertEqual(
                    instance._get_cache_dir(),
                    "/machines/sandy.__cache",
                )
            self.assertEqual(
                instance._get_port_mappings_path(),
                "/machines/sandy.__cache/port_mappings.json",
            )
            self.assertEqual(
                instance._get_port_mappings_lock_path(),
                "/machines/sandy.__cache/port_mappings.lock",
            )

    def test_existing_cache_directory_is_verified(self):
        instance = make_sandy()
        with patch.object(sandy.os.path, "exists", return_value=True):
            with patch.object(sandy, "_verify_safe_dir") as verify:
                cache_dir = instance._get_cache_dir()
        verify.assert_called_once_with(cache_dir)

    def test_ensure_cache_directory_creates_or_verifies_and_chmods(self):
        instance = make_sandy()
        for exists in (False, True):
            with self.subTest(exists=exists):
                with patch.object(
                    instance,
                    "_get_cache_dir",
                    return_value="/cache",
                ):
                    with patch.object(
                        sandy.os.path,
                        "exists",
                        return_value=exists,
                    ):
                        with patch.object(sandy, "_mkdir") as mkdir:
                            with patch.object(
                                sandy,
                                "_verify_safe_dir",
                            ) as verify:
                                with patch.object(
                                    sandy.os,
                                    "chmod",
                                ) as chmod:
                                    self.assertEqual(
                                        instance._ensure_cache_dir(),
                                        "/cache",
                                    )
                if exists:
                    verify.assert_called_once_with("/cache")
                    mkdir.assert_not_called()
                else:
                    mkdir.assert_called_once_with("/cache")
                    verify.assert_not_called()
                chmod.assert_called_once_with(
                    "/cache",
                    0o700,
                    follow_symlinks=False,
                )

        with patch.object(
            instance,
            "_get_cache_dir",
            return_value="/cache",
        ):
            with patch.object(sandy.os.path, "exists", return_value=False):
                with patch.object(
                    sandy,
                    "_mkdir",
                    side_effect=FileExistsError,
                ):
                    with patch.object(sandy, "_verify_safe_dir") as verify:
                        with patch.object(sandy.os, "chmod"):
                            self.assertEqual(
                                instance._ensure_cache_dir(),
                                "/cache",
                            )
        verify.assert_called_once_with("/cache")

    def test_running_container_enumeration_skips_cache(self):
        instance = make_sandy()
        paths = [
            "/var/lib/machines/sandy.one",
            "/var/lib/machines/sandy.two",
            "/var/lib/machines/sandy.bad\n\x1b[31m",
            "/var/lib/machines/sandy.__cache",
        ]
        checked_names = []

        def is_running(name):
            checked_names.append(name)
            return "123" if name == "one" else None

        with patch.object(sandy.os.path, "exists", return_value=True):
            with patch.object(sandy.glob, "glob", return_value=paths):
                with patch.object(
                    instance,
                    "_is_container_running",
                    side_effect=is_running,
                ):
                    self.assertEqual(
                        instance._get_running_sandy_containers(),
                        ["one"],
                    )
        self.assertEqual(checked_names, ["one", "two"])

        with patch.object(sandy.os.path, "exists", return_value=False):
            self.assertEqual(instance._get_running_sandy_containers(), [])


@contextmanager
def mocked_entry_syscall(machine="x86_64", return_value=0, side_effect=None, err=0):
    """Mock libc syscall(2), the machine name, and errno for entry primitives."""
    syscall = MagicMock(return_value=return_value, side_effect=side_effect)
    with ExitStack() as stack:
        stack.enter_context(
            patch.object(sandy, "_libc", return_value=SimpleNamespace(syscall=syscall))
        )
        stack.enter_context(
            patch.object(sandy.platform, "machine", return_value=machine)
        )
        stack.enter_context(patch.object(sandy.ctypes, "get_errno", return_value=err))
        yield syscall


class EntryPrimitiveTests(unittest.TestCase):
    """Container entry syscall wrappers.

    Every test mocks libc syscall(2), platform.machine, and ctypes.get_errno.
    No test calls the kernel. E2E tests in a VM must prove the real behavior.
    """

    def test_libc_is_loaded_once_from_process_symbols(self):
        libc = MagicMock()
        with patch.object(sandy, "_LIBC", None), patch.object(
            sandy.ctypes, "CDLL", return_value=libc
        ) as cdll:
            self.assertIs(sandy._libc(), libc)
            self.assertIs(sandy._libc(), libc)
        cdll.assert_called_once_with(None, use_errno=True)
        self.assertEqual(libc.syscall.argtypes, [sandy.ctypes.c_long] * 7)
        self.assertIs(libc.syscall.restype, sandy.ctypes.c_long)

    def test_syscall_table_is_exact(self):
        # open_tree, move_mount, openat2, and mount_setattr have the same
        # number on every architecture; unshare does not.
        mount_calls = {
            "open_tree": 428,
            "move_mount": 429,
            "openat2": 437,
            "mount_setattr": 442,
        }
        self.assertEqual(
            sandy.ENTRY_SYSCALL_NUMBERS,
            {
                "x86_64": {
                    "ptrace": 101,
                    "prctl": 157,
                    "setns": 308,
                    "seccomp": 317,
                    "unshare": 272,
                    **mount_calls,
                },
                "aarch64": {
                    "ptrace": 117,
                    "prctl": 167,
                    "setns": 268,
                    "seccomp": 277,
                    "unshare": 97,
                    **mount_calls,
                },
            },
        )

    def test_struct_layout_matches_linux_filter_h(self):
        self.assertEqual(sandy.ctypes.sizeof(sandy._SockFilter), 8)
        self.assertEqual(sandy._SockFilter.code.offset, 0)
        self.assertEqual(sandy._SockFilter.jt.offset, 2)
        self.assertEqual(sandy._SockFilter.jf.offset, 3)
        self.assertEqual(sandy._SockFilter.k.offset, 4)
        self.assertEqual(sandy.ctypes.sizeof(sandy._SockFprog), 16)
        self.assertEqual(sandy._SockFprog.filter.offset, 8)

    def test_namespace_entry_order_joins_user_last(self):
        self.assertEqual(
            sandy.NAMESPACE_ENTRY_ORDER,
            (
                ("cgroup", 0x02000000),
                ("ipc", 0x08000000),
                ("uts", 0x04000000),
                ("net", 0x40000000),
                ("pid", 0x20000000),
                ("mnt", 0x00020000),
                ("user", 0x10000000),
            ),
        )

    def test_unsupported_architecture_fails_closed(self):
        for machine in ("i686", "armv7l", "riscv64", "", "x86_64 "):
            with self.subTest(machine=machine):
                with mocked_entry_syscall(machine=machine) as syscall:
                    with self.assertRaises(OSError) as raised:
                        sandy._ptrace_seize(42)
                self.assertEqual(raised.exception.errno, errno.ENOSYS)
                syscall.assert_not_called()

    def test_non_64_bit_process_fails_closed(self):
        with mocked_entry_syscall() as syscall, patch.object(
            sandy.ctypes, "sizeof", return_value=4
        ):
            with self.assertRaises(OSError) as raised:
                sandy._ptrace_seize(42)
        self.assertEqual(raised.exception.errno, errno.ENOSYS)
        syscall.assert_not_called()

    def test_unknown_syscall_name_is_rejected(self):
        with mocked_entry_syscall() as syscall:
            with self.assertRaises(ValueError):
                sandy._entry_syscall("fork", 0)
        syscall.assert_not_called()

    def test_invalid_syscall_arguments_are_rejected(self):
        for args in (
            (1, 2, 3, 4, 5, 6, 7),
            (True,),
            ("1",),
            (1.0,),
            (2**63,),
            (-(2**63) - 1,),
        ):
            with self.subTest(args=args):
                with mocked_entry_syscall() as syscall:
                    with self.assertRaises(ValueError):
                        sandy._entry_syscall("prctl", *args)
                syscall.assert_not_called()

    def test_syscall_failure_raises_errno(self):
        with mocked_entry_syscall(return_value=-1, err=errno.EPERM):
            with self.assertRaises(OSError) as raised:
                sandy._ptrace_seize(42)
        self.assertEqual(raised.exception.errno, errno.EPERM)
        self.assertIn("ptrace failed", str(raised.exception))

    def test_syscall_failure_without_errno_still_fails(self):
        with mocked_entry_syscall(return_value=-1, err=0):
            with self.assertRaises(OSError) as raised:
                sandy._capbset_drop(0)
        self.assertEqual(raised.exception.errno, errno.EIO)

    def test_syscall_negative_result_other_than_minus_one_fails_closed(self):
        # syscall(2) reports an error only as -1. A caller that ignores the
        # result, such as setns, must not treat another negative value as
        # success.
        for result in (-2, -errno.EACCES, -(2**63)):
            with self.subTest(result=result):
                with mocked_entry_syscall(return_value=result, err=errno.EPERM):
                    with self.assertRaises(OSError) as raised:
                        sandy._setns(3, sandy.CLONE_NEWNET)
                self.assertEqual(raised.exception.errno, errno.EIO)
                self.assertIn(
                    "setns returned an unexpected value", str(raised.exception)
                )

    def test_ptrace_seize_interrupt_and_detach_exact_calls(self):
        for machine, number in (("x86_64", 101), ("aarch64", 117)):
            with self.subTest(machine=machine):
                with mocked_entry_syscall(machine=machine) as syscall:
                    sandy._ptrace_seize(42)
                    sandy._ptrace_interrupt(42)
                    sandy._ptrace_detach(42)
                    sandy._ptrace_detach(42, 36)
                self.assertEqual(
                    syscall.call_args_list,
                    [
                        call(number, 0x4206, 42, 0, 0, 0, 0),
                        call(number, 0x4207, 42, 0, 0, 0, 0),
                        call(number, 17, 42, 0, 0, 0, 0),
                        call(number, 17, 42, 0, 36, 0, 0),
                    ],
                )

    def test_ptrace_detach_rejects_invalid_signal(self):
        for signal_number in (-1, 65, True, "9", None):
            with self.subTest(signal_number=signal_number):
                with mocked_entry_syscall() as syscall:
                    with self.assertRaises(ValueError):
                        sandy._ptrace_detach(42, signal_number)
                syscall.assert_not_called()

    def test_invalid_process_ids_are_rejected(self):
        for pid in (0, -1, True, "42", 42.0, None, sandy.PID_MAX_LIMIT):
            with self.subTest(pid=pid):
                with mocked_entry_syscall() as syscall:
                    for function in (
                        sandy._ptrace_seize,
                        sandy._ptrace_interrupt,
                        sandy._ptrace_detach,
                        lambda value: sandy._ptrace_get_seccomp_filter(value, 0),
                    ):
                        with self.assertRaises(ValueError):
                            function(pid)
                syscall.assert_not_called()
        with mocked_entry_syscall() as syscall:
            sandy._ptrace_seize(sandy.PID_MAX_LIMIT - 1)
        syscall.assert_called_once_with(
            101, 0x4206, sandy.PID_MAX_LIMIT - 1, 0, 0, 0, 0
        )

    def test_get_seccomp_filter_reads_length_then_program(self):
        program = bytes(range(16))

        def fake_syscall(number, request, pid, index, address, *rest):
            if address:
                sandy.ctypes.memmove(address, program, len(program))
            return 2

        with mocked_entry_syscall(side_effect=fake_syscall) as syscall:
            self.assertEqual(sandy._ptrace_get_seccomp_filter(42, 3), program)
        self.assertEqual(syscall.call_count, 2)
        self.assertEqual(syscall.call_args_list[0], call(101, 0x420C, 42, 3, 0, 0, 0))
        second = syscall.call_args_list[1].args
        self.assertEqual(second[:4], (101, 0x420C, 42, 3))
        self.assertNotEqual(second[4], 0)
        self.assertEqual(second[5:], (0, 0))

    def test_get_seccomp_filter_propagates_missing_index(self):
        with mocked_entry_syscall(return_value=-1, err=errno.ENOENT) as syscall:
            with self.assertRaises(OSError) as raised:
                sandy._ptrace_get_seccomp_filter(42, 5)
        self.assertEqual(raised.exception.errno, errno.ENOENT)
        syscall.assert_called_once_with(101, 0x420C, 42, 5, 0, 0, 0)

    def test_get_seccomp_filter_rejects_invalid_length(self):
        for count in (0, sandy.BPF_MAXINSNS + 1):
            with self.subTest(count=count):
                with mocked_entry_syscall(return_value=count) as syscall:
                    with self.assertRaises(ValueError):
                        sandy._ptrace_get_seccomp_filter(42, 0)
                syscall.assert_called_once()

    def test_get_seccomp_filter_accepts_maximum_length(self):
        count = sandy.BPF_MAXINSNS
        with mocked_entry_syscall(return_value=count) as syscall:
            program = sandy._ptrace_get_seccomp_filter(42, 0)
        self.assertEqual(len(program), count * 8)
        self.assertEqual(syscall.call_count, 2)

    def test_get_seccomp_filter_rejects_changed_length(self):
        with mocked_entry_syscall(side_effect=[2, 3]):
            with self.assertRaises(OSError) as raised:
                sandy._ptrace_get_seccomp_filter(42, 0)
        self.assertEqual(raised.exception.errno, errno.EIO)

    def test_get_seccomp_filter_rejects_invalid_index(self):
        for index in (-1, True, "0", sandy.SECCOMP_MAX_INSNS_PER_PATH + 1):
            with self.subTest(index=index):
                with mocked_entry_syscall() as syscall:
                    with self.assertRaises(ValueError):
                        sandy._ptrace_get_seccomp_filter(42, index)
                syscall.assert_not_called()

    def test_capbset_read_exact_call_and_result(self):
        for result, expected in ((1, True), (0, False)):
            with self.subTest(result=result):
                with mocked_entry_syscall(
                    machine="aarch64", return_value=result
                ) as syscall:
                    self.assertIs(sandy._capbset_read(21), expected)
                syscall.assert_called_once_with(167, 23, 21, 0, 0, 0, 0)

    def test_capbset_read_rejects_unexpected_result(self):
        with mocked_entry_syscall(return_value=2):
            with self.assertRaises(OSError) as raised:
                sandy._capbset_read(0)
        self.assertEqual(raised.exception.errno, errno.EIO)

    def test_capbset_drop_exact_call_and_error(self):
        with mocked_entry_syscall() as syscall:
            sandy._capbset_drop(63)
        syscall.assert_called_once_with(157, 24, 63, 0, 0, 0, 0)
        with mocked_entry_syscall(return_value=-1, err=errno.EPERM):
            with self.assertRaises(OSError) as raised:
                sandy._capbset_drop(12)
        self.assertEqual(raised.exception.errno, errno.EPERM)

    def test_invalid_capabilities_are_rejected(self):
        for capability in (-1, 64, True, "0", None):
            with self.subTest(capability=capability):
                with mocked_entry_syscall() as syscall:
                    with self.assertRaises(ValueError):
                        sandy._capbset_read(capability)
                    with self.assertRaises(ValueError):
                        sandy._capbset_drop(capability)
                syscall.assert_not_called()

    def test_set_child_subreaper_exact_call(self):
        with mocked_entry_syscall() as syscall:
            sandy._set_child_subreaper()
        syscall.assert_called_once_with(157, 36, 1, 0, 0, 0, 0)

    def test_set_parent_death_signal_exact_call(self):
        with mocked_entry_syscall() as syscall:
            sandy._set_parent_death_signal(sandy.signal.SIGTERM)
        syscall.assert_called_once_with(157, 1, 15, 0, 0, 0, 0)
        for signum in (0, 65, True, "15"):
            with self.subTest(signum=signum):
                with mocked_entry_syscall() as syscall:
                    with self.assertRaises(ValueError):
                        sandy._set_parent_death_signal(signum)
                syscall.assert_not_called()

    def test_setns_exact_calls_for_each_namespace(self):
        with mocked_entry_syscall() as syscall:
            for fd, (_, nstype) in enumerate(sandy.NAMESPACE_ENTRY_ORDER, start=10):
                sandy._setns(fd, nstype)
        self.assertEqual(
            syscall.call_args_list,
            [
                call(308, fd, nstype, 0, 0, 0, 0)
                for fd, (_, nstype) in enumerate(sandy.NAMESPACE_ENTRY_ORDER, start=10)
            ],
        )

    def test_setns_error_propagates(self):
        with mocked_entry_syscall(return_value=-1, err=errno.EINVAL):
            with self.assertRaises(OSError) as raised:
                sandy._setns(3, sandy.CLONE_NEWUSER)
        self.assertEqual(raised.exception.errno, errno.EINVAL)

    def test_setns_rejects_invalid_arguments(self):
        for fd, nstype in (
            (3, 0),
            (3, sandy.CLONE_NEWNET | sandy.CLONE_NEWPID),
            (3, True),
            (3, 0x00000100),
            (3, float(sandy.CLONE_NEWNET)),
            (-1, sandy.CLONE_NEWNET),
            (True, sandy.CLONE_NEWNET),
            (2**31, sandy.CLONE_NEWNET),
        ):
            with self.subTest(fd=fd, nstype=nstype):
                with mocked_entry_syscall() as syscall:
                    with self.assertRaises(ValueError):
                        sandy._setns(fd, nstype)
                syscall.assert_not_called()

    def test_seccomp_installs_program_through_sock_fprog(self):
        program = bytes(range(24))
        seen = []

        def fake_syscall(number, operation, flags, address, *rest):
            fprog = sandy._SockFprog.from_address(address)
            seen.append(
                (fprog.len, sandy.ctypes.string_at(fprog.filter, fprog.len * 8))
            )
            return 0

        with mocked_entry_syscall(side_effect=fake_syscall) as syscall:
            sandy._seccomp_set_mode_filter(program)
        self.assertEqual(seen, [(3, program)])
        args = syscall.call_args.args
        self.assertEqual(args[:3], (317, 1, 0))
        self.assertEqual(args[4:], (0, 0, 0))

    def test_seccomp_uses_aarch64_number(self):
        with mocked_entry_syscall(machine="aarch64") as syscall:
            sandy._seccomp_set_mode_filter(bytes(8 * sandy.BPF_MAXINSNS))
        self.assertEqual(syscall.call_args.args[:3], (277, 1, 0))

    def test_seccomp_error_propagates(self):
        with mocked_entry_syscall(return_value=-1, err=errno.EACCES):
            with self.assertRaises(OSError) as raised:
                sandy._seccomp_set_mode_filter(bytes(8))
        self.assertEqual(raised.exception.errno, errno.EACCES)

    def test_seccomp_refuses_a_multithreaded_process(self):
        # Without flags, a filter covers only the calling thread. Mocks: the
        # thread count and libc syscall(2).
        with mocked_entry_syscall() as syscall, patch.object(
            sandy.threading, "active_count", return_value=2
        ):
            with self.assertRaises(RuntimeError):
                sandy._seccomp_set_mode_filter(bytes(8))
        syscall.assert_not_called()

    def test_seccomp_rejects_invalid_programs(self):
        for program in (
            b"",
            bytes(7),
            bytes(9),
            bytes(8 * (sandy.BPF_MAXINSNS + 1)),
            bytearray(8),
            "12345678",
            None,
        ):
            with self.subTest(length=len(program) if program is not None else None):
                with mocked_entry_syscall() as syscall:
                    with self.assertRaises(ValueError):
                        sandy._seccomp_set_mode_filter(program)
                syscall.assert_not_called()


def ptrace_stop_status(signal_number, event=0):
    """Return a waitpid status for a ptrace stop."""
    return (event << 16) | (signal_number << 8) | 0x7F


class UpLockTests(unittest.TestCase):
    """The up lock of a container name: its file name and the lock.

    Mocks: the open of the stable lock file, which gives a temporary file.
    The flock calls are real.
    """

    def open_temporary_lock(self, temp_dir, opened):
        lock_path = Path(temp_dir) / "up-ai-dev.lock"

        def open_lock(path):
            self.assertEqual(
                path,
                os.path.join(sandy.SYSTEMD_MACHINES, "sandy.__cache", "up-ai-dev.lock"),
            )
            handle = open(lock_path, "a+", encoding="utf-8")
            opened.append(handle)
            return handle

        return open_lock

    def test_up_lock_filename_needs_a_valid_container_name(self):
        self.assertEqual(sandy._up_lock_filename("ai-dev"), "up-ai-dev.lock")
        for name in ("", "Bad", "../x", "a/b", "ai-dev\n", "a" * 64):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    sandy._up_lock_filename(name)

    def test_is_up_lock_filename(self):
        for name, expected in (
            ("up-ai-dev.lock", True),
            ("up-a.lock", True),
            ("up-" + "a" * 63 + ".lock", True),
            ("up-.lock", False),
            ("up-Bad.lock", False),
            ("up-a.b.lock", False),
            ("up-a-.lock", False),
            ("up-" + "a" * 64 + ".lock", False),
            ("up-ai-dev.lock.tmp", False),
            ("xup-ai-dev.lock", False),
            ("up-ai-dev.lock\n", False),
            ("lifecycle.lock", False),
        ):
            with self.subTest(name=name):
                self.assertEqual(sandy._is_up_lock_filename(name), expected)

    def test_up_lock_is_exclusive_and_does_not_wait(self):
        opened: list = []
        with tempfile.TemporaryDirectory() as temp_dir:
            open_lock = self.open_temporary_lock(temp_dir, opened)
            with patch.object(sandy, "_open_stable_lock_file", side_effect=open_lock):
                first = sandy._acquire_up_lock("ai-dev")
                try:
                    self.assertIs(first, opened[0])
                    # A second up of the name gets None at once, and its file
                    # closes.
                    self.assertIsNone(sandy._acquire_up_lock("ai-dev"))
                    self.assertTrue(opened[1].closed)
                finally:
                    first.close()
                # After the close, the next up gets the lock.
                third = sandy._acquire_up_lock("ai-dev")
                self.assertIs(third, opened[2])
                third.close()

    def test_up_lock_closes_its_file_when_flock_fails(self):
        lock_handle = MagicMock()
        lock_handle.fileno.return_value = 9
        with patch.object(
            sandy, "_open_stable_lock_file", return_value=lock_handle
        ), patch.object(sandy.fcntl, "flock", side_effect=OSError(errno.EBADF, "x")):
            with self.assertRaises(OSError):
                sandy._acquire_up_lock("ai-dev")
        lock_handle.close.assert_called_once_with()

    def test_up_lock_refuses_an_invalid_name_before_it_opens_a_file(self):
        with patch.object(sandy, "_open_stable_lock_file") as opened:
            with self.assertRaises(ValueError):
                sandy._acquire_up_lock("../lifecycle")
        opened.assert_not_called()


class LeaderExtractionTests(unittest.TestCase):
    """Host-side extraction of the Leader's seccomp filters and CapBnd.

    Tests mock the ptrace and prctl primitives, os.waitpid, os.pidfd_open,
    machinectl, and the lock file owner check. Lock tests use real flock on a
    temporary file. E2E tests in a VM must prove the real kernel behavior.
    """

    def open_temporary_lock(self, temp_dir):
        lock_path = Path(temp_dir) / "lifecycle.lock"

        def open_lock(path):
            self.assertEqual(
                path,
                os.path.join(sandy.SYSTEMD_MACHINES, "sandy.__cache", "lifecycle.lock"),
            )
            return open(lock_path, "a+", encoding="utf-8")

        return lock_path, open_lock

    def test_lifecycle_lock_is_exclusive_and_released(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            lock_path, open_lock = self.open_temporary_lock(temp_dir)
            with patch.object(sandy, "_open_stable_lock_file", side_effect=open_lock):
                with sandy._lifecycle_lock():
                    with open(lock_path, "a+", encoding="utf-8") as other:
                        with self.assertRaises(BlockingIOError):
                            sandy.fcntl.flock(
                                other.fileno(),
                                sandy.fcntl.LOCK_EX | sandy.fcntl.LOCK_NB,
                            )
                with open(lock_path, "a+", encoding="utf-8") as other:
                    sandy.fcntl.flock(
                        other.fileno(), sandy.fcntl.LOCK_EX | sandy.fcntl.LOCK_NB
                    )

    def test_lifecycle_lock_times_out_when_held(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            lock_path, open_lock = self.open_temporary_lock(temp_dir)
            with open(lock_path, "a+", encoding="utf-8") as holder:
                sandy.fcntl.flock(holder.fileno(), sandy.fcntl.LOCK_EX)
                with patch.object(
                    sandy, "_open_stable_lock_file", side_effect=open_lock
                ), patch.object(
                    sandy.time, "monotonic", side_effect=[100.0, 105.0, 110.0]
                ), patch.object(
                    sandy.time, "sleep"
                ) as sleep:
                    body = MagicMock()
                    with self.assertRaises(TimeoutError):
                        with sandy._lifecycle_lock():
                            body()
                body.assert_not_called()
                sleep.assert_called_once_with(sandy.LIFECYCLE_LOCK_RETRY_INTERVAL)

    def test_lifecycle_lock_retries_until_free(self):
        lock_handle = MagicMock()
        lock_handle.fileno.return_value = 9
        with patch.object(
            sandy, "_open_stable_lock_file", return_value=lock_handle
        ), patch.object(
            sandy.fcntl, "flock", side_effect=[BlockingIOError(), None, None]
        ) as flock, patch.object(
            sandy.time, "monotonic", return_value=0.0
        ), patch.object(
            sandy.time, "sleep"
        ) as sleep:
            with sandy._lifecycle_lock():
                pass
        self.assertEqual(
            flock.call_args_list,
            [
                call(9, sandy.fcntl.LOCK_EX | sandy.fcntl.LOCK_NB),
                call(9, sandy.fcntl.LOCK_EX | sandy.fcntl.LOCK_NB),
                call(9, sandy.fcntl.LOCK_UN),
            ],
        )
        sleep.assert_called_once_with(sandy.LIFECYCLE_LOCK_RETRY_INTERVAL)
        lock_handle.close.assert_called_once_with()

    def test_lifecycle_lock_releases_on_error_and_tolerates_unlock_failure(self):
        lock_handle = MagicMock()
        lock_handle.fileno.return_value = 9
        with patch.object(
            sandy, "_open_stable_lock_file", return_value=lock_handle
        ), patch.object(
            sandy.fcntl, "flock", side_effect=[None, OSError("unlock failed")]
        ) as flock:
            with self.assertRaises(RuntimeError):
                with sandy._lifecycle_lock():
                    raise RuntimeError("body failed")
        self.assertEqual(flock.call_args_list[-1], call(9, sandy.fcntl.LOCK_UN))
        lock_handle.close.assert_called_once_with()

    def test_lifecycle_lock_closes_handle_when_flock_fails(self):
        lock_handle = MagicMock()
        lock_handle.fileno.return_value = 9
        with patch.object(
            sandy, "_open_stable_lock_file", return_value=lock_handle
        ), patch.object(sandy.fcntl, "flock", side_effect=OSError(errno.EBADF, "x")):
            with self.assertRaises(OSError):
                with sandy._lifecycle_lock():
                    pass
        lock_handle.close.assert_called_once_with()

    def test_parse_leader_pid(self):
        self.assertEqual(sandy._parse_leader_pid("2"), 2)
        self.assertEqual(sandy._parse_leader_pid("4194303"), 4194303)
        for value in (
            "",
            "0",
            "1",
            "01",
            "+5",
            "-5",
            " 5",
            "5 ",
            "5\n",
            "12345678",
            "4194304",
            "\u0663",
            None,
            5,
        ):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    sandy._parse_leader_pid(value)

    def test_query_machine_leader_exact_command(self):
        result = subprocess.CompletedProcess([], 0, stdout="4242\n")
        with patch.object(sandy, "_run_secure_subprocess", return_value=result) as run:
            self.assertEqual(sandy._query_machine_leader("ai-dev"), 4242)
        run.assert_called_once_with(
            ["machinectl", "show", "ai-dev", "-p", "Leader", "--value"],
            capture_output=True,
            text=True,
            check=True,
            timeout=sandy.QUERY_COMMAND_TIMEOUT,
        )

    def test_query_machine_leader_rejects_bad_output_and_names(self):
        for stdout in ("", "\n", "4242\n\n", "4242 \n", "abc\n", "1\n"):
            with self.subTest(stdout=stdout):
                result = subprocess.CompletedProcess([], 0, stdout=stdout)
                with patch.object(sandy, "_run_secure_subprocess", return_value=result):
                    with self.assertRaises(ValueError):
                        sandy._query_machine_leader("ai-dev")
        with patch.object(sandy, "_run_secure_subprocess") as run:
            with self.assertRaises(ValueError):
                sandy._query_machine_leader("-p")
        run.assert_not_called()
        with patch.object(
            sandy,
            "_run_secure_subprocess",
            side_effect=subprocess.CalledProcessError(1, ["machinectl"]),
        ):
            with self.assertRaises(subprocess.CalledProcessError):
                sandy._query_machine_leader("ai-dev")

    def test_parse_capability_bounding_set(self):
        status = "Name:\t(sd-stubinit)\nCapEff:\t000001ffffffffff\nCapBnd:\t00000000fdecbfff\n"
        self.assertEqual(sandy._parse_capability_bounding_set(status), 0xFDECBFFF)
        for text in (
            "Name:\tx\n",
            "CapBnd:\t00000000fdecbfff\nCapBnd:\t00000000fdecbfff\n",
            "CapBnd:\t00000000FDECBFFF\n",
            "CapBnd:\t0000000fdecbfff\n",
            "CapBnd:\t000000000fdecbfff\n",
            "CapBnd: 00000000fdecbfff\n",
            "CapBnd:\t00000000fdecbfff \n",
            "CapBnd:\t0x000000fdecbfff\n",
        ):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    sandy._parse_capability_bounding_set(text)

    def test_read_capability_bounding_set_from_proc_directory(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            status = Path(temp_dir) / "status"
            status.write_text("Name:\tx\nCapBnd:\t000001ffffffffff\n")
            proc_fd = os.open(temp_dir, os.O_RDONLY | os.O_DIRECTORY)
            try:
                self.assertEqual(
                    sandy._read_capability_bounding_set(proc_fd), 0x1FFFFFFFFFF
                )
                status.write_bytes(b"CapBnd:\t000001ffffffffff\n" + b"x" * 65536)
                with self.assertRaises(ValueError):
                    sandy._read_capability_bounding_set(proc_fd)
                status.unlink()
                with self.assertRaises(FileNotFoundError):
                    sandy._read_capability_bounding_set(proc_fd)
            finally:
                os.close(proc_fd)

    def test_read_proc_file_reads_every_chunk_and_bounds_the_size(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            data = b"x" * (sandy.PROC_READ_CHUNK_BYTES * 2 + 5)
            Path(temp_dir, "status").write_bytes(data)
            dir_fd = os.open(temp_dir, sandy.DIRECTORY_OPEN_FLAGS)
            try:
                self.assertEqual(
                    sandy._read_proc_file(dir_fd, "status", len(data)), data
                )
                with self.assertRaisesRegex(ValueError, "too large"):
                    sandy._read_proc_file(dir_fd, "status", len(data) - 1)
                # The name is below the directory, and a link is not followed.
                Path(temp_dir, "link").symlink_to("status")
                with self.assertRaises(OSError):
                    sandy._read_proc_file(dir_fd, "link", len(data))
            finally:
                os.close(dir_fd)

    def test_open_process_dir_validates_the_pid(self):
        with patch.object(sandy.os, "open", return_value=7) as open_:
            self.assertEqual(sandy._open_process_dir(42), 7)
        open_.assert_called_once_with("/proc/42", sandy.DIRECTORY_OPEN_FLAGS)
        for pid in (0, -1, True, "42", 4194304):
            with self.subTest(pid=pid):
                with patch.object(sandy.os, "open") as open_:
                    with self.assertRaises(ValueError):
                        sandy._open_process_dir(pid)
                open_.assert_not_called()

    def test_parse_status_value_requires_one_well_formed_line(self):
        pattern = sandy.PPID_LINE_PATTERN
        self.assertEqual(
            sandy._parse_status_value("Name:\tx\nPPid:\t42\n", "PPid", pattern), "42"
        )
        for text in (
            "Name:\tx\n",
            "PPid:\t42\nPPid:\t42\n",
            "PPid: 42\n",
            "PPid:\t042\n",
            "PPid:\t42 \n",
            "PPid:\t12345678\n",
            "PPid:\t-1\n",
        ):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    sandy._parse_status_value(text, "PPid", pattern)

    def payload_status(
        self,
        ppid: "str | None" = "42",
        nspid: "str | None" = "77\t2",
        filters: "str | None" = "2",
        capbnd: str = "00000000fdecbfff",
        name: str = "sandy-keepalive",
    ) -> str:
        """Return /proc/<pid>/status text with the fields that Sandy reads."""
        lines = [f"Name:\t{name}", "State:\tS (sleeping)"]
        if ppid is not None:
            lines.append(f"PPid:\t{ppid}")
        if nspid is not None:
            lines.append(f"NSpid:\t{nspid}")
        lines.append(f"CapBnd:\t{capbnd}")
        lines.append("Seccomp:\t2")
        if filters is not None:
            lines.append(f"Seccomp_filters:\t{filters}")
        return "\n".join(lines) + "\n"

    def test_parse_payload_status_accepts_only_the_containers_pid_2(self):
        self.assertEqual(
            sandy._parse_payload_status(self.payload_status(), 77, 42),
            sandy.ProcessConfinement(2, 0xFDECBFFF),
        )
        for label, text, pid in (
            # An orphan that the Leader adopted.
            ("orphan", self.payload_status(nspid="77\t9"), 77),
            ("wrong parent", self.payload_status(ppid="43"), 77),
            ("no parent", self.payload_status(ppid="0"), 77),
            # Host PID 2 (kthreadd) has one NSpid entry.
            ("kthreadd", self.payload_status(ppid="0", nspid="2"), 2),
            ("host PID 2 with the Leader as parent", self.payload_status(nspid="2"), 2),
            ("host process", self.payload_status(nspid="77"), 77),
            # PID 2 of a PID namespace that the container created.
            ("nested namespace", self.payload_status(nspid="77\t9\t2"), 77),
            ("other host PID", self.payload_status(nspid="78\t2"), 77),
        ):
            with self.subTest(label=label):
                self.assertIsNone(sandy._parse_payload_status(text, pid, 42))

    def test_parse_payload_status_fails_closed_on_malformed_fields(self):
        for label, text in (
            ("no PPid", self.payload_status(ppid=None)),
            ("bad PPid", self.payload_status(ppid="x")),
            ("no NSpid", self.payload_status(nspid=None)),
            ("bad NSpid", self.payload_status(nspid="77 2")),
            ("NSpid zero", self.payload_status(nspid="77\t0")),
            ("no filter count", self.payload_status(filters=None)),
            ("bad filter count", self.payload_status(filters="-1")),
            ("bad CapBnd", self.payload_status(capbnd="fdecbfff")),
            ("two PPid lines", self.payload_status() + "PPid:\t42\n"),
        ):
            with self.subTest(label=label):
                with self.assertRaises(ValueError):
                    sandy._parse_payload_status(text, 77, 42)

    def test_parse_payload_status_reads_only_identity_of_other_children(self):
        # A child that is not the payload needs only PPid and NSpid.
        text = self.payload_status(nspid="77\t9", filters=None, capbnd="bad")
        self.assertIsNone(sandy._parse_payload_status(text, 77, 42))

    @contextmanager
    def fake_proc(
        self, children: bytes, statuses: "Mapping[int, str | None]"
    ) -> Iterator[tuple[int, MagicMock]]:
        """Build a fake host /proc with Leader 42; yield its descriptor.

        _open_process_dir is the only mock: it opens <pid> below the fake
        tree, as the real function opens /proc/<pid>.
        """
        with tempfile.TemporaryDirectory() as root:
            leader = Path(root, "42")
            (leader / "task" / "42").mkdir(parents=True)
            (leader / "task" / "42" / "children").write_bytes(children)
            for pid, text in statuses.items():
                Path(root, str(pid)).mkdir()
                if text is not None:
                    Path(root, str(pid), "status").write_text(text)

            def open_process_dir(pid):
                return os.open(os.path.join(root, str(pid)), sandy.DIRECTORY_OPEN_FLAGS)

            leader_fd = os.open(leader, sandy.DIRECTORY_OPEN_FLAGS)
            try:
                with patch.object(
                    sandy, "_open_process_dir", side_effect=open_process_dir
                ) as opened:
                    yield leader_fd, opened
            finally:
                os.close(leader_fd)

    def test_find_payload_finds_pid_2_among_orphans(self):
        statuses = {
            90: self.payload_status(nspid="90\t14", filters="9"),
            77: self.payload_status(),
            91: self.payload_status(nspid="91\t15", capbnd="0000000000000000"),
        }
        with self.fake_proc(b"90 77 91 ", statuses) as (leader_fd, opened):
            self.assertEqual(
                sandy._find_payload(leader_fd, 42),
                (77, sandy.ProcessConfinement(2, 0xFDECBFFF)),
            )
        # The search stops at the payload; it reads no later child.
        self.assertEqual(opened.call_args_list, [call(90), call(77)])

    def test_find_payload_finds_the_payload_before_many_orphans(self):
        # Regression test: with more than 131072 adopted orphans, the Leader's
        # list passed the 1 MiB limit, and every attach failed. The payload is
        # the Leader's first child; the search reads no more of the list.
        orphans = b"".join(b"%d " % pid for pid in range(1000000, 1150000))
        self.assertGreater(len(orphans), 1048576)
        statuses = {77: self.payload_status()}
        with self.fake_proc(b"77 " + orphans, statuses) as (leader_fd, opened):
            before = sandy._open_fds()
            with patch.object(sandy.os, "read", wraps=os.read) as read:
                self.assertEqual(
                    sandy._find_payload(leader_fd, 42),
                    (77, sandy.ProcessConfinement(2, 0xFDECBFFF)),
                )
            self.assertEqual(sandy._open_fds(), before)
        self.assertEqual(opened.call_args_list, [call(77)])
        # The whole list takes about 290 chunks; the search reads the first
        # one, and the payload's status.
        chunk_reads = [
            entry
            for entry in read.call_args_list
            if entry.args[1] == sandy.PROC_READ_CHUNK_BYTES
        ]
        self.assertLess(len(chunk_reads), 10)

    def test_find_payload_reads_no_child_after_the_payload(self):
        # Container root can give an adopted orphan a status that is too
        # large to read (many supplementary groups). The orphan comes after
        # the payload, so it cannot make the attach fail.
        statuses = {
            77: self.payload_status(),
            90: self.payload_status(nspid="90\t14") + "x" * 70000,
        }
        with self.fake_proc(b"77 90 ", statuses) as (leader_fd, opened):
            self.assertEqual(
                sandy._find_payload(leader_fd, 42),
                (77, sandy.ProcessConfinement(2, 0xFDECBFFF)),
            )
        self.assertEqual(opened.call_args_list, [call(77)])
        with self.fake_proc(b"90 77 ", statuses) as (leader_fd, _):
            with self.assertRaisesRegex(ValueError, "too large"):
                sandy._find_payload(leader_fd, 42)

    def test_find_payload_fails_closed_while_starting(self):
        cases = (
            ("no children", b"", {}),
            ("only an orphan", b"90 ", {90: self.payload_status(nspid="90\t3")}),
            (
                "kthreadd",
                b"2 ",
                {2: self.payload_status(ppid="0", nspid="2")},
            ),
            ("wrong parent", b"77 ", {77: self.payload_status(ppid="41")}),
            (
                "nested namespace",
                b"77 ",
                {77: self.payload_status(nspid="77\t5\t2")},
            ),
            # The payload exited after the list was read.
            ("gone", b"77 ", {}),
            ("gone before status", b"77 ", {77: None}),
        )
        for label, children, statuses in cases:
            with self.subTest(label=label):
                with self.fake_proc(children, statuses) as (leader_fd, _):
                    with self.assertRaisesRegex(ProcessLookupError, "still starting"):
                        sandy._find_payload(leader_fd, 42)

    def test_find_payload_skips_a_child_that_exits(self):
        statuses = {90: self.payload_status(nspid="90\t3"), 77: self.payload_status()}
        real_read = sandy._read_process_status
        # The first child exits between its directory open and its status read.
        results = [ProcessLookupError("gone")]

        def read_status(proc_fd):
            if results:
                raise results.pop()
            return real_read(proc_fd)

        with self.fake_proc(b"90 77 ", statuses) as (leader_fd, _):
            with patch.object(sandy, "_read_process_status", side_effect=read_status):
                self.assertEqual(
                    sandy._find_payload(leader_fd, 42),
                    (77, sandy.ProcessConfinement(2, 0xFDECBFFF)),
                )

    def test_find_payload_leaks_no_descriptor(self):
        statuses = {
            90: self.payload_status(nspid="90\t3"),
            77: self.payload_status(),
            91: None,
        }
        for children in (b"90 77 ", b"90 91 ", b"91 77 90 "):
            with self.subTest(children=children):
                with self.fake_proc(children, statuses) as (leader_fd, _):
                    before = sandy._open_fds()
                    try:
                        sandy._find_payload(leader_fd, 42)
                    except ProcessLookupError:
                        pass
                    self.assertEqual(sandy._open_fds(), before)

    def test_find_payload_fails_closed_on_bad_data(self):
        payload = {77: self.payload_status()}
        malformed = {77: self.payload_status(filters="x")}
        with self.fake_proc(b"77 ", malformed) as (leader_fd, _):
            with self.assertRaises(ValueError):
                sandy._find_payload(leader_fd, 42)
        with self.fake_proc(b"77", payload) as (leader_fd, _):
            with self.assertRaisesRegex(ValueError, "children list"):
                sandy._find_payload(leader_fd, 42)

    def fd_links(self, proc_dir: str, links: "Mapping[str, str]") -> None:
        """Create /proc/<pid>/fd entries; a symlink stands in for a magic link."""
        fd_dir = Path(proc_dir, "fd")
        fd_dir.mkdir(exist_ok=True)
        for name, target in links.items():
            os.symlink(target, fd_dir / name)

    def test_process_has_open_path_compares_link_targets(self):
        script = sandy.KEEPALIVE_SCRIPT_PATH
        self.assertEqual(script, "/run/sandy/keepalive.sh")
        cases = (
            ({"0": "/dev/pts/0", "1": "pipe:[81]", "255": script}, True),
            ({"0": "/dev/pts/0", "1": "pipe:[81]"}, False),
            # The copy was removed after the open.
            ({"255": script + " (deleted)"}, False),
            ({"3": "/run/sandy/keepalive.shx", "4": "run/sandy/keepalive.sh"}, False),
            ({}, False),
        )
        for links, expected in cases:
            with self.subTest(links=links):
                with tempfile.TemporaryDirectory() as proc_dir:
                    self.fd_links(proc_dir, links)
                    proc_fd = os.open(proc_dir, sandy.DIRECTORY_OPEN_FLAGS)
                    try:
                        before = sandy._open_fds()
                        self.assertEqual(
                            sandy._process_has_open_path(proc_fd, script), expected
                        )
                        self.assertEqual(sandy._open_fds(), before)
                    finally:
                        os.close(proc_fd)

    def test_process_has_open_path_fails_closed_on_bad_entries(self):
        script = sandy.KEEPALIVE_SCRIPT_PATH
        for links in ({"x": script}, {"01": script}, {"-1": script}):
            with self.subTest(links=links):
                with tempfile.TemporaryDirectory() as proc_dir:
                    self.fd_links(proc_dir, links)
                    proc_fd = os.open(proc_dir, sandy.DIRECTORY_OPEN_FLAGS)
                    try:
                        with self.assertRaises(ValueError):
                            sandy._process_has_open_path(proc_fd, script)
                    finally:
                        os.close(proc_fd)
        with tempfile.TemporaryDirectory() as proc_dir:
            self.fd_links(proc_dir, {"0": "a", "1": "b", "2": script})
            proc_fd = os.open(proc_dir, sandy.DIRECTORY_OPEN_FLAGS)
            try:
                with patch.object(sandy, "PROC_FD_MAX_ENTRIES", 2):
                    with self.assertRaisesRegex(ValueError, "too many"):
                        sandy._process_has_open_path(proc_fd, script)
            finally:
                os.close(proc_fd)
        # A process that has exited has no fd directory.
        with tempfile.TemporaryDirectory() as proc_dir:
            proc_fd = os.open(proc_dir, sandy.DIRECTORY_OPEN_FLAGS)
            try:
                with self.assertRaises(FileNotFoundError):
                    sandy._process_has_open_path(proc_fd, script)
            finally:
                os.close(proc_fd)

    def test_process_has_open_path_skips_a_closed_descriptor(self):
        # Mocks: os.readlink fails for fd 3, as when the process closes it
        # after the listing. The listing order is not fixed.
        script = sandy.KEEPALIVE_SCRIPT_PATH
        real_readlink = os.readlink

        def readlink(name, *, dir_fd):
            if name == "3":
                raise FileNotFoundError(name)
            return real_readlink(name, dir_fd=dir_fd)

        for links, expected in (
            ({"3": "/tmp/gone"}, False),
            ({"3": "/tmp/gone", "255": script}, True),
        ):
            with self.subTest(links=links):
                with tempfile.TemporaryDirectory() as proc_dir:
                    self.fd_links(proc_dir, links)
                    proc_fd = os.open(proc_dir, sandy.DIRECTORY_OPEN_FLAGS)
                    try:
                        with patch.object(
                            sandy.os, "readlink", side_effect=readlink
                        ) as mocked:
                            self.assertEqual(
                                sandy._process_has_open_path(proc_fd, script),
                                expected,
                            )
                    finally:
                        os.close(proc_fd)
                    if not expected:
                        mocked.assert_called_once_with("3", dir_fd=ANY)

    @contextmanager
    def keepalive_proc(
        self,
        children: bytes,
        payload_links: "Mapping[str, str]",
        reused_status: "str | None" = None,
    ) -> Iterator[MagicMock]:
        """Fake /proc with Leader 42 and payload 77; yield the open mock.

        Mocks: machinectl (Leader 42) and _open_process_dir (the fake tree).
        With reused_status, a second open of PID 77 finds another process,
        as when the payload exits and its PID goes to a new process.
        """
        with tempfile.TemporaryDirectory() as root:
            leader = Path(root, "42")
            (leader / "task" / "42").mkdir(parents=True)
            (leader / "task" / "42" / "children").write_bytes(children)
            payload = Path(root, "77")
            payload.mkdir()
            (payload / "status").write_text(self.payload_status())
            self.fd_links(str(payload), payload_links)
            reused = Path(root, "77-reused")
            reused.mkdir()
            (reused / "status").write_text(reused_status or "")
            self.fd_links(str(reused), payload_links)
            opens = []

            def open_process_dir(pid):
                name = str(pid)
                if pid == 77 and reused_status is not None and 77 in opens:
                    name = "77-reused"
                opens.append(pid)
                return os.open(os.path.join(root, name), sandy.DIRECTORY_OPEN_FLAGS)

            with patch.object(
                sandy, "_query_machine_leader", return_value=42
            ), patch.object(
                sandy, "_open_process_dir", side_effect=open_process_dir
            ) as opened:
                yield opened

    def test_payload_has_opened_keepalive_reads_the_payload_fds(self):
        script = sandy.KEEPALIVE_SCRIPT_PATH
        for links, expected in (({"255": script}, True), ({"0": "/dev/null"}, False)):
            with self.subTest(links=links):
                with self.keepalive_proc(b"77 ", links) as opened:
                    before = sandy._open_fds()
                    self.assertEqual(
                        sandy._payload_has_opened_keepalive("ai-dev"), expected
                    )
                    self.assertEqual(sandy._open_fds(), before)
                    sandy._query_machine_leader.assert_called_once_with("ai-dev")
                # The Leader for the search, then the payload for its fds.
                self.assertEqual(opened.call_args_list, [call(42), call(77), call(77)])

    def test_payload_has_opened_keepalive_fails_without_the_payload(self):
        script = sandy.KEEPALIVE_SCRIPT_PATH
        with self.keepalive_proc(b"", {"255": script}):
            with self.assertRaisesRegex(ProcessLookupError, "still starting"):
                sandy._payload_has_opened_keepalive("ai-dev")
        # The payload exited after the search, and a new process has its PID.
        other = self.payload_status(ppid="1", nspid="77")
        with self.keepalive_proc(b"77 ", {"255": script}, reused_status=other):
            before = sandy._open_fds()
            with self.assertRaisesRegex(ProcessLookupError, "changed"):
                sandy._payload_has_opened_keepalive("ai-dev")
            self.assertEqual(sandy._open_fds(), before)

    def test_require_scope_payload_cgroup(self):
        unit = "sandy-ai-dev.scope"
        for cgroup in (
            "/sandy.slice/sandy-ai-dev.scope/payload",
            "/sandy.slice/sandy-ai-dev.scope/payload/init.scope",
        ):
            with self.subTest(cgroup=cgroup):
                sandy._require_scope_payload_cgroup(cgroup, unit)
        for cgroup in (
            "/sandy.slice/sandy-ai-dev.scope/payloadx",
            "/sandy.slice/sandy-ai-dev.scope/attach-0",
            "/sandy.slice/sandy-ai-dev.scope/",
            "/sandy.slice/sandy-ai-dev.scopex",
            "/machine.slice/machine-ai-dev.scope/payload",
            "/",
        ):
            with self.subTest(cgroup=cgroup):
                with self.assertRaisesRegex(PermissionError, "restart it"):
                    sandy._require_scope_payload_cgroup(cgroup, unit)
        # During the start, nspawn moves the Leader from the scope's own
        # cgroup to payload (measured on systemd 249, 255, and 257).
        with self.assertRaisesRegex(ProcessLookupError, "still starting"):
            sandy._require_scope_payload_cgroup("/sandy.slice/sandy-ai-dev.scope", unit)

    def test_pidfd_process_alive_uses_readability(self):
        # A pipe stands in for a pidfd: readable means that the process exited.
        read_fd, write_fd = os.pipe()
        try:
            self.assertTrue(sandy._pidfd_process_alive(read_fd))
            os.write(write_fd, b"x")
            self.assertFalse(sandy._pidfd_process_alive(read_fd))
        finally:
            os.close(read_fd)
            os.close(write_fd)

    def test_stop_seized_tracee_returns_detach_signal(self):
        cases = (
            (ptrace_stop_status(sandy.signal.SIGCHLD), sandy.signal.SIGCHLD),
            (ptrace_stop_status(36), 36),
            (ptrace_stop_status(sandy.signal.SIGTRAP, 128), 0),
            (ptrace_stop_status(sandy.signal.SIGSTOP, 128), 0),
        )
        for status, expected in cases:
            with self.subTest(status=status):
                with patch.object(
                    sandy, "_ptrace_interrupt"
                ) as interrupt, patch.object(
                    sandy.os, "waitpid", return_value=(42, status)
                ) as waitpid:
                    self.assertEqual(sandy._stop_seized_tracee(42), expected)
                interrupt.assert_called_once_with(42)
                waitpid.assert_called_once_with(42, 0x40000000)

    def test_stop_seized_tracee_fails_when_leader_exits(self):
        for status in (0, 9):
            with self.subTest(status=status):
                with patch.object(sandy, "_ptrace_interrupt"), patch.object(
                    sandy.os, "waitpid", return_value=(42, status)
                ):
                    with self.assertRaises(ProcessLookupError):
                        sandy._stop_seized_tracee(42)

    def test_collect_seccomp_filters_returns_oldest_first(self):
        with patch.object(
            sandy,
            "_ptrace_get_seccomp_filter",
            side_effect=[b"oldest", b"middle", b"newest", OSError(errno.ENOENT, "x")],
        ) as get_filter:
            # Regression: index 0 is the oldest filter, so the list must not
            # be reversed. A reversed list installs the filters in the wrong
            # order (measured in E2E: the session's programs were reversed).
            self.assertEqual(
                sandy._collect_seccomp_filters(42), (b"oldest", b"middle", b"newest")
            )
        self.assertEqual(
            get_filter.call_args_list,
            [call(42, 0), call(42, 1), call(42, 2), call(42, 3)],
        )

    def test_collect_seccomp_filters_fails_on_other_errors(self):
        for err in (errno.EACCES, errno.EINVAL, errno.ESRCH, errno.EMEDIUMTYPE):
            with self.subTest(err=err):
                with patch.object(
                    sandy,
                    "_ptrace_get_seccomp_filter",
                    side_effect=[b"newest", OSError(err, "x")],
                ):
                    with self.assertRaises(OSError) as raised:
                        sandy._collect_seccomp_filters(42)
                self.assertEqual(raised.exception.errno, err)

    def test_collect_seccomp_filters_requires_a_filter(self):
        with patch.object(
            sandy,
            "_ptrace_get_seccomp_filter",
            side_effect=OSError(errno.ENOENT, "x"),
        ):
            with self.assertRaises(PermissionError):
                sandy._collect_seccomp_filters(42)

    def test_collect_seccomp_filters_bounds_the_index(self):
        with patch.object(sandy, "SECCOMP_MAX_INSNS_PER_PATH", 2), patch.object(
            sandy, "_ptrace_get_seccomp_filter", return_value=b"filter"
        ) as get_filter:
            with self.assertRaises(OSError) as raised:
                sandy._collect_seccomp_filters(42)
        self.assertEqual(raised.exception.errno, errno.E2BIG)
        self.assertEqual(get_filter.call_count, 3)

    def ptrace_mocks(self, stop_signal=0, collect=None, detach=None):
        manager = MagicMock()
        manager.stop.return_value = stop_signal
        if collect is not None:
            manager.collect.side_effect = collect
        if detach is not None:
            manager.detach.side_effect = detach
        stack = ExitStack()
        stack.enter_context(patch.object(sandy, "_ptrace_seize", manager.seize))
        stack.enter_context(patch.object(sandy, "_stop_seized_tracee", manager.stop))
        stack.enter_context(
            patch.object(sandy, "_collect_seccomp_filters", manager.collect)
        )
        stack.enter_context(patch.object(sandy, "_ptrace_detach", manager.detach))
        return manager, stack

    def test_read_seccomp_filters_detaches_with_saved_signal(self):
        manager, stack = self.ptrace_mocks(stop_signal=17)
        manager.collect.return_value = (b"old", b"new")
        with stack:
            self.assertEqual(sandy._read_seccomp_filters(42), (b"old", b"new"))
        self.assertEqual(
            manager.mock_calls,
            [call.seize(42), call.stop(42), call.collect(42), call.detach(42, 17)],
        )

    def test_read_seccomp_filters_detaches_on_error(self):
        manager, stack = self.ptrace_mocks(
            collect=OSError(errno.EACCES, "denied"),
            detach=OSError(errno.ESRCH, "gone"),
        )
        with stack:
            with self.assertRaises(OSError) as raised:
                sandy._read_seccomp_filters(42)
        self.assertEqual(raised.exception.errno, errno.EACCES)
        manager.detach.assert_called_once_with(42, 0)

    def test_read_seccomp_filters_reports_detach_failure(self):
        manager, stack = self.ptrace_mocks(detach=OSError(errno.ESRCH, "gone"))
        with stack:
            with self.assertRaises(OSError) as raised:
                sandy._read_seccomp_filters(42)
        self.assertEqual(raised.exception.errno, errno.ESRCH)

    def test_read_seccomp_filters_does_not_detach_without_stop(self):
        manager, stack = self.ptrace_mocks()
        manager.stop.side_effect = ProcessLookupError("gone")
        with stack:
            with self.assertRaises(ProcessLookupError):
                sandy._read_seccomp_filters(42)
        manager.collect.assert_not_called()
        manager.detach.assert_not_called()

    def test_close_leader_confinement_closes_every_descriptor(self):
        confinement = sandy.LeaderConfinement(
            pidfd=3,
            namespace_fds=(4, 5),
            seccomp_filters=(),
            capability_bounding_set=0,
            attach_kill_fd=6,
            oom_score_adj=0,
        )
        with patch.object(
            sandy.os, "close", side_effect=[None, OSError(errno.EBADF, "x"), None, None]
        ) as close:
            sandy._close_leader_confinement(confinement)
        self.assertEqual(close.call_args_list, [call(3), call(4), call(5), call(6)])

    @contextmanager
    def extraction_mocks(self, **overrides):
        """Mock every host boundary of _extract_leader_confinement."""
        manager = MagicMock()
        next_fd = iter(range(20, 40))

        @contextmanager
        def lock():
            manager.lock_enter()
            try:
                yield
            finally:
                manager.lock_exit()

        def open_fd(path, flags, dir_fd=None):
            manager.open(path, flags, dir_fd=dir_fd)
            if "open" in overrides and path == overrides["open"]:
                raise FileNotFoundError(path)
            return next(next_fd)

        manager.pidfd_open.return_value = 10
        manager.query.return_value = overrides.get("leader", 42)
        manager.filters.return_value = (b"old", b"new")
        manager.capbnd.return_value = 0xFDECBFFF
        manager.oom.return_value = -500
        manager.cgroup.return_value = overrides.get(
            "cgroup", "/sandy.slice/sandy-ai-dev.scope/payload"
        )
        manager.join.return_value = 30
        manager.alive.return_value = overrides.get("alive", True)
        manager.pending.return_value = None
        manager.payload.return_value = (
            77,
            overrides.get(
                "payload_confinement", sandy.ProcessConfinement(2, 0xFDECBFFF)
            ),
        )
        for name in (
            "filters",
            "capbnd",
            "oom",
            "pidfd_open",
            "join",
            "payload",
            "pending",
        ):
            if name in overrides:
                getattr(manager, name).side_effect = overrides[name]
        if "cgroup_error" in overrides:
            manager.cgroup.side_effect = overrides["cgroup_error"]
        with ExitStack() as stack:
            stack.enter_context(patch.object(sandy, "_lifecycle_lock", lock))
            stack.enter_context(
                patch.object(sandy.os, "pidfd_open", manager.pidfd_open, create=True)
            )
            stack.enter_context(
                patch.object(sandy, "_query_machine_leader", manager.query)
            )
            stack.enter_context(patch.object(sandy.os, "open", side_effect=open_fd))
            stack.enter_context(patch.object(sandy.os, "close", manager.close))
            stack.enter_context(
                patch.object(sandy, "_read_seccomp_filters", manager.filters)
            )
            stack.enter_context(
                patch.object(sandy, "_read_capability_bounding_set", manager.capbnd)
            )
            stack.enter_context(patch.object(sandy, "_read_oom_score_adj", manager.oom))
            stack.enter_context(
                patch.object(sandy, "_read_process_cgroup", manager.cgroup)
            )
            stack.enter_context(
                patch.object(sandy, "_require_no_pending_mounts", manager.pending)
            )
            stack.enter_context(patch.object(sandy, "_find_payload", manager.payload))
            stack.enter_context(
                patch.object(sandy, "_pidfd_process_alive", manager.alive)
            )
            stack.enter_context(patch.object(sandy, "_join_attach_leaf", manager.join))
            yield manager

    def test_extract_leader_confinement_success_order(self):
        with self.extraction_mocks() as manager:
            confinement = sandy._extract_leader_confinement("ai-dev", 42, ATTACH_LEAF)
        self.assertEqual(
            confinement,
            sandy.LeaderConfinement(
                pidfd=10,
                namespace_fds=(21, 22, 23, 24, 25, 26, 27),
                seccomp_filters=(b"old", b"new"),
                capability_bounding_set=0xFDECBFFF,
                attach_kill_fd=30,
                oom_score_adj=-500,
            ),
        )
        ns_flags = os.O_RDONLY | os.O_CLOEXEC
        self.assertEqual(
            manager.mock_calls,
            [
                call.lock_enter(),
                call.pidfd_open(42),
                call.query("ai-dev"),
                call.open("/proc/42", sandy.DIRECTORY_OPEN_FLAGS, dir_fd=None),
                call.cgroup(20),
                # No attach before up has mounted the directories (item 6).
                call.pending("ai-dev"),
                # The payload exists before the Leader's namespaces and
                # filters are opened or read (specs/security-parity.md item 5).
                call.payload(20, 42),
                call.open("ns/cgroup", ns_flags, dir_fd=20),
                call.open("ns/ipc", ns_flags, dir_fd=20),
                call.open("ns/uts", ns_flags, dir_fd=20),
                call.open("ns/net", ns_flags, dir_fd=20),
                call.open("ns/pid", ns_flags, dir_fd=20),
                call.open("ns/mnt", ns_flags, dir_fd=20),
                call.open("ns/user", ns_flags, dir_fd=20),
                call.filters(42),
                call.capbnd(20),
                # From the pinned Leader directory (item 2).
                call.oom(20),
                call.close(20),
                call.alive(10),
                call.join("ai-dev", ATTACH_LEAF),
                call.lock_exit(),
            ],
        )

    def test_extract_leader_confinement_accepts_nested_payload_cgroup(self):
        cgroup = "/sandy.slice/sandy-ai-dev.scope/payload/init.scope"
        with self.extraction_mocks(cgroup=cgroup) as manager:
            confinement = sandy._extract_leader_confinement("ai-dev", 42, ATTACH_LEAF)
        self.assertEqual(confinement.attach_kill_fd, 30)
        manager.join.assert_called_once_with("ai-dev", ATTACH_LEAF)

    def test_extract_leader_confinement_rejects_leader_outside_scope(self):
        for cgroup, error, message in (
            (
                "/machine.slice/machine-ai-dev.scope/payload",
                PermissionError,
                "restart it",
            ),
            (
                "/sandy.slice/sandy-ai-dev.scope/supervisor",
                PermissionError,
                "restart it",
            ),
            (
                "/sandy.slice/sandy-ai-dev.scope/payloadx",
                PermissionError,
                "restart it",
            ),
            (
                "/sandy.slice/sandy-other.scope/payload",
                PermissionError,
                "restart it",
            ),
            # nspawn has not yet moved the Leader below payload.
            ("/sandy.slice/sandy-ai-dev.scope", ProcessLookupError, "still starting"),
        ):
            with self.subTest(cgroup=cgroup):
                with self.extraction_mocks(cgroup=cgroup) as manager:
                    with self.assertRaisesRegex(error, message):
                        sandy._extract_leader_confinement("ai-dev", 42, ATTACH_LEAF)
                # A container of an earlier Sandy has no payload at PID 2, so
                # the scope check comes first and asks for a restart.
                manager.pending.assert_not_called()
                manager.payload.assert_not_called()
                manager.filters.assert_not_called()
                manager.join.assert_not_called()
                self.assertEqual(manager.close.call_args_list, [call(20), call(10)])
                manager.lock_exit.assert_called_once_with()

    def test_extract_leader_confinement_refuses_while_mounts_are_pending(self):
        # Mocks: the marker check. A real marker is a cgroup of the scope; the
        # marker tests and the E2E suite prove it. Nothing of the Leader is
        # read or joined while up has not mounted the directories.
        pending = ProcessLookupError("Container is still starting; try again")
        with self.extraction_mocks(pending=pending) as manager:
            with self.assertRaisesRegex(ProcessLookupError, "still starting"):
                sandy._extract_leader_confinement("ai-dev", 42, ATTACH_LEAF)
        manager.pending.assert_called_once_with("ai-dev")
        manager.payload.assert_not_called()
        manager.filters.assert_not_called()
        manager.capbnd.assert_not_called()
        manager.alive.assert_not_called()
        manager.join.assert_not_called()
        self.assertEqual(
            [entry for entry in manager.mock_calls if entry[0] == "open"],
            [call.open("/proc/42", sandy.DIRECTORY_OPEN_FLAGS, dir_fd=None)],
        )
        self.assertEqual(manager.close.call_args_list, [call(20), call(10)])
        manager.lock_exit.assert_called_once_with()

    def test_extract_leader_confinement_closes_fds_when_join_fails(self):
        with self.extraction_mocks(join=OSError(errno.ENOENT, "x")) as manager:
            with self.assertRaises(OSError):
                sandy._extract_leader_confinement("ai-dev", 42, ATTACH_LEAF)
        self.assertEqual(
            manager.close.call_args_list[1:],
            [call(fd) for fd in (10, 21, 22, 23, 24, 25, 26, 27)],
        )

    def test_extract_leader_confinement_validates_leaf_and_name_before_lock(self):
        for machine, leaf in (
            ("ai-dev", "attach-x"),
            ("ai-dev", "../payload"),
            ("ai-dev", ATTACH_LEAF + "0"),
            ("Bad", ATTACH_LEAF),
        ):
            with self.subTest(machine=machine, leaf=leaf):
                with self.extraction_mocks() as manager:
                    with self.assertRaises(ValueError):
                        sandy._extract_leader_confinement(machine, 42, leaf)
                manager.lock_enter.assert_not_called()

    def test_extract_leader_confinement_rejects_changed_leader(self):
        with self.extraction_mocks(leader=43) as manager:
            with self.assertRaises(PermissionError):
                sandy._extract_leader_confinement("ai-dev", 42, ATTACH_LEAF)
        manager.open.assert_not_called()
        manager.close.assert_called_once_with(10)
        manager.lock_exit.assert_called_once_with()

    def test_extract_leader_confinement_closes_fds_when_leader_exits(self):
        with self.extraction_mocks(alive=False) as manager:
            with self.assertRaises(ProcessLookupError):
                sandy._extract_leader_confinement("ai-dev", 42, ATTACH_LEAF)
        self.assertEqual(
            manager.close.call_args_list,
            [
                call(20),
                call(10),
                call(21),
                call(22),
                call(23),
                call(24),
                call(25),
                call(26),
                call(27),
            ],
        )

    def test_extract_leader_confinement_closes_fds_on_partial_open(self):
        with self.extraction_mocks(open="ns/pid") as manager:
            with self.assertRaises(FileNotFoundError):
                sandy._extract_leader_confinement("ai-dev", 42, ATTACH_LEAF)
        manager.filters.assert_not_called()
        self.assertEqual(
            manager.close.call_args_list,
            [call(20), call(10), call(21), call(22), call(23), call(24)],
        )

    def test_extract_leader_confinement_fails_closed_on_read_errors(self):
        for name, error in (
            ("filters", OSError(errno.EACCES, "x")),
            ("capbnd", ValueError("bad")),
            ("oom", ValueError("Malformed oom_score_adj")),
            ("pidfd_open", ProcessLookupError("gone")),
            ("cgroup_error", ValueError("bad")),
            ("payload", ValueError("bad")),
        ):
            with self.subTest(name=name):
                with self.extraction_mocks(**{name: error}) as manager:
                    with self.assertRaises(type(error)):
                        sandy._extract_leader_confinement("ai-dev", 42, ATTACH_LEAF)
                manager.alive.assert_not_called()
                manager.join.assert_not_called()
                manager.lock_exit.assert_called_once_with()
                if name != "pidfd_open":
                    self.assertIn(call(10), manager.close.call_args_list)

    def test_extract_leader_confinement_fails_closed_while_starting(self):
        # No payload yet: nothing of the Leader is opened, stopped, or read.
        starting = ProcessLookupError("Container is still starting; try again")
        with self.extraction_mocks(payload=starting) as manager:
            with self.assertRaisesRegex(ProcessLookupError, "still starting"):
                sandy._extract_leader_confinement("ai-dev", 42, ATTACH_LEAF)
        self.assertEqual(
            [entry for entry in manager.mock_calls if entry[0] == "open"],
            [call.open("/proc/42", sandy.DIRECTORY_OPEN_FLAGS, dir_fd=None)],
        )
        manager.filters.assert_not_called()
        manager.capbnd.assert_not_called()
        manager.oom.assert_not_called()
        manager.alive.assert_not_called()
        manager.join.assert_not_called()
        self.assertEqual(manager.close.call_args_list, [call(20), call(10)])
        manager.lock_exit.assert_called_once_with()

    def test_extract_leader_confinement_rejects_a_payload_mismatch(self):
        for payload in (
            sandy.ProcessConfinement(1, 0xFDECBFFF),
            sandy.ProcessConfinement(3, 0xFDECBFFF),
            sandy.ProcessConfinement(2, 0xFDECABFF),
            sandy.ProcessConfinement(2, 0x1FFFFFFFFFF),
        ):
            with self.subTest(payload=payload):
                with self.extraction_mocks(payload_confinement=payload) as manager:
                    with self.assertRaisesRegex(PermissionError, "differs"):
                        sandy._extract_leader_confinement("ai-dev", 42, ATTACH_LEAF)
                manager.alive.assert_called_once_with(10)
                manager.join.assert_not_called()
                self.assertEqual(
                    manager.close.call_args_list,
                    [call(fd) for fd in (20, 10, 21, 22, 23, 24, 25, 26, 27)],
                )
                manager.lock_exit.assert_called_once_with()

    def test_extract_leader_confinement_validates_pid_before_lock(self):
        for pid in (0, True, "42"):
            with self.subTest(pid=pid):
                with self.extraction_mocks() as manager:
                    with self.assertRaises(ValueError):
                        sandy._extract_leader_confinement("ai-dev", pid, ATTACH_LEAF)
                manager.lock_enter.assert_not_called()

    def test_extract_leader_confinement_opens_nothing_without_lock(self):
        with patch.object(
            sandy, "_lifecycle_lock", side_effect=TimeoutError("busy")
        ), patch.object(sandy.os, "pidfd_open", create=True) as pidfd_open:
            with self.assertRaises(TimeoutError):
                sandy._extract_leader_confinement("ai-dev", 42, ATTACH_LEAF)
        pidfd_open.assert_not_called()


class _ExitCalled(Exception):
    """Raised by a mocked os._exit so that a test can observe the exit code."""


ATTACH_LEAF = "attach-" + "0123456789abcdef" * 2
MIB = 1024 * 1024
GIB = 1024 * MIB
# A host with 8 CPUs, 16 GiB, and a task limit of 131072. By default the
# containers share CPUs 2-7, 12 GiB, and 98304 tasks, and one container gets
# 24576 tasks.
HOST_FACTS = sandy.HostFacts(tuple(range(8)), 16 * GIB, 131072)
DEFAULT_GROUP = sandy.GroupLimits(tuple(range(2, 8)), 12 * GIB, 98304)


def entry_args(**overrides):
    """Return valid entry helper arguments that follow the mode argument."""
    values = {
        "machine": "ai-dev",
        "leader": "4242",
        "parent": "4100",
        "attach_leaf": ATTACH_LEAF,
        "user": "developer",
        "home": "/home/developer",
        "workdir": "/home/developer/workspace",
        "kind": "tty",
        "command": "exec bash --login",
    }
    values.update(overrides)
    return list(values.values())


def entry_request(**overrides):
    return sandy._parse_entry_request(entry_args(**overrides))


def entry_confinement(mask=0b101010):
    return sandy.LeaderConfinement(
        pidfd=10,
        namespace_fds=(21, 22, 23, 24, 25, 26, 27),
        seccomp_filters=(b"oldest00", b"newest00"),
        capability_bounding_set=mask,
        attach_kill_fd=30,
        oom_score_adj=-500,
    )


class EntryHelperTests(unittest.TestCase):
    """The internal entry helper mode.

    Tests mock fork, setns, prctl, seccomp, the id changes, execve, _exit,
    signal state, and the Leader extraction. No test enters a namespace. E2E
    tests in a VM must prove the real confinement.
    """

    def test_parse_entry_request_accepts_user_and_root(self):
        self.assertEqual(
            entry_request(),
            sandy.EntryRequest(
                machine="ai-dev",
                leader_pid=4242,
                parent_pid=4100,
                attach_leaf=ATTACH_LEAF,
                user="developer",
                home="/home/developer",
                workdir="/home/developer/workspace",
                kind="tty",
                command="exec bash --login",
            ),
        )
        root = entry_request(
            user="root",
            home="/root",
            workdir="/",
            kind="sh",
            command="/bin/sh /init.sh",
        )
        self.assertEqual((root.user, root.home, root.kind), ("root", "/root", "sh"))

    def test_parse_entry_request_rejects_invalid_fields(self):
        cases = {
            "machine": ("-p", "Ai", ""),
            "leader": ("1", "01", "abc", "4194304"),
            "user": ("Root", "-x", ""),
            "home": ("/home/other", "/root", ""),
            "workdir": ("", "relative", "/a/../b", "/a/", "//a", "/a/./b", "/a\nb"),
            "kind": ("bash", "", "TTY"),
            "command": ("", "x" * (sandy.ENTRY_COMMAND_MAX_BYTES + 1)),
        }
        for field, values in cases.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    with self.assertRaises(ValueError):
                        sandy._parse_entry_request(entry_args(**{field: value}))
        for extra in ([], entry_args() + ["x"], entry_args()[:-1]):
            with self.subTest(count=len(extra)):
                with self.assertRaises(ValueError):
                    sandy._parse_entry_request(extra)

    def test_command_limit_counts_bytes(self):
        command = "\u00e9" * (sandy.ENTRY_COMMAND_MAX_BYTES // 2)
        self.assertEqual(entry_request(command=command).command, command)
        with self.assertRaises(ValueError):
            entry_request(command=command + "x")

    def test_entry_helper_argv_exact(self):
        with tempfile.TemporaryFile() as script:
            fd = script.fileno()
            with patch.object(sandy.sys, "executable", "/usr/bin/python3"):
                argv = sandy._entry_helper_argv(fd, entry_request())
        self.assertEqual(
            argv,
            ["/usr/bin/python3", "-I", f"/proc/self/fd/{fd}", "__sandy-entry-helper"]
            + entry_args(),
        )
        self.assertEqual(sandy._parse_entry_request(argv[4:]), entry_request())

    def test_entry_helper_argv_rejects_unparsable_request(self):
        bad = entry_request()._replace(workdir="relative")
        with tempfile.TemporaryFile() as script:
            with self.assertRaises(ValueError):
                sandy._entry_helper_argv(script.fileno(), bad)

    def test_entry_helper_argv_rejects_request_that_changes_in_parsing(self):
        # Text is not the int that parsing returns.
        changed = entry_request()._replace(leader_pid="4242")
        with tempfile.TemporaryFile() as script:
            with self.assertRaises(ValueError):
                sandy._entry_helper_argv(script.fileno(), changed)

    def test_resolve_container_identity_matches_nspawn(self):
        passwd = (
            "root:x:0:0:root:/root:/bin/bash\n"
            "# comment\n"
            "\n"
            "developer:x:1000:1000:AI User,,,:/home/developer:/bin/bash\n"
        )
        group = (
            "root:x:0:\n"
            "developer:x:1000:developer\n"
            "aitwo:x:2002:root,developer\n"
            "aione:x:2001:developer,developer\n"
            "aithree:x:2003:other,developers\n"
            "empty:x:2004:\n"
            "aitwo-alias:x:2002:developer\n"
        )
        # The measured nspawn result: file order, no duplicates, the primary
        # gid only when listed, and no supplementary groups for root.
        self.assertEqual(
            sandy._resolve_container_identity("developer", passwd, group),
            (1000, 1000, (1000, 2002, 2001)),
        )
        self.assertEqual(
            sandy._resolve_container_identity("root", passwd, group), (0, 0, ())
        )
        self.assertEqual(
            sandy._resolve_container_identity(
                "developer", passwd, "developer:x:1000:\n"
            ),
            (1000, 1000, ()),
        )

    def test_resolve_container_identity_fails_closed(self):
        passwd = "root:x:0:0::/root:/bin/sh\ndeveloper:x:1000:1000::/home/developer:/bin/sh\n"
        cases = (
            ("developer", "root:x:0:0::/root:/bin/sh\n", "", "missing user"),
            ("developer", passwd + "developer:x:1001:1001::/h:/s\n", "", "twice"),
            ("developer", passwd + "broken:x:1\n", "", "short passwd line"),
            ("developer", passwd.replace(":1000:1000:", ":01000:1000:"), "", "uid"),
            ("developer", passwd.replace(":1000:1000:", ":1000:65535:"), "", "gid"),
            ("developer", passwd.replace(":1000:1000:", ":0:1000:"), "", "uid 0"),
            ("root", passwd.replace("root:x:0:0", "root:x:5:0"), "", "root uid"),
            ("developer", passwd, "g:x:2001\n", "short group line"),
            ("developer", passwd, "g:x:x:developer\n", "group gid"),
            ("root", passwd, "g:x:x:root\n", "group gid for root"),
            (
                "developer",
                passwd,
                "".join(f"g{i}:x:{2000 + i}:developer\n" for i in range(65)),
                "too many groups",
            ),
        )
        for user, passwd_text, group_text, label in cases:
            with self.subTest(label=label):
                with self.assertRaises(ValueError):
                    sandy._resolve_container_identity(user, passwd_text, group_text)

    def test_read_container_account_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "group"
            path.write_bytes(b"g:x:1:\xff\n")
            self.assertEqual(
                sandy._read_container_account_file(str(path)), "g:x:1:\udcff\n"
            )
            link = Path(temp_dir) / "link"
            link.symlink_to(path)
            self.assertEqual(
                sandy._read_container_account_file(str(link)), "g:x:1:\udcff\n"
            )
            path.write_bytes(b"x" * (sandy.CONTAINER_ACCOUNT_FILE_MAX_BYTES + 1))
            with self.assertRaises(ValueError):
                sandy._read_container_account_file(str(path))
            fifo = Path(temp_dir) / "fifo"
            os.mkfifo(fifo)
            # O_NONBLOCK: the open does not wait for a writer.
            with self.assertRaises(ValueError):
                sandy._read_container_account_file(str(fifo))
            with self.assertRaises(ValueError):
                sandy._read_container_account_file(temp_dir)
            with self.assertRaises(FileNotFoundError):
                sandy._read_container_account_file(str(Path(temp_dir) / "none"))

    def test_entry_exec_argv(self):
        self.assertEqual(
            sandy._entry_exec_argv(entry_request(command="echo 'a b'; id")),
            ["/bin/bash", "-c", "script -qec 'echo '\"'\"'a b'\"'\"'; id' /dev/null"],
        )
        self.assertEqual(
            sandy._entry_exec_argv(entry_request(kind="sh", command="echo $x")),
            ["/bin/sh", "-c", "echo $x"],
        )

    def test_open_fds_lists_only_open_descriptors(self):
        read_fd, write_fd = os.pipe()
        os.close(write_fd)
        try:
            fds = sandy._open_fds()
        finally:
            os.close(read_fd)
        self.assertIn(read_fd, fds)
        self.assertNotIn(write_fd, fds)
        self.assertTrue({0, 1, 2} <= fds)

    def verify_fds(self, path, fds, mode=stat.S_IFREG | 0o755, uid=0):
        script_stat = SimpleNamespace(st_mode=mode, st_uid=uid)
        with patch.object(sandy, "_open_fds", return_value=fds), patch.object(
            sandy.os, "fstat", return_value=script_stat
        ):
            return sandy._verify_entry_helper_fds(path)

    def test_verify_entry_helper_fds_accepts_pinned_script(self):
        self.assertEqual(self.verify_fds("/proc/self/fd/3", {0, 1, 2, 3}), 3)
        self.assertEqual(self.verify_fds("/proc/self/fd/12", {0, 1, 2, 12}), 12)

    def test_verify_entry_helper_fds_rejects_direct_calls(self):
        for path, fds in (
            ("/usr/local/lib/sandy/sandy", {0, 1, 2}),
            ("sandy", {0, 1, 2}),
            ("/proc/self/fd/2", {0, 1, 2}),
            ("/proc/self/fd/03", {0, 1, 2, 3}),
            ("/proc/1/fd/3", {0, 1, 2, 3}),
            ("/proc/self/fd/3", {0, 1, 2}),
            ("/proc/self/fd/3", {1, 2, 3}),
            ("/proc/self/fd/3", {0, 1, 2, 3, 4}),
        ):
            with self.subTest(path=path, fds=fds):
                with self.assertRaises(PermissionError):
                    self.verify_fds(path, fds)

    def test_verify_entry_helper_fds_accepts_owner_only_writable_script(self):
        # The parent already runs this file as root; any owner is accepted.
        for uid in (0, 1000):
            with self.subTest(uid=uid):
                self.assertEqual(
                    self.verify_fds(
                        "/proc/self/fd/3", {0, 1, 2, 3}, stat.S_IFREG | 0o755, uid
                    ),
                    3,
                )

    def test_verify_entry_helper_fds_rejects_unsafe_script(self):
        for mode, uid in (
            (stat.S_IFREG | 0o775, 0),
            (stat.S_IFREG | 0o757, 0),
            (stat.S_IFREG | 0o775, 1000),
            (stat.S_IFIFO | 0o755, 0),
        ):
            with self.subTest(mode=oct(mode), uid=uid):
                with self.assertRaises(PermissionError):
                    self.verify_fds("/proc/self/fd/3", {0, 1, 2, 3}, mode, uid)

    def test_read_cap_last_cap(self):
        for data, expected in ((b"40\n", 40), (b"0\n", 0), (b"63\n", 63)):
            with self.subTest(data=data):
                with patch.object(
                    sandy.os, "open", return_value=99
                ) as opened, patch.object(
                    sandy.os, "read", return_value=data
                ), patch.object(
                    sandy.os, "close"
                ) as close:
                    self.assertEqual(sandy._read_cap_last_cap(), expected)
                opened.assert_called_once_with(
                    "/proc/sys/kernel/cap_last_cap", sandy.READ_FILE_OPEN_FLAGS
                )
                close.assert_called_once_with(99)
        for data in (b"40", b"64\n", b"x\n", b"123\n", b"4 0\n", b""):
            with self.subTest(data=data):
                with patch.object(sandy.os, "open", return_value=99), patch.object(
                    sandy.os, "read", return_value=data
                ), patch.object(sandy.os, "close"):
                    with self.assertRaises(ValueError):
                        sandy._read_cap_last_cap()

    def test_read_own_child_pids_lists_running_and_unreaped_children(self):
        # No mocks: the helper finds the session in this list, and a session
        # that exits at once must still be listed until it is reaped.
        child = subprocess.Popen(
            [sys.executable, "-c", "import sys; sys.stdin.read()"],
            stdin=subprocess.PIPE,
        )
        try:
            self.assertIn(child.pid, sandy._read_own_child_pids())
            assert child.stdin is not None
            child.stdin.close()
            os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOWAIT)
            self.assertIn(child.pid, sandy._read_own_child_pids())
        finally:
            child.wait(timeout=30)
        self.assertNotIn(child.pid, sandy._read_own_child_pids())

    def test_read_own_child_pids_opens_this_process_and_closes_it(self):
        with patch.object(sandy.os, "getpid", return_value=55), patch.object(
            sandy, "_open_process_dir", return_value=99
        ) as open_dir, patch.object(
            sandy, "_read_child_pids", return_value=(88,)
        ) as read, patch.object(
            sandy.os, "close"
        ) as close:
            self.assertEqual(sandy._read_own_child_pids(), (88,))
        open_dir.assert_called_once_with(55)
        read.assert_called_once_with(99, 55)
        close.assert_called_once_with(99)
        with patch.object(sandy.os, "getpid", return_value=55), patch.object(
            sandy, "_open_process_dir", return_value=99
        ), patch.object(
            sandy, "_read_child_pids", side_effect=ValueError("bad")
        ), patch.object(
            sandy.os, "close"
        ) as close:
            with self.assertRaises(ValueError):
                sandy._read_own_child_pids()
        close.assert_called_once_with(99)

    def write_children(self, root: str, pid: int, data: bytes) -> None:
        task = Path(root) / "task" / str(pid)
        task.mkdir(parents=True, exist_ok=True)
        (task / "children").write_bytes(data)

    def test_read_child_pids_parses_strictly(self):
        # A temporary directory stands in for the host /proc/<pid>.
        cases = ((b"", ()), (b"88 ", (88,)), (b"88 89 ", (88, 89)))
        with tempfile.TemporaryDirectory() as temp_dir:
            proc_fd = os.open(temp_dir, sandy.DIRECTORY_OPEN_FLAGS)
            try:
                for data, expected in cases:
                    with self.subTest(data=data):
                        self.write_children(temp_dir, 55, data)
                        self.assertEqual(sandy._read_child_pids(proc_fd, 55), expected)
                for data in (b"88", b"x ", b"088 ", b"88  ", b"-1 ", b"4194304 "):
                    with self.subTest(data=data):
                        self.write_children(temp_dir, 55, data)
                        with self.assertRaises(ValueError):
                            sandy._read_child_pids(proc_fd, 55)
                with self.assertRaises(FileNotFoundError):
                    sandy._read_child_pids(proc_fd, 56)
                for pid in (0, True, "55"):
                    with self.subTest(pid=pid):
                        with self.assertRaises(ValueError):
                            sandy._read_child_pids(proc_fd, pid)
            finally:
                os.close(proc_fd)

    def test_read_child_pids_reads_any_size_one_chunk_at_a_time(self):
        # Regression test: the list had a 1 MiB limit, and the Leader's list
        # holds every orphan of its container. Entries of 1 to 6 digits, so
        # that chunk ends split entries; more than 1 MiB in all. The next
        # test has entries of 7 digits.
        pids = range(1, 200000)
        many = b"".join(b"%d " % pid for pid in pids)
        self.assertGreater(len(many), 1048576)
        self.assertNotEqual(len(many) % sandy.PROC_READ_CHUNK_BYTES, 0)
        with tempfile.TemporaryDirectory() as temp_dir:
            proc_fd = os.open(temp_dir, sandy.DIRECTORY_OPEN_FLAGS)
            try:
                self.write_children(temp_dir, 55, many)
                before = sandy._open_fds()
                self.assertEqual(sandy._read_child_pids(proc_fd, 55), tuple(pids))
                self.assertEqual(sandy._open_fds(), before)
            finally:
                os.close(proc_fd)

    def test_iter_child_pids_accepts_seven_digits_that_end_a_chunk(self):
        # Regression test: no test had an entry whose 7 digits end one chunk
        # while its space starts the next. A bound of 6 digits, or ">=" in
        # place of ">", then rejected a valid PID, and the attach failed.
        pids = (1, *range(1000000, 1000510), 100000, 1234567)
        data = b"".join(b"%d " % pid for pid in pids)
        chunk = sandy.PROC_READ_CHUNK_BYTES
        self.assertEqual(data[chunk - 7 : chunk + 1], b"1234567 ")
        with tempfile.TemporaryDirectory() as temp_dir:
            proc_fd = os.open(temp_dir, sandy.DIRECTORY_OPEN_FLAGS)
            try:
                self.write_children(temp_dir, 55, data)
                self.assertEqual(sandy._read_child_pids(proc_fd, 55), pids)
            finally:
                os.close(proc_fd)

    def test_iter_child_pids_bounds_an_entry_and_checks_each_chunk(self):
        chunk = sandy.PROC_READ_CHUNK_BYTES
        cases = (
            # More digits than a PID has, with no space: the memory stays small.
            b"12345678",
            b"1" * (chunk + 1),
            # A bad entry in a later chunk, and a last entry without its space.
            b"88 " * chunk + b"x ",
            b"88 " * chunk + b"89",
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            proc_fd = os.open(temp_dir, sandy.DIRECTORY_OPEN_FLAGS)
            try:
                for data in cases:
                    with self.subTest(size=len(data), end=data[-2:]):
                        self.write_children(temp_dir, 55, data)
                        before = sandy._open_fds()
                        with self.assertRaisesRegex(ValueError, "children list"):
                            sandy._read_child_pids(proc_fd, 55)
                        self.assertEqual(sandy._open_fds(), before)
                # An early stop closes the file.
                self.write_children(temp_dir, 55, b"88 " * chunk)
                before = sandy._open_fds()
                with closing(sandy._iter_child_pids(proc_fd, 55)) as children:
                    self.assertEqual(next(children), 88)
                    self.assertNotEqual(sandy._open_fds(), before)
                self.assertEqual(sandy._open_fds(), before)
            finally:
                os.close(proc_fd)

    def test_entry_error_removes_control_characters(self):
        with captured_output() as (_, stderr):
            sandy._entry_error(OSError("bad\x1b[2Jname"))
        self.assertEqual(
            stderr.getvalue(), "E: Container entry failed: 'bad\\x1b[2Jname'\n"
        )
        broken = MagicMock()
        broken.write.side_effect = OSError("closed")
        with patch.object(sandy.sys, "stderr", broken):
            sandy._entry_error(OSError("x"))

    def test_wait_ending_attach_on_signal_installs_then_unblocks_then_waits(self):
        manager = MagicMock()
        manager.waitpid.return_value = (77, 0x300)
        with patch.object(sandy.signal, "signal", manager.signal), patch.object(
            sandy.signal, "pthread_sigmask", manager.sigmask
        ), patch.object(sandy.os, "waitpid", manager.waitpid), patch.object(
            sandy.os, "kill", manager.kill
        ), patch.object(
            sandy.os, "write", manager.write
        ):
            self.assertEqual(sandy._wait_ending_attach_on_signal(77, 30), 0x300)
            handler = manager.signal.call_args_list[0].args[1]
            handler(sandy.signal.SIGTERM, None)
            handler(sandy.signal.SIGHUP, None)
        self.assertEqual(
            manager.mock_calls,
            [
                call.signal(sandy.signal.SIGHUP, handler),
                call.signal(sandy.signal.SIGTERM, handler),
                call.sigmask(sandy.signal.SIG_UNBLOCK, sandy.ENTRY_END_SIGNALS),
                call.waitpid(77, 0),
                call.write(30, b"1"),
                call.write(30, b"1"),
            ],
        )

    def test_wait_ending_attach_on_signal_forwards_when_kill_fails(self):
        manager = MagicMock()
        manager.waitpid.return_value = (77, 0)
        manager.write.side_effect = OSError(errno.EBADF, "x")
        with patch.object(sandy.signal, "signal", manager.signal), patch.object(
            sandy.signal, "pthread_sigmask", manager.sigmask
        ), patch.object(sandy.os, "waitpid", manager.waitpid), patch.object(
            sandy.os, "kill", manager.kill
        ), patch.object(
            sandy.os, "write", manager.write
        ):
            sandy._wait_ending_attach_on_signal(77, 30)
            handler = manager.signal.call_args_list[0].args[1]
            handler(sandy.signal.SIGTERM, None)
            manager.kill.side_effect = ProcessLookupError()
            handler(sandy.signal.SIGHUP, None)
        self.assertEqual(
            manager.mock_calls[-4:],
            [
                call.write(30, b"1"),
                call.kill(77, sandy.signal.SIGTERM),
                call.write(30, b"1"),
                call.kill(77, sandy.signal.SIGHUP),
            ],
        )

    def test_propagate_wait_status(self):
        self.assertEqual(sandy._propagate_wait_status(3 << 8), 3)
        self.assertEqual(sandy._propagate_wait_status(0), 0)
        # A stopped status is not an exit.
        self.assertEqual(sandy._propagate_wait_status(0x137F), 125)
        manager = MagicMock()
        with patch.object(sandy.signal, "signal", manager.signal), patch.object(
            sandy.signal, "pthread_sigmask", manager.sigmask
        ), patch.object(sandy.os, "kill", manager.kill), patch.object(
            sandy.os, "getpid", return_value=55
        ):
            self.assertEqual(sandy._propagate_wait_status(sandy.signal.SIGTERM), 143)
        self.assertEqual(
            manager.mock_calls,
            [
                call.signal(sandy.signal.SIGTERM, sandy.signal.SIG_DFL),
                call.sigmask(sandy.signal.SIG_UNBLOCK, {sandy.signal.SIGTERM}),
                call.kill(55, sandy.signal.SIGTERM),
            ],
        )

    def test_propagate_wait_status_ends_real_process_with_signal(self):
        # No mocks: a child interpreter must die by the same signal.
        code = (
            "import importlib.machinery, importlib.util, sys\n"
            "loader = importlib.machinery.SourceFileLoader('s', sys.argv[1])\n"
            "spec = importlib.util.spec_from_loader('s', loader)\n"
            "module = importlib.util.module_from_spec(spec)\n"
            "loader.exec_module(module)\n"
            "module._propagate_wait_status(int(sys.argv[2]))\n"
        )
        for signum in (sandy.signal.SIGKILL, sandy.signal.SIGTERM, sandy.signal.SIGHUP):
            with self.subTest(signum=signum):
                # Pass the number: on Python 3.10, str() of a Signals member
                # is its name, such as "Signals.SIGHUP".
                result = subprocess.run(
                    [sys.executable, "-c", code, str(SANDY_PATH), str(int(signum))],
                    capture_output=True,
                    timeout=30,
                )
                self.assertEqual(result.returncode, -signum, result.stderr)

    def test_propagate_wait_status_passes_on_sigkill(self):
        # Regression: signal.signal(SIGKILL, ...) raises OSError(EINVAL), so
        # a SIGKILL exit (for example, a container stop) became exit 125.
        manager = MagicMock()
        with patch.object(sandy.signal, "signal", manager.signal), patch.object(
            sandy.signal, "pthread_sigmask", manager.sigmask
        ), patch.object(sandy.os, "kill", manager.kill), patch.object(
            sandy.os, "getpid", return_value=55
        ):
            self.assertEqual(sandy._propagate_wait_status(sandy.signal.SIGKILL), 137)
        self.assertEqual(manager.mock_calls, [call.kill(55, sandy.signal.SIGKILL)])

    @contextmanager
    def confine_mocks(self, mask):
        manager = MagicMock()
        manager.capbset_read.side_effect = lambda cap: bool(mask & (1 << cap))
        manager.exit.side_effect = _ExitCalled
        account_files = {
            "/etc/passwd": "developer:x:1000:1000::/home/developer:/bin/bash\n",
            "/etc/group": "aitwo:x:2002:developer\naione:x:2001:developer\n",
        }
        manager.read_account.side_effect = account_files.__getitem__
        targets = (
            (sandy, "_read_container_account_file", "read_account"),
            (sandy, "_capbset_drop", "capbset_drop"),
            (sandy, "_capbset_read", "capbset_read"),
            (sandy, "_seccomp_set_mode_filter", "seccomp"),
            (sandy.os, "setgroups", "setgroups"),
            (sandy.os, "setresgid", "setresgid"),
            (sandy.os, "setresuid", "setresuid"),
            (sandy.os, "chdir", "chdir"),
            (sandy.signal, "signal", "signal"),
            (sandy.signal, "pthread_sigmask", "sigmask"),
            (sandy.os, "execve", "execve"),
            (sandy.os, "_exit", "exit"),
            (sandy, "_entry_error", "error"),
        )
        with ExitStack() as stack:
            for owner, name, attribute in targets:
                stack.enter_context(
                    patch.object(owner, name, getattr(manager, attribute))
                )
            yield manager

    def test_confine_and_exec_order(self):
        mask = 0b101010
        request = entry_request()
        environment = {"HOME": "/home/developer"}
        with self.confine_mocks(mask) as manager:
            with self.assertRaises(_ExitCalled):
                sandy._confine_and_exec(
                    request, environment, entry_confinement(mask), 5
                )
        expected = [call.capbset_drop(0), call.capbset_drop(2), call.capbset_drop(4)]
        expected += [call.capbset_read(cap) for cap in range(6)]
        expected += [
            call.seccomp(b"oldest00"),
            call.seccomp(b"newest00"),
            # The account files are read only after the filters are in place.
            call.read_account("/etc/passwd"),
            call.read_account("/etc/group"),
            call.setgroups([2002, 2001]),
            call.setresgid(1000, 1000, 1000),
            call.setresuid(1000, 1000, 1000),
            call.chdir("/home/developer/workspace"),
        ]
        expected += [
            call.signal(signum, sandy.signal.SIG_DFL)
            for signum in sandy.ENTRY_RESET_SIGNALS
        ]
        expected += [
            call.sigmask(sandy.signal.SIG_SETMASK, set()),
            call.execve(
                "/bin/bash",
                sandy._entry_exec_argv(request),
                environment,
            ),
            # Only a mocked execve returns.
            call.exit(125),
        ]
        self.assertEqual(manager.mock_calls, expected)
        self.assertEqual(
            set(sandy.ENTRY_RESET_SIGNALS),
            {
                sandy.signal.SIGHUP,
                sandy.signal.SIGINT,
                sandy.signal.SIGQUIT,
                sandy.signal.SIGTERM,
                sandy.signal.SIGPIPE,
                sandy.signal.SIGXFSZ,
            },
        )

    def test_confine_and_exec_fails_closed_at_each_step(self):
        steps = (
            ("capbset_drop", "seccomp"),
            ("seccomp", "read_account"),
            ("read_account", "setgroups"),
            ("setgroups", "setresgid"),
            ("setresgid", "setresuid"),
            ("setresuid", "chdir"),
            ("chdir", "execve"),
        )
        for failing, never in steps:
            with self.subTest(failing=failing):
                with self.confine_mocks(0b101010) as manager:
                    getattr(manager, failing).side_effect = OSError(errno.EPERM, "x")
                    with self.assertRaises(_ExitCalled):
                        sandy._confine_and_exec(
                            entry_request(), {}, entry_confinement(), 5
                        )
                getattr(manager, never).assert_not_called()
                manager.execve.assert_not_called()
                manager.error.assert_called_once()
                manager.exit.assert_called_once_with(125)

    def test_confine_and_exec_rejects_unknown_user(self):
        with self.confine_mocks(0b101010) as manager:
            manager.read_account.side_effect = lambda path: "root:x:0:0::/r:/s\n"
            with self.assertRaises(_ExitCalled):
                sandy._confine_and_exec(entry_request(), {}, entry_confinement(), 5)
        manager.setgroups.assert_not_called()
        manager.execve.assert_not_called()
        self.assertIsInstance(manager.error.call_args.args[0], ValueError)
        manager.exit.assert_called_once_with(125)

    def test_confine_and_exec_rejects_bounding_set_mismatch(self):
        with self.confine_mocks(0b101010) as manager:
            manager.capbset_read.side_effect = None
            manager.capbset_read.return_value = True
            with self.assertRaises(_ExitCalled):
                sandy._confine_and_exec(entry_request(), {}, entry_confinement(), 5)
        manager.seccomp.assert_not_called()
        manager.execve.assert_not_called()
        self.assertIsInstance(manager.error.call_args.args[0], PermissionError)

    @contextmanager
    def middle_mocks(self, fork_result=77):
        manager = MagicMock()
        manager.fork.return_value = fork_result
        manager.exit.side_effect = _ExitCalled
        manager.confine.side_effect = _ExitCalled
        with patch.object(sandy, "_setns", manager.setns), patch.object(
            sandy.os, "setgroups", manager.setgroups
        ), patch.object(sandy.os, "setresgid", manager.setresgid), patch.object(
            sandy.os, "setresuid", manager.setresuid
        ), patch.object(
            sandy.sys, "meta_path", ["finder"]
        ), patch.object(
            sandy.sys, "path", ["/usr/lib/python3"]
        ), patch.object(
            sandy, "_close_leader_confinement", manager.close
        ), patch.object(
            sandy, "_close_fds", manager.close_fds
        ), patch.object(
            sandy.os, "fork", manager.fork
        ), patch.object(
            sandy, "_wait_ending_attach_on_signal", manager.wait
        ), patch.object(
            sandy, "_propagate_wait_status", manager.propagate
        ), patch.object(
            sandy, "_confine_and_exec", manager.confine
        ), patch.object(
            sandy.os, "_exit", manager.exit
        ), patch.object(
            sandy, "_entry_error", manager.error
        ):
            yield manager

    def test_middle_joins_namespaces_in_order_forks_and_exits(self):
        confinement = entry_confinement()
        import_state = []
        with self.middle_mocks() as manager:
            manager.setns.side_effect = lambda fd, nstype: import_state.append(
                (list(sandy.sys.meta_path), list(sandy.sys.path))
            )
            with self.assertRaises(_ExitCalled):
                sandy._enter_namespaces_and_fork(entry_request(), {}, confinement, 5)
        # Imports are blocked before the first setns.
        self.assertEqual(import_state, [([], [])] * 7)
        self.assertEqual(
            manager.mock_calls,
            [
                # Only the helper keeps the attach leaf's cgroup.kill.
                call.close_fds((30,)),
                call.setns(21, sandy.CLONE_NEWCGROUP),
                call.setns(22, sandy.CLONE_NEWIPC),
                call.setns(23, sandy.CLONE_NEWUTS),
                call.setns(24, sandy.CLONE_NEWNET),
                call.setns(25, sandy.CLONE_NEWPID),
                call.setns(26, sandy.CLONE_NEWNS),
                call.setns(27, sandy.CLONE_NEWUSER),
                call.setgroups([]),
                call.setresgid(0, 0, 0),
                call.setresuid(0, 0, 0),
                call.close_fds((10, 21, 22, 23, 24, 25, 26, 27)),
                call.fork(),
                # The middle process does not wait: the session is reparented
                # to the helper.
                call.exit(0),
            ],
        )

    def test_middle_fails_closed_when_setns_fails(self):
        with self.middle_mocks() as manager:
            manager.setns.side_effect = [None, None, OSError(errno.EPERM, "x")]
            with self.assertRaises(_ExitCalled):
                sandy._enter_namespaces_and_fork(
                    entry_request(), {}, entry_confinement(), 5
                )
        manager.fork.assert_not_called()
        manager.error.assert_called_once()
        manager.exit.assert_called_once_with(125)

    def test_middle_fails_closed_when_uid_change_fails(self):
        for failing in ("setgroups", "setresgid", "setresuid"):
            with self.subTest(failing=failing):
                with self.middle_mocks() as manager:
                    getattr(manager, failing).side_effect = OSError(errno.EPERM, "x")
                    with self.assertRaises(_ExitCalled):
                        sandy._enter_namespaces_and_fork(
                            entry_request(), {}, entry_confinement(), 5
                        )
                manager.fork.assert_not_called()
                manager.exit.assert_called_once_with(125)

    def test_middle_child_confines(self):
        request = entry_request()
        confinement = entry_confinement()
        with self.middle_mocks(fork_result=0) as manager:
            with self.assertRaises(_ExitCalled):
                sandy._enter_namespaces_and_fork(request, {"A": "b"}, confinement, 5)
        manager.confine.assert_called_once_with(request, {"A": "b"}, confinement, 5)

    @contextmanager
    def run_mocks(self, fork_result: object = 77, middle_status=0, children=(88,)):
        manager = MagicMock()
        if isinstance(fork_result, BaseException):
            manager.fork.side_effect = fork_result
        else:
            manager.fork.return_value = fork_result
        manager.waitpid.return_value = (77, middle_status)
        if isinstance(children, BaseException):
            manager.children.side_effect = children
        else:
            manager.children.return_value = children
        manager.wait.return_value = 0
        manager.propagate.return_value = 0
        manager.middle.side_effect = _ExitCalled
        with patch.object(
            sandy.signal, "pthread_sigmask", manager.sigmask
        ), patch.object(sandy.signal, "signal", manager.signal), patch.object(
            sandy, "_set_child_subreaper", manager.subreaper
        ), patch.object(
            sandy.os, "fork", manager.fork
        ), patch.object(
            sandy.os, "waitpid", manager.waitpid
        ), patch.object(
            sandy, "_read_own_child_pids", manager.children
        ), patch.object(
            sandy.os, "kill", manager.kill
        ), patch.object(
            sandy, "_close_leader_confinement", manager.close
        ), patch.object(
            sandy, "_close_fds", manager.close_fds
        ), patch.object(
            sandy, "_wait_ending_attach_on_signal", manager.wait
        ), patch.object(
            sandy, "_propagate_wait_status", manager.propagate
        ), patch.object(
            sandy, "_enter_namespaces_and_fork", manager.middle
        ), patch.object(
            sandy, "_entry_error", manager.error
        ):
            yield manager

    def test_run_confined_entry_waits_for_reparented_session(self):
        confinement = entry_confinement()
        with self.run_mocks() as manager:
            self.assertEqual(
                sandy._run_confined_entry(entry_request(), {}, confinement, 5), 0
            )
        self.assertEqual(
            manager.mock_calls,
            [
                call.sigmask(sandy.signal.SIG_BLOCK, sandy.ENTRY_END_SIGNALS),
                call.signal(sandy.signal.SIGINT, sandy.signal.SIG_IGN),
                call.signal(sandy.signal.SIGQUIT, sandy.signal.SIG_IGN),
                call.subreaper(),
                call.fork(),
                # The helper keeps the leaf's cgroup.kill for its handler.
                call.close_fds((10, 21, 22, 23, 24, 25, 26, 27)),
                call.waitpid(77, 0),
                call.children(),
                call.wait(88, 30),
                call.propagate(0),
            ],
        )

    def test_run_confined_entry_passes_on_middle_failure(self):
        for status in (125 << 8, sandy.signal.SIGKILL):
            with self.subTest(status=status):
                with self.run_mocks(middle_status=status) as manager:
                    manager.propagate.return_value = 125
                    self.assertEqual(
                        sandy._run_confined_entry(
                            entry_request(), {}, entry_confinement(), 5
                        ),
                        125,
                    )
                manager.propagate.assert_called_once_with(status)
                manager.children.assert_not_called()
                manager.wait.assert_not_called()

    def test_run_confined_entry_requires_exactly_one_session(self):
        for children in ((), (88, 89)):
            with self.subTest(children=children):
                with self.run_mocks(children=children) as manager:
                    manager.kill.side_effect = [None, ProcessLookupError()][
                        : len(children)
                    ]
                    self.assertEqual(
                        sandy._run_confined_entry(
                            entry_request(), {}, entry_confinement(), 5
                        ),
                        125,
                    )
                self.assertEqual(
                    manager.kill.call_args_list,
                    [call(pid, sandy.signal.SIGKILL) for pid in children],
                )
                manager.wait.assert_not_called()
                manager.error.assert_called_once()

    def test_run_confined_entry_fails_when_children_cannot_be_read(self):
        for error in (FileNotFoundError("children"), ValueError("bad")):
            with self.subTest(error=type(error).__name__):
                with self.run_mocks(children=error) as manager:
                    self.assertEqual(
                        sandy._run_confined_entry(
                            entry_request(), {}, entry_confinement(), 5
                        ),
                        125,
                    )
                manager.wait.assert_not_called()
                manager.error.assert_called_once_with(error)

    def test_run_confined_entry_subreaper_failure_does_not_fork(self):
        confinement = entry_confinement()
        with self.run_mocks() as manager:
            manager.subreaper.side_effect = OSError(errno.EINVAL, "x")
            self.assertEqual(
                sandy._run_confined_entry(entry_request(), {}, confinement, 5), 125
            )
        manager.fork.assert_not_called()
        manager.close.assert_called_once_with(confinement)
        manager.error.assert_called_once()

    def test_run_confined_entry_fork_failure_closes_descriptors(self):
        confinement = entry_confinement()
        with self.run_mocks(fork_result=OSError(errno.EAGAIN, "x")) as manager:
            self.assertEqual(
                sandy._run_confined_entry(entry_request(), {}, confinement, 5), 125
            )
        manager.close.assert_called_once_with(confinement)
        manager.waitpid.assert_not_called()
        manager.error.assert_called_once()

    def test_run_confined_entry_child_runs_middle(self):
        request = entry_request()
        confinement = entry_confinement()
        with self.run_mocks(fork_result=0) as manager:
            with self.assertRaises(_ExitCalled):
                sandy._run_confined_entry(request, {"A": "b"}, confinement, 5)
        manager.middle.assert_called_once_with(request, {"A": "b"}, confinement, 5)
        manager.close.assert_not_called()
        manager.close_fds.assert_not_called()

    @contextmanager
    def helper_mocks(self, **overrides):
        manager = MagicMock()
        manager.geteuid.return_value = overrides.get("euid", 0)
        manager.active_count.return_value = overrides.get("threads", 1)
        manager.verify.return_value = 3
        manager.cap_last.return_value = 40
        manager.extract.return_value = overrides.get(
            "confinement", entry_confinement(0xFDECBFFF)
        )
        manager.run.return_value = 0
        manager.getppid.return_value = overrides.get("ppid", 4100)
        for name in ("verify", "extract", "cap_last", "pdeathsig", "oom"):
            if name in overrides:
                getattr(manager, name).side_effect = overrides[name]
        with patch.object(sandy.os, "geteuid", manager.geteuid), patch.object(
            sandy, "_set_parent_death_signal", manager.pdeathsig
        ), patch.object(sandy.os, "getppid", manager.getppid), patch.object(
            sandy.threading, "active_count", manager.active_count
        ), patch.object(
            sandy, "_verify_entry_helper_fds", manager.verify
        ), patch.object(
            sandy.os, "close", manager.os_close
        ), patch.object(
            sandy, "_read_cap_last_cap", manager.cap_last
        ), patch.object(
            sandy, "_extract_leader_confinement", manager.extract
        ), patch.object(
            sandy, "_close_leader_confinement", manager.close
        ), patch.object(
            sandy, "_write_own_oom_score_adj", manager.oom
        ), patch.object(
            sandy, "_run_confined_entry", manager.run
        ), patch.object(
            sandy, "_entry_error", manager.error
        ), patch.dict(
            sandy.os.environ, {"TERM": "xterm"}
        ):
            yield manager

    def helper_argv(self, **overrides):
        return ["/proc/self/fd/3", "__sandy-entry-helper"] + entry_args(**overrides)

    def test_entry_helper_main_success(self):
        with self.helper_mocks() as manager:
            self.assertEqual(sandy._entry_helper_main(self.helper_argv()), 0)
        manager.verify.assert_called_once_with("/proc/self/fd/3")
        manager.os_close.assert_called_once_with(3)
        manager.pdeathsig.assert_called_once_with(sandy.signal.SIGTERM)
        manager.extract.assert_called_once_with("ai-dev", 4242, ATTACH_LEAF)
        # The parent-death signal is set before the parent check and before
        # the extraction joins the attach leaf.
        names = [entry[0] for entry in manager.mock_calls]
        self.assertLess(names.index("pdeathsig"), names.index("getppid"))
        self.assertLess(names.index("getppid"), names.index("extract"))
        # The session gets the Leader's OOM score adjustment before it starts.
        manager.oom.assert_called_once_with(-500)
        self.assertLess(names.index("extract"), names.index("oom"))
        self.assertLess(names.index("oom"), names.index("run"))
        manager.run.assert_called_once_with(
            entry_request(),
            sandy._container_environment("developer", "/home/developer")
            | {"TERM": "xterm"},
            entry_confinement(0xFDECBFFF),
            40,
        )
        manager.error.assert_not_called()

    def test_entry_helper_main_fails_closed_before_extraction(self):
        cases = (
            ({"euid": 1000}, self.helper_argv()),
            ({"threads": 2}, self.helper_argv()),
            ({}, ["/proc/self/fd/3", "up"] + entry_args()),
            ({}, ["/proc/self/fd/3"]),
            ({"verify": PermissionError("fds")}, self.helper_argv()),
            ({}, self.helper_argv(workdir="relative")),
            ({}, self.helper_argv(parent="0")),
            ({}, self.helper_argv(attach_leaf="attach-../x")),
            ({"pdeathsig": OSError(errno.EINVAL, "x")}, self.helper_argv()),
            # The parent exited before the prctl, so this is a new parent.
            ({"ppid": 1}, self.helper_argv()),
            ({"cap_last": ValueError("bad")}, self.helper_argv()),
        )
        for overrides, argv in cases:
            with self.subTest(overrides=overrides, argv=argv[1:2]):
                with self.helper_mocks(**overrides) as manager:
                    self.assertEqual(sandy._entry_helper_main(argv), 125)
                manager.extract.assert_not_called()
                manager.oom.assert_not_called()
                manager.run.assert_not_called()
                manager.error.assert_called_once()

    def test_entry_helper_main_fails_closed_on_extraction_error(self):
        for error in (
            PermissionError("changed"),
            TimeoutError("busy"),
            ValueError("CapBnd"),
            subprocess.CalledProcessError(1, ["machinectl"]),
            ProcessLookupError("Container is still starting; try again"),
        ):
            with self.subTest(error=type(error).__name__):
                with self.helper_mocks(extract=error) as manager:
                    self.assertEqual(sandy._entry_helper_main(self.helper_argv()), 125)
                manager.oom.assert_not_called()
                manager.run.assert_not_called()
                manager.error.assert_called_once_with(error)

    def test_entry_helper_main_rejects_unknown_capabilities(self):
        confinement = entry_confinement(1 << 41)
        with self.helper_mocks(confinement=confinement) as manager:
            self.assertEqual(sandy._entry_helper_main(self.helper_argv()), 125)
        manager.close.assert_called_once_with(confinement)
        manager.oom.assert_not_called()
        manager.run.assert_not_called()

    def test_entry_helper_main_fails_closed_without_the_oom_value(self):
        # Mocks: as helper_mocks; the write of oom_score_adj fails.
        error = OSError(errno.EACCES, "x")
        with self.helper_mocks(oom=error) as manager:
            self.assertEqual(sandy._entry_helper_main(self.helper_argv()), 125)
        manager.close.assert_called_once_with(entry_confinement(0xFDECBFFF))
        manager.error.assert_called_once_with(error)
        manager.run.assert_not_called()

    def test_main_dispatches_entry_helper_before_argument_parsing(self):
        argv = ["/proc/self/fd/3", "__sandy-entry-helper", "x"]
        with patch.object(sandy.sys, "argv", argv), patch.object(
            sandy, "_entry_helper_main", return_value=7
        ) as helper, patch.object(sandy, "parse_args_custom") as parse:
            with self.assertRaises(SystemExit) as raised:
                sandy.main()
        self.assertEqual(raised.exception.code, 7)
        helper.assert_called_once_with(argv)
        parse.assert_not_called()


@contextmanager
def fake_mount_kernel(failing=None):
    """Mock libc syscall(2) for the mount calls; yield the recorded calls.

    Each record holds the syscall name, its arguments, and what the pointer
    arguments hold at the time of the call. failing maps a syscall name to
    the errno that the call returns.
    """
    failing = failing or {}
    names = {
        number: name for name, number in sandy.ENTRY_SYSCALL_NUMBERS["x86_64"].items()
    }
    results = {"open_tree": 50, "openat2": 60}
    calls = []
    state = {"errno": 0}

    def syscall(number, *args):
        name = names[number]
        record = {"name": name, "args": args}
        if name == "openat2":
            record["path"] = sandy.ctypes.string_at(args[1])
            record["how"] = struct.unpack(
                "<3Q", sandy.ctypes.string_at(args[2], args[3])
            )
        elif name == "open_tree":
            record["path"] = sandy.ctypes.string_at(args[1])
        elif name == "mount_setattr":
            record["path"] = sandy.ctypes.string_at(args[1])
            record["attr"] = struct.unpack(
                "<4Q", sandy.ctypes.string_at(args[3], args[4])
            )
        elif name == "move_mount":
            record["from_path"] = sandy.ctypes.string_at(args[1])
            record["to_path"] = sandy.ctypes.string_at(args[3])
        calls.append(record)
        if name in failing:
            state["errno"] = failing[name]
            return -1
        return results.get(name, 0)

    with ExitStack() as stack:
        stack.enter_context(
            patch.object(
                sandy,
                "_libc",
                return_value=SimpleNamespace(syscall=MagicMock(side_effect=syscall)),
            )
        )
        stack.enter_context(
            patch.object(sandy.platform, "machine", return_value="x86_64")
        )
        stack.enter_context(
            patch.object(sandy.ctypes, "get_errno", side_effect=lambda: state["errno"])
        )
        yield calls


class MountPrimitiveTests(unittest.TestCase):
    """The system calls that mount a host directory in the container.

    Mocks: libc syscall(2), os.fork, os.kill, os.waitpid, and the /proc map
    files of a child. The pipes are real. No test calls the kernel: the E2E
    suite proves the real user namespaces, mounts, and errors.
    """

    @contextmanager
    def fake_pipes(self):
        """Record the pipes that os.pipe makes. A duplicate of each read end
        stays open, so a test can read what a mocked child wrote."""
        pairs = []
        real_pipe = os.pipe

        def pipe():
            read_fd, write_fd = real_pipe()
            pairs.append((read_fd, write_fd, os.dup(read_fd)))
            return read_fd, write_fd

        try:
            with patch.object(sandy.os, "pipe", side_effect=pipe):
                yield pairs
        finally:
            for pair in pairs:
                for fd in pair:
                    try:
                        os.close(fd)
                    except OSError:
                        pass

    @staticmethod
    def is_open(fd):
        try:
            os.fstat(fd)
        except OSError:
            return False
        return True

    def test_struct_layouts_match_the_kernel_headers(self):
        self.assertEqual(sandy.ctypes.sizeof(sandy._MountAttr), 32)
        for offset, field in enumerate(
            ("attr_set", "attr_clr", "propagation", "userns_fd")
        ):
            self.assertEqual(getattr(sandy._MountAttr, field).offset, 8 * offset)
        self.assertEqual(sandy.ctypes.sizeof(sandy._OpenHow), 24)
        for offset, field in enumerate(("flags", "mode", "resolve")):
            self.assertEqual(getattr(sandy._OpenHow, field).offset, 8 * offset)

    def test_mount_constants_match_the_kernel_headers(self):
        self.assertEqual(sandy.AT_FDCWD, -100)
        self.assertEqual(sandy.AT_EMPTY_PATH, 0x1000)
        self.assertEqual(sandy.OPEN_TREE_CLONE, 1)
        self.assertEqual(sandy.OPEN_TREE_CLOEXEC, os.O_CLOEXEC)
        self.assertEqual(sandy.MOVE_MOUNT_F_EMPTY_PATH, 0x4)
        self.assertEqual(sandy.MOVE_MOUNT_T_EMPTY_PATH, 0x40)
        self.assertEqual(sandy.MOUNT_ATTR_NOSUID, 0x2)
        self.assertEqual(sandy.MOUNT_ATTR_NODEV, 0x4)
        self.assertEqual(sandy.MOUNT_ATTR_IDMAP, 0x100000)
        self.assertEqual(sandy.MS_PRIVATE, 1 << 18)
        self.assertEqual(sandy.RESOLVE_NO_MAGICLINKS, 0x02)
        self.assertEqual(sandy.RESOLVE_NO_SYMLINKS, 0x04)
        self.assertEqual(sandy.RESOLVE_IN_ROOT, 0x10)

    def test_openat2_no_links_resolves_with_no_links(self):
        with fake_mount_kernel() as calls:
            fd = sandy._openat2_no_links(
                "/home/developer/workspace", os.O_PATH | os.O_DIRECTORY
            )
        self.assertEqual(fd, 60)
        (record,) = calls
        self.assertEqual(record["name"], "openat2")
        self.assertEqual(record["path"], b"/home/developer/workspace")
        self.assertEqual(
            record["how"],
            (os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC, 0, 0x04 | 0x02),
        )
        # The directory descriptor is ignored for an absolute path; the size
        # is the size of struct open_how.
        self.assertEqual(record["args"][0], sandy.AT_FDCWD)
        self.assertEqual(record["args"][3], 24)

    def test_openat2_no_links_keeps_the_path_below_a_root_descriptor(self):
        with fake_mount_kernel() as calls:
            sandy._openat2_no_links(
                "/home/developer/workspace", os.O_PATH | os.O_DIRECTORY, root_fd=7
            )
        (record,) = calls
        self.assertEqual(record["args"][0], 7)
        self.assertEqual(record["path"], b"/home/developer/workspace")
        self.assertEqual(
            record["how"],
            (os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC, 0, 0x04 | 0x02 | 0x10),
        )

    def test_openat2_no_links_encodes_the_path_like_the_file_system(self):
        with fake_mount_kernel() as calls:
            sandy._openat2_no_links("/tmp/\udcff", os.O_PATH)
        self.assertEqual(calls[0]["path"], b"/tmp/\xff")

    def test_openat2_no_links_rejects_paths_before_the_syscall(self):
        for path in (
            "",
            "relative/path",
            "/a/../b",
            "/a/./b",
            "//a",
            "/a//b",
            "/a\x00b",
            "/a\nb",
            "/a\x1b[31m",
            "/" + "a" * 4100,
            None,
            b"/a",
            7,
        ):
            with self.subTest(path=path):
                with fake_mount_kernel() as calls:
                    with self.assertRaises(ValueError):
                        sandy._openat2_no_links(path, os.O_PATH)
                self.assertEqual(calls, [])

    def test_openat2_no_links_raises_the_errno_of_the_kernel(self):
        # ELOOP is what the kernel gives for a link in any component.
        with fake_mount_kernel(failing={"openat2": errno.ELOOP}):
            with self.assertRaises(OSError) as raised:
                sandy._openat2_no_links("/home/developer", os.O_PATH)
        self.assertEqual(raised.exception.errno, errno.ELOOP)
        self.assertIn("openat2 failed", str(raised.exception))

    def test_idmapped_tree_clones_and_maps_the_directory(self):
        with fake_mount_kernel() as calls:
            tree_fd = sandy._idmapped_tree(11, 12)
        self.assertEqual(tree_fd, 50)
        clone, setattr_ = calls
        self.assertEqual(clone["name"], "open_tree")
        # The descriptor is the tree; the path is empty.
        self.assertEqual(clone["args"][0], 11)
        self.assertEqual(clone["path"], b"")
        self.assertEqual(
            clone["args"][2],
            sandy.OPEN_TREE_CLONE | os.O_CLOEXEC | sandy.AT_EMPTY_PATH,
        )
        self.assertEqual(setattr_["name"], "mount_setattr")
        self.assertEqual(setattr_["args"][0], 50)
        self.assertEqual(setattr_["path"], b"")
        self.assertEqual(setattr_["args"][2], sandy.AT_EMPTY_PATH)
        self.assertEqual(setattr_["args"][4], 32)
        # attr_set, attr_clr, propagation, userns_fd. The mount is private: a
        # peer of the host mount would let mounts cross in both directions.
        self.assertEqual(
            setattr_["attr"],
            (0x100000 | 0x2 | 0x4, 0, 0x40000, 12),
        )

    def test_idmapped_tree_closes_the_tree_when_the_map_fails(self):
        with fake_mount_kernel(failing={"mount_setattr": errno.EINVAL}):
            with patch.object(sandy.os, "close") as close:
                with self.assertRaises(OSError) as raised:
                    sandy._idmapped_tree(11, 12)
        self.assertEqual(raised.exception.errno, errno.EINVAL)
        close.assert_called_once_with(50)

    def test_idmapped_tree_opens_nothing_when_the_clone_fails(self):
        with fake_mount_kernel(failing={"open_tree": errno.ENOSYS}) as calls:
            with patch.object(sandy.os, "close") as close:
                with self.assertRaises(OSError) as raised:
                    sandy._idmapped_tree(11, 12)
        self.assertEqual(raised.exception.errno, errno.ENOSYS)
        self.assertEqual([record["name"] for record in calls], ["open_tree"])
        close.assert_not_called()

    def test_write_id_map_writes_the_whole_line_once(self):
        with patch.object(sandy.os, "open", return_value=77) as open_, patch.object(
            sandy.os, "write", return_value=14
        ) as write, patch.object(sandy.os, "close") as close:
            sandy._write_id_map(4242, "uid_map", "1234 525288 1\n")
        open_.assert_called_once_with("/proc/4242/uid_map", os.O_WRONLY | os.O_CLOEXEC)
        write.assert_called_once_with(77, b"1234 525288 1\n")
        close.assert_called_once_with(77)

    def test_write_id_map_rejects_short_writes_and_bad_input(self):
        with patch.object(sandy.os, "open", return_value=77), patch.object(
            sandy.os, "write", return_value=3
        ), patch.object(sandy.os, "close") as close:
            with self.assertRaises(OSError) as raised:
                sandy._write_id_map(4242, "gid_map", "1234 525288 1\n")
        self.assertEqual(raised.exception.errno, errno.EIO)
        close.assert_called_once_with(77)
        with patch.object(sandy.os, "open") as open_:
            with self.assertRaises(ValueError):
                sandy._write_id_map(4242, "setgroups", "deny\n")
            with self.assertRaises(ValueError):
                sandy._write_id_map(0, "uid_map", "1 1 1\n")
            with self.assertRaises(ValueError):
                sandy._write_id_map(4242, "../uid_map", "1 1 1\n")
        open_.assert_not_called()

    def test_read_helper_message(self):
        read_fd, write_fd = os.pipe()
        self.addCleanup(os.close, read_fd)
        # Nothing yet: the timeout gives b"".
        self.assertEqual(sandy._read_helper_message(read_fd, 0), b"")
        os.write(write_fd, b"ok")
        self.assertEqual(sandy._read_helper_message(read_fd, 1), b"ok")
        # A writer that closes without a message gives EOF, so b"".
        os.close(write_fd)
        self.assertEqual(sandy._read_helper_message(read_fd, 1), b"")

    def test_read_helper_message_reads_at_most_the_limit(self):
        read_fd, write_fd = os.pipe()
        self.addCleanup(os.close, read_fd)
        self.addCleanup(os.close, write_fd)
        os.write(write_fd, b"x" * (sandy.HELPER_MESSAGE_MAX_BYTES + 10))
        self.assertEqual(
            len(sandy._read_helper_message(read_fd, 1)),
            sandy.HELPER_MESSAGE_MAX_BYTES,
        )

    def test_end_helper_child_kills_then_reaps(self):
        manager = MagicMock()
        with patch.object(sandy.os, "kill", manager.kill), patch.object(
            sandy.os, "waitpid", manager.waitpid
        ):
            sandy._end_helper_child(4242)
        self.assertEqual(
            manager.mock_calls,
            [call.kill(4242, sandy.signal.SIGKILL), call.waitpid(4242, 0)],
        )

    def test_end_helper_child_reaps_a_child_that_is_gone(self):
        with patch.object(
            sandy.os, "kill", side_effect=ProcessLookupError
        ), patch.object(sandy.os, "waitpid") as waitpid:
            sandy._end_helper_child(4242)
        waitpid.assert_called_once_with(4242, 0)

    def test_check_helper_result(self):
        sandy._check_helper_result(b"ok")
        with self.assertRaises(sandy._MountError) as raised:
            sandy._check_helper_result(b"move_mount 22")
        self.assertEqual(
            str(raised.exception), "move_mount failed: Invalid argument (errno 22)"
        )
        for message in (
            b"",
            b"ok ",
            b"okay",
            b"move_mount",
            b"move_mount x",
            b"move_mount 123456",
            b"Move_mount 1",
            b"move mount 1",
            b"move_mount 1\n",
            b"\xff\xfe",
        ):
            with self.subTest(message=message):
                with self.assertRaisesRegex(sandy._MountError, "gave no result"):
                    sandy._check_helper_result(message)

    def test_mount_step_error_without_an_errno_is_an_io_error(self):
        self.assertEqual(
            str(sandy._mount_step_error("step", None)),
            f"step failed: {os.strerror(errno.EIO)} (errno {errno.EIO})",
        )

    def test_move_mount_parent_waits_for_the_child_and_ends_it(self):
        manager = MagicMock()
        with self.fake_pipes() as pairs:

            def fork():
                os.write(pairs[0][1], b"ok")
                return 4242

            with patch.object(sandy.os, "fork", side_effect=fork), patch.object(
                sandy.os, "kill", manager.kill
            ), patch.object(sandy.os, "waitpid", manager.waitpid):
                sandy._move_mount_in_namespace(7, 8, "/home/developer/workspace")
            self.assertEqual(
                manager.mock_calls,
                [call.kill(4242, sandy.signal.SIGKILL), call.waitpid(4242, 0)],
            )
            # Both ends of the pipe are closed in the parent.
            self.assertFalse(self.is_open(pairs[0][0]))
            self.assertFalse(self.is_open(pairs[0][1]))

    def test_move_mount_parent_reports_the_failed_step(self):
        for message, text in (
            (b"setns 1", "setns failed: Operation not permitted (errno 1)"),
            (
                b"openat2 40",
                "openat2 failed: Too many levels of symbolic links (errno 40)",
            ),
            (b"move_mount 22", "move_mount failed: Invalid argument (errno 22)"),
            (b"", "helper process gave no result"),
        ):
            with self.subTest(message=message):
                with self.fake_pipes() as pairs:

                    def fork():
                        os.write(pairs[0][1], message)
                        return 4242

                    with patch.object(sandy.os, "fork", side_effect=fork), patch.object(
                        sandy.os, "kill"
                    ) as kill, patch.object(sandy.os, "waitpid") as waitpid:
                        with self.assertRaises(sandy._MountError) as raised:
                            sandy._move_mount_in_namespace(
                                7, 8, "/home/developer/workspace"
                            )
                self.assertEqual(str(raised.exception), text)
                kill.assert_called_once_with(4242, sandy.signal.SIGKILL)
                waitpid.assert_called_once_with(4242, 0)

    def test_move_mount_parent_ends_a_child_that_does_not_answer(self):
        with self.fake_pipes():
            with patch.object(sandy.os, "fork", return_value=4242), patch.object(
                sandy.select, "select", return_value=([], [], [])
            ) as select, patch.object(sandy.os, "kill") as kill, patch.object(
                sandy.os, "waitpid"
            ) as waitpid:
                with self.assertRaisesRegex(sandy._MountError, "gave no result"):
                    sandy._move_mount_in_namespace(7, 8, "/home/developer/workspace")
        self.assertEqual(select.call_args.args[3], sandy.MOUNT_HELPER_TIMEOUT)
        kill.assert_called_once_with(4242, sandy.signal.SIGKILL)
        waitpid.assert_called_once_with(4242, 0)

    def test_move_mount_rejects_the_target_before_the_fork(self):
        for target in ("home/developer", "/a/../b", "/a\x00b", "", "/a\nb"):
            with self.subTest(target=target):
                with patch.object(sandy.os, "fork") as fork, patch.object(
                    sandy.os, "pipe"
                ) as pipe:
                    with self.assertRaises(sandy._MountError):
                        sandy._move_mount_in_namespace(7, 8, target)
                fork.assert_not_called()
                pipe.assert_not_called()

    def test_move_mount_closes_the_pipe_when_the_fork_fails(self):
        with self.fake_pipes() as pairs:
            with patch.object(sandy.os, "fork", side_effect=BlockingIOError):
                with self.assertRaises(BlockingIOError):
                    sandy._move_mount_in_namespace(7, 8, "/home/developer/workspace")
            self.assertFalse(self.is_open(pairs[0][0]))
            self.assertFalse(self.is_open(pairs[0][1]))

    @contextmanager
    def move_mount_child(self, **kernel_failures):
        """Run the child branch of _move_mount_in_namespace in this process."""
        meta_path, path = ["finder"], ["/usr/lib/python3"]
        manager = MagicMock()
        manager.exit.side_effect = lambda code: (_ for _ in ()).throw(_ExitCalled(code))
        with self.fake_pipes() as pairs, fake_mount_kernel(
            failing=kernel_failures
        ) as calls, patch.object(sandy.os, "fork", return_value=0), patch.object(
            sandy.os, "_exit", manager.exit
        ), patch.object(
            sandy.sys, "meta_path", meta_path
        ), patch.object(
            sandy.sys, "path", path
        ):
            yield pairs, calls, manager, meta_path, path

    def run_move_mount_child(self, **kernel_failures):
        """Run the child branch to its os._exit; return what it did.

        The assertions come after the patches end, because the child branch
        empties sys.meta_path and sys.path, and an import would then fail.
        """
        exit_args = None
        with self.move_mount_child(**kernel_failures) as (
            pairs,
            calls,
            manager,
            meta_path,
            path,
        ):
            try:
                sandy._move_mount_in_namespace(7, 8, "/home/developer/workspace")
            except _ExitCalled as exc:
                exit_args = exc.args
            message = os.read(pairs[0][2], 64)
        return exit_args, message, calls, (meta_path, path)

    def test_move_mount_child_joins_the_namespace_then_mounts_on_the_descriptor(self):
        exit_args, message, calls, import_state = self.run_move_mount_child()
        self.assertEqual(exit_args, (0,))
        self.assertEqual(message, b"ok")
        # No import can load code from the container's file system.
        self.assertEqual(import_state, ([], []))
        setns, openat2, move = calls
        self.assertEqual(
            (setns["name"], setns["args"][:2]), ("setns", (7, sandy.CLONE_NEWNS))
        )
        self.assertEqual(openat2["path"], b"/home/developer/workspace")
        self.assertEqual(
            openat2["how"],
            (os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC, 0, 0x04 | 0x02),
        )
        self.assertEqual(move["name"], "move_mount")
        # from: the detached tree (empty path); to: the target descriptor.
        self.assertEqual(move["args"][0], 8)
        self.assertEqual(move["from_path"], b"")
        self.assertEqual(move["args"][2], 60)
        self.assertEqual(move["to_path"], b"")
        self.assertEqual(move["args"][4], 0x4 | 0x40)

    def test_move_mount_child_reports_each_failed_step(self):
        for failing, message, calls_made in (
            ({"setns": errno.EPERM}, b"setns 1", ["setns"]),
            ({"openat2": errno.ELOOP}, b"openat2 40", ["setns", "openat2"]),
            (
                {"move_mount": errno.EINVAL},
                b"move_mount 22",
                ["setns", "openat2", "move_mount"],
            ),
        ):
            with self.subTest(failing=failing):
                exit_args, written, calls, _ = self.run_move_mount_child(**failing)
                self.assertEqual(exit_args, (1,))
                self.assertEqual(written, message)
                self.assertEqual([record["name"] for record in calls], calls_made)

    @contextmanager
    def userns_parent(self, message=b"ok", maps_fail=None):
        """Run the parent branch of _new_idmap_userns with a mocked child."""
        manager = MagicMock()
        real_open = os.open
        with self.fake_pipes() as pairs:

            def fork():
                os.write(pairs[0][1], message)
                return 4242

            def open_(path, *args, **kwargs):
                if path == "/proc/4242/ns/user":
                    manager.open_ns(path, *args)
                    return 77
                return real_open(path, *args, **kwargs)

            manager.write_map.side_effect = maps_fail
            with patch.object(sandy.os, "fork", side_effect=fork), patch.object(
                sandy.os, "open", side_effect=open_
            ), patch.object(sandy, "_write_id_map", manager.write_map), patch.object(
                sandy.os, "kill", manager.kill
            ), patch.object(
                sandy.os, "waitpid", manager.waitpid
            ):
                yield pairs, manager

    def test_new_idmap_userns_writes_both_maps_then_opens_the_namespace(self):
        with self.userns_parent() as (pairs, manager):
            fd = sandy._new_idmap_userns("1234 525288 1\n", "100 525288 1\n")
            self.assertEqual(fd, 77)
            self.assertEqual(
                manager.mock_calls,
                [
                    call.write_map(4242, "uid_map", "1234 525288 1\n"),
                    call.write_map(4242, "gid_map", "100 525288 1\n"),
                    call.open_ns("/proc/4242/ns/user", os.O_RDONLY | os.O_CLOEXEC),
                    call.kill(4242, sandy.signal.SIGKILL),
                    call.waitpid(4242, 0),
                ],
            )
            # The parent closes every pipe end (the child holds its own).
            for pair in pairs:
                self.assertFalse(self.is_open(pair[0]))
                self.assertFalse(self.is_open(pair[1]))

    def test_new_idmap_userns_reports_a_failed_unshare(self):
        for message, text in (
            (b"unshare 1", "unshare failed: Operation not permitted (errno 1)"),
            (b"unshare 28", "unshare failed: No space left on device (errno 28)"),
            (b"", "helper process gave no result"),
        ):
            with self.subTest(message=message):
                with self.userns_parent(message) as (pairs, manager):
                    with self.assertRaises(sandy._MountError) as raised:
                        sandy._new_idmap_userns("1 1 1\n", "1 1 1\n")
                self.assertEqual(str(raised.exception), text)
                # No map is written, and the child is still ended and reaped.
                self.assertEqual(
                    manager.mock_calls,
                    [call.kill(4242, sandy.signal.SIGKILL), call.waitpid(4242, 0)],
                )

    def test_new_idmap_userns_reports_a_failed_map_write(self):
        for failing_map, text in (
            ("uid_map", "write of uid_map failed: Invalid argument (errno 22)"),
            ("gid_map", "write of gid_map failed: Operation not permitted (errno 1)"),
        ):
            error = OSError(
                errno.EINVAL if failing_map == "uid_map" else errno.EPERM, "x"
            )
            maps_fail = [error] if failing_map == "uid_map" else [None, error]
            with self.subTest(failing_map=failing_map):
                with self.userns_parent(maps_fail=maps_fail) as (pairs, manager):
                    with self.assertRaises(sandy._MountError) as raised:
                        sandy._new_idmap_userns("1 1 1\n", "1 1 1\n")
                self.assertEqual(str(raised.exception), text)
                manager.open_ns.assert_not_called()
                manager.kill.assert_called_once_with(4242, sandy.signal.SIGKILL)
                manager.waitpid.assert_called_once_with(4242, 0)

    def test_new_idmap_userns_reports_a_failed_namespace_open(self):
        with self.userns_parent() as (pairs, manager):
            with patch.object(
                sandy.os,
                "open",
                side_effect=OSError(errno.ENOENT, "gone"),
            ):
                with self.assertRaisesRegex(
                    sandy._MountError,
                    r"open of ns/user failed: No such file or directory \(errno 2\)",
                ):
                    sandy._new_idmap_userns("1 1 1\n", "1 1 1\n")
            manager.kill.assert_called_once_with(4242, sandy.signal.SIGKILL)

    def test_new_idmap_userns_closes_the_pipes_when_the_fork_fails(self):
        with self.fake_pipes() as pairs:
            with patch.object(sandy.os, "fork", side_effect=BlockingIOError):
                with self.assertRaises(BlockingIOError):
                    sandy._new_idmap_userns("1 1 1\n", "1 1 1\n")
            for pair in pairs:
                self.assertFalse(self.is_open(pair[0]))
                self.assertFalse(self.is_open(pair[1]))

    @contextmanager
    def userns_child(self, **kernel_failures):
        manager = MagicMock()
        manager.exit.side_effect = lambda code: (_ for _ in ()).throw(_ExitCalled(code))
        with self.fake_pipes() as pairs, fake_mount_kernel(
            failing=kernel_failures
        ) as calls, patch.object(sandy.os, "fork", return_value=0), patch.object(
            sandy.os, "_exit", manager.exit
        ):
            yield pairs, calls, manager

    def run_userns_child(self, **kernel_failures):
        exit_args = None
        with self.userns_child(**kernel_failures) as (pairs, calls, manager):
            try:
                sandy._new_idmap_userns("1 1 1\n", "1 1 1\n")
            except _ExitCalled as exc:
                exit_args = exc.args
            message = os.read(pairs[0][2], 64)
        return exit_args, message, calls

    def test_new_idmap_userns_child_unshares_and_waits_to_be_ended(self):
        # The child reports success, then waits on the pipe. Here every copy
        # of the write end is closed, so the wait ends at once.
        exit_args, message, calls = self.run_userns_child()
        self.assertEqual(exit_args, (0,))
        self.assertEqual(message, b"ok")
        (record,) = calls
        self.assertEqual(record["name"], "unshare")
        self.assertEqual(record["args"][0], sandy.CLONE_NEWUSER)

    def test_new_idmap_userns_child_reports_a_failed_unshare(self):
        exit_args, message, _ = self.run_userns_child(unshare=errno.EPERM)
        self.assertEqual(exit_args, (1,))
        self.assertEqual(message, b"unshare 1")


class MountPlanTests(unittest.TestCase):
    """The checks and steps around the primitives: maps, owners, plans.

    Mocks: the primitives of MountPrimitiveTests, the lifecycle lock, machined,
    and /proc. Real directories give the identity of a directory. The E2E
    suite proves the mounts with the kernel.
    """

    @staticmethod
    def status(uid=1234, gid=1234, dev=64768, ino=555):
        return SimpleNamespace(st_uid=uid, st_gid=gid, st_dev=dev, st_ino=ino)

    def test_parse_id_map_shift(self):
        # The format of /proc/<pid>/uid_map: three right-aligned columns.
        self.assertEqual(
            sandy._parse_id_map_shift("         0     524288      65536\n", "uid_map"),
            524288,
        )
        self.assertEqual(
            sandy._parse_id_map_shift("0 1000000 65536\n", "gid_map"), 1000000
        )
        self.assertEqual(
            sandy._parse_id_map_shift("0 4294901759 65536\n", "uid_map"), 4294901759
        )

    def test_parse_id_map_shift_fails_closed(self):
        for text in (
            "",
            "\n",
            # More than one extent, or an extent that is not the whole range.
            "0 524288 65536\n0 1000 1\n",
            "0 524288 1\n",
            "0 524288 65535\n",
            "0 524288 65537\n",
            # The map of the host itself, and a map that does not start at 0.
            "0 0 4294967295\n",
            "0 0 65536\n",
            "1 524288 65536\n",
            # Malformed.
            "0 00524288 65536\n",
            "0 -1 65536\n",
            "0 524288 65536",
            "0\t524288\t65536\n",
            "0 524288 65536 \n",
            "0 5242880000000 65536\n",
            # The last id of the range would not be a valid id.
            "0 4294901760 65536\n",
            "0 4294967295 65536\n",
        ):
            with self.subTest(text=text):
                with self.assertRaisesRegex(ValueError, "Unexpected uid_map"):
                    sandy._parse_id_map_shift(text, "uid_map")

    def test_id_map_line(self):
        self.assertEqual(sandy._id_map_line(1234, 525288), "1234 525288 1\n")

    def test_as_mount_error_names_the_errno(self):
        self.assertEqual(
            str(sandy._as_mount_error(OSError(errno.ENOENT, "No such file"))),
            "No such file (errno 2)",
        )
        self.assertEqual(
            str(sandy._as_mount_error(OSError("no errno"))),
            f"{os.strerror(errno.EIO)} (errno {errno.EIO})",
        )

    def test_check_mount_owner_refuses_root_as_user_or_group(self):
        sandy._check_mount_owner("workspace", self.status())
        sandy._check_mount_owner("workspace", self.status(uid=1, gid=1))
        for uid, gid in ((0, 1000), (1000, 0), (0, 0)):
            with self.subTest(uid=uid, gid=gid):
                with self.assertRaisesRegex(
                    sandy._MountError, "root owns the shared directory"
                ):
                    sandy._check_mount_owner("shared", self.status(uid=uid, gid=gid))

    def test_open_host_directory_opens_a_handle_without_links(self):
        with patch.object(sandy, "_openat2_no_links", return_value=9) as opened:
            self.assertEqual(sandy._open_host_directory("/srv/work"), 9)
        opened.assert_called_once_with("/srv/work", os.O_PATH | os.O_DIRECTORY)

    def test_open_host_directory_reports_errors_as_mount_errors(self):
        with patch.object(sandy, "_openat2_no_links", side_effect=ValueError("x")):
            with self.assertRaisesRegex(sandy._MountError, "path is not valid"):
                sandy._open_host_directory("relative")
        with patch.object(
            sandy,
            "_openat2_no_links",
            side_effect=OSError(errno.ELOOP, "openat2 failed: loop"),
        ):
            with self.assertRaisesRegex(sandy._MountError, r"loop \(errno 40\)"):
                sandy._open_host_directory("/srv/link")

    def test_probe_makes_the_detached_mount_and_drops_it(self):
        manager = MagicMock()
        manager.tree.return_value = 31
        with patch.object(sandy, "_new_idmap_userns", manager.userns), patch.object(
            sandy, "_idmapped_tree", manager.tree
        ), patch.object(sandy.os, "close", manager.close):
            manager.userns.return_value = 30
            sandy._probe_idmapped_mount(12, self.status(uid=1234, gid=100))
        # The owner maps to itself: the probe needs only a valid map.
        self.assertEqual(
            manager.mock_calls,
            [
                call.userns("1234 1234 1\n", "100 100 1\n"),
                call.tree(12, 30),
                call.close(31),
                call.close(30),
            ],
        )

    def test_probe_reports_an_unsupported_mount_with_a_hint(self):
        with patch.object(sandy, "_new_idmap_userns", return_value=30), patch.object(
            sandy,
            "_idmapped_tree",
            side_effect=OSError(errno.EINVAL, "mount_setattr failed: Invalid argument"),
        ), patch.object(sandy.os, "close") as close:
            with self.assertRaises(sandy._MountError) as raised:
                sandy._probe_idmapped_mount(12, self.status())
        self.assertEqual(
            str(raised.exception),
            "mount_setattr failed: Invalid argument (errno 22). "
            + sandy.IDMAP_MOUNT_HINT,
        )
        close.assert_called_once_with(30)

    def test_probe_closes_nothing_it_did_not_open(self):
        with patch.object(
            sandy, "_new_idmap_userns", side_effect=sandy._MountError("unshare failed")
        ), patch.object(sandy, "_idmapped_tree") as tree, patch.object(
            sandy.os, "close"
        ) as close:
            with self.assertRaisesRegex(sandy._MountError, "unshare failed"):
                sandy._probe_idmapped_mount(12, self.status())
        tree.assert_not_called()
        close.assert_not_called()

    def test_plan_mount_returns_the_identity_of_the_directory(self):
        manager = MagicMock()
        with tempfile.TemporaryDirectory() as temp_dir:
            real = os.stat(temp_dir)
            fd = os.open(temp_dir, os.O_RDONLY | os.O_DIRECTORY)
            manager.open.return_value = fd
            with patch.object(
                sandy, "_open_host_directory", manager.open
            ), patch.object(sandy, "_check_mount_owner", manager.owner), patch.object(
                sandy, "_probe_idmapped_mount", manager.probe
            ):
                plan = sandy._plan_mount(
                    "workspace", temp_dir, "/home/developer/workspace"
                )
            self.assertEqual(
                plan,
                sandy.MountPlan(
                    "workspace",
                    temp_dir,
                    "/home/developer/workspace",
                    real.st_dev,
                    real.st_ino,
                ),
            )
            # The owner check comes before the probe, and the descriptor is
            # closed.
            self.assertEqual(
                [entry[0] for entry in manager.mock_calls],
                ["open", "owner", "probe"],
            )
            self.assertEqual(manager.owner.call_args.args[0], "workspace")
            self.assertEqual(manager.probe.call_args.args[0], fd)
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_plan_mount_refuses_a_root_directory_before_the_probe(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            fd = os.open(temp_dir, os.O_RDONLY | os.O_DIRECTORY)
            with patch.object(
                sandy, "_open_host_directory", return_value=fd
            ), patch.object(
                sandy.os, "fstat", return_value=self.status(uid=0)
            ), patch.object(
                sandy, "_probe_idmapped_mount"
            ) as probe:
                with self.assertRaisesRegex(sandy._MountError, "root owns"):
                    sandy._plan_mount(
                        "workspace", temp_dir, "/home/developer/workspace"
                    )
            probe.assert_not_called()
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_plan_mount_closes_the_descriptor_on_every_failure(self):
        for failure in (
            {"fstat": OSError(errno.EIO, "x")},
            {"probe": sandy._MountError("no")},
        ):
            with self.subTest(failure=failure):
                with tempfile.TemporaryDirectory() as temp_dir:
                    fd = os.open(temp_dir, os.O_RDONLY | os.O_DIRECTORY)
                    real_fstat = os.fstat
                    with patch.object(
                        sandy, "_open_host_directory", return_value=fd
                    ), patch.object(
                        sandy.os,
                        "fstat",
                        side_effect=failure.get("fstat") or real_fstat,
                    ), patch.object(
                        sandy,
                        "_check_mount_owner",
                    ), patch.object(
                        sandy,
                        "_probe_idmapped_mount",
                        side_effect=failure.get("probe"),
                    ):
                        with self.assertRaises((sandy._MountError, OSError)):
                            sandy._plan_mount("workspace", temp_dir, "/home/x/w")
                    with self.assertRaises(OSError):
                        os.fstat(fd)

    @contextmanager
    def mount_one_mocks(self, source_stat=None, **failures):
        manager = MagicMock()
        manager.open.return_value = 20
        manager.userns.return_value = 21
        manager.tree.return_value = 22
        manager.fstat.return_value = source_stat or self.status()
        for name, error in failures.items():
            getattr(manager, name).side_effect = error
        with patch.object(sandy, "_open_host_directory", manager.open), patch.object(
            sandy.os, "fstat", manager.fstat
        ), patch.object(sandy, "_new_idmap_userns", manager.userns), patch.object(
            sandy, "_idmapped_tree", manager.tree
        ), patch.object(
            sandy, "_move_mount_in_namespace", manager.move
        ), patch.object(
            sandy.os, "close", manager.close
        ):
            yield manager

    plan = sandy.MountPlan(
        "workspace", "/srv/work", "/home/developer/workspace", 64768, 555
    )

    def test_mount_one_maps_the_owner_to_the_image_user(self):
        # The host owner 1234:1234 maps to container id 1000 of a container
        # whose ids start at 524288, so the map is 1234 -> 525288.
        with self.mount_one_mocks() as manager:
            sandy._mount_one(self.plan, 524288, 524288, (1000, 1000), 40)
        self.assertEqual(
            manager.mock_calls,
            [
                call.open("/srv/work"),
                call.fstat(20),
                call.userns("1234 525288 1\n", "1234 525288 1\n"),
                call.tree(20, 21),
                call.move(40, 22, "/home/developer/workspace"),
                call.close(22),
                call.close(21),
                call.close(20),
            ],
        )

    def test_mount_one_maps_user_and_group_separately(self):
        # Host owner 1234:100, image user 1001:1002, shifts of 1000000.
        with self.mount_one_mocks(
            source_stat=self.status(uid=1234, gid=100)
        ) as manager:
            sandy._mount_one(self.plan, 1000000, 2000000, (1001, 1002), 40)
        manager.userns.assert_called_once_with("1234 1001001 1\n", "100 2001002 1\n")

    def test_mount_one_refuses_a_directory_that_changed(self):
        for source_stat in (
            self.status(dev=1),
            self.status(ino=1),
        ):
            with self.subTest(source_stat=source_stat):
                with self.mount_one_mocks(source_stat=source_stat) as manager:
                    with self.assertRaisesRegex(
                        sandy._MountError,
                        "the workspace directory changed after the check",
                    ):
                        sandy._mount_one(self.plan, 524288, 524288, (1000, 1000), 40)
                manager.userns.assert_not_called()
                manager.move.assert_not_called()
                manager.close.assert_called_once_with(20)

    def test_mount_one_refuses_a_directory_that_root_owns_now(self):
        # The owner can change between the plan and the mount.
        for owner in (self.status(uid=0), self.status(gid=0)):
            with self.subTest(owner=owner):
                with self.mount_one_mocks(source_stat=owner) as manager:
                    with self.assertRaisesRegex(
                        sandy._MountError, "root owns the workspace directory"
                    ):
                        sandy._mount_one(self.plan, 524288, 524288, (1000, 1000), 40)
                manager.userns.assert_not_called()
                manager.move.assert_not_called()
                manager.close.assert_called_once_with(20)

    def test_mount_one_closes_every_descriptor_on_failure(self):
        for failure, closed in (
            ({"userns": sandy._MountError("no userns")}, [20]),
            ({"tree": OSError(errno.EINVAL, "mount_setattr failed: x")}, [21, 20]),
            ({"move": sandy._MountError("no move")}, [22, 21, 20]),
        ):
            with self.subTest(failure=failure):
                with self.mount_one_mocks(**failure) as manager:
                    with self.assertRaises(sandy._MountError):
                        sandy._mount_one(self.plan, 524288, 524288, (1000, 1000), 40)
                self.assertEqual(
                    manager.close.call_args_list, [call(fd) for fd in closed]
                )

    def test_mount_one_turns_os_errors_into_mount_errors(self):
        for failure in (
            {"open": OSError(errno.ELOOP, "openat2 failed: x")},
            {"fstat": OSError(errno.EIO, "x")},
        ):
            with self.subTest(failure=failure):
                with self.mount_one_mocks(**failure):
                    with self.assertRaises(sandy._MountError):
                        sandy._mount_one(self.plan, 524288, 524288, (1000, 1000), 40)

    def test_mount_one_rejects_an_id_beyond_the_valid_range(self):
        for shifts, ids in (
            ((0xFFFFFFFE, 524288), (1, 1000)),
            ((524288, 0xFFFFFFFE), (1000, 1)),
        ):
            with self.subTest(shifts=shifts):
                with self.mount_one_mocks() as manager:
                    with self.assertRaisesRegex(sandy._MountError, "Invalid (uid|gid)"):
                        sandy._mount_one(self.plan, *shifts, ids, 40)
                manager.userns.assert_not_called()
                manager.close.assert_called_once_with(20)


class MountContainerDirsTests(unittest.TestCase):
    """_mount_container_dirs finds the container as the entry helper does.

    Mocks: the lifecycle lock, machined, the /proc reads, the descriptors,
    and the mounts themselves. The E2E suite proves the mounts on a real
    container.
    """

    PLANS = (
        sandy.MountPlan("workspace", "/srv/work", "/home/developer/workspace", 1, 2),
        sandy.MountPlan("shared", "/srv/share", "/home/developer/shared", 1, 3),
    )
    ID_MAP = b"         0     524288      65536\n"

    @contextmanager
    def mocks(self, **overrides):
        """Mock every host boundary; overrides set a side effect by name."""
        manager = MagicMock()
        manager.query.return_value = 42
        manager.pidfd_open.return_value = 10
        manager.proc_dir.return_value = 20
        manager.cgroup.return_value = "/sandy.slice/sandy-ai-dev.scope/payload"
        manager.payload.return_value = (77, sandy.ProcessConfinement(2, 0))
        manager.read_file.return_value = self.ID_MAP
        manager.alive.return_value = True
        manager.own_scope.return_value = True
        manager.unit.return_value = 31

        @contextmanager
        def lock():
            manager.lock_enter()
            try:
                yield
            finally:
                manager.lock_exit()

        def open_fd(path, flags, dir_fd=None):
            manager.open(path, flags, dir_fd=dir_fd)
            if "open" in overrides:
                raise overrides["open"]
            return 21

        for name, error in overrides.items():
            if name != "open":
                getattr(manager, name).side_effect = error
        with ExitStack() as stack:
            stack.enter_context(patch.object(sandy, "_lifecycle_lock", lock))
            stack.enter_context(
                patch.object(sandy, "_query_machine_leader", manager.query)
            )
            stack.enter_context(
                patch.object(sandy.os, "pidfd_open", manager.pidfd_open, create=True)
            )
            stack.enter_context(
                patch.object(sandy, "_open_process_dir", manager.proc_dir)
            )
            stack.enter_context(
                patch.object(sandy, "_read_process_cgroup", manager.cgroup)
            )
            stack.enter_context(patch.object(sandy, "_find_payload", manager.payload))
            stack.enter_context(
                patch.object(sandy, "_read_proc_file", manager.read_file)
            )
            stack.enter_context(patch.object(sandy.os, "open", side_effect=open_fd))
            stack.enter_context(patch.object(sandy.os, "close", manager.close))
            stack.enter_context(
                patch.object(sandy, "_pidfd_process_alive", manager.alive)
            )
            stack.enter_context(
                patch.object(sandy, "_supervisor_in_scope", manager.own_scope)
            )
            stack.enter_context(patch.object(sandy, "_mount_one", manager.mount))
            stack.enter_context(
                patch.object(sandy, "_open_supervisor_cgroup", manager.unit)
            )
            stack.enter_context(
                patch.object(sandy, "_remove_scope_marker", manager.remove_marker)
            )
            yield manager

    def mount(self, plans=None):
        sandy._mount_container_dirs(
            "ai-dev", plans or self.PLANS, (1000, 1000), PINNED_SUPERVISOR
        )

    def test_mounts_each_directory_then_removes_the_pending_marker(self):
        with self.mocks() as manager:
            self.mount()
        self.assertEqual(
            manager.mock_calls,
            [
                call.lock_enter(),
                call.query("ai-dev"),
                call.pidfd_open(42),
                # The pidfd pins one process; confirm that it is the Leader.
                call.query("ai-dev"),
                call.proc_dir(42),
                call.cgroup(20),
                call.payload(20, 42),
                call.read_file(20, "uid_map", sandy.ID_MAP_MAX_BYTES),
                call.read_file(20, "gid_map", sandy.ID_MAP_MAX_BYTES),
                call.open("ns/mnt", os.O_RDONLY | os.O_CLOEXEC, dir_fd=20),
                call.close(20),
                call.alive(10),
                # The scope also holds the supervisor of this up.
                call.own_scope("ai-dev", PINNED_SUPERVISOR),
                call.mount(self.PLANS[0], 524288, 524288, (1000, 1000), 21),
                call.mount(self.PLANS[1], 524288, 524288, (1000, 1000), 21),
                call.unit("ai-dev"),
                call.remove_marker(31, sandy.MOUNTS_PENDING_CGROUP),
                call.close(31),
                call.close(10),
                call.close(21),
                call.lock_exit(),
            ],
        )

    def test_uses_the_shifts_of_the_two_maps(self):
        maps = {
            "uid_map": b"0 1000000 65536\n",
            "gid_map": b"0 2000000 65536\n",
        }
        with self.mocks() as manager:
            manager.read_file.side_effect = lambda fd, name, limit: maps[name]
            self.mount(self.PLANS[:1])
        manager.mount.assert_called_once_with(
            self.PLANS[0], 1000000, 2000000, (1000, 1000), 21
        )

    def test_a_container_that_is_not_registered_yet_is_still_starting(self):
        for error in (
            subprocess.CalledProcessError(1, ["machinectl"]),
            subprocess.TimeoutExpired(["machinectl"], 5),
            ValueError("Invalid container Leader PID"),
        ):
            with self.subTest(error=error):
                with self.mocks(query=error) as manager:
                    with self.assertRaisesRegex(ProcessLookupError, "still starting"):
                        self.mount()
                manager.pidfd_open.assert_not_called()
                manager.mount.assert_not_called()
                manager.remove_marker.assert_not_called()
                manager.lock_exit.assert_called_once_with()

    def test_a_leader_that_is_gone_is_retried(self):
        with self.mocks(pidfd_open=ProcessLookupError("gone")) as manager:
            with self.assertRaises(ProcessLookupError):
                self.mount()
        manager.mount.assert_not_called()
        with self.mocks(proc_dir=FileNotFoundError("/proc/42")) as manager:
            with self.assertRaisesRegex(ProcessLookupError, "Leader exited"):
                self.mount()
        manager.mount.assert_not_called()
        # The pidfd is closed.
        manager.close.assert_called_once_with(10)

    def test_a_changed_leader_is_refused(self):
        with self.mocks() as manager:
            manager.query.side_effect = [42, 43]
            with self.assertRaisesRegex(PermissionError, "Leader changed"):
                self.mount()
        manager.proc_dir.assert_not_called()
        manager.mount.assert_not_called()
        manager.close.assert_called_once_with(10)

    def test_a_container_that_is_still_starting_mounts_nothing(self):
        # Mocks: _find_payload (item 5 of specs/security-parity.md proves the
        # search) and the cgroup of the Leader.
        for override, message in (
            (
                {"payload": ProcessLookupError("Container is still starting")},
                "starting",
            ),
            ({"cgroup": "/sandy.slice/sandy-ai-dev.scope"}, "starting"),
        ):
            with self.subTest(override=override):
                with self.mocks() as manager:
                    if "cgroup" in override:
                        manager.cgroup.return_value = override["cgroup"]
                    else:
                        manager.payload.side_effect = override["payload"]
                    with self.assertRaisesRegex(ProcessLookupError, message):
                        self.mount()
                manager.read_file.assert_not_called()
                manager.mount.assert_not_called()
                manager.remove_marker.assert_not_called()
                self.assertEqual(manager.close.call_args_list, [call(20), call(10)])
                manager.lock_exit.assert_called_once_with()

    def test_a_leader_outside_the_scope_is_refused(self):
        for cgroup in (
            "/machine.slice/machine-ai-dev.scope/payload",
            "/sandy.slice/sandy-other.scope/payload",
            "/sandy.slice/sandy-ai-dev.scope/supervisor",
        ):
            with self.subTest(cgroup=cgroup):
                with self.mocks() as manager:
                    manager.cgroup.return_value = cgroup
                    with self.assertRaisesRegex(PermissionError, "restart it"):
                        self.mount()
                manager.payload.assert_not_called()
                manager.mount.assert_not_called()

    def test_a_scope_without_the_supervisor_of_this_up_gets_no_mount(self):
        # Regression test: a second up of a name whose systemd-run failed
        # found the Leader of the first up's container by its name, mounted
        # its own directories there, and removed the marker of that up.
        with self.mocks() as manager:
            manager.own_scope.return_value = False
            with self.assertRaisesRegex(PermissionError, "that this up started"):
                self.mount()
        manager.mount.assert_not_called()
        manager.remove_marker.assert_not_called()
        self.assertEqual(manager.close.call_args_list, [call(20), call(10), call(21)])
        manager.lock_exit.assert_called_once_with()
        # A supervisor that has exited: the container is gone; up retries,
        # sees the exit, and fails.
        with self.mocks(own_scope=ProcessLookupError("exited")) as manager:
            with self.assertRaises(ProcessLookupError):
                self.mount()
        manager.mount.assert_not_called()

    def test_an_unexpected_map_is_refused_before_any_mount(self):
        for name in ("uid_map", "gid_map"):
            with self.subTest(name=name):
                with self.mocks() as manager:
                    manager.read_file.side_effect = lambda fd, file, limit: (
                        b"0 0 4294967295\n" if file == name else self.ID_MAP
                    )
                    with self.assertRaisesRegex(ValueError, f"Unexpected {name}"):
                        self.mount()
                manager.mount.assert_not_called()
                manager.remove_marker.assert_not_called()
                self.assertEqual(manager.close.call_args_list, [call(20), call(10)])

    def test_a_failed_namespace_open_is_final(self):
        with self.mocks(open=FileNotFoundError("ns/mnt")) as manager:
            with self.assertRaises(FileNotFoundError):
                self.mount()
        manager.mount.assert_not_called()
        self.assertEqual(manager.close.call_args_list, [call(20), call(10)])

    def test_a_leader_that_exited_during_the_reads_is_retried(self):
        with self.mocks(alive=None) as manager:
            manager.alive.return_value = False
            with self.assertRaisesRegex(ProcessLookupError, "Leader exited"):
                self.mount()
        manager.mount.assert_not_called()
        manager.remove_marker.assert_not_called()
        self.assertEqual(manager.close.call_args_list, [call(20), call(10), call(21)])

    def test_a_failed_mount_names_the_directory_and_keeps_the_marker(self):
        for index, plan in enumerate(self.PLANS):
            with self.subTest(label=plan.label):
                errors = [None] * len(self.PLANS)
                errors[index] = sandy._MountError("move_mount failed: x (errno 22)")
                with self.mocks() as manager:
                    manager.mount.side_effect = errors
                    with self.assertRaises(sandy._MountError) as raised:
                        self.mount()
                self.assertEqual(
                    str(raised.exception),
                    f"'{plan.source}' on '{plan.target}': move_mount failed: x (errno 22)",
                )
                # Later directories are not mounted, the marker stays (the
                # caller stops the container), and every descriptor closes.
                self.assertEqual(manager.mount.call_count, index + 1)
                manager.remove_marker.assert_not_called()
                self.assertEqual(
                    manager.close.call_args_list[-2:], [call(10), call(21)]
                )
                manager.lock_exit.assert_called_once_with()

    def test_control_characters_of_the_source_are_not_reported(self):
        plan = sandy.MountPlan(
            "workspace", "/srv/\x1b[31mwork", "/home/developer/workspace", 1, 2
        )
        with self.mocks() as manager:
            manager.mount.side_effect = sandy._MountError("x")
            with self.assertRaises(sandy._MountError) as raised:
                self.mount((plan,))
        self.assertNotIn("\x1b", str(raised.exception))
        self.assertIn("/srv/[31mwork", str(raised.exception))

    def test_validates_the_name_and_takes_the_lock_first(self):
        with self.mocks() as manager:
            with self.assertRaises(ValueError):
                sandy._mount_container_dirs(
                    "Bad Name", self.PLANS, (1000, 1000), PINNED_SUPERVISOR
                )
        manager.lock_enter.assert_not_called()
        with patch.object(
            sandy, "_lifecycle_lock", side_effect=TimeoutError("busy")
        ), patch.object(sandy.os, "pidfd_open", create=True) as pidfd_open:
            with self.assertRaises(TimeoutError):
                self.mount()
        pidfd_open.assert_not_called()


class WaitForMountsTests(unittest.TestCase):
    """Sandy._wait_for_mounts: retry until the container has its payload.

    Mocks: the mount step, the supervisor, the clock, and the sleep.
    """

    plans = (
        sandy.MountPlan("workspace", "/srv/work", "/home/developer/workspace", 1, 2),
    )

    def wait(self, supervisor=None, event=None, timeout=60):
        instance = make_sandy()
        return instance._wait_for_mounts(
            self.plans,
            (1000, 1000),
            PINNED_SUPERVISOR,
            spinner_line_event=event,
            timeout=timeout,
            supervisor=supervisor,
        )

    def test_mounts_at_once(self):
        supervisor = MagicMock()
        supervisor.poll.return_value = None
        with patch.object(sandy, "_mount_container_dirs") as mount, patch.object(
            sandy.time, "sleep"
        ) as sleep:
            self.assertTrue(self.wait(supervisor))
        mount.assert_called_once_with(
            "ai-dev", self.plans, (1000, 1000), PINNED_SUPERVISOR
        )
        sleep.assert_not_called()

    def test_retries_while_the_container_is_still_starting(self):
        supervisor = MagicMock()
        supervisor.poll.return_value = None
        event = threading.Event()
        with patch.object(
            sandy,
            "_mount_container_dirs",
            side_effect=[ProcessLookupError("starting")] * 2 + [None],
        ) as mount, patch.object(sandy.time, "sleep") as sleep, patch.object(
            sandy.time, "monotonic", return_value=0.0
        ):
            with captured_output() as (stdout, _):
                self.assertTrue(self.wait(supervisor, event))
        self.assertEqual(mount.call_count, 3)
        self.assertEqual(
            sleep.call_args_list, [call(sandy.CONTAINER_READY_INTERVAL)] * 2
        )
        # One spinner dot for each retry.
        self.assertEqual(stdout.getvalue(), "..")

    def test_the_spinner_stops_when_its_line_is_finished(self):
        supervisor = MagicMock()
        supervisor.poll.return_value = None
        event = threading.Event()
        event.set()
        with patch.object(
            sandy,
            "_mount_container_dirs",
            side_effect=[ProcessLookupError("starting"), None],
        ), patch.object(sandy.time, "sleep"), patch.object(
            sandy.time, "monotonic", return_value=0.0
        ):
            with captured_output() as (stdout, _):
                self.assertTrue(self.wait(supervisor, event))
        self.assertEqual(stdout.getvalue(), "")

    def test_the_spinner_stops_when_the_line_ends_during_the_wait(self):
        supervisor = MagicMock()
        supervisor.poll.return_value = None
        event = threading.Event()
        calls = []

        def mount(*_):
            calls.append(1)
            if len(calls) == 1:
                # Something else finished the spinner line during this try.
                event.set()
                raise ProcessLookupError("starting")

        with patch.object(
            sandy, "_mount_container_dirs", side_effect=mount
        ), patch.object(sandy.time, "sleep"), patch.object(
            sandy.time, "monotonic", return_value=0.0
        ):
            with captured_output() as (stdout, _):
                self.assertTrue(self.wait(supervisor, event))
        self.assertEqual(len(calls), 2)
        self.assertEqual(stdout.getvalue(), "")

    def test_gives_up_when_the_supervisor_has_exited(self):
        supervisor = MagicMock()
        supervisor.poll.return_value = 1
        with patch.object(sandy, "_mount_container_dirs") as mount:
            self.assertFalse(self.wait(supervisor))
        mount.assert_not_called()

    def test_gives_up_when_the_container_does_not_start_in_time(self):
        supervisor = MagicMock()
        supervisor.poll.return_value = None
        with patch.object(
            sandy, "_mount_container_dirs", side_effect=ProcessLookupError("starting")
        ) as mount, patch.object(sandy.time, "sleep") as sleep, patch.object(
            sandy.time, "monotonic", side_effect=[0.0, 0.0, 0.0, 59.8, 59.8, 61.0]
        ):
            self.assertFalse(self.wait(supervisor, timeout=60))
        self.assertEqual(mount.call_count, 2)
        # The last sleep does not pass the deadline.
        self.assertAlmostEqual(sleep.call_args_list[-1].args[0], 0.2)

    def test_a_deadline_that_passed_during_a_try_ends_the_wait_at_once(self):
        supervisor = MagicMock()
        supervisor.poll.return_value = None
        with patch.object(
            sandy, "_mount_container_dirs", side_effect=ProcessLookupError("starting")
        ), patch.object(sandy.time, "sleep") as sleep, patch.object(
            sandy.time, "monotonic", side_effect=[0.0, 0.0, 60.0]
        ):
            self.assertFalse(self.wait(supervisor, timeout=60))
        sleep.assert_not_called()

    def test_a_failed_mount_is_final(self):
        supervisor = MagicMock()
        supervisor.poll.return_value = None
        error = sandy._MountError("'/srv/work' on '/h/w': move_mount failed: x")
        with patch.object(sandy, "_mount_container_dirs", side_effect=error):
            with self.assertRaises(sandy._MountError) as raised:
                self.wait(supervisor)
        self.assertIs(raised.exception, error)

    def test_other_errors_become_mount_errors(self):
        supervisor = MagicMock()
        supervisor.poll.return_value = None
        for error in (
            PermissionError("Container Leader changed during the mounts"),
            ValueError("Unexpected uid_map of the container"),
            OSError(errno.EIO, "read failed"),
            subprocess.SubprocessError("machinectl"),
        ):
            with self.subTest(error=error):
                with patch.object(sandy, "_mount_container_dirs", side_effect=error):
                    with self.assertRaisesRegex(
                        sandy._MountError, "^the directories in the container: "
                    ):
                        self.wait(supervisor)

    def test_without_a_supervisor_the_wait_is_bounded_by_the_timeout(self):
        with patch.object(sandy, "_mount_container_dirs") as mount:
            self.assertTrue(self.wait(None))
        mount.assert_called_once()
        with patch.object(sandy, "_mount_container_dirs") as mount:
            self.assertFalse(self.wait(None, timeout=0))
        mount.assert_not_called()


class PlanMountsTests(unittest.TestCase):
    """Sandy._plan_mounts and Sandy._prepare_image_mounts.

    Mocks: the check of a directory (_plan_mount) and the image user's ids.
    Real temporary directories give the paths and the images. The check of a
    target in an image is the real openat2 call.
    """

    def setUp(self):
        # Mock the mount table of the host; SubmountWarningTests cover it.
        patcher = patch.object(sandy, "_read_mountinfo", return_value="")
        self.read_mountinfo = patcher.start()
        self.addCleanup(patcher.stop)

    @staticmethod
    def fake_plan(label, source, target):
        return sandy.MountPlan(label, source, target, 1, 2)

    def test_plans_warn_about_mounts_below_each_directory(self):
        instance = make_sandy()
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "work").mkdir()
            (root / "share").mkdir()
            work = os.path.realpath(root / "work")
            share = os.path.realpath(root / "share")
            instance.workspace = str(root / "work")
            instance.shared = str(root / "share")
            self.read_mountinfo.return_value = (
                f"36 35 98:0 / {work}/sub rw - ext4 /dev/sda rw\n"
                f"37 35 98:0 / {share}/a rw - tmpfs tmpfs rw\n"
            )
            with patch.object(sandy, "_plan_mount", side_effect=self.fake_plan):
                with captured_output() as (stdout, _):
                    plans = instance._plan_mounts()
        self.assertEqual(len(plans), 2)
        self.assertEqual(
            stdout.getvalue(),
            f"W: The workspace directory '{work}' has mounts below it: '{work}/sub'\n"
            "   The container does not see these mounts\n"
            f"W: The shared directory '{share}' has mounts below it: '{share}/a'\n"
            "   The container does not see these mounts\n",
        )

    def test_a_refused_directory_gets_no_warning(self):
        instance = make_sandy()
        with tempfile.TemporaryDirectory() as temp_dir:
            instance.workspace = temp_dir
            instance.shared = None
            with patch.object(
                sandy, "_plan_mount", side_effect=sandy._MountError("no")
            ):
                with captured_output():
                    with self.assertRaises(SystemExit):
                        instance._plan_mounts()
        self.read_mountinfo.assert_not_called()

    def test_no_directory_gives_no_plan(self):
        instance = make_sandy()
        instance.workspace = None
        instance.shared = None
        with patch.object(sandy, "_plan_mount") as plan:
            self.assertEqual(instance._plan_mounts(), [])
        plan.assert_not_called()

    def test_plans_each_existing_directory_by_its_real_path(self):
        instance = make_sandy()
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "real").mkdir()
            (root / "link").symlink_to(root / "real")
            (root / "shared").mkdir()
            instance.workspace = str(root / "link")
            instance.shared = str(root / "shared")
            with patch.object(sandy, "_plan_mount", side_effect=self.fake_plan) as plan:
                plans = instance._plan_mounts()
            real = os.path.realpath(root / "real")
            shared = os.path.realpath(root / "shared")
        self.assertEqual(
            plan.call_args_list,
            [
                call("workspace", real, "/home/developer/workspace"),
                call("shared", shared, "/home/developer/shared"),
            ],
        )
        self.assertEqual([item.source for item in plans], [real, shared])

    def test_the_target_follows_the_user_of_the_container(self):
        instance = make_sandy()
        instance.user = "other"
        instance.user_home = "/home/other"
        with tempfile.TemporaryDirectory() as temp_dir:
            instance.workspace = temp_dir
            with patch.object(sandy, "_plan_mount", side_effect=self.fake_plan) as plan:
                instance._plan_mounts()
        self.assertEqual(plan.call_args.args[2], "/home/other/workspace")

    def test_skips_a_missing_directory_and_a_file_with_a_warning(self):
        instance = make_sandy()
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "file").write_text("x")
            instance.workspace = str(root / "missing")
            instance.shared = str(root / "file")
            with patch.object(sandy, "_plan_mount") as plan:
                with captured_output() as (stdout, _):
                    self.assertEqual(instance._plan_mounts(), [])
        plan.assert_not_called()
        self.assertEqual(
            stdout.getvalue(),
            f"W: Could not find '{root / 'missing'}' on the host, skipping workspace mount\n"
            f"W: Could not find '{root / 'file'}' on the host, skipping shared mount\n",
        )

    def test_control_characters_are_not_printed(self):
        instance = make_sandy()
        instance.workspace = "missing\x1b[31m"
        instance.shared = None
        with captured_output() as (stdout, _):
            instance._plan_mounts()
        self.assertNotIn("\x1b", stdout.getvalue())
        self.assertIn("'missing[31m'", stdout.getvalue())

    def test_a_refused_directory_ends_the_command(self):
        instance = make_sandy()
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "ws\x1b[0m").mkdir()
            (root / "shared").mkdir()
            instance.workspace = str(root / "ws\x1b[0m")
            instance.shared = str(root / "shared")
            with patch.object(
                sandy,
                "_plan_mount",
                side_effect=sandy._MountError("root owns the workspace directory"),
            ) as plan:
                with captured_output() as (stdout, _):
                    with self.assertRaises(SystemExit) as exited:
                        instance._plan_mounts()
            source = os.path.realpath(root / "ws\x1b[0m")
        self.assertEqual(exited.exception.code, 1)
        # The second directory is not checked.
        plan.assert_called_once()
        self.assertEqual(
            stdout.getvalue(),
            f"E: Cannot mount '{source.replace(chr(27), '')}' as the workspace "
            "directory: root owns the workspace directory\n",
        )

    @contextmanager
    def image(self, directories):
        """Yield the path and a descriptor of a temporary image root."""
        with tempfile.TemporaryDirectory() as temp_dir:
            machine = Path(temp_dir)
            for directory in directories:
                (machine / directory).mkdir(parents=True)
            machine_fd = os.open(machine, os.O_PATH | os.O_DIRECTORY)
            try:
                yield machine, machine_fd
            finally:
                os.close(machine_fd)

    plans = [
        sandy.MountPlan("workspace", "/srv/work", "/home/developer/workspace", 1, 2),
        sandy.MountPlan("shared", "/srv/share", "/home/developer/shared", 1, 3),
    ]

    def test_prepare_keeps_the_targets_that_the_image_has(self):
        instance = make_sandy()
        with self.image(["home/developer/workspace"]) as (_, machine_fd):
            with patch.object(
                sandy, "_read_image_user_ids", return_value=(1001, 1002)
            ) as read:
                with captured_output() as (stdout, _):
                    kept, ids = instance._prepare_image_mounts(machine_fd, self.plans)
        self.assertEqual(kept, (self.plans[0],))
        self.assertEqual(ids, (1001, 1002))
        read.assert_called_once_with(machine_fd, "developer")
        self.assertEqual(
            stdout.getvalue(),
            "I: Mounting '/srv/work' on '/home/developer/workspace'\n"
            "W: Could not find '/home/developer/shared' in the container. "
            "Skipping shared mount\n",
        )

    def test_prepare_reads_the_user_of_the_container(self):
        instance = make_sandy()
        instance.user = "other"
        instance.user_home = "/home/other"
        plan = sandy.MountPlan("workspace", "/srv/work", "/home/other/workspace", 1, 2)
        with self.image(["home/other/workspace"]) as (_, machine_fd):
            with patch.object(
                sandy, "_read_image_user_ids", return_value=(1000, 1000)
            ) as read:
                with captured_output():
                    instance._prepare_image_mounts(machine_fd, [plan])
        read.assert_called_once_with(machine_fd, "other")

    def test_prepare_reads_nothing_when_no_target_is_left(self):
        instance = make_sandy()
        with self.image([]) as (_, machine_fd):
            with patch.object(sandy, "_read_image_user_ids") as read:
                with captured_output():
                    result = instance._prepare_image_mounts(machine_fd, self.plans)
        self.assertEqual(result, ((), (0, 0)))
        read.assert_not_called()

    def test_prepare_ends_the_command_when_the_ids_cannot_be_read(self):
        instance = make_sandy()
        for error in (
            ValueError("Container user must have exactly one passwd entry"),
            FileNotFoundError("passwd"),
            PermissionError("Unsafe image file path component 'passwd'"),
        ):
            with self.subTest(error=error):
                with self.image(["home/developer/workspace"]) as (_, machine_fd):
                    with patch.object(sandy, "_read_image_user_ids", side_effect=error):
                        with captured_output() as (stdout, _):
                            with self.assertRaises(SystemExit) as exited:
                                instance._prepare_image_mounts(
                                    machine_fd, self.plans[:1]
                                )
                self.assertEqual(exited.exception.code, 1)
                self.assertIn(
                    "E: Could not read the uid and gid of 'developer' in the "
                    "container image: ",
                    stdout.getvalue(),
                )

    def test_prepare_checks_the_target_below_the_image_root(self):
        # A directory that only the host has is missing from the image, and
        # one that only the image has exists. Nothing is mocked but the image
        # user's ids.
        instance = make_sandy()
        image_only = f"/sandy-image-only-{os.getpid()}/workspace"
        self.assertFalse(os.path.lexists(image_only))
        with tempfile.TemporaryDirectory() as host_only:
            plans = [
                sandy.MountPlan("workspace", "/srv/work", host_only, 1, 2),
                sandy.MountPlan("shared", "/srv/share", image_only, 1, 3),
            ]
            with self.image([image_only[1:]]) as (_, machine_fd):
                with patch.object(
                    sandy, "_read_image_user_ids", return_value=(1000, 1000)
                ):
                    with captured_output() as (stdout, _):
                        kept, _ = instance._prepare_image_mounts(machine_fd, plans)
        self.assertEqual(kept, (plans[1],))
        self.assertIn(
            f"W: Could not find '{host_only}' in the container. Skipping "
            "workspace mount\n",
            stdout.getvalue(),
        )

    def test_prepare_refuses_a_link_in_the_image_before_the_start(self):
        # Regression test: os.path.isdir followed a link in the image with the
        # rules of the host, so an absolute link answered for a host
        # directory. The mount opens no link, so up refuses a target with a
        # link in its path, with the error of the mount. Nothing is mocked but
        # the image user's ids.
        instance = make_sandy()
        with tempfile.TemporaryDirectory() as host_dir:
            host = Path(host_dir)
            (host / "developer" / "workspace").mkdir(parents=True)

            def link_to_the_host(machine):
                (machine / "home" / "developer").mkdir(parents=True)
                (machine / "home" / "developer" / "workspace").symlink_to(
                    host / "developer" / "workspace"
                )

            def parent_link_to_the_host(machine):
                (machine / "home").symlink_to(host)

            def link_in_the_image(machine):
                (machine / "home" / "developer" / "real").mkdir(parents=True)
                (machine / "home" / "developer" / "workspace").symlink_to("real")

            for layout in (
                link_to_the_host,
                parent_link_to_the_host,
                link_in_the_image,
            ):
                with self.subTest(layout=layout.__name__):
                    with self.image([]) as (machine, machine_fd):
                        layout(machine)
                        # The check of the old code said yes to each layout.
                        self.assertTrue(
                            os.path.isdir(machine / "home/developer/workspace")
                        )
                        with patch.object(sandy, "_read_image_user_ids") as read:
                            with captured_output() as (stdout, _):
                                with self.assertRaises(SystemExit) as exited:
                                    instance._prepare_image_mounts(
                                        machine_fd, self.plans[:1]
                                    )
                    self.assertEqual(exited.exception.code, 1)
                    read.assert_not_called()
                    self.assertEqual(
                        stdout.getvalue(),
                        "E: Could not mount '/srv/work' on "
                        "'/home/developer/workspace': openat2 failed: "
                        f"{os.strerror(errno.ELOOP)} (errno {errno.ELOOP})\n",
                    )

    def test_prepare_skips_a_target_that_is_not_a_directory(self):
        # Nothing is mocked but the image user's ids.
        instance = make_sandy()
        for file in ("home/developer/workspace", "home/developer"):
            with self.subTest(file=file):
                with self.image(["home"]) as (machine, machine_fd):
                    (machine / file).parent.mkdir(parents=True, exist_ok=True)
                    (machine / file).write_text("")
                    with patch.object(sandy, "_read_image_user_ids") as read:
                        with captured_output() as (stdout, _):
                            result = instance._prepare_image_mounts(
                                machine_fd, self.plans[:1]
                            )
                self.assertEqual(result, ((), (0, 0)))
                read.assert_not_called()
                self.assertEqual(
                    stdout.getvalue(),
                    "W: Could not find '/home/developer/workspace' in the "
                    "container. Skipping workspace mount\n",
                )

    def test_prepare_ends_the_command_when_a_target_cannot_be_checked(self):
        # Mocks: openat2, for errors that a real image does not give here.
        instance = make_sandy()
        for error, reason in (
            (
                PermissionError(errno.EACCES, "openat2 failed: Permission denied"),
                f"openat2 failed: Permission denied (errno {errno.EACCES})",
            ),
            (ValueError("Invalid path"), "the path is not valid"),
        ):
            with self.subTest(error=error):
                with patch.object(
                    sandy, "_openat2_no_links", side_effect=error
                ) as opened, patch.object(sandy, "_read_image_user_ids") as read:
                    with captured_output() as (stdout, _):
                        with self.assertRaises(SystemExit) as exited:
                            instance._prepare_image_mounts(7, self.plans)
                self.assertEqual(exited.exception.code, 1)
                opened.assert_called_once_with(
                    "/home/developer/workspace",
                    os.O_PATH | os.O_DIRECTORY,
                    root_fd=7,
                )
                read.assert_not_called()
                self.assertEqual(
                    stdout.getvalue(),
                    "E: Could not mount '/srv/work' on '/home/developer/workspace': "
                    f"{reason}\n",
                )


class SubmountWarningTests(unittest.TestCase):
    """The warning about mounts below a directory that up mounts.

    Mocks: only the read of the mount table. The text is a real mountinfo
    sample. The E2E suite proves that the container does not see the mounts.
    """

    MOUNTINFO = (
        "22 1 8:2 / / rw,relatime shared:1 - ext4 /dev/sda2 rw\n"
        "36 22 98:0 / /srv/work rw,noatime master:1 - ext3 /dev/root rw,errors=continue\n"
        "37 36 0:30 / /srv/work/tmp\\040dir rw,nosuid shared:5 - tmpfs tmpfs rw\n"
        "38 36 0:31 /other /srv/work/b rw - ext4 /dev/sdb rw\n"
        "39 38 0:32 / /srv/work/b/deeper rw - tmpfs tmpfs rw\n"
        "40 22 0:33 / /srv/work-extra rw - ext4 /dev/sdc rw\n"
        "41 22 0:34 / /srv/workx rw master:1 shared:2 - ext4 /dev/sdd rw\n"
        "42 22 0:35 / /srv rw - ext4 /dev/sde rw\n"
    )

    def test_lists_the_mount_points_below_the_directory(self):
        self.assertEqual(
            sandy._mounts_below("/srv/work", self.MOUNTINFO),
            ["/srv/work/b", "/srv/work/b/deeper", "/srv/work/tmp dir"],
        )

    def test_does_not_list_the_directory_itself_or_a_similar_name(self):
        for directory, expected in (
            ("/srv/work/b", ["/srv/work/b/deeper"]),
            ("/srv/work/b/deeper", []),
            ("/srv/work-extra", []),
            ("/srv/wor", []),
            # A trailing slash does not change the result.
            ("/srv/work/b/", ["/srv/work/b/deeper"]),
        ):
            with self.subTest(directory=directory):
                self.assertEqual(
                    sandy._mounts_below(directory, self.MOUNTINFO), expected
                )

    def test_every_mount_is_below_the_root_directory(self):
        self.assertEqual(
            sandy._mounts_below(
                "/",
                "22 1 8:2 / / rw - ext4 /dev/sda2 rw\n"
                "23 22 0:3 / /a rw - tmpfs tmpfs rw\n",
            ),
            ["/a"],
        )

    def test_decodes_the_octal_escapes_of_the_kernel(self):
        line = "50 22 0:40 / /srv/work/a\\040b\\011c\\012d\\134e rw - tmpfs tmpfs rw\n"
        self.assertEqual(
            sandy._mounts_below("/srv/work", line), ["/srv/work/a b\tc\nd\\e"]
        )

    def test_skips_empty_lines_and_lists_each_mount_point_once(self):
        text = (
            "\n"
            "50 22 0:40 / /srv/work/a rw - tmpfs tmpfs rw\n"
            "\n"
            "51 50 0:41 / /srv/work/a rw - tmpfs tmpfs rw\n"
        )
        self.assertEqual(sandy._mounts_below("/srv/work", text), ["/srv/work/a"])

    def test_a_malformed_line_fails_the_whole_check(self):
        for line in (
            "50 22 0:40 / /srv/work/a rw tmpfs tmpfs rw",
            "50 22 0:40 / /srv/work/a",
            "garbage",
            "50 22 0:40 / /srv/work/a rw - tmpfs",
        ):
            with self.subTest(line=line):
                with self.assertRaisesRegex(ValueError, "Malformed mountinfo line"):
                    sandy._mounts_below("/srv/work", self.MOUNTINFO + line + "\n")

    def test_reads_the_mount_table_through_the_proc_directory(self):
        manager = MagicMock()
        manager.proc_dir.return_value = 9
        manager.read.return_value = b"22 1 8:2 / /\xff rw - ext4 /dev/sda2 rw\n"
        with patch.object(sandy, "_open_process_dir", manager.proc_dir), patch.object(
            sandy, "_read_proc_file", manager.read
        ), patch.object(sandy.os, "close", manager.close):
            text = sandy._read_mountinfo()
        # A file name that is not UTF-8 stays as it is.
        self.assertEqual(text, "22 1 8:2 / /\udcff rw - ext4 /dev/sda2 rw\n")
        self.assertEqual(
            manager.mock_calls,
            [
                call.proc_dir(os.getpid()),
                call.read(9, "mountinfo", sandy.MOUNTINFO_MAX_BYTES),
                call.close(9),
            ],
        )

    def test_reading_closes_the_proc_directory_on_failure(self):
        with patch.object(sandy, "_open_process_dir", return_value=9), patch.object(
            sandy, "_read_proc_file", side_effect=ValueError("too large")
        ), patch.object(sandy.os, "close") as close:
            with self.assertRaises(ValueError):
                sandy._read_mountinfo()
        close.assert_called_once_with(9)

    def warn(self, mountinfo, source="/srv/work", label="workspace"):
        instance = make_sandy()
        with patch.object(sandy, "_read_mountinfo", return_value=mountinfo):
            with captured_output() as (stdout, _):
                instance._warn_about_submounts(label, source)
        return stdout.getvalue()

    def test_warns_with_the_mounts_below_the_directory(self):
        self.assertEqual(
            self.warn(self.MOUNTINFO),
            "W: The workspace directory '/srv/work' has mounts below it: "
            "'/srv/work/b', '/srv/work/b/deeper', '/srv/work/tmp dir'\n"
            "   The container does not see these mounts\n",
        )

    def test_says_nothing_without_mounts_below(self):
        self.assertEqual(self.warn(self.MOUNTINFO, "/srv/work/b/deeper"), "")
        self.assertEqual(self.warn(""), "")

    def test_lists_at_most_three_mounts_and_counts_the_rest(self):
        lines = "".join(
            f"{50 + number} 22 0:{40 + number} / /srv/work/m{number} rw - tmpfs tmpfs rw\n"
            for number in range(5)
        )
        output = self.warn(lines, label="shared")
        self.assertEqual(
            output.splitlines()[0],
            "W: The shared directory '/srv/work' has mounts below it: "
            "'/srv/work/m0', '/srv/work/m1', '/srv/work/m2' and 2 more",
        )
        self.assertEqual(sandy.SUBMOUNT_LIST_MAX, 3)

    def test_does_not_print_control_characters(self):
        output = self.warn("50 22 0:40 / /srv/work/\x1b[31mred rw - tmpfs tmpfs rw\n")
        self.assertNotIn("\x1b", output)
        self.assertIn("'/srv/work/[31mred'", output)

    def test_reports_an_unreadable_mount_table_and_goes_on(self):
        instance = make_sandy()
        for error in (
            OSError(errno.EACCES, "Permission denied"),
            ValueError("Malformed mountinfo line"),
        ):
            with self.subTest(error=error):
                with patch.object(sandy, "_read_mountinfo", side_effect=error):
                    with captured_output() as (stdout, _):
                        instance._warn_about_submounts("workspace", "/srv/work")
                self.assertTrue(
                    stdout.getvalue().startswith(
                        "W: Could not check for mounts below the workspace "
                        "directory: "
                    )
                )


class ImageUserIdsTests(unittest.TestCase):
    """The uid and gid of the container user, read from the image's passwd.

    Mocks: only the check that the image's directories belong to root.
    """

    PASSWD = (
        "root:x:0:0:root:/root:/bin/bash\n"
        "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
        "developer:x:1001:100::/home/developer:/bin/bash\n"
    )

    def test_resolve_container_user_ids(self):
        self.assertEqual(
            sandy._resolve_container_user_ids("developer", self.PASSWD), (1001, 100)
        )
        self.assertEqual(
            sandy._resolve_container_user_ids("ubuntu", self.PASSWD), (1000, 1000)
        )
        self.assertEqual(sandy._resolve_container_user_ids("root", self.PASSWD), (0, 0))

    def test_resolve_container_user_ids_fails_closed(self):
        for user, text in (
            ("missing", self.PASSWD),
            ("developer", self.PASSWD + "developer:x:1002:1002::/h:/s\n"),
            ("developer", self.PASSWD + "broken:x:1\n"),
            ("developer", self.PASSWD.replace(":1001:100:", ":01001:100:")),
            ("developer", self.PASSWD.replace(":1001:100:", ":1001:65535:")),
            ("developer", self.PASSWD.replace(":1001:100:", ":0:100:")),
            ("root", self.PASSWD.replace("root:x:0:0", "root:x:5:0")),
        ):
            with self.subTest(user=user, text=text):
                with self.assertRaises(ValueError):
                    sandy._resolve_container_user_ids(user, text)

    @contextmanager
    def image(self, passwd=None):
        with tempfile.TemporaryDirectory() as temp_dir:
            machine = Path(temp_dir)
            (machine / "etc").mkdir(mode=0o755)
            if passwd is not None:
                file = machine / "etc" / "passwd"
                file.write_text(passwd)
                file.chmod(0o644)
            machine_fd = os.open(machine, sandy.DIRECTORY_OPEN_FLAGS)
            try:
                with patch.object(sandy, "_verify_owned_directory"):
                    yield machine, machine_fd
            finally:
                os.close(machine_fd)

    def test_reads_the_ids_through_the_pinned_image_root(self):
        with self.image(self.PASSWD) as (_, machine_fd):
            self.assertEqual(
                sandy._read_image_user_ids(machine_fd, "developer"), (1001, 100)
            )
            self.assertEqual(
                sandy._read_image_user_ids(machine_fd, "ubuntu"), (1000, 1000)
            )

    def test_fails_closed_on_an_unsafe_or_missing_passwd(self):
        with self.image() as (machine, machine_fd):
            with self.assertRaises(FileNotFoundError):
                sandy._read_image_user_ids(machine_fd, "developer")
            # A link is not followed out of the image, and a directory is not
            # a regular file.
            (machine / "etc" / "passwd").symlink_to("/etc/passwd")
            with self.assertRaises(PermissionError):
                sandy._read_image_user_ids(machine_fd, "developer")
            (machine / "etc" / "passwd").unlink()
            (machine / "etc" / "passwd").mkdir()
            with self.assertRaises(PermissionError):
                sandy._read_image_user_ids(machine_fd, "developer")

    def test_fails_closed_on_malformed_or_large_passwd_text(self):
        with self.image("developer:x:1001\n") as (_, machine_fd):
            with self.assertRaisesRegex(ValueError, "Malformed container passwd"):
                sandy._read_image_user_ids(machine_fd, "developer")
        with self.image(self.PASSWD) as (_, machine_fd):
            with patch.object(sandy, "CONTAINER_ACCOUNT_FILE_MAX_BYTES", 10):
                with self.assertRaisesRegex(ValueError, "is too large"):
                    sandy._read_image_user_ids(machine_fd, "developer")

    def test_closes_the_file_it_opened(self):
        with self.image(self.PASSWD) as (_, machine_fd):
            opened = []
            real_open_image_file = sandy._open_image_file

            def open_image_file(*args):
                fd = real_open_image_file(*args)
                opened.append(fd)
                return fd

            with patch.object(sandy, "_open_image_file", side_effect=open_image_file):
                sandy._read_image_user_ids(machine_fd, "developer")
            with patch.object(sandy, "_open_image_file", side_effect=open_image_file):
                with self.assertRaises(ValueError):
                    sandy._read_image_user_ids(machine_fd, "missing")
        for fd in opened:
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_read_account_fd_reads_a_regular_file_of_bounded_size(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "passwd"
            path.write_bytes(b"a:x:1:\xff\n")
            fd = os.open(path, os.O_RDONLY)
            try:
                self.assertEqual(
                    sandy._read_account_fd(fd, "/etc/passwd"), "a:x:1:\udcff\n"
                )
            finally:
                os.close(fd)
            directory = os.open(temp_dir, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaisesRegex(ValueError, "not a regular file"):
                    sandy._read_account_fd(directory, "/etc/passwd")
            finally:
                os.close(directory)


class PinnedSupervisorTests(unittest.TestCase):
    """The pinned supervisor of up, and the check that the scope holds it.

    _pin_supervisor uses a real pidfd of this process. The scope check mocks
    the /proc reads and the pidfd; the E2E suite proves both with a real
    systemd-run scope.
    """

    def test_pin_supervisor_pins_a_live_process(self):
        pinned = sandy._pin_supervisor(os.getpid())
        try:
            self.assertEqual(pinned.pid, os.getpid())
            self.assertTrue(sandy._pidfd_process_alive(pinned.pidfd))
        finally:
            os.close(pinned.pidfd)
        for pid in (0, -1, True, "1"):
            with self.subTest(pid=pid):
                with self.assertRaises(ValueError):
                    sandy._pin_supervisor(pid)

    @contextmanager
    def proc(self, cgroup, alive=True):
        """Mock the /proc reads of the supervisor; cgroup may be an error."""
        with patch.object(
            sandy, "_open_process_dir", return_value=55
        ) as open_dir, patch.object(
            sandy, "_read_process_cgroup", side_effect=[cgroup]
        ) as read, patch.object(
            sandy.os, "close"
        ) as close, patch.object(
            sandy, "_pidfd_process_alive", return_value=alive
        ) as alive_check:
            yield open_dir, read, close, alive_check

    def test_the_scope_and_a_cgroup_below_it_hold_the_supervisor(self):
        for cgroup, expected in (
            # systemd-run joins the scope; nspawn can move below it.
            ("/sandy.slice/sandy-ai-dev.scope", True),
            ("/sandy.slice/sandy-ai-dev.scope/supervisor", True),
            # A failed systemd-run stays in the cgroup of its caller.
            ("/user.slice/user-1000.slice/session-3.scope", False),
            ("/sandy.slice/sandy-other.scope", False),
            ("/sandy.slice/sandy-ai-dev.scope2", False),
            ("/system.slice/sandy-ai-dev.scope", False),
        ):
            with self.subTest(cgroup=cgroup):
                with self.proc(cgroup) as (open_dir, read, close, alive):
                    self.assertIs(
                        sandy._supervisor_in_scope("ai-dev", PINNED_SUPERVISOR),
                        expected,
                    )
                open_dir.assert_called_once_with(4242)
                read.assert_called_once_with(55)
                close.assert_called_once_with(55)
                # The read refers to the supervisor only while it is alive.
                alive.assert_called_once_with(-1)

    def test_a_supervisor_that_exited_is_not_checked(self):
        with self.proc("/sandy.slice/sandy-ai-dev.scope", alive=False):
            with self.assertRaisesRegex(ProcessLookupError, "supervisor exited"):
                sandy._supervisor_in_scope("ai-dev", PINNED_SUPERVISOR)
        # A failed read of a supervisor that exited is that exit.
        for error in (FileNotFoundError("gone"), ValueError("Malformed")):
            with self.subTest(error=error):
                with self.proc(error, alive=False):
                    with self.assertRaisesRegex(
                        ProcessLookupError, "supervisor exited"
                    ):
                        sandy._supervisor_in_scope("ai-dev", PINNED_SUPERVISOR)
                # A failed read of a live supervisor is an error of its own.
                with self.proc(error):
                    with self.assertRaises(type(error)):
                        sandy._supervisor_in_scope("ai-dev", PINNED_SUPERVISOR)

    def test_the_name_is_validated_before_any_read(self):
        with self.proc("/sandy.slice/sandy-ai-dev.scope") as (open_dir, _, _, _):
            with self.assertRaises(ValueError):
                sandy._supervisor_in_scope("Bad Name", PINNED_SUPERVISOR)
        open_dir.assert_not_called()


class ScopeMarkerTests(unittest.TestCase):
    """The mounts-pending marker, and the marker helpers that it shares.

    Tests use plain directories in place of cgroupfs, as AttachCgroupTests
    does. Mocks: the check that the scope holds the supervisor of this up,
    and its pidfd (PinnedSupervisorTests cover them). The E2E suite proves the
    real marker in a real scope.
    """

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.unit = Path(self.tempdir.name) / "sandy-ai-dev.scope"
        self.unit.mkdir()
        in_scope = patch.object(sandy, "_supervisor_in_scope", return_value=True)
        self.in_scope = in_scope.start()
        self.addCleanup(in_scope.stop)
        alive = patch.object(sandy, "_pidfd_process_alive", return_value=True)
        self.alive = alive.start()
        self.addCleanup(alive.stop)

    def open_unit(self):
        return os.open(self.unit, sandy.DIRECTORY_OPEN_FLAGS)

    def test_the_marker_is_not_an_attach_leaf(self):
        self.assertIsNone(
            sandy.ATTACH_LEAF_PATTERN.fullmatch(sandy.MOUNTS_PENDING_CGROUP)
        )
        self.assertNotEqual(sandy.MOUNTS_PENDING_CGROUP, sandy.UP_CONSOLE_CGROUP)
        # An attach count ignores the marker and does not remove it.
        unit_fd = self.open_unit()
        self.addCleanup(os.close, unit_fd)
        (self.unit / sandy.MOUNTS_PENDING_CGROUP).mkdir()
        self.assertEqual(sandy._count_populated_attaches(unit_fd), 0)
        self.assertTrue((self.unit / sandy.MOUNTS_PENDING_CGROUP).is_dir())

    def test_marker_lifecycle(self):
        unit_fd = self.open_unit()
        self.addCleanup(os.close, unit_fd)
        marker = sandy.MOUNTS_PENDING_CGROUP
        self.assertFalse(sandy._scope_marker_exists(unit_fd, marker))
        with patch.object(
            sandy, "_open_supervisor_cgroup", side_effect=lambda _: self.open_unit()
        ):
            sandy._create_mounts_pending_marker("ai-dev", PINNED_SUPERVISOR)
            # Creating it twice is not an error.
            sandy._create_mounts_pending_marker("ai-dev", PINNED_SUPERVISOR)
        self.assertTrue((self.unit / marker).is_dir())
        self.assertTrue(sandy._scope_marker_exists(unit_fd, marker))
        # The other marker is separate.
        self.assertFalse(sandy._up_console_marker_exists(unit_fd))
        sandy._remove_scope_marker(unit_fd, marker)
        sandy._remove_scope_marker(unit_fd, marker)
        self.assertFalse(sandy._scope_marker_exists(unit_fd, marker))
        # A file of that name is not the marker, and a link is not followed.
        (self.unit / marker).write_text("")
        self.assertFalse(sandy._scope_marker_exists(unit_fd, marker))
        (self.unit / marker).unlink()
        (self.unit / marker).symlink_to(self.unit)
        self.assertFalse(sandy._scope_marker_exists(unit_fd, marker))

    def test_create_waits_for_the_scope_then_times_out(self):
        opens = [FileNotFoundError(), None]

        def open_unit(_name):
            result = opens.pop(0)
            if result is not None:
                raise result
            return self.open_unit()

        with patch.object(
            sandy, "_open_supervisor_cgroup", side_effect=open_unit
        ), patch.object(sandy.time, "sleep") as sleep:
            sandy._create_mounts_pending_marker("ai-dev", PINNED_SUPERVISOR)
        sleep.assert_called_once_with(sandy.UP_CONSOLE_POLL_INTERVAL)
        self.assertTrue((self.unit / sandy.MOUNTS_PENDING_CGROUP).is_dir())
        with patch.object(
            sandy, "_open_supervisor_cgroup", side_effect=FileNotFoundError
        ), patch.object(sandy.time, "sleep"), patch.object(
            sandy.time, "monotonic", side_effect=[0, 1, 10]
        ):
            with self.assertRaisesRegex(TimeoutError, "did not appear"):
                sandy._create_mounts_pending_marker("ai-dev", PINNED_SUPERVISOR)

    def test_no_marker_in_a_scope_that_another_up_started(self):
        # Regression test: a second up of a name that waited for the lock
        # found the scope of the first up, made its marker there, and failed.
        # Every attach to the first container then failed until sandy down.
        # Its systemd-run fails and exits without joining that scope.
        self.in_scope.side_effect = [False, ProcessLookupError("exited")]
        before = sandy._open_fds()
        with patch.object(
            sandy, "_open_supervisor_cgroup", side_effect=lambda _: self.open_unit()
        ), patch.object(sandy.time, "sleep"):
            with self.assertRaisesRegex(ProcessLookupError, "exited"):
                sandy._create_mounts_pending_marker("ai-dev", PINNED_SUPERVISOR)
        self.assertFalse((self.unit / sandy.MOUNTS_PENDING_CGROUP).exists())
        self.assertEqual(sandy._open_fds(), before)
        self.assertEqual(
            self.in_scope.call_args_list, [call("ai-dev", PINNED_SUPERVISOR)] * 2
        )

    def test_the_marker_waits_until_the_scope_holds_the_supervisor(self):
        # systemd makes the cgroup of the scope, then moves systemd-run in.
        self.in_scope.side_effect = [False, False, True]
        with patch.object(
            sandy, "_open_supervisor_cgroup", side_effect=lambda _: self.open_unit()
        ), patch.object(sandy.time, "sleep") as sleep:
            sandy._create_mounts_pending_marker("ai-dev", PINNED_SUPERVISOR)
        self.assertEqual(sleep.call_count, 2)
        self.assertTrue((self.unit / sandy.MOUNTS_PENDING_CGROUP).is_dir())

    def test_a_supervisor_that_exits_before_any_scope_exists_fails(self):
        self.alive.return_value = False
        with patch.object(
            sandy, "_open_supervisor_cgroup", side_effect=FileNotFoundError
        ), patch.object(sandy.time, "sleep") as sleep:
            with self.assertRaisesRegex(ProcessLookupError, "supervisor exited"):
                sandy._create_mounts_pending_marker("ai-dev", PINNED_SUPERVISOR)
        sleep.assert_not_called()
        self.alive.assert_called_once_with(-1)

    def test_a_scope_that_never_holds_the_supervisor_times_out(self):
        self.in_scope.return_value = False
        with patch.object(
            sandy, "_open_supervisor_cgroup", side_effect=lambda _: self.open_unit()
        ), patch.object(sandy.time, "sleep"), patch.object(
            sandy.time, "monotonic", side_effect=[0, 1, 10]
        ):
            with self.assertRaisesRegex(TimeoutError, "did not appear"):
                sandy._create_mounts_pending_marker("ai-dev", PINNED_SUPERVISOR)
        self.assertFalse((self.unit / sandy.MOUNTS_PENDING_CGROUP).exists())

    def test_a_marker_of_another_up_stays_where_this_up_cannot_mark(self):
        # The first up made its marker; the second up's check fails, and it
        # leaves that marker alone (the first up removes it after its mounts).
        (self.unit / sandy.MOUNTS_PENDING_CGROUP).mkdir()
        self.in_scope.side_effect = ProcessLookupError("exited")
        with patch.object(
            sandy, "_open_supervisor_cgroup", side_effect=lambda _: self.open_unit()
        ):
            with self.assertRaises(ProcessLookupError):
                sandy._create_mounts_pending_marker("ai-dev", PINNED_SUPERVISOR)
        self.assertTrue((self.unit / sandy.MOUNTS_PENDING_CGROUP).is_dir())

    def test_an_attach_is_refused_while_the_marker_exists(self):
        unit_fd = self.open_unit()
        self.addCleanup(os.close, unit_fd)
        with patch.object(
            sandy, "_open_supervisor_cgroup", side_effect=lambda _: self.open_unit()
        ), patch.object(sandy.os, "close", wraps=os.close) as close:
            sandy._require_no_pending_mounts("ai-dev")
            (self.unit / sandy.MOUNTS_PENDING_CGROUP).mkdir()
            with self.assertRaisesRegex(
                ProcessLookupError,
                r"^Container is still starting; try again "
                r"\(if sandy up has ended, stop the container with sandy down\)$",
            ):
                sandy._require_no_pending_mounts("ai-dev")
            (self.unit / sandy.MOUNTS_PENDING_CGROUP).rmdir()
            sandy._require_no_pending_mounts("ai-dev")
        # Each call closed the descriptor that it opened.
        self.assertEqual(close.call_count, 3)

    def test_the_up_console_marker_does_not_refuse_an_attach(self):
        (self.unit / sandy.UP_CONSOLE_CGROUP).mkdir()
        with patch.object(
            sandy, "_open_supervisor_cgroup", side_effect=lambda _: self.open_unit()
        ):
            sandy._require_no_pending_mounts("ai-dev")

    def test_a_missing_scope_is_not_hidden(self):
        with patch.object(
            sandy, "_open_supervisor_cgroup", side_effect=FileNotFoundError
        ):
            with self.assertRaises(FileNotFoundError):
                sandy._require_no_pending_mounts("ai-dev")


class NetworkCoreTests(unittest.TestCase):
    def test_constructor_prefers_iptables_and_reuses_bridge(self):
        def which(name):
            if name in {"iptables", "ip6tables", "nft"}:
                return f"/usr/sbin/{name}"
            return None

        with patch.object(sandy.shutil, "which", side_effect=which):
            with patch.object(sandy.SandyNet, "_bridge_exists", return_value=True):
                with patch.object(
                    sandy.SandyNet,
                    "_detect_existing_config",
                    return_value=True,
                ):
                    network = sandy.SandyNet()
        self.assertEqual(network.firewall_backend, "iptables")
        self.assertTrue(network.configured)

    def test_constructor_falls_back_to_nftables(self):
        def which(name):
            return "/usr/sbin/nft" if name == "nft" else None

        with patch.object(sandy.shutil, "which", side_effect=which):
            with patch.object(sandy.SandyNet, "_bridge_exists", return_value=False):
                with patch.object(sandy.SandyNet, "_setup_bridge", return_value=True):
                    with captured_output():
                        network = sandy.SandyNet()
        self.assertEqual(network.firewall_backend, "nftables")
        self.assertTrue(network.configured)

    def test_constructor_without_create_only_inspects(self):
        # Mocks: the tool lookup and the read-only bridge queries. With
        # create=False the constructor must never set up the bridge.
        for exists, detected, configured in (
            (False, False, False),
            (True, True, True),
            (True, False, False),
        ):
            with self.subTest(exists=exists, detected=detected):
                with patch.object(
                    sandy.shutil, "which", side_effect=lambda name: f"/usr/sbin/{name}"
                ):
                    with patch.object(
                        sandy.SandyNet, "_bridge_exists", return_value=exists
                    ):
                        with patch.object(
                            sandy.SandyNet,
                            "_detect_existing_config",
                            return_value=detected,
                        ):
                            with patch.object(
                                sandy.SandyNet, "_setup_bridge", autospec=True
                            ) as setup:
                                with captured_output():
                                    network = sandy.SandyNet(create=False)
                setup.assert_not_called()
                self.assertIs(network.configured, configured)
                self.assertEqual(network.firewall_backend, "iptables")

    def test_preview_bridge_network_reuses_existing_bridge_without_mutation(self):
        def detect_existing(preview):
            preview.network = "10.222.5.0"
            preview.network_cidr = "10.222.5.0/24"
            preview.gateway = "10.222.5.1"
            return True

        with patch.object(
            sandy.SandyNet,
            "_bridge_exists",
            autospec=True,
            return_value=True,
        ):
            with patch.object(
                sandy.SandyNet,
                "_detect_existing_config",
                autospec=True,
                side_effect=detect_existing,
            ):
                with patch.object(
                    sandy.SandyNet,
                    "_find_unused_network",
                    autospec=True,
                ) as find_unused:
                    with patch.object(
                        sandy.SandyNet,
                        "_setup_bridge",
                        autospec=True,
                    ) as setup:
                        guest_network, planned_network = (
                            sandy.SandyNet.preview_bridge_network()
                        )

        self.assertEqual(guest_network, ("10.222.5.0/24", "10.222.5.1"))
        self.assertIsNone(planned_network)
        find_unused.assert_not_called()
        setup.assert_not_called()

    def test_preview_bridge_network_plans_unused_network_without_mutation(self):
        planned = ("10.222.5.0", "10.222.5.0/24", "10.222.5.1")
        with patch.object(
            sandy.SandyNet,
            "_bridge_exists",
            autospec=True,
            return_value=False,
        ):
            with patch.object(
                sandy.SandyNet,
                "_find_unused_network",
                autospec=True,
                return_value=planned,
            ) as find_unused:
                with patch.object(
                    sandy.SandyNet,
                    "_setup_bridge",
                    autospec=True,
                ) as setup:
                    guest_network, planned_network = (
                        sandy.SandyNet.preview_bridge_network()
                    )

        self.assertEqual(guest_network, ("10.222.5.0/24", "10.222.5.1"))
        self.assertEqual(planned_network, planned)
        find_unused.assert_called_once()
        setup.assert_not_called()

    def test_preview_bridge_network_rejects_invalid_existing_or_missing_plan(self):
        def detect_public_network(preview):
            preview.network = "8.8.8.0"
            preview.network_cidr = "8.8.8.0/24"
            preview.gateway = "8.8.8.1"
            return True

        with patch.object(
            sandy.SandyNet,
            "_bridge_exists",
            autospec=True,
            return_value=True,
        ):
            with patch.object(
                sandy.SandyNet,
                "_detect_existing_config",
                autospec=True,
                side_effect=detect_public_network,
            ):
                with self.assertRaisesRegex(PermissionError, "Invalid Sandy network"):
                    sandy.SandyNet.preview_bridge_network()

        with patch.object(
            sandy.SandyNet,
            "_bridge_exists",
            autospec=True,
            return_value=False,
        ):
            with patch.object(
                sandy.SandyNet,
                "_find_unused_network",
                autospec=True,
                return_value=None,
            ):
                with self.assertRaisesRegex(PermissionError, "unused network"):
                    sandy.SandyNet.preview_bridge_network()

    def test_bridge_exists(self):
        network = make_network()
        for returncode, expected in [(0, True), (1, False)]:
            with self.subTest(returncode=returncode):
                result = SimpleNamespace(returncode=returncode)
                with patch.object(sandy, "_run_secure_subprocess", return_value=result):
                    self.assertEqual(network._bridge_exists(), expected)

    def test_ensure_gateway_parses_ip_json(self):
        network = make_network()
        network.gateway = None
        network.network = None
        network.network_cidr = None
        payload = json.dumps(
            [
                {
                    "ifname": "sandybr0",
                    "addr_info": [
                        {
                            "family": "inet",
                            "local": "10.222.5.1",
                            "prefixlen": 24,
                        }
                    ],
                }
            ]
        )
        result = SimpleNamespace(stdout=payload)
        with patch.object(sandy, "_run_secure_subprocess", return_value=result):
            self.assertTrue(network._ensure_gateway())
        self.assertEqual(network.gateway, "10.222.5.1")
        self.assertEqual(network.network, "10.222.5.0")
        self.assertEqual(network.network_cidr, "10.222.5.0/24")

    def test_ensure_gateway_rejects_invalid_output(self):
        network = make_network()
        network.gateway = None
        network.network_cidr = None
        for output in ("not-json", "[]"):
            with self.subTest(output=output):
                result = SimpleNamespace(stdout=output)
                with patch.object(sandy, "_run_secure_subprocess", return_value=result):
                    with captured_output():
                        self.assertFalse(network._ensure_gateway())

    def test_network_conflict_checks_routes_and_addresses(self):
        network = make_network()
        conflict_route = SimpleNamespace(stdout="10.20.0.0/16 dev eth0\n")
        with patch.object(
            sandy,
            "_run_secure_subprocess",
            return_value=conflict_route,
        ):
            self.assertTrue(network._check_network_conflict("10.20.30.0/24"))

        no_route = SimpleNamespace(stdout="default via 192.0.2.1\n")
        conflict_address = SimpleNamespace(
            stdout="    inet 10.20.30.1/24 scope global\n"
        )
        with patch.object(
            sandy,
            "_run_secure_subprocess",
            side_effect=[no_route, conflict_address],
        ):
            self.assertTrue(network._check_network_conflict("10.20.30.0/24"))

        no_address = SimpleNamespace(stdout="    inet 192.168.1.1/24 scope global\n")
        with patch.object(
            sandy,
            "_run_secure_subprocess",
            side_effect=[no_route, no_address],
        ):
            self.assertFalse(network._check_network_conflict("10.20.30.0/24"))

    def test_find_unused_network_is_deterministic_and_bounded(self):
        network = make_network()
        with patch.object(network, "_get_seed_from_machine_id", return_value=1):
            with patch.object(
                network,
                "_check_network_conflict",
                side_effect=[True, False],
            ) as conflict:
                selected = network._find_unused_network()
        self.assertEqual(conflict.call_count, 2)
        self.assertEqual(selected[0] + "/24", selected[1])
        self.assertTrue(selected[2].endswith(".1"))

        with patch.object(network, "_get_seed_from_machine_id", return_value=1):
            with patch.object(network, "_check_network_conflict", return_value=True):
                self.assertIsNone(network._find_unused_network())

    def test_bridge_command_helpers(self):
        network = make_network()
        success = SimpleNamespace(returncode=0, stderr="")
        with patch.object(sandy, "_run_secure_subprocess", return_value=success) as run:
            self.assertTrue(network._create_bridge())
            self.assertTrue(network._configure_bridge_ip("10.200.1.1"))
            self.assertTrue(network._enable_ip_forwarding())
            self.assertTrue(network._enable_route_localnet())

        commands = [entry.args[0] for entry in run.call_args_list]
        self.assertIn(
            ["ip", "link", "add", "name", "sandybr0", "type", "bridge"],
            commands,
        )
        self.assertIn(
            ["ip", "addr", "add", "10.200.1.1/24", "dev", "sandybr0"],
            commands,
        )
        self.assertIn(["sysctl", "-w", "net.ipv4.ip_forward=1"], commands)

    def test_firewall_command_helpers(self):
        network = make_network()
        success = SimpleNamespace(returncode=0, stderr="")
        with patch.object(sandy, "_run_secure_subprocess", return_value=success) as run:
            self.assertTrue(
                network._run_iptables(
                    "-L",
                    "sandy-fwd",
                    table="filter",
                )
            )
            self.assertTrue(network._run_ip6tables("-L", "sandy-fwd6"))
            self.assertTrue(network._run_nft("list", "tables"))
            self.assertTrue(network._iptables_chain_exists("sandy-fwd"))
            self.assertTrue(network._ip6tables_chain_exists("sandy-fwd6"))
            self.assertTrue(network._nft_table_exists("ip", "sandy"))
            self.assertTrue(network._nft_chain_exists("ip", "sandy", "forward"))

        commands = [entry.args[0] for entry in run.call_args_list]
        self.assertIn(["iptables", "-t", "filter", "-L", "sandy-fwd"], commands)
        self.assertIn(["ip6tables", "-L", "sandy-fwd6"], commands)
        self.assertIn(["nft", "list", "tables"], commands)

    def test_firewall_helpers_return_false_on_failure(self):
        network = make_network()
        failed = SimpleNamespace(returncode=1, stderr="denied")
        for method, arguments in [
            (network._run_iptables, ("-L",)),
            (network._run_ip6tables, ("-L",)),
            (network._run_nft, ("list", "tables")),
        ]:
            with self.subTest(method=method.__name__):
                with patch.object(sandy, "_run_secure_subprocess", return_value=failed):
                    with captured_output():
                        self.assertFalse(method(*arguments))

    def test_setup_bridge_dispatches_firewall_backend(self):
        for backend in ("iptables", "nftables", None):
            with self.subTest(backend=backend):
                network = make_network()
                network.firewall_backend = backend
                with patch.object(
                    network,
                    "_find_unused_network",
                    return_value=("10.210.1.0", "10.210.1.0/24", "10.210.1.1"),
                ):
                    with patch.object(network, "_create_bridge", return_value=True):
                        with patch.object(network, "_enable_ip_forwarding"):
                            with patch.object(network, "_enable_route_localnet"):
                                with patch.object(
                                    network,
                                    "_configure_bridge_ip",
                                    return_value=True,
                                ):
                                    with patch.object(
                                        network,
                                        "_setup_iptables_chains",
                                        return_value=True,
                                    ) as ipt_chains:
                                        with patch.object(
                                            network,
                                            "_setup_ipv4_firewall_ipt",
                                            return_value=True,
                                        ):
                                            with patch.object(
                                                network,
                                                "_setup_ipv6_firewall_ipt",
                                            ):
                                                with patch.object(
                                                    network,
                                                    "_setup_ipv4_firewall_nft",
                                                    return_value=True,
                                                ) as nft:
                                                    with patch.object(
                                                        network,
                                                        "_setup_ipv6_firewall_nft",
                                                    ):
                                                        with captured_output():
                                                            self.assertTrue(
                                                                network._setup_bridge()
                                                            )
                self.assertEqual(network.gateway, "10.210.1.1")
                if backend == "iptables":
                    ipt_chains.assert_called_once_with("10.210.1.0/24")
                if backend == "nftables":
                    nft.assert_called_once_with("10.210.1.0/24")

    def test_setup_bridge_uses_valid_plan_and_skips_discovery(self):
        network = make_network()
        network.firewall_backend = None
        planned = ("10.222.5.0", "10.222.5.0/24", "10.222.5.1")
        with patch.object(network, "_find_unused_network") as find_unused:
            with patch.object(
                network,
                "_check_network_conflict",
                return_value=False,
            ) as conflict:
                with patch.object(network, "_create_bridge", return_value=True):
                    with patch.object(network, "_enable_ip_forwarding"):
                        with patch.object(network, "_enable_route_localnet"):
                            with patch.object(
                                network,
                                "_configure_bridge_ip",
                                return_value=True,
                            ):
                                with captured_output():
                                    self.assertTrue(network._setup_bridge(planned))

        find_unused.assert_not_called()
        conflict.assert_called_once_with("10.222.5.0/24")
        self.assertEqual(network.network, "10.222.5.0")
        self.assertEqual(network.network_cidr, "10.222.5.0/24")
        self.assertEqual(network.gateway, "10.222.5.1")

    def test_setup_bridge_rejects_invalid_plans_before_mutation(self):
        cases = (
            ("10.222.5.0", "not-cidr", "10.222.5.1"),
            ("10.222.6.0", "10.222.5.0/24", "10.222.5.1"),
            ("10.222.5.0", "10.222.5.0/24", "10.222.6.1"),
        )
        for planned in cases:
            with self.subTest(planned=planned):
                network = make_network()
                with patch.object(network, "_find_unused_network") as find_unused:
                    with patch.object(network, "_create_bridge") as create_bridge:
                        with captured_output():
                            self.assertFalse(network._setup_bridge(planned))
                find_unused.assert_not_called()
                create_bridge.assert_not_called()

    def test_setup_bridge_rejects_conflicting_plan_before_mutation(self):
        network = make_network()
        planned = ("10.222.5.0", "10.222.5.0/24", "10.222.5.1")
        with patch.object(network, "_find_unused_network") as find_unused:
            with patch.object(
                network,
                "_check_network_conflict",
                return_value=True,
            ) as conflict:
                with patch.object(network, "_create_bridge") as create_bridge:
                    with captured_output():
                        self.assertFalse(network._setup_bridge(planned))

        find_unused.assert_not_called()
        conflict.assert_called_once_with("10.222.5.0/24")
        create_bridge.assert_not_called()

    def test_cleanup_nftables_and_bridge(self):
        network = make_network()
        network.firewall_backend = "nftables"
        success = SimpleNamespace(returncode=0, stderr="")
        with patch.object(network, "_bridge_exists", return_value=True):
            with patch.object(network, "_nft_table_exists", return_value=True):
                with patch.object(network, "_run_nft") as run_nft:
                    with patch.object(
                        sandy,
                        "_run_secure_subprocess",
                        return_value=success,
                    ) as run:
                        with captured_output():
                            network.cleanup()

        self.assertEqual(run_nft.call_count, 2)
        run.assert_called_once_with(
            ["ip", "link", "delete", "sandybr0"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertFalse(network.configured)
        self.assertIsNone(network.network)

    def test_constructor_reports_unavailable_firewall_and_setup_failure(self):
        with patch.object(sandy.shutil, "which", return_value=None):
            with patch.object(sandy.SandyNet, "_bridge_exists", return_value=False):
                with patch.object(
                    sandy.SandyNet,
                    "_setup_bridge",
                    return_value=False,
                ):
                    with captured_output() as (stdout, _):
                        network = sandy.SandyNet()
        self.assertIsNone(network.firewall_backend)
        self.assertFalse(network.configured)
        self.assertIn("Neither iptables nor nftables", stdout.getvalue())
        self.assertIn("Failed to setup bridge", stdout.getvalue())

    def test_constructor_reports_invalid_existing_bridge(self):
        with patch.object(sandy.shutil, "which", return_value="/tool"):
            with patch.object(sandy.SandyNet, "_bridge_exists", return_value=True):
                with patch.object(
                    sandy.SandyNet,
                    "_detect_existing_config",
                    return_value=False,
                ):
                    with captured_output() as (stdout, _):
                        network = sandy.SandyNet()
        self.assertFalse(network.configured)
        self.assertIn("Could not detect network config", stdout.getvalue())

    def test_bridge_exists_handles_command_errors(self):
        network = make_network()
        for error in (
            FileNotFoundError(),
            subprocess.CalledProcessError(1, ["ip"]),
        ):
            with self.subTest(error=type(error).__name__):
                with patch.object(
                    sandy,
                    "_run_secure_subprocess",
                    side_effect=error,
                ):
                    self.assertFalse(network._bridge_exists())

    def test_gateway_detection_cached_errors_and_skipped_addresses(self):
        network = make_network()
        with patch.object(sandy, "_run_secure_subprocess") as run:
            self.assertTrue(network._detect_existing_config())
        run.assert_not_called()

        network.gateway = None
        network.network_cidr = None
        errors = (
            subprocess.CalledProcessError(
                1,
                ["ip"],
                output="failed stdout",
                stderr="failed stderr",
            ),
            RuntimeError("unexpected"),
        )
        for error in errors:
            with self.subTest(error=type(error).__name__):
                with patch.object(
                    sandy,
                    "_run_secure_subprocess",
                    side_effect=error,
                ):
                    with captured_output():
                        self.assertFalse(network._ensure_gateway())

    def test_gateway_detection_escapes_wrapper_error_once(self):
        network = make_network()
        network.gateway = None
        network.network_cidr = None
        error = subprocess.CalledProcessError(
            1,
            ["ip"],
            stderr="bad\nforged",
        )

        with patch.object(sandy.subprocess, "run", side_effect=error):
            with captured_output() as (stdout, _):
                self.assertFalse(network._ensure_gateway())

        output = stdout.getvalue()
        self.assertIn("'bad\\nforged'", output)
        self.assertNotIn("bad\nforged", output)
        self.assertNotIn("bad\\\\nforged", output)

        payload = json.dumps(
            [
                {"ifname": "other", "addr_info": []},
                {
                    "ifname": "sandybr0",
                    "addr_info": [
                        {"family": "inet6", "local": "::1", "prefixlen": 128},
                        {"family": "inet", "prefixlen": 24},
                        {
                            "family": "inet",
                            "local": "invalid",
                            "prefixlen": 24,
                        },
                    ],
                },
            ]
        )
        with patch.object(
            sandy,
            "_run_secure_subprocess",
            return_value=SimpleNamespace(stdout=payload),
        ):
            with captured_output():
                self.assertFalse(network._ensure_gateway())

    def test_machine_id_seed_and_fallback(self):
        network = make_network()
        with patch("builtins.open", mock_open(read_data="12345678abcdef\n")):
            self.assertEqual(network._get_seed_from_machine_id(), 0x12345678)

        for error in (FileNotFoundError(), ValueError("invalid")):
            with self.subTest(error=type(error).__name__):
                opened = mock_open(read_data="not-hex")
                if isinstance(error, FileNotFoundError):
                    opened.side_effect = error
                with patch("builtins.open", opened):
                    with captured_output():
                        self.assertEqual(
                            network._get_seed_from_machine_id(),
                            0xDEADBEEF,
                        )

    def test_network_conflict_fails_closed_on_invalid_input(self):
        network = make_network()
        with captured_output():
            self.assertTrue(network._check_network_conflict("invalid"))

        routes = SimpleNamespace(stdout="not-a-route dev eth0\n")
        addresses = SimpleNamespace(stdout="inet invalid\ninet\ninet6 ::1/128\n")
        with patch.object(
            sandy,
            "_run_secure_subprocess",
            side_effect=[routes, addresses],
        ):
            self.assertFalse(network._check_network_conflict("10.200.1.0/24"))

    def test_bridge_and_sysctl_failure_paths(self):
        network = make_network()
        failed = SimpleNamespace(returncode=1, stderr="denied")
        success = SimpleNamespace(returncode=0, stderr="")

        with patch.object(
            sandy,
            "_run_secure_subprocess",
            return_value=failed,
        ):
            with captured_output():
                self.assertFalse(network._create_bridge())
                self.assertFalse(network._configure_bridge_ip("10.200.1.1"))
                self.assertFalse(network._enable_ip_forwarding())
                self.assertFalse(network._enable_route_localnet())

        with patch.object(
            sandy,
            "_run_secure_subprocess",
            side_effect=[success, failed],
        ):
            with captured_output():
                self.assertFalse(network._create_bridge())

        for method, arguments in (
            (network._create_bridge, ()),
            (network._configure_bridge_ip, ("10.200.1.1",)),
            (network._enable_ip_forwarding, ()),
            (network._enable_route_localnet, ()),
        ):
            with self.subTest(method=method.__name__):
                with patch.object(
                    sandy,
                    "_run_secure_subprocess",
                    side_effect=RuntimeError("failure"),
                ):
                    with captured_output():
                        self.assertFalse(method(*arguments))

    def test_firewall_helper_exception_paths(self):
        network = make_network()
        methods = (
            (network._run_iptables, ("-L",)),
            (network._run_ip6tables, ("-L",)),
            (network._run_nft, ("list", "tables")),
            (network._iptables_chain_exists, ("chain", "filter")),
            (network._ip6tables_chain_exists, ("chain", "filter")),
            (network._nft_table_exists, ("ip", "sandy")),
            (network._nft_chain_exists, ("ip", "sandy", "forward")),
        )
        for method, arguments in methods:
            with self.subTest(method=method.__name__):
                with patch.object(
                    sandy,
                    "_run_secure_subprocess",
                    side_effect=RuntimeError("failure"),
                ):
                    with captured_output():
                        self.assertFalse(method(*arguments))

    def test_setup_bridge_short_circuits_on_critical_failures(self):
        network = make_network()
        network_info = ("10.200.1.0", "10.200.1.0/24", "10.200.1.1")
        with patch.object(network, "_find_unused_network", return_value=None):
            with captured_output():
                self.assertFalse(network._setup_bridge())

        cases = (
            ("_create_bridge", False, "iptables"),
            ("_configure_bridge_ip", False, "iptables"),
            ("_setup_iptables_chains", False, "iptables"),
            ("_setup_ipv4_firewall_ipt", False, "iptables"),
            ("_setup_ipv4_firewall_nft", False, "nftables"),
        )
        for failing_method, result, backend in cases:
            with self.subTest(failing_method=failing_method):
                network = make_network()
                network.firewall_backend = backend
                patches = {
                    "_find_unused_network": network_info,
                    "_create_bridge": True,
                    "_enable_ip_forwarding": True,
                    "_enable_route_localnet": True,
                    "_configure_bridge_ip": True,
                    "_setup_iptables_chains": True,
                    "_setup_ipv4_firewall_ipt": True,
                    "_setup_ipv6_firewall_ipt": True,
                    "_setup_ipv4_firewall_nft": True,
                    "_setup_ipv6_firewall_nft": True,
                }
                patches[failing_method] = result
                patchers = [
                    patch.object(network, name, return_value=value)
                    for name, value in patches.items()
                ]
                for patcher in patchers:
                    patcher.start()
                try:
                    with captured_output():
                        self.assertFalse(network._setup_bridge())
                finally:
                    for patcher in reversed(patchers):
                        patcher.stop()

    def test_cleanup_handles_missing_bridge_and_delete_failure(self):
        network = make_network()
        with patch.object(network, "_bridge_exists", return_value=False):
            with captured_output() as (stdout, _):
                network.cleanup()
        self.assertIn("nothing to clean up", stdout.getvalue())

        network = make_network()
        network.firewall_backend = "nftables"
        failed = SimpleNamespace(returncode=1, stderr="busy")
        with patch.object(network, "_bridge_exists", return_value=True):
            with patch.object(network, "_nft_table_exists", return_value=False):
                with patch.object(
                    sandy,
                    "_run_secure_subprocess",
                    return_value=failed,
                ):
                    with captured_output():
                        network.cleanup()
        self.assertTrue(network.configured)


class FirewallPolicyTests(unittest.TestCase):
    def test_nftables_base_creates_every_required_table_and_chain(self):
        network = make_network()
        with patch.object(network, "_nft_table_exists", return_value=False):
            with patch.object(network, "_nft_chain_exists", return_value=False):
                with patch.object(network, "_run_nft", return_value=True) as run:
                    self.assertTrue(network._setup_nftables_base())

        commands = [entry.args for entry in run.call_args_list]
        self.assertEqual(len(commands), 8)
        self.assertIn(("add", "table", "ip", "sandy"), commands)
        self.assertIn(("add", "table", "ip6", "sandy"), commands)
        chain_names = {
            entry.args[4]
            for entry in run.call_args_list
            if entry.args[:2] == ("add", "chain")
        }
        self.assertEqual(
            chain_names,
            {
                "postrouting",
                "prerouting",
                "output",
                "forward",
                "output_filter",
            },
        )

    def test_nftables_nat_output_chain_uses_numeric_priority(self):
        # Regression: nft 1.0.2 rejects "priority dstnat" for the output hook
        # (measured on the systemd 249 VM), so the chain was never created.
        network = make_network()
        with patch.object(network, "_nft_table_exists", return_value=False):
            with patch.object(network, "_nft_chain_exists", return_value=False):
                with patch.object(network, "_run_nft", return_value=True) as run:
                    network._setup_nftables_base()
        output = [
            entry.args
            for entry in run.call_args_list
            if entry.args[:5] == ("add", "chain", "ip", "sandy", "output")
        ]
        self.assertEqual(len(output), 1)
        self.assertIn("-100", output[0])
        self.assertNotIn("dstnat", output[0])

    def test_nftables_base_reuses_existing_objects(self):
        network = make_network()
        with patch.object(network, "_nft_table_exists", return_value=True):
            with patch.object(network, "_nft_chain_exists", return_value=True):
                with patch.object(network, "_run_nft") as run:
                    self.assertTrue(network._setup_nftables_base())
        run.assert_not_called()

    def test_iptables_chains_create_isolated_chain_topology(self):
        network = make_network()
        network._ensure_gateway = MagicMock(return_value=True)
        with patch.object(
            network,
            "_iptables_chain_exists",
            return_value=False,
        ):
            with patch.object(
                network,
                "_run_iptables",
                return_value=True,
            ) as run:
                self.assertTrue(network._setup_iptables_chains("10.200.1.0/24"))

        commands = [entry.args for entry in run.call_args_list]
        created_chains = {command[1] for command in commands if command[0] == "-N"}
        self.assertEqual(
            created_chains,
            {
                "sandy-nat-post",
                "sandy-nat-out",
                "sandy-nat-pre",
                "sandy-rej",
                "sandy-fwd",
                "sandy-out",
            },
        )
        self.assertTrue(
            any(
                command[:2] == ("-I", "FORWARD") and "10.200.1.0/24" in command
                for command in commands
            )
        )
        self.assertTrue(
            any(
                command[:2] == ("-A", "sandy-rej") and "REJECT" in command
                for command in commands
            )
        )

    def test_iptables_chains_flush_existing_chains(self):
        network = make_network()
        network._ensure_gateway = MagicMock(return_value=True)
        with patch.object(
            network,
            "_iptables_chain_exists",
            return_value=True,
        ):
            with patch.object(
                network,
                "_run_iptables",
                return_value=True,
            ) as run:
                self.assertTrue(network._setup_iptables_chains("10.200.1.0/24"))

        commands = [entry.args for entry in run.call_args_list]
        self.assertFalse(any(command[0] == "-N" for command in commands))
        for chain in (
            "sandy-nat-post",
            "sandy-nat-out",
            "sandy-nat-pre",
            "sandy-rej",
            "sandy-fwd",
            "sandy-out",
        ):
            with self.subTest(chain=chain):
                self.assertTrue(
                    any(command[:2] == ("-F", chain) for command in commands)
                )

    def test_ipv4_iptables_policy_blocks_private_destinations(self):
        network = make_network()
        with patch.object(
            network,
            "_run_iptables",
            return_value=True,
        ) as run:
            self.assertTrue(network._setup_ipv4_firewall_ipt("10.200.1.0/24"))

        commands = [entry.args for entry in run.call_args_list]
        for private_network in network.PRIVATE_NETWORKS:
            with self.subTest(network=private_network):
                self.assertTrue(
                    any(
                        command[:2] == ("-I", "sandy-fwd")
                        and private_network in command
                        and "sandy-rej" in command
                        for command in commands
                    )
                )
        self.assertTrue(
            any(
                command[:2] == ("-A", "sandy-nat-post") and "MASQUERADE" in command
                for command in commands
            )
        )
        self.assertTrue(
            any(
                command[:2] == ("-A", "sandy-out") and "REJECT" in command
                for command in commands
            )
        )

    def test_ipv6_iptables_policy_create_and_reuse(self):
        network = make_network()
        with patch.object(sandy.shutil, "which", return_value="/sbin/ip6tables"):
            with patch.object(
                network,
                "_ip6tables_chain_exists",
                return_value=False,
            ):
                with patch.object(
                    network,
                    "_run_ip6tables",
                    return_value=True,
                ) as create:
                    self.assertTrue(network._setup_ipv6_firewall_ipt())

            commands = [entry.args for entry in create.call_args_list]
            self.assertTrue(
                any(
                    command[:2] == ("-I", "FORWARD") and "sandy-fwd6" in command
                    for command in commands
                )
            )
            for private_network in network.IPV6_PRIVATE_NETWORKS:
                self.assertTrue(any(private_network in command for command in commands))

            with patch.object(
                network,
                "_ip6tables_chain_exists",
                return_value=True,
            ):
                with patch.object(
                    network,
                    "_run_ip6tables",
                    return_value=True,
                ) as reuse:
                    self.assertTrue(network._setup_ipv6_firewall_ipt())
        self.assertTrue(
            any(
                entry.args[:2] == ("-F", "sandy-rej6") for entry in reuse.call_args_list
            )
        )
        self.assertTrue(
            any(
                entry.args[:2] == ("-F", "sandy-fwd6") for entry in reuse.call_args_list
            )
        )

    def test_ipv6_iptables_policy_skips_when_tool_is_missing(self):
        network = make_network()
        with patch.object(sandy.shutil, "which", return_value=None):
            with patch.object(network, "_run_ip6tables") as run:
                self.assertTrue(network._setup_ipv6_firewall_ipt())
        run.assert_not_called()

    def test_ipv4_nft_policy_blocks_private_destinations(self):
        network = make_network()
        network._ensure_gateway = MagicMock(return_value=True)
        with patch.object(
            network,
            "_setup_nftables_base",
            return_value=True,
        ):
            with patch.object(
                network,
                "_setup_output_firewall_nft",
                return_value=True,
            ) as output:
                with patch.object(
                    network,
                    "_run_nft",
                    return_value=True,
                ) as run:
                    self.assertTrue(network._setup_ipv4_firewall_nft("10.200.1.0/24"))

        output.assert_called_once_with("10.200.1.0/24")
        commands = [entry.args for entry in run.call_args_list]
        for private_network in network.PRIVATE_NETWORKS:
            with self.subTest(network=private_network):
                matching = [
                    command for command in commands if private_network in command
                ]
                self.assertEqual(len(matching), 2)
                self.assertTrue(any("log" in command for command in matching))
                self.assertTrue(any("reject" in command for command in matching))
        self.assertTrue(any("masquerade" in command for command in commands))

    def test_nft_output_policy_allows_replies_then_rejects_new_traffic(self):
        network = make_network()
        network._ensure_gateway = MagicMock(return_value=True)
        with patch.object(
            network,
            "_setup_nftables_base",
            return_value=True,
        ):
            with patch.object(
                network,
                "_run_nft",
                return_value=True,
            ) as run:
                self.assertTrue(network._setup_output_firewall_nft("10.200.1.0/24"))

        commands = [entry.args for entry in run.call_args_list]
        self.assertEqual(len(commands), 5)
        self.assertTrue(
            any("icmp" in command and "accept" in command for command in commands)
        )
        self.assertTrue(
            any(
                "established,related" in command and "accept" in command
                for command in commands
            )
        )
        self.assertTrue(any("log" in command for command in commands))
        self.assertTrue(any("reject" in command for command in commands))

    def test_ipv6_nft_policy_logs_and_rejects_all_container_traffic(self):
        network = make_network()
        with patch.object(
            network,
            "_setup_nftables_base",
            return_value=True,
        ):
            with patch.object(
                network,
                "_run_nft",
                return_value=True,
            ) as run:
                self.assertTrue(network._setup_ipv6_firewall_nft())

        commands = [entry.args for entry in run.call_args_list]
        for private_network in network.IPV6_PRIVATE_NETWORKS:
            matching = [command for command in commands if private_network in command]
            self.assertEqual(len(matching), 2)
            self.assertTrue(any("log" in command for command in matching))
            self.assertTrue(any("reject" in command for command in matching))
        self.assertTrue(
            any(
                "reject" in command
                and not any(
                    private in command for private in network.IPV6_PRIVATE_NETWORKS
                )
                for command in commands
            )
        )

    def test_firewall_setup_precondition_failures(self):
        network = make_network()
        for method, arguments in (
            (network._setup_iptables_chains, ("10.200.1.0/24",)),
            (network._setup_ipv4_firewall_nft, ("10.200.1.0/24",)),
            (network._setup_output_firewall_nft, ("10.200.1.0/24",)),
        ):
            with self.subTest(method=method.__name__, condition="query"):
                network._ensure_gateway = MagicMock(return_value=False)
                with captured_output():
                    self.assertFalse(method(*arguments))

            with self.subTest(method=method.__name__, condition="missing"):
                network._ensure_gateway = MagicMock(return_value=True)
                network.gateway = None
                with captured_output():
                    self.assertFalse(method(*arguments))
                network.gateway = "10.200.1.1"

    def test_firewall_setup_exception_paths(self):
        network = make_network()
        network._ensure_gateway = MagicMock(return_value=True)
        cases = (
            ("_setup_nftables_base", "_nft_table_exists", ()),
            (
                "_setup_iptables_chains",
                "_iptables_chain_exists",
                ("10.200.1.0/24",),
            ),
            (
                "_setup_ipv4_firewall_ipt",
                "_run_iptables",
                ("10.200.1.0/24",),
            ),
            ("_setup_ipv6_firewall_ipt", "_ip6tables_chain_exists", ()),
            (
                "_setup_ipv4_firewall_nft",
                "_setup_nftables_base",
                ("10.200.1.0/24",),
            ),
            (
                "_setup_output_firewall_nft",
                "_setup_nftables_base",
                ("10.200.1.0/24",),
            ),
            (
                "_setup_ipv6_firewall_nft",
                "_setup_nftables_base",
                (),
            ),
        )
        for method_name, failing_name, arguments in cases:
            with self.subTest(method=method_name):
                with patch.object(
                    sandy.shutil,
                    "which",
                    return_value="/sbin/ip6tables",
                ):
                    with patch.object(
                        network,
                        failing_name,
                        side_effect=RuntimeError("failure"),
                    ):
                        with captured_output():
                            self.assertFalse(getattr(network, method_name)(*arguments))

    def test_cleanup_iptables_removes_all_chains_and_bridge(self):
        network = make_network()
        network.firewall_backend = "iptables"
        network.has_ip6tables = True
        success = SimpleNamespace(returncode=0, stderr="")
        with patch.object(network, "_bridge_exists", return_value=True):
            with patch.object(
                network,
                "_iptables_chain_exists",
                return_value=True,
            ):
                with patch.object(
                    network,
                    "_ip6tables_chain_exists",
                    return_value=True,
                ):
                    with patch.object(
                        network,
                        "_run_iptables",
                        return_value=True,
                    ) as iptables:
                        with patch.object(
                            network,
                            "_run_ip6tables",
                            return_value=True,
                        ) as ip6tables:
                            with patch.object(
                                sandy,
                                "_run_secure_subprocess",
                                return_value=success,
                            ) as run:
                                with captured_output():
                                    network.cleanup()

        deleted = [entry.args[0] for entry in run.call_args_list]
        self.assertIn(["ip", "link", "delete", "sandybr0"], deleted)
        self.assertGreaterEqual(iptables.call_count, 12)
        self.assertEqual(ip6tables.call_count, 4)
        self.assertFalse(network.configured)


class PortStateTests(unittest.TestCase):
    def test_state_serialization_and_parsing(self):
        instance = make_sandy()
        state = {"tcp:8080": {"container": "test", "container_port": 80}}
        serialized = instance._serialize_port_mapping_state(state)
        self.assertEqual(
            serialized,
            '{"tcp:8080":{"container":"test","container_port":80}}\n',
        )
        self.assertEqual(instance._parse_port_mapping_state(serialized), state)

        with captured_output():
            self.assertEqual(instance._parse_port_mapping_state("{bad"), {})
        self.assertEqual(instance._parse_port_mapping_state("[]"), {})
        self.assertEqual(instance._parse_port_mapping_state(""), {})

    def test_state_entry_sanitization(self):
        instance = make_sandy()
        entry = {
            "container": "test-box",
            "container_port": 80,
            "ip": "10.20.30.10",
        }
        self.assertEqual(
            instance._sanitize_state_entry("tcp:8080", entry),
            {
                "proto": "tcp",
                "host_port": 8080,
                "container_port": 80,
                "container": "test-box",
                "ip": "10.20.30.10",
            },
        )

        invalid = [
            ("bad-key", entry),
            ("tcp:8080", "not-a-dict"),
            ("tcp:8080", {**entry, "container": "Bad"}),
            ("tcp:0", entry),
            ("sctp:8080", entry),
            ("tcp:8080", {**entry, "container_port": 70000}),
        ]
        for key, value in invalid:
            with self.subTest(key=key, value=value):
                self.assertIsNone(instance._sanitize_state_entry(key, value))

    def test_state_storage_drops_derived_and_invalid_fields(self):
        instance = make_sandy()
        state = {
            "tcp:8080": {
                "proto": "tcp",
                "host_port": 8080,
                "container_port": 80,
                "container": "test-box",
                "ip": "10.20.30.10",
            },
            "invalid": {"container": "Bad"},
        }
        self.assertEqual(
            instance._serialize_port_state_for_storage(state),
            {
                "tcp:8080": {
                    "container": "test-box",
                    "container_port": 80,
                    "ip": "10.20.30.10",
                }
            },
        )

    def test_load_state_sanitizes_entries(self):
        instance = make_sandy()
        handle = io.StringIO(
            json.dumps(
                {
                    "tcp:8080": {
                        "container": "test-box",
                        "container_port": 80,
                    },
                    "bad": {"container": "Bad"},
                }
            )
        )
        loaded = instance._load_port_mapping_state(handle)
        self.assertEqual(list(loaded), ["tcp:8080"])
        self.assertEqual(loaded["tcp:8080"]["host_port"], 8080)

    def test_dedupe_port_mappings_preserves_first_value(self):
        instance = make_sandy()
        mappings = [
            ("tcp", 8080, 80),
            ("udp", 5353, 53),
            ("tcp", 8080, 8081),
        ]
        self.assertEqual(
            instance._dedupe_port_mappings(mappings),
            [("tcp", 8080, 80), ("udp", 5353, 53)],
        )

    def test_extract_ports_and_preferred_ip(self):
        instance = make_sandy()
        entries = [
            {
                "proto": "tcp",
                "host_port": 8080,
                "container_port": 80,
                "ip": "10.20.30.10",
            },
            {
                "proto": "udp",
                "host_port": 5353,
                "container_port": 53,
                "ip": "10.20.30.11",
            },
        ]
        self.assertEqual(
            instance._extract_ports_from_state(entries),
            (
                [("tcp", 8080, 80), ("udp", 5353, 53)],
                "10.20.30.10",
            ),
        )

    def test_update_port_state_rejects_cross_container_conflict(self):
        instance = make_sandy()
        instance.port_mappings = [("tcp", 8080, 80)]
        existing = {
            "tcp:8080": {
                "proto": "tcp",
                "host_port": 8080,
                "container_port": 8081,
                "container": "other-box",
                "ip": "10.20.30.11",
            }
        }
        raw = instance._serialize_port_mapping_state(
            instance._serialize_port_state_for_storage(existing)
        )
        with patch.object(
            instance,
            "_port_mapping_lock",
            side_effect=lambda **_kwargs: state_file_handle(raw),
        ):
            with patch.object(instance, "_persist_port_mapping_state"):
                with captured_output():
                    with self.assertRaises(SystemExit):
                        instance._update_port_mapping_state(
                            "test-box",
                            "10.20.30.10",
                        )

    def test_update_port_state_replaces_own_entries(self):
        instance = make_sandy()
        instance.port_mappings = [
            ("tcp", 8080, 80),
            ("tcp", 8080, 81),
        ]
        raw = json.dumps(
            {
                "udp:9000": {
                    "container": "test-box",
                    "container_port": 90,
                }
            }
        )
        persisted = MagicMock()
        with patch.object(
            instance,
            "_port_mapping_lock",
            side_effect=lambda **_kwargs: state_file_handle(raw),
        ):
            with patch.object(
                instance,
                "_persist_port_mapping_state",
                persisted,
            ):
                instance._update_port_mapping_state(
                    "test-box",
                    "10.20.30.10",
                )

        state = persisted.call_args.args[0]
        self.assertEqual(list(state), ["tcp:8080"])
        self.assertEqual(state["tcp:8080"]["container_port"], 80)
        self.assertEqual(state["tcp:8080"]["ip"], "10.20.30.10")

    def test_persist_state_writes_restrictive_file_or_unlinks(self):
        instance = make_sandy()
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "ports.json"
            with patch.object(
                instance,
                "_get_port_mappings_path",
                return_value=str(path),
            ):
                with patch.object(instance, "_ensure_cache_dir"):
                    with patch.object(sandy, "_write") as write:
                        instance._persist_port_mapping_state(
                            {
                                "tcp:8080": {
                                    "container": "test-box",
                                    "container_port": 80,
                                }
                            }
                        )
            write.assert_called_once()
            self.assertEqual(write.call_args.kwargs["mode"], 0o600)

            path.write_text("{}")
            with patch.object(
                instance,
                "_get_port_mappings_path",
                return_value=str(path),
            ):
                instance._persist_port_mapping_state({})
            self.assertFalse(path.exists())

    def test_port_mapping_lock_handles_missing_and_existing_files(self):
        instance = make_sandy()
        with tempfile.TemporaryDirectory() as temp_dir:
            state_path = Path(temp_dir) / "ports.json"
            lock_path = Path(temp_dir) / "ports.lock"

            def open_lock(_path):
                return lock_path.open("a+", encoding="utf-8")

            def open_state(_path):
                try:
                    return state_path.open("r", encoding="utf-8")
                except FileNotFoundError:
                    return None

            with patch.object(
                instance,
                "_get_port_mappings_path",
                return_value=str(state_path),
            ):
                with patch.object(
                    instance,
                    "_get_port_mappings_lock_path",
                    return_value=str(lock_path),
                ):
                    with patch.object(instance, "_ensure_cache_dir"):
                        with patch.object(
                            sandy,
                            "_open_stable_lock_file",
                            side_effect=open_lock,
                        ):
                            with patch.object(
                                sandy,
                                "_open_existing_managed_text_file",
                                side_effect=open_state,
                            ):
                                with instance._port_mapping_lock(
                                    exclusive=False
                                ) as handle:
                                    self.assertIsNone(handle)

                                state_path.write_text("{}\n", encoding="utf-8")
                                with instance._port_mapping_lock(
                                    exclusive=True,
                                ) as handle:
                                    self.assertIsNotNone(handle)
                                    self.assertEqual(handle.read(), "{}\n")
            self.assertTrue(lock_path.is_file())

    def test_port_mapping_lock_tolerates_unlock_failure(self):
        instance = make_sandy()
        lock_handle = MagicMock()
        lock_handle.fileno.return_value = 10
        state_handle = MagicMock()
        with patch.object(instance, "_ensure_cache_dir"):
            with patch.object(
                sandy,
                "_open_stable_lock_file",
                return_value=lock_handle,
            ):
                with patch.object(
                    sandy,
                    "_open_existing_managed_text_file",
                    return_value=state_handle,
                ):
                    with patch.object(
                        sandy.fcntl,
                        "flock",
                        side_effect=[None, OSError("unlock failed")],
                    ):
                        with instance._port_mapping_lock(exclusive=False) as locked:
                            self.assertIs(locked, state_handle)
        state_handle.close.assert_called_once_with()
        lock_handle.close.assert_called_once_with()

    def test_port_mapping_lock_with_a_timeout_does_not_wait_longer(self):
        # Mocks: the clock and the opens. The flock calls are real, on a
        # temporary lock file that another descriptor holds.
        instance = make_sandy()
        with tempfile.TemporaryDirectory() as temp_dir:
            lock_path = Path(temp_dir) / "ports.lock"
            opened = []

            def open_lock(_path):
                handle = lock_path.open("a+", encoding="utf-8")
                opened.append(handle)
                return handle

            with patch.object(instance, "_ensure_cache_dir"), patch.object(
                sandy, "_open_stable_lock_file", side_effect=open_lock
            ), patch.object(
                sandy, "_open_existing_managed_text_file", return_value=None
            ) as open_state:
                with lock_path.open("a+", encoding="utf-8") as holder:
                    sandy.fcntl.flock(holder.fileno(), sandy.fcntl.LOCK_EX)
                    body = MagicMock()
                    with patch.object(
                        sandy.time, "monotonic", side_effect=[100.0, 104.0, 106.0]
                    ), patch.object(sandy.time, "sleep") as sleep:
                        with self.assertRaisesRegex(
                            TimeoutError,
                            "^Timed out waiting for the Sandy port mapping lock$",
                        ):
                            with instance._port_mapping_lock(exclusive=True, timeout=5):
                                body()
                    body.assert_not_called()
                    sleep.assert_called_once_with(sandy.LIFECYCLE_LOCK_RETRY_INTERVAL)
                    open_state.assert_not_called()
                    self.assertTrue(opened[0].closed)
                # The lock is free now: the same call takes it at once.
                with instance._port_mapping_lock(exclusive=True, timeout=5) as handle:
                    self.assertIsNone(handle)
                open_state.assert_called_once()

    def test_port_mapping_lock_passes_its_timeout_and_name(self):
        instance = make_sandy()
        lock_path = instance._get_port_mappings_lock_path()
        state_path = instance._get_port_mappings_path()
        with patch.object(instance, "_ensure_cache_dir"), patch.object(
            sandy, "_locked_state_file"
        ) as locked:
            with instance._port_mapping_lock(exclusive=False, timeout=3):
                pass
            with instance._port_mapping_lock(exclusive=True):
                pass
        self.assertEqual(
            locked.call_args_list,
            [
                call(lock_path, state_path, False, 3, "port mapping"),
                call(lock_path, state_path, True, None, "port mapping"),
            ],
        )

    def test_port_mapping_lock_does_not_lock_again_in_an_exclusive_hold(self):
        # up publishes its ports, and removes them when the start fails, in
        # one hold of the lock. A second flock(2) on a new open of the lock
        # file would wait for that hold. Mocks: the paths and the opens
        # (temporary files); the flock calls are real and recorded. Another
        # thread does not share the hold (see the waiter test below).
        instance = make_sandy()
        locks = []
        real_flock = sandy.fcntl.flock

        def flock(fd, operation):
            locks.append(operation)
            return real_flock(fd, operation)

        with tempfile.TemporaryDirectory() as temp_dir:
            state_path = Path(temp_dir) / "ports.json"
            lock_path = Path(temp_dir) / "ports.lock"

            def open_state(_path):
                try:
                    return state_path.open("r", encoding="utf-8")
                except FileNotFoundError:
                    return None

            with patch.object(instance, "_ensure_cache_dir"), patch.object(
                instance, "_get_port_mappings_path", return_value=str(state_path)
            ), patch.object(
                instance, "_get_port_mappings_lock_path", return_value=str(lock_path)
            ), patch.object(
                sandy,
                "_open_stable_lock_file",
                side_effect=lambda _path: lock_path.open("a+", encoding="utf-8"),
            ), patch.object(
                sandy, "_open_existing_managed_text_file", side_effect=open_state
            ), patch.object(
                sandy.fcntl, "flock", side_effect=flock
            ):
                with instance._port_mapping_lock(exclusive=True) as handle:
                    self.assertIsNone(handle)
                    with instance._port_mapping_lock(
                        exclusive=True, timeout=5
                    ) as inner:
                        self.assertIsNone(inner)
                    # A write in the hold replaces the state file. A call in
                    # the hold opens the new file, and closes it.
                    state_path.write_text("{}\n", encoding="utf-8")
                    with instance._port_mapping_lock(exclusive=False) as inner:
                        self.assertEqual(inner.read(), "{}\n")
                    self.assertTrue(inner.closed)
                    self.assertEqual(locks, [sandy.fcntl.LOCK_EX])
                self.assertIsNone(instance._port_mapping_lock_holder)
                # After the hold, a call locks again. A body that raises ends
                # its hold, and a shared hold is never reentrant.
                with self.assertRaisesRegex(ValueError, "^body failed$"):
                    with instance._port_mapping_lock(exclusive=True):
                        raise ValueError("body failed")
                self.assertIsNone(instance._port_mapping_lock_holder)
                with instance._port_mapping_lock(exclusive=False):
                    self.assertIsNone(instance._port_mapping_lock_holder)
        unlock = sandy.fcntl.LOCK_UN
        self.assertEqual(
            locks,
            [
                sandy.fcntl.LOCK_EX,
                unlock,
                sandy.fcntl.LOCK_EX,
                unlock,
                sandy.fcntl.LOCK_SH,
                unlock,
            ],
        )

    def test_port_mapping_waiter_reads_state_only_after_stable_lock(self):
        instance = make_sandy()
        with tempfile.TemporaryDirectory() as temp_dir:
            state_path = Path(temp_dir) / "ports.json"
            lock_path = Path(temp_dir) / "ports.lock"
            state_path.write_text("old\n", encoding="utf-8")
            lock_path.touch()
            original_lock_stat = lock_path.stat()

            waiter_opened_lock = threading.Event()
            waiter_acquired_lock = threading.Event()
            waiter_result = []
            waiter_errors = []
            main_thread = threading.current_thread()

            def open_lock(_path):
                handle = lock_path.open("r+", encoding="utf-8")
                if threading.current_thread() is not main_thread:
                    waiter_opened_lock.set()
                return handle

            def open_state(_path):
                return state_path.open("r", encoding="utf-8")

            def wait_for_state():
                try:
                    with instance._port_mapping_lock(exclusive=True) as state_handle:
                        waiter_acquired_lock.set()
                        self.assertIsNotNone(state_handle)
                        waiter_result.append(state_handle.read())
                except BaseException as exc:
                    waiter_errors.append(exc)

            with patch.object(instance, "_ensure_cache_dir"):
                with patch.object(
                    instance,
                    "_get_port_mappings_lock_path",
                    return_value=str(lock_path),
                ):
                    with patch.object(
                        instance,
                        "_get_port_mappings_path",
                        return_value=str(state_path),
                    ):
                        with patch.object(
                            sandy,
                            "_open_stable_lock_file",
                            side_effect=open_lock,
                        ):
                            with patch.object(
                                sandy,
                                "_open_existing_managed_text_file",
                                side_effect=open_state,
                            ):
                                with instance._port_mapping_lock(exclusive=True):
                                    waiter = threading.Thread(
                                        target=wait_for_state,
                                    )
                                    waiter.start()
                                    self.assertTrue(waiter_opened_lock.wait(timeout=2))
                                    self.assertFalse(
                                        waiter_acquired_lock.wait(timeout=0.05)
                                    )
                                    replacement = state_path.with_suffix(".new")
                                    replacement.write_text(
                                        "new\n",
                                        encoding="utf-8",
                                    )
                                    os.replace(replacement, state_path)

                                waiter.join(timeout=2)

            self.assertFalse(waiter.is_alive())
            self.assertEqual(waiter_errors, [])
            self.assertEqual(waiter_result, ["new\n"])
            self.assertTrue(sandy._same_inode(original_lock_stat, lock_path.stat()))

    def test_state_none_and_missing_unlink_are_safe(self):
        instance = make_sandy()
        self.assertEqual(instance._load_port_mapping_state(None), {})
        with patch.object(
            instance,
            "_get_port_mappings_path",
            return_value="/missing",
        ):
            with patch.object(
                sandy.os,
                "unlink",
                side_effect=FileNotFoundError,
            ):
                instance._persist_port_mapping_state({})

    def test_cleanup_port_state_dispatches_and_restores_instance(self):
        instance = make_sandy()
        original_network = make_network()
        instance.network = original_network
        instance.port_mappings = [("udp", 5353, 53)]
        stored = [
            {
                "proto": "tcp",
                "host_port": 8080,
                "container_port": 80,
                "container": "other",
                "ip": "10.20.30.10",
            }
        ]
        with patch.object(
            instance,
            "_remove_port_mappings_from_state",
            return_value=stored,
        ):
            with patch.object(
                instance,
                "_cleanup_port_forwarding_ipt",
            ) as cleanup:
                instance._cleanup_port_mappings_for_container("other")

        cleanup.assert_called_once_with("10.20.30.10")
        self.assertEqual(instance.container, "ai-dev")
        self.assertEqual(instance.port_mappings, [("udp", 5353, 53)])
        self.assertIs(instance.network, original_network)

    def test_remove_port_mappings_filters_only_target_container(self):
        instance = make_sandy()
        raw = json.dumps(
            {
                "tcp:8080": {
                    "container": "target",
                    "container_port": 80,
                },
                "udp:5353": {
                    "container": "other",
                    "container_port": 53,
                },
            }
        )
        persisted = MagicMock()
        with patch.object(
            instance,
            "_port_mapping_lock",
            side_effect=lambda **_kwargs: state_file_handle(raw),
        ):
            with patch.object(
                instance,
                "_persist_port_mapping_state",
                persisted,
            ):
                removed = instance._remove_port_mappings_from_state("target")

        self.assertEqual(len(removed), 1)
        self.assertEqual(removed[0]["container"], "target")
        remaining = persisted.call_args.args[0]
        self.assertEqual(list(remaining), ["udp:5353"])

    def test_remove_port_mappings_handles_missing_or_empty_state(self):
        instance = make_sandy()
        for handle in (None, io.StringIO("{}")):
            with self.subTest(handle=handle):

                @contextmanager
                def locked():
                    yield handle

                with patch.object(
                    instance,
                    "_port_mapping_lock",
                    return_value=locked(),
                ):
                    with patch.object(
                        instance,
                        "_persist_port_mapping_state",
                    ) as persist:
                        self.assertEqual(
                            instance._remove_port_mappings_from_state("target"),
                            [],
                        )
                persist.assert_not_called()

    def test_clear_port_mapping_state_is_locked(self):
        instance = make_sandy()

        for handle in (io.StringIO("{}"), None):
            with self.subTest(handle=handle):

                @contextmanager
                def locked():
                    yield handle

                with patch.object(
                    instance,
                    "_port_mapping_lock",
                    return_value=locked(),
                ) as lock:
                    with patch.object(
                        instance,
                        "_persist_port_mapping_state",
                    ) as persist:
                        instance._clear_port_mapping_state()
                lock.assert_called_once_with(exclusive=True)
                if handle is None:
                    persist.assert_not_called()
                else:
                    persist.assert_called_once_with({})

    def test_update_empty_port_state_removes_own_stale_entries(self):
        instance = make_sandy()
        instance.port_mappings = []
        raw = json.dumps(
            {
                "tcp:8080": {
                    "container": "test-box",
                    "container_port": 80,
                },
                "udp:5353": {
                    "container": "other",
                    "container_port": 53,
                },
            }
        )
        persisted = MagicMock()
        with patch.object(
            instance,
            "_port_mapping_lock",
            side_effect=lambda **_kwargs: state_file_handle(raw),
        ):
            with patch.object(
                instance,
                "_persist_port_mapping_state",
                persisted,
            ):
                instance._update_port_mapping_state("test-box", "public")
        self.assertEqual(list(persisted.call_args.args[0]), ["udp:5353"])

        @contextmanager
        def missing_handle():
            yield None

        with patch.object(
            instance,
            "_port_mapping_lock",
            return_value=missing_handle(),
        ):
            with patch.object(
                instance,
                "_persist_port_mapping_state",
            ) as persist:
                instance._update_port_mapping_state("test-box", "")
        persist.assert_not_called()

    def test_existing_network_reuses_or_inspects_without_creating(self):
        # Mocks: the SandyNet type, so that no host command runs.
        instance = make_sandy()
        configured = make_network()
        instance.network = configured
        with patch.object(sandy, "SandyNet") as network_type:
            self.assertIs(instance._existing_network(), configured)
        network_type.assert_not_called()

        unconfigured = make_network()
        unconfigured.configured = False
        for current in (None, unconfigured):
            with self.subTest(current=current):
                instance.network = current
                inspected = make_network()
                with patch.object(
                    sandy, "SandyNet", return_value=inspected
                ) as network_type:
                    self.assertIs(instance._existing_network(), inspected)
                network_type.assert_called_once_with(create=False)

    def test_cleanup_port_state_handles_incomplete_state(self):
        instance = make_sandy()
        cases = (
            ([], ""),
            ([{"invalid": True}], ""),
            (
                [
                    {
                        "proto": "tcp",
                        "host_port": 8080,
                        "container_port": 80,
                    }
                ],
                "Could not determine IP",
            ),
        )
        for stored, message in cases:
            with self.subTest(message=message, stored=stored):
                with patch.object(
                    instance,
                    "_remove_port_mappings_from_state",
                    return_value=stored,
                ):
                    with patch.object(
                        instance,
                        "_get_container_ip",
                        return_value=None,
                    ):
                        with patch.object(instance, "_existing_network") as existing:
                            with captured_output() as (stdout, _):
                                instance._cleanup_port_mappings_for_container("target")
                existing.assert_not_called()
                if message:
                    self.assertIn(message, stdout.getvalue())

    def test_cleanup_port_state_dispatches_nftables_when_table_exists(self):
        # Mocks: the port state, the nft table query, and the rule cleanup.
        stored = [
            {
                "proto": "tcp",
                "host_port": 8080,
                "container_port": 80,
                "ip": "10.20.30.10",
            }
        ]
        for table_exists in (True, False):
            with self.subTest(table_exists=table_exists):
                instance = make_sandy()
                network = make_network()
                network.firewall_backend = "nftables"
                instance.network = network
                with patch.object(
                    instance,
                    "_remove_port_mappings_from_state",
                    return_value=stored,
                ):
                    with patch.object(
                        network, "_nft_table_exists", return_value=table_exists
                    ) as table:
                        with patch.object(
                            instance,
                            "_cleanup_port_forwarding_nft",
                        ) as cleanup:
                            instance._cleanup_port_mappings_for_container("target")
                table.assert_called_once_with("ip", "sandy")
                if table_exists:
                    cleanup.assert_called_once_with("10.20.30.10")
                else:
                    cleanup.assert_not_called()
                self.assertIs(instance.network, network)

    def test_cleanup_port_state_never_creates_network(self):
        # Regression test for `up --network host` building the bridge. Mocks:
        # the port state, the firewall tool lookup, and Sandy's subprocess
        # wrapper; the bridge is missing, as after a host reboot. Only
        # read-only queries may run, and nothing may be created.
        stored = [
            {
                "proto": "tcp",
                "host_port": 8080,
                "container_port": 80,
                "container": "target",
                "ip": "10.20.30.10",
            }
        ]
        cases = (
            (
                "iptables",
                False,
                [["ip", "link", "show", "sandybr0"]],
            ),
            (
                "nftables",
                True,
                [
                    ["ip", "link", "show", "sandybr0"],
                    ["nft", "list", "table", "ip", "sandy"],
                ],
            ),
            (
                "nftables",
                False,
                [
                    ["ip", "link", "show", "sandybr0"],
                    ["nft", "list", "table", "ip", "sandy"],
                ],
            ),
            # No firewall tool: the state goes, and no rule command runs.
            (None, False, [["ip", "link", "show", "sandybr0"]]),
        )
        for backend, table_exists, expected_commands in cases:
            with self.subTest(backend=backend, table_exists=table_exists):
                instance = make_sandy()
                commands = []

                def run(command, **_kwargs):
                    commands.append(command)
                    found = command[0] == "nft" and table_exists
                    return SimpleNamespace(
                        returncode=0 if found else 1, stdout="", stderr=""
                    )

                tools = {
                    "iptables": {"iptables", "ip6tables", "nft"},
                    "nftables": {"nft"},
                    None: set(),
                }[backend]
                with ExitStack() as stack:
                    remove = stack.enter_context(
                        patch.object(
                            instance,
                            "_remove_port_mappings_from_state",
                            return_value=stored,
                        )
                    )
                    stack.enter_context(
                        patch.object(
                            sandy.shutil,
                            "which",
                            side_effect=lambda name: (
                                f"/usr/sbin/{name}" if name in tools else None
                            ),
                        )
                    )
                    stack.enter_context(
                        patch.object(sandy, "_run_secure_subprocess", side_effect=run)
                    )
                    setup = stack.enter_context(
                        patch.object(sandy.SandyNet, "_setup_bridge", autospec=True)
                    )
                    ipt = stack.enter_context(
                        patch.object(instance, "_cleanup_port_forwarding_ipt")
                    )
                    nft = stack.enter_context(
                        patch.object(instance, "_cleanup_port_forwarding_nft")
                    )
                    stack.enter_context(captured_output())
                    instance._cleanup_port_mappings_for_container("target")

                # No limit on the wait for the port mapping lock.
                remove.assert_called_once_with("target", None)
                setup.assert_not_called()
                ipt.assert_not_called()
                if backend == "nftables" and table_exists:
                    nft.assert_called_once_with("10.20.30.10")
                else:
                    nft.assert_not_called()
                self.assertEqual(commands, expected_commands)
                # A lenient `up` builds its own network after this cleanup.
                self.assertIsNone(instance.network)

    def test_cleanup_port_state_uses_existing_bridge(self):
        # Mocks: the port state, the read-only bridge queries, and the rule
        # cleanup. An existing bridge is reused; nothing is set up.
        instance = make_sandy()
        stored = [
            {
                "proto": "tcp",
                "host_port": 8080,
                "container_port": 80,
                "ip": "10.20.30.10",
            }
        ]
        with ExitStack() as stack:
            stack.enter_context(
                patch.object(
                    instance, "_remove_port_mappings_from_state", return_value=stored
                )
            )
            stack.enter_context(
                patch.object(
                    sandy.shutil, "which", side_effect=lambda name: f"/usr/sbin/{name}"
                )
            )
            stack.enter_context(
                patch.object(sandy.SandyNet, "_bridge_exists", return_value=True)
            )
            stack.enter_context(
                patch.object(
                    sandy.SandyNet, "_detect_existing_config", return_value=True
                )
            )
            setup = stack.enter_context(
                patch.object(sandy.SandyNet, "_setup_bridge", autospec=True)
            )
            ipt = stack.enter_context(
                patch.object(instance, "_cleanup_port_forwarding_ipt")
            )
            instance._cleanup_port_mappings_for_container("target")
        setup.assert_not_called()
        ipt.assert_called_once_with("10.20.30.10")
        self.assertIsNone(instance.network)


class CacheTests(unittest.TestCase):
    def test_hash_and_cache_key_are_deterministic(self):
        instance = make_sandy()
        with tempfile.TemporaryDirectory() as temp_dir:
            bootstrap = Path(temp_dir) / "bootstrap.sh"
            setup = Path(temp_dir) / "setup.sh"
            bootstrap.write_text("bootstrap")
            setup.write_text("setup")
            instance.bootstrap_script = str(bootstrap)
            instance.cn_setup_container = str(setup)
            with patch.dict(sandy.os.environ, {}, clear=True):
                first = instance._compute_cache_key()
                second = instance._compute_cache_key()
        self.assertEqual(first, second)
        self.assertEqual(len(first), 64)

    def test_cache_key_changes_with_each_manifest_input(self):
        instance = make_sandy()
        with tempfile.TemporaryDirectory() as temp_dir:
            bootstrap = Path(temp_dir) / "bootstrap.sh"
            setup = Path(temp_dir) / "setup.sh"
            bootstrap.write_text("bootstrap")
            setup.write_text("setup")
            instance.bootstrap_script = str(bootstrap)
            instance.cn_setup_container = str(setup)

            with patch.dict(sandy.os.environ, {}, clear=True):
                baseline = instance._compute_cache_key()
                changed_keys = []

                instance.bootstrap_method = "debootstrap"
                changed_keys.append(instance._compute_cache_key())
                instance.bootstrap_method = "OCI"

                instance.base_image = "ubuntu:noble"
                changed_keys.append(instance._compute_cache_key())
                instance.base_image = "debian:trixie-slim"

                instance.user = "tester"
                changed_keys.append(instance._compute_cache_key())
                instance.user = "developer"

                bootstrap.write_text("changed bootstrap")
                changed_keys.append(instance._compute_cache_key())
                bootstrap.write_text("bootstrap")

                setup.write_text("changed setup")
                changed_keys.append(instance._compute_cache_key())

        for changed_key in changed_keys:
            with self.subTest(changed_key=changed_key):
                self.assertNotEqual(changed_key, baseline)
        self.assertEqual(len(set(changed_keys)), len(changed_keys))

    def test_custom_setup_script_must_exist(self):
        instance = make_sandy()
        with tempfile.TemporaryDirectory() as temp_dir:
            custom = Path(temp_dir) / "custom.sh"
            custom.write_text("safe")
            with patch.dict(
                sandy.os.environ,
                {"SANDY_SETUP_SCRIPT": str(custom)},
                clear=True,
            ):
                self.assertEqual(instance._get_setup_script_path(), str(custom))
            with patch.dict(
                sandy.os.environ,
                {"SANDY_SETUP_SCRIPT": str(custom) + ".missing"},
                clear=True,
            ):
                self.assertEqual(
                    instance._get_setup_script_path(),
                    instance.cn_setup_container,
                )

    def test_build_uses_cache_when_present(self):
        instance = make_sandy()
        with patch.object(instance, "_get_machine_dir", return_value="/machine"):
            with patch.object(sandy.os.path, "exists", side_effect=[False, True]):
                with patch.object(
                    instance,
                    "_get_cache_path",
                    return_value="/cache/key.tar",
                ):
                    with patch.object(
                        instance,
                        "_new_machine_from_cache",
                    ) as cached:
                        with patch.object(
                            instance,
                            "_new_machine_from_scratch",
                        ) as fresh:
                            with patch.dict(sandy.os.environ, {}, clear=True):
                                with captured_output():
                                    instance._build()
        cached.assert_called_once_with("/cache/key.tar", "/machine", None)
        fresh.assert_not_called()

    def test_build_can_disable_cache(self):
        instance = make_sandy()
        with patch.object(instance, "_get_machine_dir", return_value="/machine"):
            with patch.object(sandy.os.path, "exists", return_value=False):
                with patch.object(instance, "_new_machine_from_scratch") as fresh:
                    with patch.dict(
                        sandy.os.environ,
                        {"SANDY_CONTAINER_CACHE": "no"},
                        clear=True,
                    ):
                        instance._build()
        fresh.assert_called_once_with("/machine", False, None)

    def test_build_skips_existing_machine_and_uses_fresh_cache_miss(self):
        instance = make_sandy()
        with patch.object(instance, "_get_machine_dir", return_value="/machine"):
            with patch.object(sandy.os.path, "exists", return_value=True):
                with patch.object(
                    instance,
                    "_new_machine_from_scratch",
                ) as fresh:
                    with captured_output():
                        instance._build()
        fresh.assert_not_called()

        with patch.object(instance, "_get_machine_dir", return_value="/machine"):
            with patch.object(
                sandy.os.path,
                "exists",
                side_effect=[False, False],
            ):
                with patch.object(
                    instance,
                    "_get_cache_path",
                    return_value="/cache/key.tar",
                ):
                    with patch.object(
                        instance,
                        "_new_machine_from_scratch",
                    ) as fresh:
                        with patch.dict(sandy.os.environ, {}, clear=True):
                            instance._build()
        fresh.assert_called_once_with("/machine", True, None)

    def test_cache_path_combines_manifest_hash(self):
        instance = make_sandy()
        with patch.object(
            instance,
            "_get_cache_dir",
            return_value="/cache",
        ):
            with patch.object(
                instance,
                "_compute_cache_key",
                return_value="abc123",
            ):
                self.assertEqual(
                    instance._get_cache_path(),
                    "/cache/abc123.tar",
                )

    def test_clear_cache_preserves_port_state(self):
        instance = make_sandy()
        with tempfile.TemporaryDirectory() as temp_dir:
            cache = Path(temp_dir)
            state = cache / sandy.PORT_MAPPINGS_FILENAME
            lock = cache / sandy.PORT_MAPPINGS_LOCK_FILENAME
            lifecycle_lock = cache / sandy.LIFECYCLE_LOCK_FILENAME
            # The saved shared limits are configuration, and their lock
            # inode is permanent.
            shared_limits = cache / sandy.SHARED_LIMITS_FILENAME
            shared_limits_lock = cache / sandy.SHARED_LIMITS_LOCK_FILENAME
            # The up lock of each container name is permanent too, and so is
            # the lock of the addresses.
            up_lock = cache / "up-ai-dev.lock"
            addresses_lock = cache / sandy.ADDRESSES_LOCK_FILENAME
            look_alike = cache / "up-Bad.lock"
            archive = cache / "cache.tar"
            directory = cache / "partial"
            state_alias = cache / "state-alias"
            directory_alias = cache / "directory-alias"
            state.write_text("{}")
            lock.write_text("")
            lifecycle_lock.write_text("")
            shared_limits.write_text("{}\n")
            shared_limits_lock.write_text("")
            up_lock.write_text("")
            addresses_lock.write_text("")
            look_alike.write_text("")
            archive.write_text("archive")
            directory.mkdir()
            (directory / "file").write_text("partial")
            state_alias.symlink_to(state)
            directory_alias.symlink_to(directory, target_is_directory=True)
            with patch.object(instance, "_get_cache_dir", return_value=temp_dir):
                with patch.object(
                    instance,
                    "_get_port_mappings_path",
                    return_value=str(state),
                ):
                    with patch.object(sandy, "_remove_managed_tree") as rmtree:
                        self.assertTrue(instance._clear_cache_contents())
            self.assertTrue(state.exists())
            self.assertTrue(lock.exists())
            self.assertTrue(lifecycle_lock.exists())
            self.assertTrue(shared_limits.exists())
            self.assertTrue(shared_limits_lock.exists())
            self.assertTrue(up_lock.exists())
            self.assertTrue(addresses_lock.exists())
            self.assertFalse(look_alike.exists())
            self.assertFalse(archive.exists())
            self.assertFalse(state_alias.exists())
            self.assertFalse(directory_alias.exists())
            self.assertTrue(directory.exists())
            rmtree.assert_called_once_with(str(directory))

    def test_create_cache_writes_manifest_and_hardened_tar_command(self):
        instance = make_sandy()
        instance._create_manifest_content = MagicMock(
            return_value=["bootstrap=hash", "setup=hash"]
        )
        success = SimpleNamespace(returncode=0)
        with tempfile.TemporaryDirectory() as source:
            manifest = Path(source) / ".sandy.manifest"

            def write_manifest(path, content, mode=0o600):
                self.assertEqual(mode, 0o600)
                Path(path).write_text(content)

            with patch.object(sandy, "_verify_safe_dir") as verify:
                with patch.object(instance, "_ensure_cache_dir"):
                    with patch.object(
                        instance,
                        "_get_cache_path",
                        return_value="/cache/key.tar",
                    ):
                        with patch.object(
                            sandy,
                            "_write",
                            side_effect=write_manifest,
                        ):
                            with patch.object(
                                sandy,
                                "_run_secure_subprocess",
                                return_value=success,
                            ) as run:
                                with captured_output():
                                    instance._create_cache(source)

            verify.assert_called_once_with(source)
            command = run.call_args.args[0]
            self.assertEqual(
                command[:4],
                ["tar", "--create", "--file", "/cache/key.tar"],
            )
            self.assertIn("--numeric-owner", command)
            self.assertIn("--xattrs", command)
            self.assertIn("--acls", command)
            self.assertIn("--exclude=etc/machine-id", command)
            self.assertFalse(manifest.exists())

    def test_create_cache_removes_partial_archive_after_failure(self):
        instance = make_sandy()
        failed = SimpleNamespace(returncode=1)
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "source"
            source.mkdir()
            archive = Path(temp_dir) / "cache.tar"

            def write_file(path, content, mode=0o600):
                _ = mode
                Path(path).write_text(content)

            def run_tar(_command):
                archive.write_text("partial")
                return failed

            with patch.object(sandy, "_verify_safe_dir"):
                with patch.object(instance, "_ensure_cache_dir"):
                    with patch.object(
                        instance,
                        "_get_cache_path",
                        return_value=str(archive),
                    ):
                        with patch.object(
                            sandy,
                            "_write",
                            side_effect=write_file,
                        ):
                            with patch.object(
                                sandy,
                                "_run_secure_subprocess",
                                side_effect=run_tar,
                            ):
                                with captured_output():
                                    instance._create_cache(str(source))
            self.assertFalse(archive.exists())
            self.assertFalse((source / ".sandy.manifest").exists())

    def test_clear_cache_missing_and_racy_entries(self):
        instance = make_sandy()
        with patch.object(instance, "_get_cache_dir", return_value="/missing"):
            with patch.object(sandy.os.path, "exists", return_value=False):
                self.assertFalse(instance._clear_cache_contents())

        with patch.object(instance, "_get_cache_dir", return_value="/cache"):
            with patch.object(
                instance,
                "_get_port_mappings_path",
                return_value="/cache/ports.json",
            ):
                with patch.object(sandy.os.path, "exists", return_value=True):
                    with patch.object(
                        sandy.os,
                        "listdir",
                        return_value=["vanished"],
                    ):
                        with patch.object(
                            sandy.os,
                            "lstat",
                            side_effect=FileNotFoundError,
                        ):
                            self.assertFalse(instance._clear_cache_contents())

    def test_new_machine_from_cache_restores_identity_and_network(self):
        instance = make_sandy()
        instance.network = make_network()
        instance.network._ensure_gateway = MagicMock(return_value=True)
        success = SimpleNamespace(returncode=0)
        with tempfile.TemporaryDirectory() as temp_dir:
            machine_fd = os.open(temp_dir, sandy.DIRECTORY_OPEN_FLAGS)
            with patch.object(sandy, "_verify_safe_dir") as verify:
                with patch.object(sandy, "_mkdir") as mkdir:
                    with patch.object(
                        sandy,
                        "_open_verified_dir",
                        return_value=machine_fd,
                    ) as open_dir:
                        with patch.object(
                            sandy,
                            "_run_secure_subprocess",
                            return_value=success,
                        ) as run:
                            with patch.object(sandy, "_create_guest_files") as guest:
                                with captured_output():
                                    instance._new_machine_from_cache(
                                        "/cache/key.tar",
                                        "/machine",
                                    )

        verify.assert_called_once_with("/cache")
        mkdir.assert_called_once_with("/machine")
        open_dir.assert_called_once_with("/machine")
        self.assertEqual(run.call_count, 2)
        extract = run.call_args_list[0].args[0]
        self.assertEqual(extract[:4], ["tar", "--extract", "--file", "/cache/key.tar"])
        machine_id = run.call_args_list[1]
        self.assertEqual(machine_id.args[0][0], "systemd-machine-id-setup")
        self.assertRegex(machine_id.args[0][1], r"^--root=/proc/self/fd/[0-9]+$")
        self.assertEqual(len(machine_id.kwargs["pass_fds"]), 1)
        guest.assert_called_once_with(
            "/machine",
            "ai-dev",
            "10.200.1.0/24",
            "10.200.1.1",
        )

    def test_new_machine_from_cache_exits_on_invalid_archive(self):
        instance = make_sandy()
        failed = SimpleNamespace(returncode=2)
        with patch.object(sandy, "_verify_safe_dir"):
            with patch.object(sandy, "_mkdir"):
                with patch.object(
                    sandy,
                    "_run_secure_subprocess",
                    return_value=failed,
                ):
                    with captured_output():
                        with self.assertRaises(SystemExit):
                            instance._new_machine_from_cache(
                                "/cache/bad.tar",
                                "/machine",
                            )

    def test_new_machine_from_scratch_bootstraps_and_caches(self):
        instance = make_sandy()
        instance.network = make_network()
        instance.network._ensure_gateway = MagicMock(return_value=True)
        success = SimpleNamespace(returncode=0)
        setup_content = "#!/bin/sh\nuser=%%MACHINE_USER%%\n"
        with patch.object(
            sandy,
            "_run_secure_subprocess",
            return_value=success,
        ) as run:
            with tempfile.TemporaryDirectory() as temp_dir:
                machine_fd = os.open(temp_dir, sandy.DIRECTORY_OPEN_FLAGS)
                with patch.object(sandy, "_verify_safe_dir") as verify:
                    with patch.object(
                        sandy,
                        "_open_verified_dir",
                        return_value=machine_fd,
                    ) as open_dir:
                        with patch.object(
                            sandy.os.path,
                            "exists",
                            return_value=False,
                        ):
                            with patch(
                                "builtins.open",
                                mock_open(read_data=setup_content),
                            ):
                                with patch.object(sandy, "_write") as write:
                                    with patch.object(
                                        sandy,
                                        "_create_guest_files",
                                    ) as guest:
                                        with patch.object(
                                            instance,
                                            "_create_cache",
                                        ) as create_cache:
                                            with captured_output():
                                                instance._new_machine_from_scratch(
                                                    "/machine",
                                                    cache_enabled=True,
                                                )

        self.assertEqual(
            run.call_args_list[0].args[0],
            [instance.bootstrap_script, "/machine", instance.base_image],
        )
        verify.assert_called_once_with("/machine")
        open_dir.assert_called_once_with("/machine")
        written_content = write.call_args.args[1]
        self.assertIn("user=developer", written_content)
        self.assertNotIn("%%MACHINE_USER%%", written_content)
        machine_id = run.call_args_list[1]
        self.assertEqual(machine_id.args[0][0], "systemd-machine-id-setup")
        self.assertRegex(machine_id.args[0][1], r"^--root=/proc/self/fd/[0-9]+$")
        self.assertEqual(len(machine_id.kwargs["pass_fds"]), 1)
        setup_call = run.call_args_list[2]
        self.assertEqual(setup_call.args[0][0], "systemd-nspawn")
        self.assertRegex(setup_call.args[0][1], r"^--directory=/proc/self/fd/[0-9]+$")
        self.assertEqual(
            setup_call.kwargs["env"],
            sandy._container_environment("root", "/root"),
        )
        self.assertEqual(len(setup_call.kwargs["pass_fds"]), 1)
        guest.assert_called_once_with(
            "/machine",
            "ai-dev",
            "10.200.1.0/24",
            "10.200.1.1",
        )
        create_cache.assert_called_once_with("/machine")

    def test_new_machine_from_scratch_handles_bootstrap_failure(self):
        instance = make_sandy()
        failed = SimpleNamespace(returncode=1)
        with patch.object(
            sandy,
            "_run_secure_subprocess",
            return_value=failed,
        ):
            with patch.object(instance, "_remove_machine_dir") as remove:
                with captured_output():
                    with self.assertRaises(SystemExit):
                        instance._new_machine_from_scratch("/machine")
        remove.assert_called_once_with("/machine", prompt=False)

    def test_new_machine_from_scratch_skips_existing_setup(self):
        instance = make_sandy()
        success = SimpleNamespace(returncode=0)
        with patch.object(
            sandy,
            "_run_secure_subprocess",
            return_value=success,
        ) as run:
            with tempfile.TemporaryDirectory() as temp_dir:
                machine_fd = os.open(temp_dir, sandy.DIRECTORY_OPEN_FLAGS)
                with patch.object(sandy, "_verify_safe_dir"):
                    with patch.object(
                        sandy,
                        "_open_verified_dir",
                        return_value=machine_fd,
                    ):
                        with patch.object(sandy.os.path, "exists", return_value=True):
                            with patch.object(sandy, "_write") as write:
                                with captured_output():
                                    instance._new_machine_from_scratch("/machine")
        self.assertEqual(run.call_count, 2)
        self.assertEqual(run.call_args_list[1].args[0][0], "systemd-machine-id-setup")
        self.assertRegex(run.call_args_list[1].args[0][1], r"^--root=/proc/self/fd/")
        write.assert_not_called()

    def test_purge_cache_all_outcomes(self):
        instance = make_sandy()
        cases = (
            (False, False, "No cache directory"),
            (
                True,
                True,
                "except coordination state and saved shared limits",
            ),
            (
                True,
                False,
                "retained only coordination state and saved shared limits",
            ),
        )
        for cache_exists, removed, message in cases:
            with self.subTest(message=message):

                @contextmanager
                def locked():
                    yield None

                with patch.object(
                    instance,
                    "_get_cache_dir",
                    return_value="/cache",
                ):
                    with patch.object(
                        sandy.os.path,
                        "exists",
                        return_value=cache_exists,
                    ):
                        with patch.object(
                            instance,
                            "_port_mapping_lock",
                            return_value=locked(),
                        ) as lock:
                            with patch.object(
                                instance,
                                "_clear_cache_contents",
                                return_value=removed,
                            ) as clear:
                                with captured_output() as (stdout, _):
                                    instance._purge_cache()
                self.assertIn(message, stdout.getvalue())
                if cache_exists:
                    lock.assert_called_once_with(exclusive=True)
                    clear.assert_called_once_with(preserve_state=True)
                else:
                    lock.assert_not_called()
                    clear.assert_not_called()


class ExecutionTests(unittest.TestCase):
    def setUp(self):
        # The session's OOM report reads cgroupfs; OomReportTests cover it.
        memory_events = patch.object(
            sandy, "_container_memory_events", return_value=None
        )
        memory_events.start()
        self.addCleanup(memory_events.stop)

    def test_is_container_running(self):
        instance = make_sandy()
        result = SimpleNamespace(stdout="1234\n")
        with patch.object(sandy, "_run_secure_subprocess", return_value=result) as run:
            self.assertEqual(instance._is_container_running(), "1234")
        run.assert_called_once_with(
            ["machinectl", "show", "ai-dev", "-p", "Leader", "--value"],
            capture_output=True,
            text=True,
            check=True,
            timeout=sandy.QUERY_COMMAND_TIMEOUT,
            env=ANY,
        )
        # sandy parses the error text, so the query runs in the C locale.
        environment = run.call_args.kwargs["env"]
        self.assertEqual((environment["LANG"], environment["LC_ALL"]), ("C", "C"))
        # A wait for a stop gives a shorter timeout, so that the query ends
        # by the deadline of the wait.
        with patch.object(sandy, "_run_secure_subprocess", return_value=result) as run:
            self.assertEqual(instance._is_container_running("other", 0.5), "1234")
        self.assertEqual(run.call_args.kwargs["timeout"], 0.5)

        # The error of machined for an unknown name, as systemd 249 and 257
        # print it, is the only failure that means "not running".
        unknown = subprocess.CalledProcessError(
            1,
            ["machinectl"],
            stderr="Could not get path to machine: No machine 'ai-dev' known\n",
        )
        with patch.object(sandy, "_run_secure_subprocess", side_effect=unknown):
            self.assertIsNone(instance._is_container_running())
        with patch.object(sandy, "_run_secure_subprocess", side_effect=unknown):
            self.assertIsNone(instance._is_container_running("ai-dev"))

    def test_is_container_running_does_not_read_a_failed_query_as_stopped(self):
        # Regression test: each machinectl failure meant "not running", so rm,
        # for example, removed the image of a running container when the
        # system bus was gone. Mocks: machinectl, which exits 1 for each
        # failure (measured on systemd 249 and 257).
        instance = make_sandy()
        cases = (
            (
                1,
                "Failed to connect to bus: No such file or directory\n",
                "'Failed to connect to bus: No such file or directory'",
            ),
            (
                1,
                "Failed to connect to system scope bus via local transport: "
                "Connection refused\n",
                "'Failed to connect to system scope bus via local transport: "
                "Connection refused'",
            ),
            (
                1,
                "Could not get path to machine: No machine 'other' known\n",
                "\"Could not get path to machine: No machine 'other' known\"",
            ),
            (
                2,
                "Could not get path to machine: No machine 'ai-dev' known\n",
                "\"Could not get path to machine: No machine 'ai-dev' known\"",
            ),
            (1, "", "'exit status 1'"),
            (1, None, "'exit status 1'"),
            (1, "denied\x1b[31m\nforged\n", "'denied\\x1b[31m\\nforged'"),
        )
        for returncode, stderr, detail in cases:
            with self.subTest(returncode=returncode, stderr=stderr):
                failure = subprocess.CalledProcessError(
                    returncode, ["machinectl"], stderr=stderr
                )
                with patch.object(sandy, "_run_secure_subprocess", side_effect=failure):
                    with self.assertRaises(subprocess.SubprocessError) as raised:
                        instance._is_container_running()
                self.assertIsInstance(raised.exception, sandy._MachineQueryError)
                self.assertIs(raised.exception.__cause__, failure)
                self.assertEqual(
                    str(raised.exception),
                    f"Could not query machine 'ai-dev': {detail}",
                )

    def test_c_locale_environment_keeps_the_rest_of_the_environment(self):
        # Mocks: the environment of sandy, with a German locale.
        with patch.dict(
            sandy.os.environ,
            {
                "LANG": "de_DE.UTF-8",
                "LANGUAGE": "de",
                "LC_ALL": "de_DE.UTF-8",
                "PATH": "/usr/sbin:/usr/bin",
            },
        ):
            environment = sandy._c_locale_environment()
            self.assertEqual(sandy.os.environ["LANG"], "de_DE.UTF-8")
            self.assertEqual(sandy.os.environ["LANGUAGE"], "de")
        self.assertEqual(environment["LANG"], "C")
        self.assertEqual(environment["LC_ALL"], "C")
        self.assertNotIn("LANGUAGE", environment)
        self.assertEqual(environment["PATH"], "/usr/sbin:/usr/bin")

    def test_is_container_running_does_not_read_a_timeout_as_stopped(self):
        # Regression test: the query had no timeout. A timeout must not mean
        # "not running": rm, for example, then removes the image.
        instance = make_sandy()
        with patch.object(
            sandy,
            "_run_secure_subprocess",
            side_effect=subprocess.TimeoutExpired(["machinectl"], 3),
        ):
            with self.assertRaises(subprocess.TimeoutExpired):
                instance._is_container_running()

    def test_machine_poweroff_cleans_state_first(self):
        # Mocks: the query, the cleanup, the commands, the wait, and a clock
        # that stands still.
        instance = make_sandy()
        manager = MagicMock()
        manager.wait.return_value = True
        with patch.object(instance, "_is_container_running", return_value="123"):
            with patch.object(
                instance, "_cleanup_port_mappings_for_container", manager.cleanup
            ):
                with patch.object(sandy, "_run_secure_subprocess", manager.run):
                    with patch.object(
                        instance, "_wait_for_container_stop", manager.wait
                    ), patch.object(sandy.time, "monotonic", return_value=100.0):
                        self.assertIs(instance._machine_poweroff(), True)
        # A successful poweroff is not followed by terminate, which would
        # fail with "No machine known". By default (down and rm), the
        # poweroff gets CONTAINER_POWEROFF_TIMEOUT, and its command ends in
        # QUERY_COMMAND_TIMEOUT.
        self.assertEqual(
            manager.mock_calls,
            [
                call.cleanup("ai-dev", lock_timeout=None),
                call.run(
                    ["machinectl", "poweroff", "ai-dev"],
                    timeout=sandy.QUERY_COMMAND_TIMEOUT,
                ),
                call.wait("ai-dev", sandy.CONTAINER_POWEROFF_TIMEOUT),
            ],
        )

    def test_machine_poweroff_with_a_busy_port_lock_changes_nothing(self):
        # The stop after the last session passes a limit. Mocks: the query,
        # the port cleanup, which times out on the port mapping lock, and the
        # machinectl commands.
        instance = make_sandy()
        manager = MagicMock()
        manager.cleanup.side_effect = TimeoutError(
            "Timed out waiting for the Sandy port mapping lock"
        )
        with patch.object(
            instance, "_is_container_running", return_value="123"
        ), patch.object(
            instance, "_cleanup_port_mappings_for_container", manager.cleanup
        ), patch.object(
            sandy, "_run_secure_subprocess", manager.run
        ), patch.object(
            instance, "_wait_for_container_stop", manager.wait
        ):
            with self.assertRaises(TimeoutError):
                instance._machine_poweroff(port_lock_timeout=5)
        self.assertEqual(manager.mock_calls, [call.cleanup("ai-dev", lock_timeout=5)])

    def test_machine_poweroff_terminates_only_after_timeout(self):
        # Mocks: the query, the cleanup, the commands, and the waits, which use
        # up their whole time on a clock. The poweroff gets the first half of
        # stop_timeout, and the terminate the rest; each command ends by its
        # part too. down and rm use the default; the stop after the last
        # session, under the lifecycle lock, uses CONTAINER_POWEROFF_TIMEOUT.
        locked = sandy.CONTAINER_POWEROFF_TIMEOUT
        for stop_timeout, half, command_timeout in (
            (None, sandy.CONTAINER_POWEROFF_TIMEOUT, sandy.QUERY_COMMAND_TIMEOUT),
            (locked, locked / 2, locked / 2),
        ):
            for stopped_after_terminate in (True, False):
                with self.subTest(
                    stop_timeout=stop_timeout,
                    stopped_after_terminate=stopped_after_terminate,
                ):
                    instance = make_sandy()
                    manager = MagicMock()
                    clock = [100.0]
                    results = iter([False, stopped_after_terminate])

                    def wait(_name: str, timeout: float) -> bool:
                        clock[0] += timeout
                        return next(results)

                    manager.wait.side_effect = wait
                    options = {} if stop_timeout is None else {"stop_timeout": locked}
                    with patch.object(
                        instance, "_is_container_running", return_value="123"
                    ), patch.object(
                        instance,
                        "_cleanup_port_mappings_for_container",
                        manager.cleanup,
                    ), patch.object(
                        sandy, "_run_secure_subprocess", manager.run
                    ), patch.object(
                        instance, "_wait_for_container_stop", manager.wait
                    ), patch.object(
                        sandy.time, "monotonic", side_effect=lambda: clock[0]
                    ):
                        with captured_output() as (stdout, _):
                            stopped = instance._machine_poweroff("other", **options)
                    # The callers need the result: rm keeps the image, and down
                    # exits 1, when the container did not stop.
                    self.assertIs(stopped, stopped_after_terminate)
                    self.assertEqual(
                        manager.mock_calls[1:],
                        [
                            call.run(
                                ["machinectl", "poweroff", "other"],
                                timeout=command_timeout,
                            ),
                            call.wait("other", half),
                            call.run(
                                ["machinectl", "terminate", "other"],
                                stderr=subprocess.DEVNULL,
                                timeout=command_timeout,
                            ),
                            call.wait("other", half),
                        ],
                    )
                    self.assertEqual(
                        "did not stop" in stdout.getvalue(),
                        not stopped_after_terminate,
                    )

    def test_machine_poweroff_skips_stopped_container(self):
        instance = make_sandy()
        with patch.object(instance, "_is_container_running", return_value=None):
            with patch.object(sandy, "_run_secure_subprocess") as run:
                with captured_output() as (stdout, _):
                    self.assertIs(instance._machine_poweroff(), True)
        run.assert_not_called()
        self.assertIn("not found or not running", stdout.getvalue())

    def test_wait_for_container_stop_needs_machine_and_scope_gone(self):
        instance = make_sandy()
        with patch.object(
            instance, "_is_container_running", side_effect=["123", None, None]
        ) as running, patch.object(
            sandy,
            "_supervisor_unit_loaded",
            side_effect=[ValueError("Malformed"), False],
        ) as loaded, patch.object(
            sandy.time, "sleep"
        ) as sleep:
            self.assertTrue(instance._wait_for_container_stop("ai-dev"))
        self.assertEqual(running.call_count, 3)
        self.assertEqual(
            loaded.call_args_list,
            [call("ai-dev", timeout=sandy.QUERY_COMMAND_TIMEOUT)] * 2,
        )
        self.assertEqual(
            sleep.call_args_list, [call(sandy.CONTAINER_STOP_POLL_INTERVAL)] * 2
        )

    def test_query_timeout_until_a_deadline(self):
        # Mocks: the clock. A step far from the deadline gets the usual
        # query timeout, a step near it the time left, and a step at or after
        # it one short chance.
        with patch.object(sandy.time, "monotonic", return_value=100.0):
            self.assertEqual(
                sandy._query_timeout_until(110.0), sandy.QUERY_COMMAND_TIMEOUT
            )
            self.assertEqual(sandy._query_timeout_until(101.5), 1.5)
            for deadline in (100.0, 90.0):
                with self.subTest(deadline=deadline):
                    self.assertEqual(
                        sandy._query_timeout_until(deadline),
                        sandy.CONTAINER_STOP_POLL_INTERVAL,
                    )

    def test_wait_for_container_stop_times_out(self):
        # Mocks: the queries (the scope stays), and a clock that each sleep
        # moves on by 2 s. Each query ends by the deadline (5 s); a query at
        # or after it still gets one short chance.
        instance = make_sandy()
        clock = [100.0]

        def sleep_two_seconds(_seconds: float) -> None:
            clock[0] += 2.0

        with patch.object(
            instance, "_is_container_running", return_value=None
        ) as running, patch.object(
            sandy, "_supervisor_unit_loaded", return_value=True
        ) as loaded, patch.object(
            sandy.time, "monotonic", side_effect=lambda: clock[0]
        ), patch.object(
            sandy.time, "sleep", side_effect=sleep_two_seconds
        ) as sleep:
            self.assertFalse(instance._wait_for_container_stop("ai-dev"))
        self.assertEqual(sleep.call_count, 3)
        timeouts = [3, 3, 1, sandy.CONTAINER_STOP_POLL_INTERVAL]
        self.assertEqual(
            running.call_args_list,
            [call("ai-dev", timeout=timeout) for timeout in timeouts],
        )
        self.assertEqual(
            loaded.call_args_list,
            [call("ai-dev", timeout=timeout) for timeout in timeouts],
        )

    @contextmanager
    def entry_script(self, instance):
        """Give _open_entry_script a real descriptor; record its closing."""
        script = tempfile.TemporaryFile()
        closed = []
        real_close = os.close

        def close(fd):
            closed.append(fd)
            real_close(fd)

        fd = os.dup(script.fileno())
        script.close()
        with patch.object(sandy, "_open_entry_script", return_value=fd), patch.object(
            sandy.os, "close", side_effect=close
        ), patch.object(instance, "_ensure_cache_dir") as ensure, patch.object(
            sandy.sys, "executable", "/usr/bin/python3"
        ), patch.object(
            sandy, "_new_attach_leaf", return_value=ATTACH_LEAF
        ), patch.object(
            sandy.os, "getpid", return_value=4100
        ), patch.object(
            sandy, "_remove_attach_leaf"
        ) as remove_leaf, patch.object(
            instance, "_stop_if_last_attach"
        ) as rule:
            yield SimpleNamespace(
                fd=fd, closed=closed, ensure=ensure, remove_leaf=remove_leaf, rule=rule
            )

    def helper_argv(self, fd, *args):
        return [
            "/usr/bin/python3",
            "-I",
            f"/proc/self/fd/{fd}",
            "__sandy-entry-helper",
            *args,
        ]

    def test_exec_runs_entry_helper_with_pinned_script(self):
        instance = make_sandy()
        with patch.object(instance, "_is_container_running", return_value="123"):
            with patch.object(instance, "_get_machine_dir", return_value="/machine"):
                with patch.object(sandy.os.path, "isdir", return_value=True) as isdir:
                    with self.entry_script(instance) as script:
                        with patch.object(
                            instance, "_run_container_interactive", return_value=23
                        ) as interactive:
                            status = instance._exec("printf 'safe'")

        self.assertEqual(status, 23)
        isdir.assert_called_once_with("/machine/home/developer/workspace")
        interactive.assert_called_once_with(
            self.helper_argv(
                script.fd,
                "ai-dev",
                "123",
                "4100",
                ATTACH_LEAF,
                "developer",
                "/home/developer",
                "/home/developer/workspace",
                "tty",
                "printf 'safe'",
            ),
            environment=sandy._container_environment("developer", "/home/developer"),
            pass_fds=(script.fd,),
        )
        script.ensure.assert_called_once_with()
        self.assertEqual(script.closed, [script.fd])
        script.remove_leaf.assert_called_once_with("ai-dev", ATTACH_LEAF)
        environment = interactive.call_args.kwargs["environment"]
        self.assertNotIn("SANDY_TEST_HOST_SECRET", environment)

    def test_exec_reports_oom_kills_before_the_last_attach_stop(self):
        # Mocks: as in the entry helper test, plus the memory events.
        instance = make_sandy()
        events = []
        before = sandy.MemoryEvents(0, 0, 0)
        with patch.object(
            sandy,
            "_container_memory_events",
            side_effect=lambda name: events.append(("read", name)) or before,
        ), patch.object(instance, "_is_container_running", return_value="123"):
            with patch.object(instance, "_get_machine_dir", return_value="/machine"):
                with patch.object(sandy.os.path, "isdir", return_value=True):
                    with self.entry_script(instance):
                        with patch.object(
                            instance,
                            "_run_container_interactive",
                            side_effect=lambda *a, **k: events.append(("run",)) or 0,
                        ), patch.object(
                            instance,
                            "_report_oom_kills",
                            side_effect=lambda value: events.append(("report", value)),
                        ), patch.object(
                            instance,
                            "_stop_if_last_attach",
                            side_effect=lambda console: events.append(("stop",)),
                        ):
                            instance._exec("true")
        self.assertEqual(
            events, [("read", "ai-dev"), ("run",), ("report", before), ("stop",)]
        )

    def test_exec_rejects_missing_container_or_command(self):
        instance = make_sandy()
        with patch.object(instance, "_is_container_running", return_value=None):
            with captured_output():
                with self.assertRaises(SystemExit):
                    instance._exec("true")

        with patch.object(instance, "_is_container_running", return_value="123"):
            with captured_output():
                with self.assertRaises(SystemExit):
                    instance._exec(None)

    def test_exec_rejects_invalid_entry_before_starting_helper(self):
        instance = make_sandy()
        instance.workspace = None
        for leader, command in (
            ("abc", "true"),
            ("1", "true"),
            ("123", "x" * (sandy.ENTRY_COMMAND_MAX_BYTES + 1)),
        ):
            with self.subTest(leader=leader, length=len(command)):
                with patch.object(
                    instance, "_is_container_running", return_value=leader
                ), patch.object(sandy, "_open_entry_script") as open_script:
                    with captured_output() as (stdout, _):
                        with self.assertRaises(SystemExit):
                            instance._exec(command)
                open_script.assert_not_called()
                self.assertIn("E: Invalid container entry", stdout.getvalue())

    def test_exec_login_shell_and_root_user_workdir(self):
        instance = make_sandy()
        instance.workspace = None
        with patch.object(instance, "_is_container_running", return_value="123"):
            with self.entry_script(instance) as script:
                with patch.object(
                    instance, "_run_container_interactive", return_value=17
                ) as interactive:
                    status = instance._exec(None, login_shell=True)
        self.assertEqual(status, 17)
        self.assertEqual(
            interactive.call_args.args[0],
            self.helper_argv(
                script.fd,
                "ai-dev",
                "123",
                "4100",
                ATTACH_LEAF,
                "developer",
                "/home/developer",
                "/",
                "tty",
                "exec bash --login",
            ),
        )

        # -u root uses <home>/workspace too, as the nsenter path did.
        instance.workspace = "workspace"
        instance.user = "root"
        instance.user_home = "/root"
        with patch.object(instance, "_is_container_running", return_value="123"):
            with patch.object(instance, "_get_machine_dir", return_value="/machine"):
                with patch.object(sandy.os.path, "isdir", return_value=False):
                    with self.entry_script(instance) as script:
                        with patch.object(
                            instance, "_run_container_interactive", return_value=0
                        ) as interactive:
                            instance._exec("id")
        self.assertEqual(
            interactive.call_args.args[0][8:12], ["root", "/root", "/", "tty"]
        )

    def test_exec_as_root_runs_entry_helper(self):
        instance = make_sandy()
        result = SimpleNamespace(returncode=0)
        with patch.object(instance, "_is_container_running", return_value="123"):
            with patch.object(sandy.os.path, "isdir") as isdir:
                with self.entry_script(instance) as script:
                    with patch.object(
                        sandy, "_run_secure_subprocess", return_value=result
                    ) as run:
                        self.assertIs(
                            instance._exec_as_root("/bin/sh /init.sh"), result
                        )
        # init.sh never changes into the workspace.
        isdir.assert_not_called()
        run.assert_called_once_with(
            self.helper_argv(
                script.fd,
                "ai-dev",
                "123",
                "4100",
                ATTACH_LEAF,
                "root",
                "/root",
                "/",
                "sh",
                "/bin/sh /init.sh",
            ),
            env=sandy._container_environment("root", "/root"),
            pass_fds=(script.fd,),
        )
        self.assertEqual(script.closed, [script.fd])
        script.remove_leaf.assert_called_once_with("ai-dev", ATTACH_LEAF)

        with captured_output():
            with self.assertRaises(SystemExit):
                instance._exec_as_root("")

    def test_exec_as_root_rejects_invalid_leader(self):
        instance = make_sandy()
        with patch.object(instance, "_is_container_running", return_value="0123"):
            with patch.object(sandy, "_run_secure_subprocess") as run:
                with captured_output() as (stdout, _):
                    with self.assertRaises(SystemExit):
                        instance._exec_as_root("true")
        run.assert_not_called()
        self.assertIn("E: Invalid container entry", stdout.getvalue())

    def test_entry_helper_command_closes_script_on_error(self):
        instance = make_sandy()
        request = sandy.EntryRequest(
            machine="ai-dev",
            leader_pid=123,
            parent_pid=4100,
            attach_leaf=ATTACH_LEAF,
            user="root",
            home="/root",
            workdir="/",
            kind="sh",
            command="true",
        )
        with self.entry_script(instance) as script:
            with self.assertRaises(RuntimeError):
                with instance._entry_helper_command(request):
                    raise RuntimeError("helper failed")
        self.assertEqual(script.closed, [script.fd])
        script.remove_leaf.assert_called_once_with("ai-dev", ATTACH_LEAF)

    def test_entry_helper_command_reports_setup_errors(self):
        # Mocks: the cache directory check, the script open, and the leaf
        # removal. A setup error starts no attach, so no leaf is removed.
        instance = make_sandy()
        request = sandy.EntryRequest(
            machine="ai-dev",
            leader_pid=123,
            parent_pid=4100,
            attach_leaf=ATTACH_LEAF,
            user="root",
            home="/root",
            workdir="/",
            kind="sh",
            command="true",
        )
        script_error = PermissionError(
            "Sandy script must be a regular file that only its owner can write"
        )
        cases = (
            ("cache", PermissionError("Directory 'sandy.__cache' has unsafe mode")),
            ("cache", ValueError("Managed path must begin with a Sandy directory")),
            ("script", script_error),
            ("script", FileNotFoundError(errno.ENOENT, "No such file")),
        )
        for target, error in cases:
            with self.subTest(target=target, error=type(error).__name__):
                with ExitStack() as stack:
                    ensure = stack.enter_context(
                        patch.object(
                            instance,
                            "_ensure_cache_dir",
                            side_effect=error if target == "cache" else None,
                        )
                    )
                    open_script = stack.enter_context(
                        patch.object(
                            sandy,
                            "_open_entry_script",
                            side_effect=error if target == "script" else None,
                        )
                    )
                    remove = stack.enter_context(
                        patch.object(sandy, "_remove_attach_leaf")
                    )
                    with self.assertRaises(sandy._EntrySetupError) as raised:
                        with instance._entry_helper_command(request):
                            self.fail("The helper command must not start")
                self.assertIs(raised.exception.__cause__, error)
                self.assertEqual(str(raised.exception), str(error))
                ensure.assert_called_once_with()
                if target == "cache":
                    open_script.assert_not_called()
                remove.assert_not_called()

    def test_exec_as_root_reports_entry_setup_errors(self):
        # Regression test for entry setup errors that escaped as a traceback.
        # Mocks: the running check, the cache directory, the script open (it
        # fails as for a group-writable script), and the subprocess wrapper.
        instance = make_sandy()
        error = PermissionError("Sandy script is writable\x1b[31m")
        with patch.object(
            instance, "_is_container_running", return_value="123"
        ), patch.object(instance, "_ensure_cache_dir"), patch.object(
            sandy, "_open_entry_script", side_effect=error
        ), patch.object(
            sandy, "_run_secure_subprocess"
        ) as run:
            with captured_output() as (stdout, _):
                with self.assertRaises(SystemExit) as exited:
                    instance._exec_as_root("/bin/sh /init.sh")
        self.assertEqual(exited.exception.code, 1)
        self.assertIn("E: Could not prepare the container entry", stdout.getvalue())
        self.assertNotIn("\x1b", stdout.getvalue())
        run.assert_not_called()

    def test_wait_for_container_ready_does_not_retry_setup_errors(self):
        # Mocks: the probe and the sleep. A setup error does not go away by
        # itself, so the probe fails at once.
        instance = make_sandy()
        error = sandy._EntrySetupError("script is writable")
        with patch.object(instance, "_run_as_root", side_effect=error) as run:
            with patch("time.sleep") as sleep:
                with self.assertRaises(sandy._EntrySetupError):
                    instance._wait_for_container_ready()
        run.assert_called_once_with("true", capture_output=True, timeout=5)
        sleep.assert_not_called()

    def test_entry_helper_command_warns_when_leaf_removal_fails(self):
        instance = make_sandy()
        for error in (
            TimeoutError("Attach cgroup did not become empty"),
            OSError(errno.EBUSY, "busy\x1b[0m"),
            ValueError("Malformed cgroup.events"),
        ):
            with self.subTest(error=type(error).__name__):
                with patch.object(
                    sandy, "_remove_attach_leaf", side_effect=error
                ) as remove:
                    with captured_output() as (stdout, _):
                        instance._end_attach_leaf(ATTACH_LEAF)
                remove.assert_called_once_with("ai-dev", ATTACH_LEAF)
                self.assertIn(
                    f"W: Could not remove attach cgroup {ATTACH_LEAF}",
                    stdout.getvalue(),
                )
                self.assertNotIn("\x1b", stdout.getvalue())

    def test_open_entry_script_checks_the_running_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            script = Path(temp_dir) / "sandy"
            script.write_text("#!/usr/bin/env python3\n")
            link = Path(temp_dir) / "sandy-link"
            link.symlink_to(script)
            for mode in (0o755, 0o700):
                script.chmod(mode)
                with self.subTest(mode=oct(mode)):
                    # The symlink is resolved first, as an installed link would be.
                    with patch.object(sandy, "__file__", str(link)):
                        fd = sandy._open_entry_script()
                    try:
                        self.assertTrue(os.path.samestat(os.fstat(fd), script.stat()))
                    finally:
                        os.close(fd)
            for mode in (0o775, 0o757):
                script.chmod(mode)
                with self.subTest(mode=oct(mode)):
                    with patch.object(sandy, "__file__", str(script)), patch.object(
                        sandy.os, "close", wraps=os.close
                    ) as close:
                        with self.assertRaises(PermissionError):
                            sandy._open_entry_script()
                    close.assert_called_once()

    def test_no_nsenter_path_remains(self):
        source = SANDY_PATH.read_text(encoding="utf-8")
        self.assertNotIn('"nsenter"', source)
        self.assertNotIn('"su"', source)

    def test_interactive_wrapper_wires_callbacks(self):
        instance = make_sandy()

        def run_pty(command, *, master_read, stdin_read, environment, pass_fds):
            self.assertEqual(command, ["tool"])
            self.assertEqual(environment, {"PATH": sandy.CONTAINER_PATH})
            self.assertEqual(pass_fds, ())
            with patch.object(sandy.os, "read", return_value=b"output"):
                self.assertEqual(master_read(10), b"output")
                self.assertEqual(stdin_read(0), b"output")
            return 7

        with patch.object(
            sandy,
            "_run_secure_subprocess_pty",
            side_effect=run_pty,
        ):
            with captured_output():
                self.assertEqual(
                    instance._run_container_interactive(
                        ["tool"],
                        environment={"PATH": sandy.CONTAINER_PATH},
                    ),
                    7,
                )

    def test_wait_for_container_ready_retries(self):
        instance = make_sandy()
        result = SimpleNamespace(returncode=0)
        with patch.object(
            instance, "_run_as_root", side_effect=[None, result]
        ) as run_as_root:
            with patch("time.sleep") as sleep:
                self.assertTrue(instance._wait_for_container_ready())
        sleep.assert_called_once_with(sandy.CONTAINER_READY_INTERVAL)
        self.assertEqual(
            run_as_root.call_args_list,
            [call("true", capture_output=True, timeout=5)] * 2,
        )

    def test_wait_for_container_ready_retries_a_failed_machine_query(self):
        # A failed query during the start is a state that the wait does not
        # know yet, as a query that does not answer is: it tries again until
        # its deadline. Mocks: _run_as_root and the sleep.
        instance = make_sandy()
        result = SimpleNamespace(returncode=0)
        failure = sandy._MachineQueryError("ai-dev", "Connection refused")
        with patch.object(instance, "_run_as_root", side_effect=[failure, result]):
            with patch("time.sleep") as sleep:
                self.assertTrue(instance._wait_for_container_ready())
        sleep.assert_called_once_with(sandy.CONTAINER_READY_INTERVAL)

    def test_wait_for_container_ready_retries_while_the_container_starts(self):
        # The entry helper refuses an attach before the payload exists
        # (status 125); the probe must retry, not fail the start.
        instance = make_sandy()
        refused = SimpleNamespace(returncode=sandy.ENTRY_HELPER_FAILURE)
        ready = SimpleNamespace(returncode=0)
        with patch.object(
            instance, "_run_as_root", side_effect=[refused, refused, ready]
        ) as run_as_root:
            with patch("time.sleep") as sleep:
                self.assertTrue(instance._wait_for_container_ready())
        self.assertEqual(run_as_root.call_count, 3)
        self.assertEqual(
            sleep.call_args_list, [call(sandy.CONTAINER_READY_INTERVAL)] * 2
        )

    def test_wait_for_keepalive_open_retries_until_the_script_is_open(self):
        # Mocks: the payload check and the poll sleep. Every failed check is
        # retried: the payload can still be in execve.
        instance = make_sandy()
        supervisor = MagicMock()
        supervisor.poll.return_value = None
        with patch.object(
            sandy,
            "_payload_has_opened_keepalive",
            side_effect=[
                ProcessLookupError("Container is still starting; try again"),
                False,
                ValueError("Malformed process descriptor entry"),
                subprocess.CalledProcessError(1, ["machinectl"]),
                True,
            ],
        ) as check, patch("time.sleep") as sleep:
            self.assertTrue(instance._wait_for_keepalive_open(supervisor))
        self.assertEqual(check.call_args_list, [call("ai-dev")] * 5)
        self.assertEqual(
            sleep.call_args_list, [call(sandy.KEEPALIVE_OPEN_INTERVAL)] * 4
        )

    def test_wait_for_keepalive_open_stops_when_the_supervisor_exits(self):
        instance = make_sandy()
        supervisor = MagicMock()
        supervisor.poll.side_effect = [None, 1]
        with patch.object(
            sandy, "_payload_has_opened_keepalive", return_value=False
        ) as check, patch("time.sleep"):
            self.assertFalse(instance._wait_for_keepalive_open(supervisor))
        check.assert_called_once_with("ai-dev")

    def test_wait_for_keepalive_open_times_out(self):
        instance = make_sandy()
        supervisor = MagicMock()
        supervisor.poll.return_value = None
        with patch.object(
            sandy, "_payload_has_opened_keepalive", return_value=False
        ) as check, patch(
            "time.monotonic", side_effect=[0.0, 5.0, sandy.KEEPALIVE_OPEN_TIMEOUT]
        ), patch(
            "time.sleep"
        ) as sleep:
            self.assertFalse(instance._wait_for_keepalive_open(supervisor))
        self.assertEqual(check.call_count, 2)
        sleep.assert_called_once_with(sandy.KEEPALIVE_OPEN_INTERVAL)

    def test_wait_for_container_ready_times_out_without_running_machine(self):
        instance = make_sandy()
        with patch.object(instance, "_run_as_root", return_value=None) as run:
            with patch("time.monotonic", side_effect=[0, 0, 1]):
                with patch("time.sleep") as sleep:
                    self.assertFalse(instance._wait_for_container_ready(timeout=1))
        run.assert_called_once_with("true", capture_output=True, timeout=5)
        sleep.assert_not_called()

    def test_run_as_root_returns_none_without_running_machine(self):
        instance = make_sandy()
        with patch.object(instance, "_is_container_running", return_value=None):
            with patch.object(sandy, "_open_entry_script") as open_script:
                self.assertIsNone(instance._run_as_root("true"))
        open_script.assert_not_called()

    def test_get_container_ip(self):
        instance = make_sandy()
        with tempfile.TemporaryDirectory() as temp_dir:
            init_script = Path(temp_dir) / "init.sh"
            init_script.write_text('CONTAINER_IP="10.20.30.10"\n')
            init_script.chmod(0o644)

            def open_machine(path):
                return os.open(path, sandy.DIRECTORY_OPEN_FLAGS)

            with patch.object(instance, "_get_machine_dir", return_value=temp_dir):
                with patch.object(
                    sandy,
                    "_open_verified_dir",
                    side_effect=open_machine,
                ):
                    self.assertEqual(instance._get_container_ip(), "10.20.30.10")
            init_script.write_text("no address")
            init_script.chmod(0o644)
            with patch.object(instance, "_get_machine_dir", return_value=temp_dir):
                with patch.object(
                    sandy,
                    "_open_verified_dir",
                    side_effect=open_machine,
                ):
                    self.assertIsNone(instance._get_container_ip())

    def test_get_container_ip_rejects_oversized_invalid_and_out_of_network_init(self):
        instance = make_sandy()
        instance.network = make_network()
        with tempfile.TemporaryDirectory() as temp_dir:
            init_script = Path(temp_dir) / "init.sh"

            def open_machine(path):
                return os.open(path, sandy.DIRECTORY_OPEN_FLAGS)

            cases = (
                ('CONTAINER_IP="999.1.1.1"\n', "invalid IP"),
                ('CONTAINER_IP="10.20.30.10"\n', "outside the Sandy network"),
                ("#" * (sandy.INIT_SCRIPT_MAX_BYTES + 1), "too large"),
            )
            for content, expected in cases:
                with self.subTest(expected=expected):
                    init_script.write_text(content, encoding="utf-8")
                    init_script.chmod(0o644)
                    with patch.object(
                        instance, "_get_machine_dir", return_value=temp_dir
                    ):
                        with patch.object(
                            sandy,
                            "_open_verified_dir",
                            side_effect=open_machine,
                        ):
                            with captured_output() as (stdout, _):
                                self.assertIsNone(instance._get_container_ip())
                    self.assertIn(expected, stdout.getvalue())

    def test_run_init_script_conditions_and_success(self):
        instance = make_sandy()
        instance.network = make_network()
        result = SimpleNamespace(returncode=0)
        with patch.object(instance, "_get_machine_dir", return_value="/machine"):
            with patch.object(sandy.os.path, "exists", return_value=True):
                with patch.object(
                    instance,
                    "_exec_as_root",
                    return_value=result,
                ) as execute:
                    with captured_output() as (stdout, _):
                        instance._run_init_script(network_mode="host")
                        execute.assert_not_called()
                        instance._run_init_script()
        execute.assert_called_once_with("/bin/sh /init.sh")
        self.assertEqual(stdout.getvalue(), "")

    def test_spinner_finishes_once_with_optional_suffix(self):
        event = threading.Event()
        with captured_output() as (stdout, _):
            sandy._finish_spinner_line(event, suffix=" done")
            sandy._finish_spinner_line(event, suffix=" duplicate")
        self.assertEqual(stdout.getvalue(), " done\r\n")
        self.assertTrue(event.is_set())

        with captured_output() as (stdout, _):
            sandy._finish_spinner_line(None)
        self.assertEqual(stdout.getvalue(), "\r\n")

    def test_exec_as_root_rejects_missing_container_and_long_command(self):
        instance = make_sandy()
        with captured_output():
            with self.assertRaises(SystemExit):
                instance._exec_as_root("x" * 1025)

        with patch.object(instance, "_run_as_root", return_value=None):
            with captured_output():
                with self.assertRaises(SystemExit):
                    instance._exec_as_root("true")

    def test_interactive_wrapper_handles_io_errors_and_pty_failure(self):
        instance = make_sandy()

        def run_pty(_command, *, master_read, stdin_read, environment, pass_fds):
            self.assertEqual(environment, {"PATH": sandy.CONTAINER_PATH})
            self.assertEqual(pass_fds, ())
            with patch.object(sandy.os, "read", side_effect=OSError):
                self.assertEqual(master_read(10), b"")
                self.assertEqual(stdin_read(0), b"")
            raise RuntimeError("pty failed")

        with patch.object(
            sandy,
            "_run_secure_subprocess_pty",
            side_effect=run_pty,
        ):
            with self.assertRaisesRegex(RuntimeError, "pty failed"):
                instance._run_container_interactive(
                    ["tool"],
                    environment={"PATH": sandy.CONTAINER_PATH},
                )

    def test_wait_for_container_ready_handles_failures_and_spinner_stop(self):
        instance = make_sandy()
        spinner = threading.Event()
        spinner.clear()

        def stop_spinner(_seconds):
            spinner.set()

        result = SimpleNamespace(returncode=1)
        with patch.object(
            instance,
            "_run_as_root",
            side_effect=[
                subprocess.TimeoutExpired(["true"], 5),
                ValueError("Invalid container Leader PID"),
                result,
                SimpleNamespace(returncode=0),
            ],
        ):
            if True:
                with patch("time.sleep", side_effect=stop_spinner):
                    with captured_output() as (stdout, _):
                        self.assertTrue(
                            instance._wait_for_container_ready(
                                spinner_line_event=spinner
                            )
                        )
        self.assertEqual(stdout.getvalue(), ".")

    def test_get_container_ip_handles_missing_and_read_error(self):
        instance = make_sandy()
        with patch.object(
            instance,
            "_get_machine_dir",
            return_value="/machine",
        ):
            with patch.object(
                sandy, "_open_verified_dir", side_effect=FileNotFoundError
            ):
                with captured_output() as (stdout, _):
                    self.assertIsNone(instance._get_container_ip())

            with patch.object(
                sandy,
                "_open_verified_dir",
                side_effect=PermissionError("denied"),
            ):
                with captured_output() as (stdout, _):
                    self.assertIsNone(instance._get_container_ip())
        self.assertIn("Could not read container IP", stdout.getvalue())

    def test_run_init_script_skips_without_network_or_script(self):
        instance = make_sandy()
        with patch.object(instance, "_exec_as_root") as execute:
            instance._run_init_script()
            instance.network = make_network()
            with patch.object(
                instance,
                "_get_machine_dir",
                return_value="/machine",
            ):
                with patch.object(sandy.os.path, "exists", return_value=False):
                    instance._run_init_script()
        execute.assert_not_called()

    def test_run_init_script_reports_command_failure(self):
        instance = make_sandy()
        instance.network = make_network()
        failed = SimpleNamespace(returncode=1)
        with patch.object(
            instance,
            "_get_machine_dir",
            return_value="/machine",
        ):
            with patch.object(sandy.os.path, "exists", return_value=True):
                with patch.object(
                    instance,
                    "_exec_as_root",
                    return_value=failed,
                ):
                    with captured_output() as (stdout, _):
                        instance._run_init_script()
        self.assertIn("script failed", stdout.getvalue())


class PortForwardingTests(unittest.TestCase):
    def configured_instance(self, backend="iptables"):
        instance = make_sandy()
        instance.port_mappings = [("tcp", 8080, 80)]
        instance.network = make_network()
        instance.network.network = "10.20.30.0"
        instance.network.network_cidr = "10.20.30.0/24"
        instance.network.gateway = "10.20.30.1"
        instance.network.firewall_backend = backend
        instance.network._ensure_gateway = MagicMock(return_value=True)
        instance.network._run_iptables = MagicMock(return_value=True)
        instance.network._run_nft = MagicMock(return_value=True)
        return instance

    def test_setup_port_forwarding_dispatches_backend_and_state(self):
        for backend, expected_method in [
            ("iptables", "_setup_port_forwarding_ipt"),
            ("nftables", "_setup_port_forwarding_nft"),
        ]:
            with self.subTest(backend=backend):
                instance = self.configured_instance(backend)
                with patch.object(
                    instance,
                    "_get_container_ip",
                    return_value="10.20.30.10",
                ):
                    with patch.object(
                        instance,
                        "_update_port_mapping_state",
                    ) as update:
                        with patch.object(instance, expected_method) as setup:
                            instance._setup_port_forwarding_rules()
                update.assert_called_once_with("ai-dev", "10.20.30.10")
                setup.assert_called_once_with("10.20.30.10")

        instance = self.configured_instance()
        with patch.object(instance, "_get_container_ip") as get_ip:
            with patch.object(
                instance,
                "_update_port_mapping_state",
            ) as update:
                with patch.object(instance, "_setup_port_forwarding_ipt") as setup:
                    instance._setup_port_forwarding_rules("10.20.30.10")
        get_ip.assert_not_called()
        update.assert_called_once_with("ai-dev", "10.20.30.10")
        setup.assert_called_once_with("10.20.30.10")

    def test_port_cleanup_with_a_busy_lock_removes_no_state_and_no_rule(self):
        # The stop after the last session removes the ports with a limit.
        # Mocks: the lock, which stays busy, and the backends.
        instance = self.configured_instance()
        network = instance.network
        with patch.object(
            instance,
            "_port_mapping_lock",
            side_effect=TimeoutError(
                "Timed out waiting for the Sandy port mapping lock"
            ),
        ) as lock, patch.object(
            instance, "_persist_port_mapping_state"
        ) as persist, patch.object(
            instance, "_cleanup_port_forwarding_ipt"
        ) as cleanup:
            with self.assertRaises(TimeoutError):
                instance._cleanup_port_mappings_for_container("other", lock_timeout=2)
        lock.assert_called_once_with(exclusive=True, timeout=2)
        persist.assert_not_called()
        cleanup.assert_not_called()
        # The container, the ports, and the network of the caller come back.
        self.assertEqual(instance.container, "ai-dev")
        self.assertEqual(instance.port_mappings, [("tcp", 8080, 80)])
        self.assertIs(instance.network, network)

    def test_iptables_setup_and_cleanup_create_five_rules(self):
        instance = self.configured_instance()
        with captured_output():
            self.assertTrue(instance._setup_port_forwarding_ipt("10.20.30.10"))
        self.assertEqual(instance.network._run_iptables.call_count, 5)
        setup_commands = [
            entry.args for entry in instance.network._run_iptables.call_args_list
        ]
        self.assertIn("--to-destination", setup_commands[0])
        self.assertIn("10.20.30.10:80", setup_commands[0])

        instance.network._run_iptables.reset_mock()
        with captured_output():
            self.assertTrue(instance._cleanup_port_forwarding_ipt("10.20.30.10"))
        self.assertEqual(instance.network._run_iptables.call_count, 5)
        self.assertTrue(
            all(
                entry.args[0] == "-D"
                for entry in instance.network._run_iptables.call_args_list
            )
        )

    def test_nft_rule_builders_and_setup_cleanup(self):
        instance = self.configured_instance("nftables")
        dnat = instance._nft_dnat_rule_args(
            "output",
            "tcp",
            8080,
            "10.20.30.10:80",
        )
        self.assertEqual(dnat[:4], ["rule", "ip", "sandy", "output"])
        self.assertEqual(dnat[-3:], ["dnat", "to", "10.20.30.10:80"])

        with captured_output():
            self.assertTrue(instance._setup_port_forwarding_nft("10.20.30.10"))
        self.assertEqual(instance.network._run_nft.call_count, 5)
        calls = instance.network._run_nft.call_args_list
        self.assertEqual(
            [entry.args[0] for entry in calls],
            ["add", "add", "add", "insert", "insert"],
        )
        # Every rule of the mapping carries the mapping's comment.
        self.assertEqual(
            [entry.args[4] for entry in calls],
            ["output", "prerouting", "postrouting", "forward", "output_filter"],
        )
        for entry in calls:
            self.assertEqual(entry.args[-2:], ("comment", '"sandy:ai-dev:tcp:8080"'))

    def nft_listing(self, chain, rules):
        """Return `nft -j -a list chain` output with (handle, comment) rules."""
        items = [
            {"metainfo": {"version": "1.0.9", "json_schema_version": 1}},
            {"chain": {"family": "ip", "table": "sandy", "name": chain, "handle": 1}},
        ]
        for handle, comment in rules:
            rule = {
                "family": "ip",
                "table": "sandy",
                "chain": chain,
                "handle": handle,
                "expr": [{"accept": None}],
            }
            if comment is not None:
                rule["comment"] = comment
            items.append({"rule": rule})
        return json.dumps({"nftables": items})

    def test_nft_cleanup_deletes_only_commented_rules_by_handle(self):
        instance = self.configured_instance("nftables")
        instance.port_mappings = [("tcp", 8080, 80)]
        mine = "sandy:ai-dev:tcp:8080"
        listings = {
            "output": [(5, mine), (6, "sandy:other:tcp:8081"), (7, None)],
            "prerouting": [(8, "sandy:ai-dev:tcp:80800"), (9, mine)],
            "postrouting": [(10, mine), (11, mine)],
            "forward": [],
            "output_filter": [(12, "sandy:ai-dev:udp:8080"), (13, mine)],
        }

        def run(cmd, **kwargs):
            self.assertEqual(
                cmd[:7], ["nft", "-j", "-a", "list", "chain", "ip", "sandy"]
            )
            self.assertEqual(
                kwargs, {"capture_output": True, "text": True, "check": False}
            )
            return SimpleNamespace(
                returncode=0,
                stdout=self.nft_listing(cmd[7], listings[cmd[7]]),
                stderr="",
            )

        with patch.object(sandy, "_run_secure_subprocess", side_effect=run):
            with captured_output() as (stdout, _):
                self.assertTrue(instance._cleanup_port_forwarding_nft("10.20.30.10"))
        self.assertEqual(
            [entry.args for entry in instance.network._run_nft.call_args_list],
            [
                ("delete", "rule", "ip", "sandy", "output", "handle", "5"),
                ("delete", "rule", "ip", "sandy", "prerouting", "handle", "9"),
                ("delete", "rule", "ip", "sandy", "postrouting", "handle", "10"),
                ("delete", "rule", "ip", "sandy", "postrouting", "handle", "11"),
                ("delete", "rule", "ip", "sandy", "output_filter", "handle", "13"),
            ],
        )
        self.assertIn("Removed port forwarding: 127.0.0.1:8080", stdout.getvalue())

    def test_nft_cleanup_continues_past_unlistable_chains(self):
        mine = "sandy:ai-dev:tcp:8080"
        for failure in (
            SimpleNamespace(returncode=1, stdout="", stderr="No such file\x1b"),
            SimpleNamespace(returncode=0, stdout="not json", stderr=""),
        ):
            with self.subTest(returncode=failure.returncode):
                instance = self.configured_instance("nftables")
                instance.port_mappings = [("tcp", 8080, 80)]

                def run(cmd, **kwargs):
                    _ = kwargs
                    if cmd[7] == "output":
                        return failure
                    return SimpleNamespace(
                        returncode=0,
                        stdout=self.nft_listing(cmd[7], [(40, mine)]),
                        stderr="",
                    )

                with patch.object(sandy, "_run_secure_subprocess", side_effect=run):
                    with captured_output() as (stdout, _):
                        self.assertFalse(
                            instance._cleanup_port_forwarding_nft("10.20.30.10")
                        )
                self.assertEqual(
                    [
                        entry.args[4]
                        for entry in instance.network._run_nft.call_args_list
                    ],
                    ["prerouting", "postrouting", "forward", "output_filter"],
                )
                self.assertIn("W: ", stdout.getvalue())
                self.assertNotIn("\x1b", stdout.getvalue())

    def test_nft_port_rule_comment_validates_fields(self):
        self.assertEqual(
            sandy._nft_port_rule_comment("ai-dev", "udp", 53), "sandy:ai-dev:udp:53"
        )
        for args in (
            ("Bad", "tcp", 1),
            ("a", "sctp", 1),
            ("a", "tcp", 0),
            ("a", "tcp", 65536),
            ("a", "tcp", True),
            ("a", "tcp", "80"),
        ):
            with self.subTest(args=args):
                with self.assertRaises(ValueError):
                    sandy._nft_port_rule_comment(*args)

    def test_parse_nft_rule_handles_rejects_malformed_output(self):
        good = self.nft_listing("output", [(5, "c")])
        self.assertEqual(sandy._parse_nft_rule_handles(good, "output", "c"), [5])
        self.assertEqual(sandy._parse_nft_rule_handles(good, "output", "d"), [])

        def listing(rule):
            return json.dumps({"nftables": [{"rule": rule}]})

        base = {"family": "ip", "table": "sandy", "chain": "output", "comment": "c"}
        for output in (
            "[]",
            "{}",
            '{"nftables": {}}',
            "x" * (sandy.NFT_LIST_MAX_BYTES + 1),
            "{",
            listing("rule"),
            listing(dict(base, handle=0)),
            listing(dict(base, handle=True)),
            listing(dict(base, handle="5")),
            listing(dict(base, handle=5, chain="forward")),
            listing(dict(base, handle=5, table="nat")),
            listing(dict(base, handle=5, family="ip6")),
        ):
            with self.subTest(output=output[:60]):
                with self.assertRaises(ValueError):
                    sandy._parse_nft_rule_handles(output, "output", "c")

    def test_cleanup_dispatches_backend(self):
        instance = self.configured_instance("nftables")
        with patch.object(instance, "_cleanup_port_forwarding_nft") as cleanup:
            instance._cleanup_port_forwarding_rules("10.20.30.10")
        cleanup.assert_called_once_with("10.20.30.10")

    def test_forwarding_requires_gateway(self):
        instance = self.configured_instance()
        instance.network._ensure_gateway.return_value = False
        with captured_output():
            self.assertFalse(instance._setup_port_forwarding_ipt("10.20.30.10"))

    def test_forwarding_noops_without_mappings_or_container_ip(self):
        instance = self.configured_instance()
        instance.port_mappings = []
        with patch.object(instance, "_get_container_ip") as get_ip:
            instance._setup_port_forwarding_rules()
        get_ip.assert_not_called()
        self.assertTrue(instance._setup_port_forwarding_ipt("10.20.30.10"))
        self.assertTrue(instance._setup_port_forwarding_nft("10.20.30.10"))
        self.assertTrue(instance._cleanup_port_forwarding_ipt("10.20.30.10"))
        self.assertTrue(instance._cleanup_port_forwarding_nft("10.20.30.10"))

        instance.port_mappings = [("tcp", 8080, 80)]
        with patch.object(instance, "_get_container_ip", return_value=None):
            with captured_output() as (stdout, _):
                instance._setup_port_forwarding_rules()
        self.assertIn("Could not determine container IP", stdout.getvalue())

        with patch.object(instance, "_get_container_ip") as get_ip:
            with captured_output() as (stdout, _):
                instance._setup_port_forwarding_rules(None)
        get_ip.assert_not_called()
        self.assertIn("Could not determine container IP", stdout.getvalue())

        with self.assertRaisesRegex(ValueError, "Container IP override"):
            instance._setup_port_forwarding_rules(object())

    def test_forwarding_without_backend_persists_but_skips_rules(self):
        instance = self.configured_instance()
        instance.network.firewall_backend = None
        with patch.object(
            instance,
            "_get_container_ip",
            return_value="10.20.30.10",
        ):
            with patch.object(
                instance,
                "_update_port_mapping_state",
            ) as update:
                with captured_output() as (stdout, _):
                    instance._setup_port_forwarding_rules()
        update.assert_called_once_with("ai-dev", "10.20.30.10")
        self.assertIn("No firewall backend", stdout.getvalue())

    def test_forwarding_rejects_missing_gateway_value(self):
        # nftables cleanup deletes by comment and needs no gateway.
        for method_name in (
            "_setup_port_forwarding_ipt",
            "_setup_port_forwarding_nft",
            "_cleanup_port_forwarding_ipt",
        ):
            with self.subTest(method=method_name):
                instance = self.configured_instance()
                instance.network.gateway = None
                with captured_output():
                    self.assertFalse(getattr(instance, method_name)("10.20.30.10"))

    def test_forwarding_rejects_gateway_query_failure(self):
        for method_name in (
            "_setup_port_forwarding_nft",
            "_cleanup_port_forwarding_ipt",
        ):
            with self.subTest(method=method_name):
                instance = self.configured_instance()
                instance.network._ensure_gateway.return_value = False
                with captured_output():
                    self.assertFalse(getattr(instance, method_name)("10.20.30.10"))

    def test_forwarding_backends_report_rule_errors(self):
        cases = (
            ("_setup_port_forwarding_ipt", "_run_iptables"),
            ("_setup_port_forwarding_nft", "_run_nft"),
            ("_cleanup_port_forwarding_ipt", "_run_iptables"),
            ("_cleanup_port_forwarding_nft", "_run_nft"),
        )
        for method_name, runner_name in cases:
            with self.subTest(method=method_name):
                backend = "nftables" if runner_name == "_run_nft" else "iptables"
                instance = self.configured_instance(backend)
                setattr(
                    instance.network,
                    runner_name,
                    MagicMock(side_effect=RuntimeError("rule failure")),
                )
                listing = SimpleNamespace(
                    returncode=0,
                    stdout=self.nft_listing("output", [(5, "sandy:ai-dev:tcp:8080")]),
                    stderr="",
                )
                with patch.object(
                    sandy, "_run_secure_subprocess", return_value=listing
                ), captured_output():
                    self.assertFalse(getattr(instance, method_name)("10.20.30.10"))

    def test_cleanup_forwarding_skips_missing_ip_and_dispatches_iptables(self):
        instance = self.configured_instance()
        with patch.object(instance, "_get_container_ip", return_value=None):
            with patch.object(
                instance,
                "_cleanup_port_forwarding_ipt",
            ) as cleanup:
                instance._cleanup_port_forwarding_rules()
        cleanup.assert_not_called()

        with patch.object(
            instance,
            "_cleanup_port_forwarding_ipt",
        ) as cleanup:
            instance._cleanup_port_forwarding_rules("10.20.30.10")
        cleanup.assert_called_once_with("10.20.30.10")


class CommandMethodTests(unittest.TestCase):
    def test_run_bash_variants(self):
        instance = make_sandy()
        args = SimpleNamespace(bash_args=[])
        with patch.object(instance, "_exec", return_value=0) as execute:
            instance.run_bash(args)
        execute.assert_called_once_with(None, login_shell=True)

        args = SimpleNamespace(bash_args=["--", "-c", "echo", "safe"])
        with patch.object(instance, "_exec", return_value=0) as execute:
            instance.run_bash(args)
        execute.assert_called_once_with("echo safe")

    def test_run_bash_rejects_only_c_flag(self):
        instance = make_sandy()
        with captured_output():
            with self.assertRaises(SystemExit):
                instance.run_bash(SimpleNamespace(bash_args=["-c"]))

    def test_run_exec_strips_separator_and_requires_command(self):
        instance = make_sandy()
        with patch.object(instance, "_exec", return_value=0) as execute:
            instance.run_exec(SimpleNamespace(exec_command=["--", "python3", "-V"]))
        execute.assert_called_once_with("python3 -V")

        with captured_output():
            with self.assertRaises(SystemExit):
                instance.run_exec(SimpleNamespace(exec_command=[]))

    def test_run_exec_and_bash_propagate_container_failures(self):
        instance = make_sandy()
        cases = (
            (
                instance.run_exec,
                SimpleNamespace(exec_command=["false"]),
                7,
                7,
            ),
            (
                instance.run_bash,
                SimpleNamespace(bash_args=["-c", "false"]),
                -15,
                143,
            ),
            (
                instance.run_bash,
                SimpleNamespace(bash_args=[]),
                31,
                31,
            ),
        )
        for method, arguments, status, expected in cases:
            with self.subTest(method=method.__name__, status=status):
                with patch.object(instance, "_exec", return_value=status):
                    with self.assertRaises(SystemExit) as raised:
                        method(arguments)
                self.assertEqual(raised.exception.code, expected)

    def test_status_uses_machinectl_and_reports_oom_kills(self):
        # Mocks: the subprocess wrapper and the memory events.
        instance = make_sandy()
        for events, line in (
            (
                sandy.MemoryEvents(3, 2, 5),
                "OOM kills: 3 (memory limit reached: 5 times by all Sandy "
                "containers, 2 times inside this container)\n",
            ),
            (
                sandy.MemoryEvents(1, 0, 1),
                "OOM kills: 1 (memory limit reached: 1 time by all Sandy "
                "containers, 0 times inside this container)\n",
            ),
            (None, ""),
        ):
            with self.subTest(events=events):
                with patch.object(sandy, "_run_secure_subprocess") as run, patch.object(
                    sandy, "_container_memory_events", return_value=events
                ) as read:
                    with captured_output() as (stdout, _):
                        instance.run_status()
                run.assert_called_once_with(
                    ["machinectl", "status", "--no-pager", "--full", "ai-dev"]
                )
                read.assert_called_once_with("ai-dev")
                self.assertEqual(stdout.getvalue(), line)

    def test_list_sorts_and_reports_status(self):
        instance = make_sandy()
        paths = [
            "/var/lib/machines/sandy.zed",
            "/var/lib/machines/sandy.bad\n\x1b[31m",
            "/var/lib/machines/sandy.alpha",
            "/var/lib/machines/sandy.__cache",
        ]
        with patch.object(sandy.os.path, "exists", return_value=True):
            with patch.object(sandy.glob, "glob", return_value=paths):
                with patch.object(
                    instance,
                    "_get_cache_dir",
                    return_value=paths[-1],
                ):
                    with patch.object(
                        instance,
                        "_is_container_running",
                        side_effect=lambda name: "123" if name == "alpha" else None,
                    ):
                        with captured_output() as (stdout, _):
                            instance.run_list()
        output = stdout.getvalue()
        self.assertIn("alpha", output)
        self.assertIn("running", output)
        self.assertNotIn("\x1b", output)
        self.assertLess(output.index("alpha"), output.index("zed"))

    def test_down_powers_off(self):
        instance = make_sandy()
        with patch.object(instance, "_machine_poweroff", return_value=True) as poweroff:
            instance.run_down(SimpleNamespace())
        poweroff.assert_called_once_with()

    def test_down_exits_1_when_the_container_did_not_stop(self):
        # Regression test: down exited 0 after "did not stop", so a script
        # went on as if the container had stopped. Mocks: the poweroff.
        instance = make_sandy()
        with patch.object(instance, "_machine_poweroff", return_value=False):
            with self.assertRaises(SystemExit) as exited:
                instance.run_down(SimpleNamespace())
        self.assertEqual(exited.exception.code, 1)


class RemovalTests(unittest.TestCase):
    def test_remove_machine_dir_confirmation_and_success(self):
        instance = make_sandy()
        path = "/var/lib/machines/sandy.test"
        with patch.object(instance, "_confirm", return_value=False):
            with patch.object(sandy, "_remove_managed_tree") as rmtree:
                with captured_output():
                    instance._remove_machine_dir(path)
        rmtree.assert_not_called()

        with patch.object(instance, "_confirm", return_value=True):
            with patch.object(sandy, "_remove_managed_tree") as rmtree:
                with captured_output():
                    instance._remove_machine_dir(path)
        rmtree.assert_called_once_with(path)

    def test_remove_machine_dir_rejects_invalid_name_before_display(self):
        instance = make_sandy()
        path = "/var/lib/machines/sandy.bad\n\x1b[31m"

        with patch.object(instance, "_confirm") as confirm:
            with patch.object(sandy, "_remove_managed_tree") as remove:
                with captured_output() as (stdout, _):
                    instance._remove_machine_dir(path)

        output = stdout.getvalue().rstrip("\n")
        confirm.assert_not_called()
        remove.assert_not_called()
        self.assertFalse(sandy._contains_control_character(output))
        self.assertNotIn(path, output)
        self.assertIn("sandy.bad\\n\\x1b[31m", output)

    def test_rm_all_skips_invalid_filesystem_names_before_display(self):
        instance = make_sandy()
        invalid_path = "/var/lib/machines/sandy.bad\n\x1b[31m"
        valid_path = "/var/lib/machines/sandy.valid"
        args = SimpleNamespace(container=None, force=True)

        with patch.object(sandy.os.path, "exists", return_value=True):
            with patch.object(
                instance,
                "_get_cache_dir",
                return_value="/var/lib/machines/sandy.__cache",
            ):
                with patch.object(
                    sandy.glob,
                    "glob",
                    return_value=[invalid_path, valid_path],
                ):
                    with patch.object(
                        instance,
                        "_is_container_running",
                        return_value=None,
                    ) as running:
                        with patch.object(
                            instance,
                            "_cleanup_port_mappings_for_container",
                        ) as cleanup:
                            with patch.object(
                                instance, "_remove_machine_dir"
                            ) as remove:
                                with captured_output() as (stdout, _):
                                    instance.run_rm(args, all=True)

        output = stdout.getvalue().rstrip("\n")
        self.assertFalse(sandy._contains_control_character(output))
        self.assertNotIn(invalid_path, output)
        self.assertIn("sandy.bad\\n\\x1b[31m", output)
        running.assert_called_once_with("valid")
        cleanup.assert_called_once_with("valid")
        remove.assert_called_once_with(valid_path, prompt=False)

    def test_rm_rejects_incompatible_cache_options(self):
        instance = make_sandy()
        cases = [
            (True, False, SimpleNamespace(container=None, force=True)),
            (False, True, SimpleNamespace(container="test", force=True)),
        ]
        for all_value, network, args in cases:
            with self.subTest(all=all_value, network=network):
                with captured_output():
                    with self.assertRaises(SystemExit):
                        instance.run_rm(
                            args,
                            all=all_value,
                            cache=True,
                            network=network,
                        )

    def test_rm_cache_purges_with_force(self):
        instance = make_sandy()
        args = SimpleNamespace(container=None, force=True)
        with patch.object(instance, "_get_cache_dir", return_value="/cache"):
            with patch.object(sandy.os.path, "exists", return_value=True):
                with patch.object(instance, "_purge_cache") as purge:
                    with captured_output():
                        instance.run_rm(args, cache=True)
        purge.assert_called_once_with()

    def test_rm_network_refuses_while_containers_run(self):
        instance = make_sandy()
        instance.network = make_network()
        args = SimpleNamespace(container=None, force=True)
        with patch.object(
            instance,
            "_get_running_sandy_containers",
            return_value=["test-box"],
        ):
            with captured_output():
                with self.assertRaises(SystemExit):
                    instance.run_rm(args, network=True)

    def test_rm_keeps_a_container_that_did_not_stop(self):
        # Regression test: after "did not stop", rm still cleaned the ports
        # again and removed the image of the container, which still ran on
        # it. Mocks: the query (the container runs), the poweroff and
        # terminate commands, the stop waits (both time out), the port
        # cleanup, and the removal. _machine_poweroff is real.
        instance = make_sandy()
        args = SimpleNamespace(container="ai-dev", force=True)
        events: list[object] = []
        with patch.object(
            instance,
            "_get_machine_dir",
            return_value="/var/lib/machines/sandy.ai-dev",
        ):
            with patch.object(sandy.os.path, "exists", return_value=True):
                with patch.object(
                    instance, "_is_container_running", return_value="123"
                ):
                    with patch.object(
                        instance,
                        "_cleanup_port_mappings_for_container",
                        side_effect=lambda *a, **k: events.append(("cleanup", a, k)),
                    ):
                        with patch.object(
                            sandy,
                            "_run_secure_subprocess",
                            side_effect=lambda command, **_: events.append(command),
                        ):
                            with patch.object(
                                instance, "_wait_for_container_stop", return_value=False
                            ):
                                with patch.object(
                                    instance, "_remove_machine_dir"
                                ) as remove:
                                    with captured_output() as (stdout, _):
                                        with self.assertRaises(SystemExit) as exited:
                                            instance.run_rm(args)
        self.assertEqual(exited.exception.code, 1)
        remove.assert_not_called()
        # Only the cleanup of the poweroff ran; rm did not clean again.
        self.assertEqual(
            events,
            [
                ("cleanup", ("ai-dev",), {"lock_timeout": None}),
                ["machinectl", "poweroff", "ai-dev"],
                ["machinectl", "terminate", "ai-dev"],
            ],
        )
        self.assertIn("W: Container 'ai-dev' did not stop\n", stdout.getvalue())
        self.assertIn(
            "E: Did not remove container 'ai-dev': it did not stop\n",
            stdout.getvalue(),
        )

    def test_rm_all_removes_the_others_when_one_did_not_stop(self):
        # Mocks: two running containers; the poweroff of "stuck" fails. rm
        # --all keeps that one, removes the other, and exits 1 at the end.
        instance = make_sandy()
        args = SimpleNamespace(container=None, force=True)
        directories = [
            "/var/lib/machines/sandy.stuck",
            "/var/lib/machines/sandy.other",
        ]
        with patch.object(sandy.os.path, "exists", return_value=True):
            with patch.object(sandy.glob, "glob", return_value=directories):
                with patch.object(
                    instance,
                    "_get_cache_dir",
                    return_value="/var/lib/machines/sandy.__cache",
                ):
                    with patch.object(
                        instance, "_is_container_running", return_value="123"
                    ):
                        with patch.object(
                            instance,
                            "_machine_poweroff",
                            side_effect=lambda name: name != "stuck",
                        ) as poweroff:
                            with patch.object(
                                instance, "_cleanup_port_mappings_for_container"
                            ) as cleanup:
                                with patch.object(
                                    instance, "_remove_machine_dir"
                                ) as remove:
                                    with captured_output() as (stdout, _):
                                        with self.assertRaises(SystemExit) as exited:
                                            instance.run_rm(args, all=True)
        self.assertEqual(exited.exception.code, 1)
        self.assertEqual(poweroff.call_args_list, [call("stuck"), call("other")])
        cleanup.assert_called_once_with("other")
        remove.assert_called_once_with("/var/lib/machines/sandy.other", prompt=False)
        self.assertIn(
            "E: Did not remove container 'stuck': it did not stop\n",
            stdout.getvalue(),
        )

    def test_rm_removes_nothing_when_the_machine_query_fails(self):
        # Regression test: a failed query meant "not running", so rm removed
        # the image of a running container when the system bus was gone.
        # Mocks: machinectl fails as systemd 257 does with no system bus; the
        # poweroff, the port cleanup, and the removal record their calls.
        instance = make_sandy()
        args = SimpleNamespace(container="ai-dev", force=True)
        failure = subprocess.CalledProcessError(
            1,
            ["machinectl"],
            stderr="Failed to connect to system scope bus via local transport: "
            "Connection refused\n",
        )
        with patch.object(
            instance,
            "_get_machine_dir",
            return_value="/var/lib/machines/sandy.ai-dev",
        ):
            with patch.object(sandy.os.path, "exists", return_value=True):
                with patch.object(
                    sandy, "_run_secure_subprocess", side_effect=failure
                ) as run:
                    with patch.object(instance, "_machine_poweroff") as poweroff:
                        with patch.object(
                            instance, "_cleanup_port_mappings_for_container"
                        ) as cleanup:
                            with patch.object(
                                instance, "_remove_machine_dir"
                            ) as remove:
                                with self.assertRaises(
                                    subprocess.SubprocessError
                                ) as raised:
                                    instance.run_rm(args)
        self.assertIsInstance(raised.exception, sandy._MachineQueryError)
        self.assertEqual(
            run.call_args.args[0],
            ["machinectl", "show", "ai-dev", "-p", "Leader", "--value"],
        )
        poweroff.assert_not_called()
        cleanup.assert_not_called()
        remove.assert_not_called()

    def test_rm_network_keeps_the_network_when_a_machine_query_fails(self):
        # Regression test: a failed query meant "not running", so rm
        # --network removed the bridge and the rules of a running container.
        # Mocks: one image; machinectl fails as systemd 249 does with no
        # system bus; the network cleanup records its calls.
        instance = make_sandy()
        instance.network = make_network()
        args = SimpleNamespace(container=None, force=True)
        failure = subprocess.CalledProcessError(
            1,
            ["machinectl"],
            stderr="Failed to connect to bus: Connection refused\n",
        )
        with patch.object(sandy.os.path, "exists", return_value=True):
            with patch.object(
                sandy.glob,
                "glob",
                return_value=["/var/lib/machines/sandy.ai-dev"],
            ):
                with patch.object(sandy, "_run_secure_subprocess", side_effect=failure):
                    with patch.object(instance.network, "cleanup") as cleanup:
                        with patch.object(
                            instance, "_clear_port_mapping_state"
                        ) as clear:
                            with captured_output():
                                with self.assertRaises(
                                    subprocess.SubprocessError
                                ) as raised:
                                    instance.run_rm(args, network=True)
        self.assertIsInstance(raised.exception, sandy._MachineQueryError)
        cleanup.assert_not_called()
        clear.assert_not_called()

    def test_rm_single_container_cleans_and_removes(self):
        instance = make_sandy()
        args = SimpleNamespace(container="ai-dev", force=True)
        with patch.object(
            instance,
            "_get_machine_dir",
            return_value="/var/lib/machines/sandy.ai-dev",
        ):
            with patch.object(sandy.os.path, "exists", return_value=True):
                with patch.object(instance, "_is_container_running", return_value=None):
                    with patch.object(
                        instance,
                        "_cleanup_port_mappings_for_container",
                    ) as cleanup:
                        with patch.object(instance, "_remove_machine_dir") as remove:
                            instance.run_rm(args)
        cleanup.assert_called_once_with("ai-dev")
        remove.assert_called_once_with(
            "/var/lib/machines/sandy.ai-dev",
            prompt=False,
        )

    def test_rm_cache_handles_network_conflict_missing_and_decline(self):
        instance = make_sandy()
        conflict_args = SimpleNamespace(container=None, force=True)
        with captured_output():
            with self.assertRaises(SystemExit):
                instance.run_rm(
                    conflict_args,
                    cache=True,
                    network=True,
                )

        args = SimpleNamespace(container=None, force=False)
        with patch.object(instance, "_get_cache_dir", return_value="/cache"):
            with patch.object(sandy.os.path, "exists", return_value=False):
                with captured_output() as (stdout, _):
                    instance.run_rm(args, cache=True)
        self.assertIn("No cache to remove", stdout.getvalue())

        with patch.object(instance, "_get_cache_dir", return_value="/cache"):
            with patch.object(sandy.os.path, "exists", return_value=True):
                with patch.object(instance, "_confirm", return_value=False):
                    with patch.object(instance, "_purge_cache") as purge:
                        with captured_output() as (stdout, _):
                            instance.run_rm(args, cache=True)
        purge.assert_not_called()
        self.assertIn("Skipped cache removal", stdout.getvalue())

    def test_rm_network_rejects_incompatible_targets(self):
        instance = make_sandy()
        for all_value, container in (
            (True, None),
            (False, "target"),
        ):
            with self.subTest(all=all_value, container=container):
                args = SimpleNamespace(container=container, force=True)
                with captured_output():
                    with self.assertRaises(SystemExit):
                        instance.run_rm(
                            args,
                            all=all_value,
                            network=True,
                        )

    def test_rm_network_initializes_cleans_or_declines(self):
        instance = make_sandy()
        args = SimpleNamespace(container=None, force=True)
        network = make_network()
        with patch.object(sandy, "SandyNet", return_value=network):
            with patch.object(
                instance,
                "_get_running_sandy_containers",
                return_value=[],
            ):
                with patch.object(
                    instance,
                    "_clear_port_mapping_state",
                ) as clear:
                    with patch.object(network, "cleanup") as cleanup:
                        with captured_output():
                            instance.run_rm(args, network=True)
        cleanup.assert_called_once_with()
        clear.assert_called_once_with()

        instance.network = make_network()
        args.force = False
        with patch.object(
            instance,
            "_get_running_sandy_containers",
            return_value=[],
        ):
            with patch.object(instance, "_confirm", return_value=False):
                with patch.object(
                    instance,
                    "_clear_port_mapping_state",
                ) as clear:
                    with captured_output() as (stdout, _):
                        instance.run_rm(args, network=True)
        clear.assert_not_called()
        self.assertIn("Skipped network removal", stdout.getvalue())

    def test_rm_missing_single_container_exits(self):
        instance = make_sandy()
        args = SimpleNamespace(container="ai-dev", force=True)
        with patch.object(
            instance,
            "_get_machine_dir",
            return_value="/missing",
        ):
            with patch.object(sandy.os.path, "exists", return_value=False):
                with captured_output():
                    with self.assertRaises(SystemExit):
                        instance.run_rm(args)

    def test_rm_all_skips_cache_and_removes_each_container(self):
        instance = make_sandy()
        args = SimpleNamespace(container=None, force=True)
        paths = [
            "/var/lib/machines/sandy.one",
            "/var/lib/machines/sandy.__cache",
            "/var/lib/machines/sandy.two",
        ]
        with patch.object(sandy.os.path, "exists", return_value=True):
            with patch.object(sandy.glob, "glob", return_value=paths):
                with patch.object(
                    instance,
                    "_get_cache_dir",
                    return_value=paths[1],
                ):
                    with patch.object(
                        instance,
                        "_is_container_running",
                        return_value=None,
                    ):
                        with patch.object(
                            instance,
                            "_cleanup_port_mappings_for_container",
                        ) as cleanup:
                            with patch.object(
                                instance,
                                "_remove_machine_dir",
                            ) as remove:
                                instance.run_rm(args, all=True)
        self.assertEqual(
            cleanup.call_args_list,
            [call("one"), call("two")],
        )
        self.assertEqual(remove.call_count, 2)

    def test_rm_running_container_confirm_and_decline(self):
        instance = make_sandy()
        args = SimpleNamespace(container="ai-dev", force=False)
        path = "/var/lib/machines/sandy.ai-dev"
        with patch.object(
            instance,
            "_get_machine_dir",
            return_value=path,
        ):
            with patch.object(sandy.os.path, "exists", return_value=True):
                with patch.object(
                    instance,
                    "_is_container_running",
                    return_value="123",
                ):
                    with patch.object(
                        instance,
                        "_confirm",
                        side_effect=[False],
                    ):
                        with patch.object(
                            instance,
                            "_machine_poweroff",
                        ) as poweroff:
                            with patch.object(
                                instance,
                                "_remove_machine_dir",
                            ) as remove:
                                with captured_output():
                                    instance.run_rm(args)
        poweroff.assert_not_called()
        remove.assert_not_called()

        with patch.object(
            instance,
            "_get_machine_dir",
            return_value=path,
        ):
            with patch.object(sandy.os.path, "exists", return_value=True):
                with patch.object(
                    instance,
                    "_is_container_running",
                    return_value="123",
                ):
                    with patch.object(
                        instance,
                        "_confirm",
                        return_value=True,
                    ):
                        with patch.object(
                            instance,
                            "_machine_poweroff",
                        ) as poweroff:
                            with patch.object(
                                instance,
                                "_cleanup_port_mappings_for_container",
                            ):
                                with patch.object(
                                    instance,
                                    "_remove_machine_dir",
                                ) as remove:
                                    instance.run_rm(args)
        poweroff.assert_called_once_with("ai-dev")
        remove.assert_called_once_with(path, prompt=False)


class ResourceLimitTests(unittest.TestCase):
    """Parsing, defaults, and messages of the resource limits (item 2).

    Most tests use no mocks. Each test that mocks says what.
    """

    def test_parse_size_argument_takes_docker_units(self):
        cases = {
            "0": 0,
            "512": 512,
            "512b": 512,
            "1k": 1024,
            "64m": 64 * MIB,
            "64M": 64 * MIB,
            "2g": 2 * GIB,
            "1048576g": 1048576 * GIB,
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(sandy._parse_size_argument(value), expected)
        for value in (
            "",
            "-1",
            "01",
            "1.5g",
            "1gb",
            "1t",
            " 1g",
            "1g ",
            "1e3",
            "١g",
            "1048577g",
            "1" * 17,
        ):
            with self.subTest(value=value):
                with self.assertRaises(sandy.argparse.ArgumentTypeError):
                    sandy._parse_size_argument(value)

    def test_parse_memory_and_tmp_size_arguments(self):
        # The shared memory: 0 (no limit) or at least 64m.
        for value, expected in (("0", 0), ("64m", 64 * MIB), ("24g", 24 * GIB)):
            with self.subTest(value=value):
                self.assertEqual(sandy._parse_memory_argument(value), expected)
        for value in ("1", "512", "63m", str(64 * MIB - 1), "x"):
            with self.subTest(value=value):
                with self.assertRaises(sandy.argparse.ArgumentTypeError):
                    sandy._parse_memory_argument(value)
        # /tmp: 0 (the tmpfs default) or at least 1m.
        for value, expected in (("0", 0), ("1m", MIB), ("1024k", MIB), ("2g", 2 * GIB)):
            with self.subTest(value=value):
                self.assertEqual(sandy._parse_tmp_size_argument(value), expected)
        for value in ("1", "1023k", "-1", "1.5m"):
            with self.subTest(value=value):
                with self.assertRaises(sandy.argparse.ArgumentTypeError):
                    sandy._parse_tmp_size_argument(value)

    def test_parse_pids_limit_argument(self):
        for value, expected in (("-1", -1), ("1", 1), ("16384", 16384)):
            with self.subTest(value=value):
                self.assertEqual(sandy._parse_pids_limit_argument(value), expected)
        self.assertEqual(
            sandy._parse_pids_limit_argument(str(sandy.PID_MAX_LIMIT - 1)),
            sandy.PID_MAX_LIMIT - 1,
        )
        for value in ("0", "-2", str(sandy.PID_MAX_LIMIT), "01", "", "1.0", "1k"):
            with self.subTest(value=value):
                with self.assertRaises(sandy.argparse.ArgumentTypeError):
                    sandy._parse_pids_limit_argument(value)

    def test_parse_oom_score_adj_argument(self):
        for value in ("-999", "-500", "0", "1", "500", "1000"):
            with self.subTest(value=value):
                self.assertEqual(sandy._parse_oom_score_adj_argument(value), int(value))
        # -1000 would make every process of the containers unkillable.
        for value in ("-1000", "1001", "-0", "01", "+1", "", "1.0", " 1", "١"):
            with self.subTest(value=value):
                with self.assertRaises(sandy.argparse.ArgumentTypeError):
                    sandy._parse_oom_score_adj_argument(value)

    def test_parse_and_format_cpu_lists(self):
        cases = {
            "0": (0,),
            "0-3": (0, 1, 2, 3),
            "0-1,4,6-7": (0, 1, 4, 6, 7),
            "3,1-2": (1, 2, 3),
            "8191": (8191,),
        }
        for text, cpus in cases.items():
            with self.subTest(text=text):
                self.assertEqual(sandy._parse_cpu_list(text), cpus)
        for cpus, text in (
            ((0,), "0"),
            ((0, 1, 2, 3), "0-3"),
            ((0, 1, 4, 6, 7), "0-1,4,6-7"),
            ((2, 4, 6), "2,4,6"),
            ((4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15), "4-15"),
        ):
            with self.subTest(cpus=cpus):
                self.assertEqual(sandy._format_cpu_list(cpus), text)
        for text in (
            "",
            "a",
            "1-",
            "-1",
            "1,",
            ",1",
            "3-1",
            "8192",
            "0 1",
            "1\n",
            "١",
            "1--2",
            "1-2-3",
            "12345",
        ):
            with self.subTest(text=text):
                with self.assertRaisesRegex(ValueError, "Malformed CPU list"):
                    sandy._parse_cpu_list(text)

    def test_parse_cpuset_argument(self):
        self.assertEqual(sandy._parse_cpuset_argument("4-7,9"), (4, 5, 6, 7, 9))
        for value in ("", "4-", "a", "0 1", "8192", "0," * 2048 + "0"):
            with self.subTest(value=value[:16]):
                with self.assertRaises(sandy.argparse.ArgumentTypeError):
                    sandy._parse_cpuset_argument(value)

    def test_host_online_cpus(self):
        # Mocks: os.open and os.read of the online CPU list.
        for data, expected in (
            (b"0-7\n", tuple(range(8))),
            (b"0-1,4-5\n", (0, 1, 4, 5)),
        ):
            with self.subTest(data=data):
                with patch.object(sandy.os, "open", return_value=99), patch.object(
                    sandy.os, "read", return_value=data
                ), patch.object(sandy.os, "close") as close:
                    self.assertEqual(sandy._host_online_cpus(), expected)
                close.assert_called_once_with(99)
        for data in (b"0-7", b"", b"x\n", b"0" * 4096 + b"\n"):
            with self.subTest(data=data[:8]):
                with patch.object(sandy.os, "open", return_value=99), patch.object(
                    sandy.os, "read", return_value=data
                ), patch.object(sandy.os, "close") as close:
                    with self.assertRaises(ValueError):
                        sandy._host_online_cpus()
                close.assert_called_once_with(99)

    def test_host_task_limit_is_the_smaller_kernel_value(self):
        with tempfile.TemporaryDirectory() as directory:
            threads_max = Path(directory, "threads-max")
            pid_max = Path(directory, "pid_max")
            with patch.object(
                sandy, "THREADS_MAX_PATH", str(threads_max)
            ), patch.object(sandy, "PID_MAX_PATH", str(pid_max)):
                for threads, pids, expected in (
                    ("30516\n", "4194304\n", 30516),
                    ("1000000\n", "32768\n", 32768),
                ):
                    with self.subTest(threads=threads, pids=pids):
                        threads_max.write_text(threads)
                        pid_max.write_text(pids)
                        self.assertEqual(sandy._host_task_limit(), expected)
                pid_max.write_text("32768\n")
                for text in ("0\n", "01\n", "x\n", "1", "", "1" * 11 + "\n", "1" * 40):
                    with self.subTest(text=text):
                        threads_max.write_text(text)
                        with self.assertRaises(ValueError):
                            sandy._host_task_limit()

    def test_read_host_facts(self):
        # Mocks: the three host readers.
        with patch.object(
            sandy, "_host_online_cpus", return_value=(0, 1)
        ), patch.object(
            sandy, "_host_memory_bytes", return_value=4 * GIB
        ), patch.object(
            sandy, "_host_task_limit", return_value=32768
        ) as task_limit:
            self.assertEqual(
                sandy._read_host_facts(), sandy.HostFacts((0, 1), 4 * GIB, 32768)
            )
            for error in (
                ValueError("Malformed /proc/sys/kernel/pid_max"),
                FileNotFoundError("No such file"),
            ):
                with self.subTest(error=error):
                    task_limit.side_effect = error
                    with captured_output() as (stdout, _):
                        with self.assertRaises(SystemExit) as raised:
                            sandy._read_host_facts()
                    self.assertEqual(raised.exception.code, 1)
                    self.assertEqual(
                        stdout.getvalue(),
                        "E: Could not read the CPUs, the memory, or the task limit "
                        f"of the host: '{error}'\n",
                    )

    def test_host_memory(self):
        # Mocks: os.sysconf.
        values = {"SC_PHYS_PAGES": 4096, "SC_PAGE_SIZE": 4096}
        with patch.object(sandy.os, "sysconf", side_effect=values.__getitem__):
            self.assertEqual(sandy._host_memory_bytes(), 16 * MIB)
        for broken in (
            {"SC_PHYS_PAGES": -1, "SC_PAGE_SIZE": 4096},
            {"SC_PHYS_PAGES": 4096, "SC_PAGE_SIZE": 0},
        ):
            with self.subTest(broken=broken):
                with patch.object(sandy.os, "sysconf", side_effect=broken.__getitem__):
                    with self.assertRaises(ValueError):
                        sandy._host_memory_bytes()

    def test_default_group_keeps_the_lowest_cpus(self):
        # The host keeps 4 CPUs of 16 or more, 2 of 8 or more, otherwise 1;
        # the containers get at least 1 CPU.
        cases = {
            1: (0,),
            2: (1,),
            4: (1, 2, 3),
            7: tuple(range(1, 7)),
            8: tuple(range(2, 8)),
            15: tuple(range(2, 15)),
            16: tuple(range(4, 16)),
            64: tuple(range(4, 64)),
        }
        for count, expected in cases.items():
            with self.subTest(count=count):
                facts = sandy.HostFacts(tuple(range(count)), 16 * GIB, 131072)
                self.assertEqual(sandy._default_group_limits(facts).cpus, expected)
        # Online CPUs need not be contiguous.
        facts = sandy.HostFacts((0, 2, 4, 6, 8, 10, 12, 14), 16 * GIB, 131072)
        self.assertEqual(sandy._default_group_limits(facts).cpus, (4, 6, 8, 10, 12, 14))

    def test_default_group_memory_and_tasks_per_host_size(self):
        # The host keeps 25% of its memory, at least 4 GiB, never more than
        # half; the containers get the same share of the system task limit.
        # The task limits are those of kernel.threads-max at these sizes.
        for memory_gib, task_limit, shared_gib, tasks in (
            (4, 32768, 2, 16384),
            (8, 65536, 4, 32768),
            (12, 98304, 8, 65536),
            (16, 131072, 12, 98304),
            (32, 262144, 24, 196608),
            (64, 524288, 48, 393216),
        ):
            with self.subTest(memory_gib=memory_gib):
                facts = sandy.HostFacts((0, 1), memory_gib * GIB, task_limit)
                group = sandy._default_group_limits(facts)
                self.assertEqual(
                    (group.memory_max, group.tasks_max), (shared_gib * GIB, tasks)
                )
        # Measured VM: 3984496 KiB and threads-max 30516. Half, rounded down
        # to MiB, and the same share of the tasks.
        facts = sandy.HostFacts((0, 1), 3984496 * 1024, 30516)
        self.assertEqual(
            sandy._default_group_limits(facts),
            sandy.GroupLimits((1,), 1945 * MIB, 30516 * 1945 * MIB // (3984496 * 1024)),
        )

    def test_container_tasks_default_per_host_size(self):
        # 25% of the shared process limit, at least 8192, never more than
        # half of it.
        for memory_gib, task_limit, expected in (
            (4, 32768, 8192),
            (8, 65536, 8192),
            (16, 131072, 24576),
            (32, 262144, 49152),
            (64, 524288, 98304),
        ):
            with self.subTest(memory_gib=memory_gib):
                facts = sandy.HostFacts((0, 1), memory_gib * GIB, task_limit)
                group = sandy._default_group_limits(facts)
                self.assertEqual(
                    sandy._container_tasks_default(group, task_limit), expected
                )
        # A small shared limit: half of it. No shared limit: the system limit.
        self.assertEqual(
            sandy._container_tasks_default(DEFAULT_GROUP._replace(tasks_max=100), 1),
            50,
        )
        self.assertEqual(
            sandy._container_tasks_default(DEFAULT_GROUP._replace(tasks_max=1), 1), 1
        )
        self.assertEqual(
            sandy._container_tasks_default(
                DEFAULT_GROUP._replace(tasks_max=None), 4194304
            ),
            1048576,
        )

    def test_effective_group_limits_prefer_the_saved_values(self):
        self.assertEqual(
            sandy._effective_group_limits(DEFAULT_GROUP, sandy.SavedGroupLimits()),
            DEFAULT_GROUP,
        )
        self.assertEqual(
            sandy._effective_group_limits(
                DEFAULT_GROUP, sandy.SavedGroupLimits((0, 1), 8 * GIB, 4096)
            ),
            sandy.GroupLimits((0, 1), 8 * GIB, 4096),
        )
        # 0 and -1 mean no limit, as on the command line.
        self.assertEqual(
            sandy._effective_group_limits(
                DEFAULT_GROUP, sandy.SavedGroupLimits(None, 0, -1)
            ),
            sandy.GroupLimits(DEFAULT_GROUP.cpus, None, None),
        )

    def test_parse_shared_limits(self):
        online = tuple(range(8))
        self.assertEqual(
            sandy._parse_shared_limits("", online), sandy.SavedGroupLimits()
        )
        self.assertEqual(
            sandy._parse_shared_limits("{}\n", online), sandy.SavedGroupLimits()
        )
        self.assertEqual(
            sandy._parse_shared_limits(
                '{"cpus":"0-1,4","memory":8589934592,"tasks":-1}\n', online
            ),
            sandy.SavedGroupLimits((0, 1, 4), 8 * GIB, -1),
        )
        # Unknown fields are discarded.
        self.assertEqual(
            sandy._parse_shared_limits('{"memory":0,"swap":1,"x":null}', online),
            sandy.SavedGroupLimits(None, 0, None),
        )
        with patch.object(sandy.json, "loads", side_effect=RecursionError):
            with self.assertRaisesRegex(ValueError, "not valid JSON"):
                sandy._parse_shared_limits("[[]]", online)
        for text, message in (
            ("{", "not valid JSON"),
            # Python 3.10 gives RecursionError, 3.13 a list.
            ("[" * 3000 + "]" * 3000, "not valid JSON|not a JSON object"),
            ('{"tasks":' + "9" * 5000 + "}", "not valid JSON"),
            ("[]", "not a JSON object"),
            ('"x"', "not a JSON object"),
            ('{"cpus":1}', "CPUs are invalid"),
            ('{"cpus":"0-"}', "CPUs are invalid"),
            ('{"cpus":"0 1"}', "CPUs are invalid"),
            ('{"cpus":"' + "0," * 2048 + '0"}', "CPUs are invalid"),
            ('{"cpus":"7-8"}', "CPUs 7-8 are not all online"),
            ('{"memory":"8g"}', "memory is invalid"),
            ('{"memory":true}', "memory is invalid"),
            ('{"memory":1.5}', "memory is invalid"),
            ('{"memory":67108863}', "memory is invalid"),
            ('{"memory":-1}', "memory is invalid"),
            ('{"memory":%d}' % (sandy.SIZE_MAX + 1), "memory is invalid"),
            ('{"tasks":0}', "process limit is invalid"),
            ('{"tasks":-2}', "process limit is invalid"),
            ('{"tasks":%d}' % sandy.PID_MAX_LIMIT, "process limit is invalid"),
            ('{"tasks":false}', "process limit is invalid"),
        ):
            with self.subTest(text=text[:24]):
                with self.assertRaisesRegex(ValueError, message):
                    sandy._parse_shared_limits(text, online)

    def test_serialize_shared_limits_round_trip(self):
        for saved, text in (
            (sandy.SavedGroupLimits(), "{}\n"),
            (
                sandy.SavedGroupLimits((4, 5, 6, 7, 9), 24 * GIB, 65536),
                '{"cpus":"4-7,9","memory":25769803776,"tasks":65536}\n',
            ),
            (sandy.SavedGroupLimits(None, 0, -1), '{"memory":0,"tasks":-1}\n'),
        ):
            with self.subTest(saved=saved):
                self.assertEqual(sandy._serialize_shared_limits(saved), text)
                self.assertEqual(
                    sandy._parse_shared_limits(text, tuple(range(16))), saved
                )

    def test_read_saved_group_limits(self):
        online = tuple(range(8))
        self.assertEqual(
            sandy._read_saved_group_limits(None, online), sandy.SavedGroupLimits()
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "shared_limits.json")
            path.write_text('{"memory":0}\n')
            with path.open(encoding="utf-8") as handle:
                self.assertEqual(
                    sandy._read_saved_group_limits(handle, online),
                    sandy.SavedGroupLimits(memory_max=0),
                )
            for data, message in (
                (b'{"memory":0}' + b" " * sandy.SHARED_LIMITS_MAX_BYTES, "too large"),
                (b'{"cpus":"\xff"}', "not valid text"),
            ):
                with self.subTest(message=message):
                    path.write_bytes(data)
                    with path.open(encoding="utf-8") as handle:
                        with self.assertRaisesRegex(ValueError, message):
                            sandy._read_saved_group_limits(handle, online)

    def args(self, **overrides):
        values = {"pids_limit": None, "tmp_size": None, "oom_score_adj": None}
        values.update(overrides)
        return SimpleNamespace(**values)

    def test_resolve_resource_limits(self):
        self.assertEqual(
            sandy._resolve_resource_limits(self.args(), DEFAULT_GROUP, 131072),
            sandy.ResourceLimits(24576, 512 * MIB, None),
        )
        self.assertEqual(
            sandy._resolve_resource_limits(
                self.args(pids_limit=512, tmp_size=64 * MIB, oom_score_adj=-500),
                DEFAULT_GROUP,
                131072,
            ),
            sandy.ResourceLimits(512, 64 * MIB, -500),
        )
        # -1 and 0 mean no process limit of its own and the tmpfs default.
        self.assertEqual(
            sandy._resolve_resource_limits(
                self.args(pids_limit=-1, tmp_size=0), DEFAULT_GROUP, 131072
            ),
            sandy.ResourceLimits(None, None, None),
        )

    def test_limit_warnings(self):
        for limits, group, expected in (
            (sandy.ResourceLimits(98304, 12 * GIB, None), DEFAULT_GROUP, []),
            (sandy.ResourceLimits(None, None, None), DEFAULT_GROUP, []),
            (
                sandy.ResourceLimits(98305, None, None),
                DEFAULT_GROUP,
                [
                    "W: --pids-limit 98305 is above the process limit that all "
                    "Sandy containers share (98304), which applies too"
                ],
            ),
            # The tmpfs default is half of the host memory.
            (
                sandy.ResourceLimits(None, None, None),
                DEFAULT_GROUP._replace(memory_max=4 * GIB),
                [
                    "W: /tmp (8.0 GiB) is larger than the memory that all Sandy "
                    "containers share (4.0 GiB). Files in /tmp count against it, "
                    "so a full /tmp ends processes"
                ],
            ),
            (
                sandy.ResourceLimits(10**6, 64 * GIB, None),
                sandy.GroupLimits((0,), None, None),
                [],
            ),
        ):
            with self.subTest(limits=limits, group=group):
                self.assertEqual(
                    sandy._limit_warnings(group, limits, 16 * GIB), expected
                )

    def test_scope_limit_properties_and_tmpfs_argument(self):
        self.assertEqual(
            sandy._scope_limit_properties(sandy.ResourceLimits(512, 64 * MIB, -500)),
            ["--property=TasksMax=512", "--property=MemorySwapMax=0"],
        )
        self.assertEqual(
            sandy._scope_limit_properties(sandy.ResourceLimits(None, None, None)),
            ["--property=TasksMax=infinity", "--property=MemorySwapMax=0"],
        )
        self.assertEqual(
            sandy._tmp_tmpfs_argument(64 * MIB),
            f"--tmpfs=/tmp:mode=1777,size={64 * MIB}",
        )
        self.assertEqual(sandy._tmp_tmpfs_argument(None), "--tmpfs=/tmp:mode=1777")

    def test_apply_group_limits(self):
        # Mocks: the subprocess wrapper.
        for group, values in (
            (
                sandy.GroupLimits((4, 5, 6, 7, 9), 8 * GIB, 4096),
                ["AllowedCPUs=4-7,9", f"MemoryMax={8 * GIB}", "TasksMax=4096"],
            ),
            (
                sandy.GroupLimits((1,), None, None),
                ["AllowedCPUs=1", "MemoryMax=infinity", "TasksMax=infinity"],
            ),
        ):
            with self.subTest(group=group):
                with patch.object(sandy, "_run_secure_subprocess") as run:
                    sandy._apply_group_limits(group)
                run.assert_called_once_with(
                    ["systemctl", "set-property", "--runtime", "sandy.slice", *values],
                    check=True,
                )

    def test_parse_systemd_values(self):
        # The formats of systemctl show, measured on systemd 249, 255, 257.
        for text, expected in (("infinity", None), ("0", 0), ("1073741824", GIB)):
            with self.subTest(text=text):
                self.assertEqual(sandy._parse_systemd_limit(text), expected)
        for text in ("", "max", "-1", "01", "1G", "1" * 21):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    sandy._parse_systemd_limit(text)
        for text, expected in (
            ("", ()),
            ("1", (1,)),
            ("0-1", (0, 1)),
            ("0 2-3 5", (0, 2, 3, 5)),
        ):
            with self.subTest(text=text):
                self.assertEqual(sandy._parse_systemd_cpu_list(text), expected)
        for text in ("0,1", "0  1", " 0", "0 ", "x", "0-"):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    sandy._parse_systemd_cpu_list(text)

    def show(self, stdout):
        # Mocks: the subprocess wrapper returns the systemctl show output.
        result = SimpleNamespace(stdout=stdout)
        with patch.object(sandy, "_run_secure_subprocess", return_value=result) as run:
            limits = sandy._read_live_group_limits()
        run.assert_called_once_with(
            [
                "systemctl",
                "show",
                "sandy.slice",
                "-p",
                "AllowedCPUs",
                "-p",
                "MemoryMax",
                "-p",
                "TasksMax",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        return limits

    def test_read_live_group_limits(self):
        self.assertEqual(
            self.show("AllowedCPUs=0 2-3 5\nMemoryMax=1000000\nTasksMax=5\n"),
            sandy.GroupLimits((0, 2, 3, 5), 1000000, 5),
        )
        # A slice that does not exist (measured), in any order.
        self.assertEqual(
            self.show("TasksMax=infinity\nAllowedCPUs=\nMemoryMax=infinity\n"),
            sandy.GroupLimits((), None, None),
        )
        for stdout in (
            "",
            "AllowedCPUs=\nMemoryMax=infinity\n",
            "AllowedCPUs=\nMemoryMax=infinity\nTasksMax=infinity\nTasksMax=1\n",
            "AllowedCPUs=\nMemoryMax=infinity\nTasksMax=infinity\nCPUQuota=1\n",
            "AllowedCPUs\nMemoryMax=infinity\nTasksMax=infinity\n",
            "AllowedCPUs=\x1b[1m\nMemoryMax=infinity\nTasksMax=infinity\n",
            "AllowedCPUs=0,1\nMemoryMax=infinity\nTasksMax=infinity\n",
            "AllowedCPUs=\nMemoryMax=max\nTasksMax=infinity\n",
            "AllowedCPUs=\nMemoryMax=infinity\nTasksMax=50%\n",
            "AllowedCPUs=" + "0 " * 4096 + "1\nMemoryMax=infinity\nTasksMax=infinity\n",
        ):
            with self.subTest(stdout=stdout[:40]):
                with self.assertRaises(ValueError):
                    self.show(stdout)

    def test_sync_group_limits_changes_only_a_different_slice(self):
        # Mocks: the systemctl query and change.
        for live, applied in (
            (DEFAULT_GROUP, False),
            (sandy.GroupLimits((), None, None), True),
            (DEFAULT_GROUP._replace(memory_max=8 * GIB), True),
            (DEFAULT_GROUP._replace(tasks_max=None), True),
            (DEFAULT_GROUP._replace(cpus=(2, 3)), True),
        ):
            with self.subTest(live=live):
                with patch.object(
                    sandy, "_read_live_group_limits", return_value=live
                ), patch.object(sandy, "_apply_group_limits") as apply:
                    sandy._sync_group_limits(DEFAULT_GROUP)
                if applied:
                    apply.assert_called_once_with(DEFAULT_GROUP)
                else:
                    apply.assert_not_called()

    def test_describe_limits(self):
        self.assertEqual(
            sandy._describe_group_limits(DEFAULT_GROUP, sandy.SavedGroupLimits()),
            "CPUs 2-7, memory 12.0 GiB, 98304 tasks",
        )
        self.assertEqual(
            sandy._describe_group_limits(
                sandy.GroupLimits((0, 1, 2, 3), None, None),
                sandy.SavedGroupLimits((0, 1, 2, 3), 0, -1),
            ),
            "CPUs 0-3 (saved), no memory limit (saved), no process limit (saved)",
        )
        self.assertEqual(
            sandy._describe_group_limits(
                DEFAULT_GROUP._replace(memory_max=512 * MIB),
                sandy.SavedGroupLimits(memory_max=512 * MIB),
            ),
            "CPUs 2-7, memory 512.0 MiB (saved), 98304 tasks",
        )
        self.assertEqual(
            sandy._describe_resource_limits(
                sandy.ResourceLimits(24576, 512 * MIB, None), 16 * GIB
            ),
            "24576 tasks, /tmp 512.0 MiB, no swap",
        )
        self.assertEqual(
            sandy._describe_resource_limits(
                sandy.ResourceLimits(None, None, -500), 16 * GIB
            ),
            "no process limit of its own, /tmp 8.0 GiB, no swap, OOM score "
            "adjustment -500",
        )
        self.assertEqual(sandy._times_text(1), "1 time")
        self.assertEqual(sandy._times_text(0), "0 times")

    def test_parse_and_read_oom_score_adj(self):
        for text, expected in (
            ("0\n", 0),
            ("-1000\n", -1000),
            ("-500\n", -500),
            ("1000\n", 1000),
        ):
            with self.subTest(text=text):
                self.assertEqual(sandy._parse_oom_score_adj(text), expected)
        for text in ("0", "-0\n", "1001\n", "-1001\n", "x\n", "\n", "1\n\n", "01\n"):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    sandy._parse_oom_score_adj(text)
        # The Leader's value from its open /proc directory.
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "oom_score_adj")
            fd = os.open(directory, sandy.DIRECTORY_OPEN_FLAGS)
            self.addCleanup(os.close, fd)
            path.write_text("-500\n")
            self.assertEqual(sandy._read_oom_score_adj(fd), -500)
            for text in ("x\n", "1" * 17):
                with self.subTest(text=text):
                    path.write_text(text)
                    with self.assertRaises(ValueError):
                        sandy._read_oom_score_adj(fd)

    def test_write_own_oom_score_adj(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "oom_score_adj")
            path.write_text("")
            with patch.object(sandy, "OWN_OOM_SCORE_ADJ_PATH", str(path)):
                sandy._write_own_oom_score_adj(-500)
                self.assertEqual(path.read_text(), "-500\n")
                # Mocks: a short write.
                with patch.object(sandy.os, "write", return_value=1):
                    with self.assertRaisesRegex(OSError, "Short write"):
                        sandy._write_own_oom_score_adj(-500)

    def test_oom_score_adj_for_children_restores_the_value(self):
        # Mocks: the write of the value; the read uses a temporary file.
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "oom_score_adj")
            path.write_text("100\n")
            with patch.object(sandy, "OWN_OOM_SCORE_ADJ_PATH", str(path)), patch.object(
                sandy, "_write_own_oom_score_adj"
            ) as write:
                with sandy._oom_score_adj_for_children(None):
                    pass
                write.assert_not_called()
                with sandy._oom_score_adj_for_children(-500):
                    self.assertEqual(write.call_args_list, [call(-500)])
                self.assertEqual(write.call_args_list, [call(-500), call(100)])
                # The value is restored after an error too.
                write.reset_mock()
                with self.assertRaises(RuntimeError):
                    with sandy._oom_score_adj_for_children(-500):
                        raise RuntimeError("start failed")
                self.assertEqual(write.call_args_list, [call(-500), call(100)])
                # A failed restore is ignored: each attach sets its own value.
                write.reset_mock()
                write.side_effect = [None, OSError(errno.EACCES, "x")]
                with sandy._oom_score_adj_for_children(-500):
                    pass
                self.assertEqual(write.call_args_list, [call(-500), call(100)])
                # A malformed value of this process: nothing is written.
                write.reset_mock(side_effect=True)
                path.write_text("x\n")
                with self.assertRaises(ValueError):
                    with sandy._oom_score_adj_for_children(-500):
                        pass
                write.assert_not_called()


class RunUpTests(unittest.TestCase):
    def setUp(self):
        def open_runtime_machine(path):
            return os.open(path, sandy.DIRECTORY_OPEN_FLAGS)

        verifier = patch.object(
            sandy,
            "_open_verified_dir",
            side_effect=open_runtime_machine,
        )
        verifier.start()
        self.addCleanup(verifier.stop)
        # Mock the systemd unit query, readiness, the console attach, and the
        # stop. The keepalive directory is real, in the temporary directory.
        self.keepalive_script = PROJECT_DIR / "sandy-keepalive.sh"
        self.supervisor_unit_loaded = self.start_patch(
            sandy, "_supervisor_unit_loaded", False
        )
        self.wait_for_container_ready = self.start_patch(
            sandy.Sandy, "_wait_for_container_ready", True
        )
        self.wait_for_keepalive_open = self.start_patch(
            sandy.Sandy, "_wait_for_keepalive_open", True
        )
        # The host facts and the shared limits; SharedLimitTests cover them.
        self.read_host_facts = self.start_patch(sandy, "_read_host_facts", HOST_FACTS)
        self.set_shared_limits = self.start_patch(
            sandy.Sandy,
            "_set_shared_limits",
            (DEFAULT_GROUP, sandy.SavedGroupLimits()),
        )
        # The OOM score adjustment around the start of the supervisor.
        self.oom_events = []

        @contextmanager
        def oom_score_adj(value):
            self.oom_events.append(("set", value))
            try:
                yield
            finally:
                self.oom_events.append(("restore", value))

        self.oom_score_adj = self.start_patch(
            sandy, "_oom_score_adj_for_children", None
        )
        self.oom_score_adj.side_effect = oom_score_adj
        self.exec = self.start_patch(sandy.Sandy, "_exec", 0)
        self.machine_poweroff = self.start_patch(sandy.Sandy, "_machine_poweroff", None)
        # The lifecycle lock and the up-console marker of up without -d.
        self.lock_events = []

        @contextmanager
        def lock():
            self.lock_events.append("enter")
            try:
                yield
            finally:
                self.lock_events.append("exit")

        self.start_patch(sandy, "_lifecycle_lock", None).side_effect = lock
        self.create_marker = self.start_patch(sandy, "_create_up_console_marker", None)
        self.create_marker.side_effect = lambda name, supervisor: (
            self.lock_events.append(f"marker {name}")
        )
        self.ensure_cache_dir = self.start_patch(sandy.Sandy, "_ensure_cache_dir", None)
        # The up lock of the container name: a mock lock file. UpLockTests
        # cover the lock itself.
        self.up_lock = MagicMock()
        self.acquire_up_lock = self.start_patch(sandy, "_acquire_up_lock", self.up_lock)
        # The mounts of the workspace and shared directories: the check of a
        # host directory (it needs root and the kernel), the wait that mounts
        # them in the container, the pending marker, and the ids of the image
        # user. MountPlanTests, MountContainerDirsTests, and WaitForMountsTests
        # cover them.
        self.start_patch(sandy, "_read_mountinfo", "")
        self.plan_mount = self.start_patch(sandy, "_plan_mount", None)
        self.plan_mount.side_effect = lambda label, source, target: sandy.MountPlan(
            label, source, target, 1, 2
        )
        self.wait_for_mounts = self.start_patch(sandy.Sandy, "_wait_for_mounts", True)
        self.read_image_user_ids = self.start_patch(
            sandy, "_read_image_user_ids", (1000, 1000)
        )
        self.pending_marker = self.start_patch(
            sandy, "_create_mounts_pending_marker", None
        )
        self.pending_marker.side_effect = lambda name, supervisor: (
            self.lock_events.append(f"pending {name}")
        )
        # The pidfd of the started supervisor: a real descriptor of
        # /dev/null, which up closes when it returns. PinnedSupervisorTests
        # cover the pin and the scope check.
        self.pinned: list = []

        def pin_supervisor(pid):
            pinned = sandy.PinnedSupervisor(os.open(os.devnull, os.O_RDONLY), pid)
            self.pinned.append(pinned)
            return pinned

        self.pin_supervisor = self.start_patch(sandy, "_pin_supervisor", None)
        self.pin_supervisor.side_effect = pin_supervisor
        # The stale port rule cleanup at the start of up.
        self.real_cleanup = sandy.Sandy._cleanup_port_mappings_for_container
        self.stale_cleanup = self.start_patch(
            sandy.Sandy, "_cleanup_port_mappings_for_container", None
        )
        # The port mapping lock, which up holds from the publish of its ports
        # until it has pinned the supervisor and made the markers that it
        # needs. A test can make it raise. PortStateTests cover the lock
        # itself.
        self.real_port_lock = sandy.Sandy._port_mapping_lock
        self.port_lock_error = None

        @contextmanager
        def port_lock(exclusive, timeout=None):
            if self.port_lock_error is not None:
                raise self.port_lock_error
            self.lock_events.append(f"port lock {timeout}")
            try:
                yield None
            finally:
                self.lock_events.append("port unlock")

        self.port_lock = self.start_patch(sandy.Sandy, "_port_mapping_lock", None)
        self.port_lock.side_effect = port_lock
        reader = patch.object(
            sandy,
            "_read_keepalive_script",
            return_value=self.keepalive_script.read_bytes(),
        )
        reader.start()
        self.addCleanup(reader.stop)

    def start_patch(self, target, attribute, value):
        patcher = patch.object(target, attribute, return_value=value)
        self.addCleanup(patcher.stop)
        return patcher.start()

    @staticmethod
    def nspawn_command(command):
        """Return the nspawn part of a systemd-run command."""
        return command[command.index("systemd-nspawn") :]

    @staticmethod
    def record_cleanup(events):
        """Return a port cleanup mock that records each call in events."""
        return lambda name: events.append(f"cleanup {name}")

    def arguments(self, **overrides):
        values = {
            "ports": None,
            "network": "host",
            "build": False,
            "persistent": False,
            "detach": True,
            "tmp_size": None,
            "pids_limit": None,
            "oom_score_adj": None,
        }
        values.update(overrides)
        return SimpleNamespace(**values)

    def test_rejects_running_container(self):
        instance = make_sandy()
        with patch.object(instance, "_is_container_running", return_value="123"):
            with captured_output():
                with self.assertRaises(SystemExit):
                    instance.run_up(self.arguments())

    def test_rejects_existing_or_unknown_unit_before_host_changes(self):
        for loaded, message in (
            ({"return_value": True}, "Unit 'sandy-ai-dev.scope' already exists"),
            (
                {"side_effect": ValueError("Malformed LoadState")},
                "Could not query unit 'sandy-ai-dev.scope': 'Malformed LoadState'",
            ),
            (
                {"side_effect": subprocess.CalledProcessError(1, ["systemctl"])},
                "Could not query unit",
            ),
        ):
            with self.subTest(message=message):
                instance = make_sandy()
                self.supervisor_unit_loaded.reset_mock(
                    return_value=True, side_effect=True
                )
                self.supervisor_unit_loaded.configure_mock(**loaded)
                with patch.object(instance, "_is_container_running", return_value=None):
                    with patch.object(instance, "_get_machine_dir") as machine_dir:
                        with patch.object(
                            sandy, "_run_secure_subprocess_popen"
                        ) as popen:
                            with captured_output() as (stdout, _):
                                with self.assertRaises(SystemExit):
                                    instance.run_up(self.arguments())
                self.assertIn(message, stdout.getvalue())
                machine_dir.assert_not_called()
                popen.assert_not_called()
                # The stale rule cleanup changes the firewall and the port
                # state, so it must come after the unit check.
                self.stale_cleanup.assert_not_called()

    def test_keepalive_failure_rejects_before_network_setup(self):
        instance = make_sandy()
        instance.workspace = None
        with tempfile.TemporaryDirectory() as machine:
            with patch.object(instance, "_is_container_running", return_value=None):
                with patch.object(instance, "_get_machine_dir", return_value=machine):
                    with patch.object(
                        sandy,
                        "_read_keepalive_script",
                        side_effect=PermissionError("unsafe"),
                    ):
                        with patch.object(sandy, "SandyNet") as network:
                            with patch.object(
                                sandy, "_run_secure_subprocess_popen"
                            ) as popen:
                                with captured_output() as (stdout, _):
                                    with self.assertRaises(SystemExit):
                                        instance.run_up(
                                            self.arguments(network="lenient")
                                        )
        self.assertIn("Could not prepare the keepalive payload", stdout.getvalue())
        network.assert_not_called()
        popen.assert_not_called()

    def test_not_ready_container_is_stopped_and_reported(self):
        for detach in (True, False):
            with self.subTest(detach=detach):
                instance = make_sandy()
                instance.workspace = None
                self.wait_for_container_ready.return_value = False
                self.exec.reset_mock()
                with tempfile.TemporaryDirectory() as machine:
                    with patch.object(
                        instance, "_is_container_running", return_value=None
                    ):
                        with patch.object(
                            instance, "_get_machine_dir", return_value=machine
                        ):
                            with patch.object(
                                instance, "_remove_port_mappings_from_state"
                            ):
                                with patch.object(
                                    sandy, "_run_secure_subprocess_popen"
                                ) as popen:
                                    with patch.object(
                                        instance, "_stop_failed_start"
                                    ) as stop:
                                        with patch.object(
                                            instance, "_run_init_script"
                                        ) as init:
                                            with captured_output() as (stdout, _):
                                                with self.assertRaises(SystemExit):
                                                    instance.run_up(
                                                        self.arguments(detach=detach)
                                                    )
                supervisor = popen.return_value
                self.wait_for_container_ready.assert_called_with(
                    spinner_line_event=ANY, supervisor=supervisor
                )
                stop.assert_called_once_with(supervisor)
                init.assert_not_called()
                self.exec.assert_not_called()
                self.assertIn("E: Container 'ai-dev'", stdout.getvalue())

    def run_detached_up(self, instance, machine):
        """Run up -d with the host mocks of these tests; return the popen mock."""
        with patch.object(instance, "_is_container_running", return_value=None):
            with patch.object(instance, "_remove_port_mappings_from_state"):
                with patch.object(instance, "_get_machine_dir", return_value=machine):
                    with patch.object(sandy, "_run_secure_subprocess_popen") as popen:
                        with patch.object(
                            instance, "_run_init_script", return_value=False
                        ):
                            with captured_output():
                                instance.run_up(self.arguments())
        return popen

    def keepalive_dir_of(self, popen):
        command = self.nspawn_command(popen.call_args.args[0])
        (bind,) = [a for a in command if a.endswith(":/run/sandy")]
        return bind.removeprefix("--bind-ro=").split(":", 1)[0]

    def test_keepalive_files_stay_until_the_payload_opened_the_script(self):
        # Regression test for review finding S2: up removed the keepalive
        # files as soon as the readiness probe worked, before bash could
        # have opened the script (reproduced on systemd 249, 255, and 257).
        # Mocks: as in the detached command test.
        instance = make_sandy()
        instance.workspace = None
        order = []
        popens = []

        def ready(**kwargs):
            order.append("ready")
            return True

        self.wait_for_container_ready.side_effect = ready

        def keepalive_open(supervisor):
            (popen,) = popens
            self.assertIs(supervisor, popen.return_value)
            present = os.path.isdir(self.keepalive_dir_of(popen))
            order.append(f"keepalive open, files present={present}")
            return True

        self.wait_for_keepalive_open.side_effect = keepalive_open
        with tempfile.TemporaryDirectory() as machine, patch.object(
            sandy, "_run_secure_subprocess_popen"
        ) as popen, patch.object(
            instance, "_is_container_running", return_value=None
        ), patch.object(
            instance, "_remove_port_mappings_from_state"
        ), patch.object(
            instance, "_run_init_script", return_value=False
        ), patch.object(
            instance, "_get_machine_dir", return_value=machine
        ):
            popens.append(popen)
            with captured_output():
                instance.run_up(self.arguments())
        self.assertEqual(order, ["ready", "keepalive open, files present=True"])
        self.assertFalse(os.path.lexists(self.keepalive_dir_of(popen)))

    def test_keepalive_open_failure_stops_the_started_container(self):
        for detach in (True, False):
            with self.subTest(detach=detach):
                instance = make_sandy()
                instance.workspace = None
                self.wait_for_keepalive_open.return_value = False
                self.exec.reset_mock()
                with tempfile.TemporaryDirectory() as machine, patch.object(
                    instance, "_is_container_running", return_value=None
                ), patch.object(
                    instance, "_get_machine_dir", return_value=machine
                ), patch.object(
                    instance, "_remove_port_mappings_from_state"
                ), patch.object(
                    sandy, "_run_secure_subprocess_popen"
                ) as popen, patch.object(
                    instance, "_stop_failed_start"
                ) as stop, patch.object(
                    instance, "_run_init_script"
                ) as init:
                    with captured_output() as (stdout, _):
                        with self.assertRaises(SystemExit):
                            instance.run_up(self.arguments(detach=detach))
                supervisor = popen.return_value
                self.wait_for_keepalive_open.assert_called_with(supervisor)
                stop.assert_called_once_with(supervisor)
                init.assert_not_called()
                self.exec.assert_not_called()
                self.assertIn("E: Container 'ai-dev'", stdout.getvalue())
                self.assertFalse(os.path.lexists(self.keepalive_dir_of(popen)))

    def run_up_with_mocks(self, instance, args, popen_side_effect=None):
        """Run up with a temporary machine; return the popen mock and output."""
        with tempfile.TemporaryDirectory() as machine, patch.object(
            instance, "_is_container_running", return_value=None
        ), patch.object(instance, "_remove_port_mappings_from_state"), patch.object(
            instance, "_get_machine_dir", return_value=machine
        ), patch.object(
            sandy, "_run_secure_subprocess_popen", side_effect=popen_side_effect
        ) as popen, patch.object(
            instance, "_run_init_script", return_value=False
        ):
            with captured_output() as (stdout, _):
                instance.run_up(args)
        return popen, stdout.getvalue()

    def test_default_limits_are_reported(self):
        instance = make_sandy()
        instance.workspace = None
        popen, output = self.run_up_with_mocks(instance, self.arguments())
        self.assertIn(
            "I: Limits of all Sandy containers: CPUs 2-7, memory 12.0 GiB, 98304 "
            "tasks\nI: Limits of this container: 24576 tasks, /tmp 512.0 MiB, no "
            "swap\n",
            output,
        )
        self.assertNotIn("W: --pids-limit", output)
        self.assertNotIn("W: /tmp", output)
        self.read_host_facts.assert_called_once_with()
        self.set_shared_limits.assert_called_once_with(HOST_FACTS)
        # Without --oom-score-adj the container keeps the value of up.
        self.assertEqual(self.oom_events, [("set", None), ("restore", None)])
        popen.assert_called_once()

    def test_explicit_limits_reach_the_scope_and_the_tmpfs(self):
        instance = make_sandy()
        instance.workspace = None
        events = self.oom_events
        args = self.arguments(pids_limit=512, tmp_size=64 * MIB, oom_score_adj=-500)
        popen, output = self.run_up_with_mocks(
            instance, args, lambda *a, **k: events.append(("popen",)) or MagicMock()
        )
        scope_command = popen.call_args.args[0]
        self.assertEqual(
            scope_command[8 : scope_command.index("--")],
            ["--property=TasksMax=512", "--property=MemorySwapMax=0"],
        )
        self.assertIn(
            f"--tmpfs=/tmp:mode=1777,size={64 * MIB}",
            self.nspawn_command(scope_command),
        )
        self.assertIn(
            "I: Limits of this container: 512 tasks, /tmp 64.0 MiB, no swap, OOM "
            "score adjustment -500\n",
            output,
        )
        # The supervisor, and so the container, inherits the value.
        self.assertEqual(events, [("set", -500), ("popen",), ("restore", -500)])

    def test_no_limits_of_its_own(self):
        instance = make_sandy()
        instance.workspace = None
        popen, output = self.run_up_with_mocks(
            instance, self.arguments(pids_limit=-1, tmp_size=0)
        )
        scope_command = popen.call_args.args[0]
        self.assertEqual(
            scope_command[8 : scope_command.index("--")],
            ["--property=TasksMax=infinity", "--property=MemorySwapMax=0"],
        )
        self.assertIn("--tmpfs=/tmp:mode=1777", self.nspawn_command(scope_command))
        # The tmpfs default is half of the host memory.
        self.assertIn(
            "I: Limits of this container: no process limit of its own, /tmp 8.0 "
            "GiB, no swap\n",
            output,
        )

    def test_up_warns_about_limits_above_the_shared_limits(self):
        for args, warnings in (
            (self.arguments(pids_limit=98304, tmp_size=12 * GIB), []),
            (
                self.arguments(pids_limit=98305),
                [
                    "W: --pids-limit 98305 is above the process limit that all "
                    "Sandy containers share (98304), which applies too"
                ],
            ),
            (
                self.arguments(tmp_size=12 * GIB + MIB),
                [
                    "W: /tmp (12.0 GiB) is larger than the memory that all Sandy "
                    "containers share (12.0 GiB). Files in /tmp count against it, "
                    "so a full /tmp ends processes"
                ],
            ),
        ):
            with self.subTest(args=args):
                instance = make_sandy()
                instance.workspace = None
                _, output = self.run_up_with_mocks(instance, args)
                self.assertEqual(
                    [
                        line
                        for line in output.splitlines()
                        if line.startswith(("W: --pids-limit", "W: /tmp"))
                    ],
                    warnings,
                )

    def test_shared_limits_are_the_first_host_change(self):
        instance = make_sandy()
        instance.workspace = None
        events = []
        self.read_host_facts.side_effect = lambda: events.append("facts") or HOST_FACTS
        self.set_shared_limits.side_effect = lambda facts: events.append("shared") or (
            DEFAULT_GROUP,
            sandy.SavedGroupLimits(),
        )
        self.stale_cleanup.side_effect = lambda name: events.append("cleanup")
        with tempfile.TemporaryDirectory() as machine, patch.object(
            instance,
            "_is_container_running",
            side_effect=lambda: events.append("running") or None,
        ), patch.object(
            instance, "_get_machine_dir", return_value=machine
        ), patch.object(
            sandy,
            "_run_secure_subprocess_popen",
            side_effect=lambda *args, **kwargs: events.append("popen") or MagicMock(),
        ), patch.object(
            instance, "_run_init_script", return_value=False
        ):
            with captured_output():
                instance.run_up(self.arguments())
        self.assertEqual(events, ["facts", "running", "shared", "cleanup", "popen"])

    def test_shared_limit_failure_stops_up_before_other_changes(self):
        # Mocks: _set_shared_limits reports its error and exits.
        instance = make_sandy()
        self.set_shared_limits.side_effect = SystemExit(1)
        with patch.object(
            instance, "_is_container_running", return_value=None
        ), patch.object(sandy, "_run_secure_subprocess_popen") as popen:
            with captured_output():
                with self.assertRaises(SystemExit) as raised:
                    instance.run_up(self.arguments())
        self.assertEqual(raised.exception.code, 1)
        self.stale_cleanup.assert_not_called()
        popen.assert_not_called()

    def test_host_fact_error_stops_up_before_any_check(self):
        instance = make_sandy()
        self.read_host_facts.side_effect = SystemExit(1)
        with patch.object(instance, "_is_container_running") as running:
            with self.assertRaises(SystemExit):
                instance.run_up(self.arguments())
        running.assert_not_called()
        self.set_shared_limits.assert_not_called()

    def test_oom_score_adjustment_failure_starts_nothing(self):
        # Mocks: the write of the value of up fails before the start.
        for error in (
            OSError(errno.EACCES, "x"),
            ValueError("Malformed oom_score_adj"),
        ):
            with self.subTest(error=error):
                instance = make_sandy()
                instance.workspace = None
                self.oom_score_adj.side_effect = error
                with tempfile.TemporaryDirectory() as machine, patch.object(
                    instance, "_is_container_running", return_value=None
                ), patch.object(
                    instance, "_get_machine_dir", return_value=machine
                ), patch.object(
                    sandy, "_run_secure_subprocess_popen"
                ) as popen:
                    with captured_output() as (stdout, _):
                        with self.assertRaises(SystemExit) as raised:
                            instance.run_up(self.arguments(oom_score_adj=-500))
                self.assertEqual(raised.exception.code, 1)
                self.assertIn("E: Could not start 'ai-dev': ", stdout.getvalue())
                popen.assert_not_called()
                self.wait_for_container_ready.assert_not_called()

    def test_a_failed_supervisor_start_removes_the_ports_that_up_added(self):
        # Regression test: up published its ports, the start failed, and up
        # exited with the port rules and state still there. Then up removed
        # them only after it released the port mapping lock, so another up
        # could find the ports of a start that failed. Now the removal comes
        # in the hold of the port mapping lock that the publish took. Mocks:
        # the lifecycle lock and the port mapping lock (setUp), the port
        # setup and its cleanup (the port forwarding tests cover the rules),
        # the OOM score adjustment, and the start.
        limit = sandy.PORT_MAPPINGS_LOCK_TIMEOUT
        oom_score_adj = self.oom_score_adj.side_effect
        for label, oom_error, popen_error, published, detach in (
            ("oom score", ValueError("Malformed oom_score_adj"), None, True, True),
            ("start", None, OSError(errno.ENOENT, "systemd-run"), True, True),
            ("interrupt", None, KeyboardInterrupt(), True, True),
            ("no ports", None, OSError(errno.ENOENT, "systemd-run"), False, True),
            # Without -d, up holds the lifecycle lock while it starts.
            ("oom score", ValueError("Malformed oom_score_adj"), None, True, False),
            ("start", None, OSError(errno.ENOENT, "systemd-run"), True, False),
            ("interrupt", None, KeyboardInterrupt(), True, False),
        ):
            with self.subTest(label=label, detach=detach):
                events = self.lock_events
                events.clear()
                instance = make_sandy()
                instance.workspace = None
                instance.network = make_network()
                instance.port_mappings = [("tcp", 8080, 80)] if published else []
                self.stale_cleanup.reset_mock()
                self.stale_cleanup.side_effect = self.record_cleanup(events)
                self.oom_score_adj.side_effect = oom_error or oom_score_adj
                with tempfile.TemporaryDirectory() as machine:
                    init_script = Path(machine) / "init.sh"
                    init_script.write_text('CONTAINER_IP="10.200.1.10"\n')
                    init_script.chmod(0o644)
                    with self.up_mocks(instance, machine) as mocks, patch.object(
                        instance,
                        "_setup_port_forwarding_rules",
                        side_effect=lambda ip: events.append(f"ports {ip}"),
                    ), patch.object(sandy.os, "fchown"):
                        mocks.popen.side_effect = popen_error
                        with captured_output() as (stdout, _):
                            with self.assertRaises(
                                (SystemExit, KeyboardInterrupt)
                            ) as raised:
                                instance.run_up(
                                    self.arguments(network="lenient", detach=detach)
                                )
                if label == "interrupt":
                    self.assertIsInstance(raised.exception, KeyboardInterrupt)
                else:
                    self.assertEqual(
                        (type(raised.exception), getattr(raised.exception, "code")),
                        (SystemExit, 1),
                    )
                    self.assertIn("E: Could not start 'ai-dev': ", stdout.getvalue())
                mocks.stop.assert_not_called()
                # The removal comes in the hold of the publish. Without the
                # lifecycle lock, up waits for the port mapping lock with no
                # limit.
                hold = [
                    f"port lock {None if detach else limit}",
                    "ports 10.200.1.10",
                    "cleanup ai-dev",
                    "port unlock",
                ]
                started = hold if published else []
                if not detach:
                    started = ["enter", *started, "exit"]
                # The first cleanup is the one of stale rules, at the start.
                self.assertEqual(events, ["cleanup ai-dev", *started])

    def test_up_removes_its_ports_on_each_exit_before_the_start(self):
        # Regression test: an interrupt or an error after the port state was
        # written and before the start (in the port rules, or in the print of
        # "Starting") left the port rules and state. The print now comes after
        # the release (see the next test). Mocks: the lifecycle lock and the
        # port mapping lock (setUp), the port setup and its cleanup (the port
        # forwarding tests cover the rules), and the start (up_mocks).
        limit = sandy.PORT_MAPPINGS_LOCK_TIMEOUT
        for label, error, detach in (
            ("rules interrupted", KeyboardInterrupt(), True),
            ("rules failed", OSError(errno.EPERM, "iptables"), True),
            # Without -d, up holds the lifecycle lock while it publishes.
            ("rules interrupted", KeyboardInterrupt(), False),
            ("rules failed", OSError(errno.EPERM, "iptables"), False),
        ):
            with self.subTest(label=label, detach=detach):
                events = self.lock_events
                events.clear()
                instance = make_sandy()
                instance.workspace = None
                instance.network = make_network()
                instance.port_mappings = [("tcp", 8080, 80)]
                self.stale_cleanup.reset_mock()
                self.stale_cleanup.side_effect = self.record_cleanup(events)

                def publish(ip):
                    # The port state is written; the rules come next.
                    events.append(f"ports {ip}")
                    raise error

                with tempfile.TemporaryDirectory() as machine:
                    init_script = Path(machine) / "init.sh"
                    init_script.write_text('CONTAINER_IP="10.200.1.10"\n')
                    init_script.chmod(0o644)
                    with self.up_mocks(instance, machine) as mocks, patch.object(
                        instance, "_setup_port_forwarding_rules", side_effect=publish
                    ), patch.object(sandy.os, "fchown"):
                        with captured_output():
                            with self.assertRaises(type(error)):
                                instance.run_up(
                                    self.arguments(network="lenient", detach=detach)
                                )
                mocks.popen.assert_not_called()
                mocks.stop.assert_not_called()
                # The removal comes in the hold of the publish.
                hold = [
                    f"port lock {None if detach else limit}",
                    "ports 10.200.1.10",
                    "cleanup ai-dev",
                    "port unlock",
                ]
                if not detach:
                    hold = ["enter", *hold, "exit"]
                # The first cleanup is the one of stale rules, at the start.
                self.assertEqual(events, ["cleanup ai-dev", *hold])

    def test_held_output_is_written_once(self):
        # A failed start writes the held output, and the handler of the exit
        # then calls the write again: it must write nothing more.
        held = io.StringIO()
        held.write("I: Starting 'ai-dev' ")
        with captured_output() as (stdout, _):
            sandy._write_held_output(held)
            sandy._write_held_output(held)
        self.assertEqual(stdout.getvalue(), "I: Starting 'ai-dev' ")
        self.assertEqual(held.getvalue(), "")

    def test_up_writes_its_output_after_the_port_mapping_lock(self):
        # Regression test: up wrote to the terminal while it held the port
        # mapping lock: the port rules, "Starting", and its errors. A write
        # that blocked (for example, after the STOP character) kept the lock
        # held. Now up holds its output back and writes it after the release,
        # also when it exits. A write error after the start stops the
        # container. Mocks: the lifecycle lock (setUp), the port mapping lock,
        # which records the output at its release, the port setup, which
        # prints, and the start and the stop of the failed start (up_mocks).
        for label in ("started", "conflict", "write failed"):
            with self.subTest(label=label):
                events = self.lock_events
                events.clear()
                at_release = []
                instance = make_sandy()
                instance.workspace = None
                instance.network = make_network()
                instance.port_mappings = [("tcp", 8080, 80)]

                @contextmanager
                def port_lock(exclusive, timeout=None):
                    events.append("port lock")
                    try:
                        yield None
                    finally:
                        at_release.append(stdout.getvalue())
                        events.append("port unlock")

                def publish(ip):
                    print(f"I: Port forwarding tcp:8080 -> {ip}:80")
                    if label == "conflict":
                        print("E: Port tcp:8080 is already allocated")
                        sys.exit(1)

                self.port_lock.side_effect = port_lock
                with tempfile.TemporaryDirectory() as machine:
                    init_script = Path(machine) / "init.sh"
                    init_script.write_text('CONTAINER_IP="10.200.1.10"\n')
                    init_script.chmod(0o644)
                    with self.up_mocks(instance, machine) as mocks, patch.object(
                        instance, "_setup_port_forwarding_rules", side_effect=publish
                    ), patch.object(sandy.os, "fchown"):
                        with captured_output() as (stdout, _):
                            write = stdout.write

                            def failing_write(text):
                                if (
                                    label == "write failed"
                                    and "Port forwarding" in text
                                ):
                                    raise OSError(errno.EIO, "Input/output error")
                                return write(text)

                            stdout.write = failing_write
                            try:
                                instance.run_up(
                                    self.arguments(network="lenient", detach=True)
                                )
                            except (SystemExit, OSError) as exc:
                                raised = exc
                            else:
                                raised = None
                output = stdout.getvalue()
                # At the release, the terminal had none of the output of the
                # hold.
                self.assertEqual(len(at_release), 1)
                self.assertNotIn("Port forwarding", at_release[0])
                self.assertNotIn("I: Starting", at_release[0])
                if label == "started":
                    self.assertIsNone(raised)
                    self.assertLess(
                        output.index("I: Port forwarding tcp:8080 -> 10.200.1.10:80"),
                        output.index("I: Starting 'ai-dev' in detached state"),
                    )
                    mocks.stop.assert_not_called()
                elif label == "conflict":
                    self.assertIsInstance(raised, SystemExit)
                    self.assertIn("E: Port tcp:8080 is already allocated", output)
                    mocks.popen.assert_not_called()
                else:
                    # The supervisor started; the failed write stops it.
                    self.assertIsInstance(raised, OSError)
                    mocks.stop.assert_called_once_with(mocks.popen.return_value)
                self.assertEqual(events, ["port lock", "port unlock"])

    def test_an_exit_before_the_port_state_write_does_not_wait_again(self):
        # Regression test: up removed its ports on each exit after it began
        # the publish, also on an exit before the port state write: a Ctrl-C
        # in the wait for the port mapping lock, or a port conflict. That
        # removal waited for the busy lock again, so the first Ctrl-C did not
        # stop up. Now up takes the lock once, before the publish, and
        # removes the ports in that hold. Mocks: the lifecycle lock and the
        # port mapping lock (setUp; a Ctrl-C in the wait raises
        # KeyboardInterrupt there), the port state (a conflict exits before
        # the write), the rules, and the start (up_mocks).
        limit = sandy.PORT_MAPPINGS_LOCK_TIMEOUT
        for label, detach in (
            ("interrupt", True),
            ("conflict", True),
            # Without -d, up waits for the port mapping lock under the
            # lifecycle lock.
            ("interrupt", False),
            ("conflict", False),
        ):
            with self.subTest(label=label, detach=detach):
                events = self.lock_events
                events.clear()
                instance = make_sandy()
                instance.workspace = None
                instance.network = make_network()
                instance.port_mappings = [("tcp", 8080, 80)]
                self.stale_cleanup.reset_mock()
                self.stale_cleanup.side_effect = self.record_cleanup(events)
                self.port_lock.reset_mock()
                interrupted = label == "interrupt"
                self.port_lock_error = KeyboardInterrupt() if interrupted else None

                def update(name, ip):
                    # The check finds the port of another container.
                    events.append(f"conflict {name} {ip}")
                    sys.exit(1)

                with tempfile.TemporaryDirectory() as machine, ExitStack() as stack:
                    init_script = Path(machine) / "init.sh"
                    init_script.write_text('CONTAINER_IP="10.200.1.10"\n')
                    init_script.chmod(0o644)
                    mocks = stack.enter_context(self.up_mocks(instance, machine))
                    if not interrupted:
                        stack.enter_context(
                            patch.object(
                                instance,
                                "_update_port_mapping_state",
                                side_effect=update,
                            )
                        )
                    rules = stack.enter_context(
                        patch.object(instance, "_setup_port_forwarding_ipt")
                    )
                    stack.enter_context(patch.object(sandy.os, "fchown"))
                    stack.enter_context(captured_output())
                    with self.assertRaises((SystemExit, KeyboardInterrupt)) as raised:
                        instance.run_up(
                            self.arguments(network="lenient", detach=detach)
                        )
                timeout = None if detach else limit
                # One wait for the port mapping lock, before the publish.
                self.port_lock.assert_called_once_with(exclusive=True, timeout=timeout)
                rules.assert_not_called()
                mocks.popen.assert_not_called()
                if interrupted:
                    self.assertIsInstance(raised.exception, KeyboardInterrupt)
                    hold = []
                else:
                    self.assertEqual(
                        (type(raised.exception), getattr(raised.exception, "code")),
                        (SystemExit, 1),
                    )
                    hold = [
                        f"port lock {timeout}",
                        "conflict ai-dev 10.200.1.10",
                        "cleanup ai-dev",
                        "port unlock",
                    ]
                if not detach:
                    hold = ["enter", *hold, "exit"]
                # The first cleanup is the one of stale rules, at the start.
                self.assertEqual(events, ["cleanup ai-dev", *hold])

    def test_no_other_process_finds_the_ports_of_a_failed_start(self):
        # Regression test: up released the port mapping lock after the publish
        # of its ports, and then the start failed. A process that took the
        # lock before the removal found the ports of a start that failed, so
        # an up of another name refused its own start ("already allocated").
        # Now up holds the lock from the publish until the start, and removes
        # the ports in that hold. Mocks: the lifecycle lock (setUp), the paths
        # and the opens of the lock and the state file (temporary files; the
        # flock calls are real), the state write, the rules, and the start,
        # which fails. A thread with a second instance takes the lock on its
        # own open of the lock file, as another process does.
        real_flock = sandy.fcntl.flock
        for detach in (True, False):
            with self.subTest(detach=detach):
                self.lock_events.clear()
                instance = make_sandy()
                instance.workspace = None
                instance.network = make_network()
                instance.port_mappings = [("tcp", 8080, 80)]
                other = make_sandy()
                found = []
                other_tried = threading.Event()

                def flock(fd, operation):
                    if threading.current_thread() is threading.main_thread():
                        return real_flock(fd, operation)
                    try:
                        return real_flock(fd, operation)
                    finally:
                        other_tried.set()

                def other_process():
                    with self.real_port_lock(
                        other, exclusive=True, timeout=5
                    ) as handle:
                        found.append(other._load_port_mapping_state(handle))

                waiter = threading.Thread(target=other_process)

                def start(*_args, **_kwargs):
                    # The ports are published. The other process tries the
                    # lock now, and up then fails to start.
                    waiter.start()
                    self.assertTrue(other_tried.wait(timeout=5))
                    raise OSError(errno.ENOENT, "systemd-run")

                with tempfile.TemporaryDirectory() as temp_dir, ExitStack() as stack:
                    root = Path(temp_dir)
                    state_path = root / "ports.json"
                    lock_path = root / "ports.lock"
                    machine = root / "machine"
                    machine.mkdir()
                    init_script = machine / "init.sh"
                    init_script.write_text('CONTAINER_IP="10.200.1.10"\n')
                    init_script.chmod(0o644)

                    def open_state(_path):
                        try:
                            return state_path.open("r", encoding="utf-8")
                        except FileNotFoundError:
                            return None

                    def write(path, content, mode):
                        self.assertEqual(mode, 0o600)
                        new_path = Path(path).with_suffix(".new")
                        new_path.write_text(content, encoding="utf-8")
                        os.replace(new_path, path)

                    def published(container_ip):
                        state = json.loads(state_path.read_text(encoding="utf-8"))
                        self.assertEqual(list(state), ["tcp:8080"])
                        self.lock_events.append(f"rules {container_ip}")

                    mocks = stack.enter_context(self.up_mocks(instance, machine))
                    for target in (instance, other):
                        stack.enter_context(
                            patch.object(
                                target,
                                "_get_port_mappings_path",
                                return_value=str(state_path),
                            )
                        )
                        stack.enter_context(
                            patch.object(
                                target,
                                "_get_port_mappings_lock_path",
                                return_value=str(lock_path),
                            )
                        )
                    stack.enter_context(
                        patch.object(
                            sandy,
                            "_open_stable_lock_file",
                            side_effect=lambda _path: lock_path.open(
                                "a+", encoding="utf-8"
                            ),
                        )
                    )
                    stack.enter_context(
                        patch.object(
                            sandy,
                            "_open_existing_managed_text_file",
                            side_effect=open_state,
                        )
                    )
                    stack.enter_context(
                        patch.object(sandy, "_write", side_effect=write)
                    )
                    stack.enter_context(
                        patch.object(sandy.fcntl, "flock", side_effect=flock)
                    )
                    # The real removal of the state, which up_mocks replaces.
                    stack.enter_context(
                        patch.object(
                            instance,
                            "_remove_port_mappings_from_state",
                            side_effect=lambda name, lock_timeout=None: (
                                sandy.Sandy._remove_port_mappings_from_state(
                                    instance, name, lock_timeout
                                )
                            ),
                        )
                    )
                    stack.enter_context(
                        patch.object(
                            instance,
                            "_setup_port_forwarding_ipt",
                            side_effect=published,
                        )
                    )
                    removed = stack.enter_context(
                        patch.object(instance, "_cleanup_port_forwarding_ipt")
                    )
                    stack.enter_context(patch.object(sandy.os, "fchown"))
                    self.port_lock.side_effect = lambda **kwargs: (
                        self.real_port_lock(instance, **kwargs)
                    )
                    self.stale_cleanup.side_effect = (
                        lambda name, lock_timeout=None: self.real_cleanup(
                            instance, name, lock_timeout
                        )
                    )
                    mocks.popen.side_effect = start
                    stdout = stack.enter_context(captured_output())[0]
                    with self.assertRaises(SystemExit) as exited:
                        instance.run_up(
                            self.arguments(network="lenient", detach=detach)
                        )
                    waiter.join(timeout=10)
                    self.assertFalse(state_path.exists())
                self.assertFalse(waiter.is_alive())
                self.assertEqual(exited.exception.code, 1)
                self.assertIn("E: Could not start 'ai-dev': ", stdout.getvalue())
                # The other process got the lock only after the removal.
                self.assertEqual(found, [{}])
                removed.assert_called_once_with("10.200.1.10")
                mocks.stop.assert_not_called()
                rules = ["rules 10.200.1.10"]
                self.assertEqual(
                    self.lock_events, rules if detach else ["enter", *rules, "exit"]
                )
                self.assertIsNone(instance._port_mapping_lock_holder)

    def test_a_failed_pin_or_marker_removes_the_ports_in_the_publish_hold(self):
        # Regression test: when the pin or a marker failed after the start, up
        # stopped the supervisor and removed the ports after it released the
        # port mapping lock. Under the lifecycle lock, that removal waited for
        # the port mapping lock with no limit, so each attach could fail. Then
        # the stop ran in the hold, and could keep the lock for
        # CONTAINER_STOP_TIMEOUT. Now up removes the ports in the hold, with no
        # wait, releases the lock, and then stops the supervisor. Without
        # ports, there is no removal and no wait. The message of the failure
        # reaches the terminal only after the release. Mocks: the lifecycle
        # lock, the pin, and the markers (setUp), the port mapping lock, which
        # records the terminal output at its release, the port setup and the
        # port cleanup, the start, and the stop of the failed start (up_mocks).
        limit = sandy.PORT_MAPPINGS_LOCK_TIMEOUT
        pin = self.pin_supervisor.side_effect
        marker = self.create_marker.side_effect
        for label, detach, published, pin_error, marker_error in (
            ("pin", True, True, OSError(errno.ESRCH, "No such process"), None),
            # Without -d, up holds the lifecycle lock while it pins.
            ("pin", False, True, OSError(errno.ESRCH, "No such process"), None),
            ("marker", False, True, None, TimeoutError("The scope did not appear")),
            ("interrupt", False, True, KeyboardInterrupt(), None),
            ("no ports", False, False, OSError(errno.ESRCH, "No such process"), None),
        ):
            with self.subTest(label=label, detach=detach):
                events = self.lock_events
                events.clear()
                instance = make_sandy()
                instance.workspace = None
                instance.network = make_network()
                instance.port_mappings = [("tcp", 8080, 80)] if published else []
                self.stale_cleanup.reset_mock()
                self.stale_cleanup.side_effect = self.record_cleanup(events)
                self.pin_supervisor.side_effect = pin_error or pin
                self.create_marker.side_effect = marker_error or marker
                at_release = []

                @contextmanager
                def port_lock(exclusive, timeout=None):
                    events.append(f"port lock {timeout}")
                    try:
                        yield None
                    finally:
                        at_release.append(stdout.getvalue())
                        events.append("port unlock")

                self.port_lock.side_effect = port_lock
                with tempfile.TemporaryDirectory() as machine:
                    init_script = Path(machine) / "init.sh"
                    init_script.write_text('CONTAINER_IP="10.200.1.10"\n')
                    init_script.chmod(0o644)
                    with self.up_mocks(instance, machine) as mocks, patch.object(
                        instance,
                        "_setup_port_forwarding_rules",
                        side_effect=lambda ip: events.append(f"ports {ip}"),
                    ), patch.object(sandy.os, "fchown"):
                        mocks.stop.side_effect = (
                            lambda supervisor, **_options: events.append("stop")
                        )
                        with captured_output() as (stdout, _):
                            with self.assertRaises(
                                (SystemExit, KeyboardInterrupt)
                            ) as raised:
                                instance.run_up(
                                    self.arguments(network="lenient", detach=detach)
                                )
                # The removal comes in the hold, and the stop after it. The
                # first cleanup is the one of stale rules, at the start.
                if published:
                    started = [
                        f"port lock {None if detach else limit}",
                        "ports 10.200.1.10",
                        "cleanup ai-dev",
                        "port unlock",
                        "stop",
                    ]
                else:
                    started = ["stop"]
                if not detach:
                    started = ["enter", *started, "exit"]
                self.assertEqual(events, ["cleanup ai-dev", *started])
                # The ports are gone already, so the stop leaves them alone.
                mocks.stop.assert_called_once_with(
                    mocks.popen.return_value, **LOCKED_STOP
                )
                if label == "interrupt":
                    self.assertIsInstance(raised.exception, KeyboardInterrupt)
                else:
                    self.assertEqual(
                        (type(raised.exception), getattr(raised.exception, "code")),
                        (SystemExit, 1),
                    )
                    self.assertIn(
                        "E: Container 'ai-dev' did not start: ", stdout.getvalue()
                    )
                # At the release, the terminal had no line of the failed start.
                self.assertEqual(len(at_release), 1 if published else 0)
                self.assertFalse(any("did not start" in text for text in at_release))

    def failed_pin_run(
        self,
        events: list[str],
        detach: bool,
        published: bool,
        pin_error: BaseException | Callable[..., object],
        cleanup: Callable[[str], None],
        stop_error: BaseException | None = None,
        terminal: io.StringIO | None = None,
    ) -> tuple[BaseException | None, str, SimpleNamespace]:
        """Run up with a pin that fails; return the exception, output, mocks.

        cleanup is the side effect of the port cleanup, also at the start. The
        stop of the failed start raises stop_error when it is set. up writes
        its stdout to terminal, a new StringIO by default. Mocks: the
        lifecycle lock and the port mapping lock (setUp), the port setup, the
        start, and the stop of the failed start (up_mocks).
        """
        stdout = io.StringIO() if terminal is None else terminal
        instance = make_sandy()
        instance.workspace = None
        instance.network = make_network()
        instance.port_mappings = [("tcp", 8080, 80)] if published else []
        self.stale_cleanup.reset_mock()
        self.stale_cleanup.side_effect = cleanup
        self.pin_supervisor.side_effect = pin_error
        with tempfile.TemporaryDirectory() as machine:
            init_script = Path(machine) / "init.sh"
            init_script.write_text('CONTAINER_IP="10.200.1.10"\n')
            init_script.chmod(0o644)
            with self.up_mocks(instance, machine) as mocks, patch.object(
                instance,
                "_setup_port_forwarding_rules",
                side_effect=lambda ip: events.append(f"ports {ip}"),
            ), patch.object(sandy.os, "fchown"):

                def stop(supervisor, **_options):
                    events.append("stop")
                    if stop_error is not None:
                        raise stop_error

                mocks.stop.side_effect = stop
                with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                    try:
                        instance.run_up(
                            self.arguments(network="lenient", detach=detach)
                        )
                    except BaseException as exc:  # checked by the caller
                        raised = exc
                    else:
                        raised = None
        return raised, stdout.getvalue(), mocks

    def test_a_failed_pin_or_marker_keeps_each_message_on_its_own_line(self):
        # Regression test: after a failed pin or marker, up removed its ports
        # in the hold before it ended the "Starting" line, and named the
        # error only after the release. The removal output then came on the
        # "Starting" line, and an empty line came before the error. Now the
        # line ends and the error comes first, in the held output. Mocks: as
        # in failed_pin_run; the port cleanup in the hold prints, as the real
        # removal does.
        removed = "I: Removed port forwarding: 127.0.0.1:8080 -> 10.200.1.10:80 (tcp)"
        pin = self.pin_supervisor.side_effect
        marker = self.create_marker.side_effect
        no_process = "'[Errno 3] No such process'"
        for label, detach, published, pin_error, marker_error, expected in (
            (
                "pin",
                True,
                True,
                OSError(errno.ESRCH, "No such process"),
                None,
                "I: Starting 'ai-dev' in detached state \r\n"
                f"E: Container 'ai-dev' did not start: {no_process}\n{removed}\n",
            ),
            (
                "marker",
                False,
                True,
                None,
                TimeoutError("The scope did not appear"),
                "I: Starting 'ai-dev' \r\n"
                "E: Container 'ai-dev' did not start: 'The scope did not appear'\n"
                f"{removed}\n",
            ),
            (
                "interrupt",
                False,
                True,
                KeyboardInterrupt(),
                None,
                f"I: Starting 'ai-dev' \r\n{removed}\n",
            ),
            (
                "no ports",
                False,
                False,
                OSError(errno.ESRCH, "No such process"),
                None,
                "I: Starting 'ai-dev' \r\n"
                f"E: Container 'ai-dev' did not start: {no_process}\n",
            ),
        ):
            with self.subTest(label=label):
                events = self.lock_events
                events.clear()

                def cleanup(name):
                    events.append(f"cleanup {name}")
                    if any(event.startswith("port lock") for event in events):
                        print(removed)

                self.create_marker.side_effect = marker_error or marker
                raised, output, _ = self.failed_pin_run(
                    events,
                    detach,
                    published,
                    pin_error or pin,
                    cleanup,
                )
                self.assertIsInstance(
                    raised, KeyboardInterrupt if label == "interrupt" else SystemExit
                )
                self.assertEqual(output[output.index("I: Starting") :], expected)
                self.assertEqual(output.count("I: Starting 'ai-dev'"), 1)

    def test_a_failed_pin_keeps_its_error_line_when_the_stop_is_interrupted(self):
        # Regression test: up named the error of a failed pin only after the
        # stop, so a Ctrl-C in the stop wait dropped that line. Now the line
        # is in the held output before the removal and the stop. Mocks: as in
        # failed_pin_run; the port cleanup in the hold prints, and the stop
        # raises KeyboardInterrupt.
        removed = "I: Removed port forwarding: 127.0.0.1:8080 -> 10.200.1.10:80 (tcp)"
        events = self.lock_events
        events.clear()

        def cleanup(name):
            events.append(f"cleanup {name}")
            if any(event.startswith("port lock") for event in events):
                print(removed)

        raised, output, mocks = self.failed_pin_run(
            events,
            True,
            True,
            OSError(errno.ESRCH, "No such process"),
            cleanup,
            stop_error=KeyboardInterrupt(),
        )
        self.assertIsInstance(raised, KeyboardInterrupt)
        mocks.stop.assert_called_once_with(mocks.popen.return_value, **LOCKED_STOP)
        self.assertEqual(
            output[output.index("I: Starting") :],
            "I: Starting 'ai-dev' in detached state \r\n"
            "E: Container 'ai-dev' did not start: '[Errno 3] No such process'\n"
            f"{removed}\n",
        )

    def test_a_failed_pin_stops_the_supervisor_when_a_terminal_write_fails(self):
        # Regression test: with no ports and no lock (up -d with no mounts),
        # up writes the end of the "Starting" line and the error of a failed
        # pin to the terminal. When it did so before the stop, a failed
        # write, for example to a closed pipe, skipped the stop: the container
        # kept running after up exited. Under the lifecycle lock (no -d), up
        # holds these lines back and writes them after the release, in one
        # write. Mocks: as in failed_pin_run; the terminal raises
        # BrokenPipeError on each write after a write of the "Starting" line.
        class BrokenTerminal(io.StringIO):
            def write(self, text: str) -> int:
                if text and "I: Starting" in self.getvalue():
                    raise BrokenPipeError(errno.EPIPE, "Broken pipe")
                return super().write(text)

        for detach in (True, False):
            with self.subTest(detach=detach):
                events = self.lock_events
                events.clear()
                raised, output, mocks = self.failed_pin_run(
                    events,
                    detach,
                    False,
                    OSError(errno.ESRCH, "No such process"),
                    self.record_cleanup(events),
                    terminal=BrokenTerminal(),
                )
                self.assertIsInstance(raised, BrokenPipeError if detach else SystemExit)
                started = ["stop"] if detach else ["enter", "stop", "exit"]
                self.assertEqual(events, ["cleanup ai-dev", *started])
                mocks.stop.assert_called_once_with(
                    mocks.popen.return_value, **LOCKED_STOP
                )
                if detach:
                    # No write after the "Starting" line reached the terminal.
                    expected = "I: Starting 'ai-dev' in detached state "
                else:
                    expected = (
                        "I: Starting 'ai-dev' \r\n"
                        "E: Container 'ai-dev' did not start: "
                        "'[Errno 3] No such process'\n"
                    )
                self.assertEqual(output[output.index("I: Starting") :], expected)

    def test_a_failed_removal_after_a_failed_pin_still_stops_the_supervisor(self):
        # The port removal in the hold can fail, for example when the disk is
        # full and the state of other containers must be written again. The
        # lock must still be released, the supervisor stopped, and the error
        # shown. Mocks: as in failed_pin_run; the port cleanup in the hold
        # raises.
        limit = sandy.PORT_MAPPINGS_LOCK_TIMEOUT
        for detach in (True, False):
            with self.subTest(detach=detach):
                events = self.lock_events
                events.clear()

                def cleanup(name):
                    events.append(f"cleanup {name}")
                    if any(event.startswith("port lock") for event in events):
                        raise OSError(errno.ENOSPC, "No space left on device")

                raised, output, mocks = self.failed_pin_run(
                    events,
                    detach,
                    True,
                    OSError(errno.ESRCH, "No such process"),
                    cleanup,
                )
                self.assertIsInstance(raised, OSError)
                self.assertEqual(getattr(raised, "errno", None), errno.ENOSPC)
                hold = [
                    f"port lock {None if detach else limit}",
                    "ports 10.200.1.10",
                    "cleanup ai-dev",
                    "port unlock",
                    "stop",
                ]
                self.assertEqual(
                    events,
                    ["cleanup ai-dev", *(hold if detach else ["enter", *hold, "exit"])],
                )
                mocks.stop.assert_called_once_with(
                    mocks.popen.return_value, **LOCKED_STOP
                )
                # The terminal still names the failed start.
                self.assertIn(
                    "E: Container 'ai-dev' did not start: "
                    "'[Errno 3] No such process'\n",
                    output,
                )

    @contextmanager
    def lock_recording_the_terminal(self, terminal: list[str]) -> Iterator[None]:
        """Mock the lifecycle lock. Record the text on the terminal, which is
        the stdout of the test (a StringIO), when up takes the lock and when
        it releases it."""

        @contextmanager
        def lock(timeout: float = sandy.LIFECYCLE_LOCK_TIMEOUT) -> Iterator[None]:
            _ = timeout
            terminal.append(getattr(sys.stdout, "getvalue")())
            try:
                yield
            finally:
                terminal.append(getattr(sys.stdout, "getvalue")())

        with patch.object(sandy, "_lifecycle_lock", side_effect=lock):
            yield

    def test_up_writes_nothing_to_the_terminal_under_the_lifecycle_lock(self):
        # Regression test: up wrote to the terminal while it held the
        # lifecycle lock: the "Starting" line when it published no ports, and
        # the refusal of the check under the lock. A write that blocked, for
        # example after the STOP character, then kept the lock held, and
        # each attach failed after 10 s. Now up holds its output back while
        # it holds the lock, and writes it after the release. Mocks: as in
        # up_mocks; the lifecycle lock records the terminal when up takes it
        # and when up releases it.
        refused = "E: Container 'ai-dev' is already running"
        for refusal in (None, refused):
            with self.subTest(refused=refusal is not None):
                terminal: list[str] = []
                instance = make_sandy()
                instance.workspace = None
                # The check before the lock passes. The check under the lock
                # finds the container of another program, or nothing.
                checks = patch.object(
                    instance, "_existing_container_error", side_effect=[None, refusal]
                )
                with tempfile.TemporaryDirectory() as machine, self.up_mocks(
                    instance, machine
                ), checks, self.lock_recording_the_terminal(
                    terminal
                ), captured_output() as (
                    stdout,
                    _,
                ):
                    if refusal:
                        with self.assertRaises(SystemExit) as exited:
                            instance.run_up(self.arguments(detach=False))
                        self.assertEqual(exited.exception.code, 1)
                    else:
                        instance.run_up(self.arguments(detach=False))
                self.assertEqual(len(terminal), 2)
                # Nothing reached the terminal under the lock.
                self.assertEqual(terminal[1], terminal[0])
                after = stdout.getvalue()[len(terminal[1]) :]
                self.assertIn(refusal or "I: Starting 'ai-dev' ", after)

    def test_a_failed_pin_writes_its_error_after_the_lifecycle_lock(self):
        # Regression test: when the pin failed, up wrote the error to the
        # terminal before it released the lifecycle lock: at once without
        # ports, and with the held output with ports. Mocks: as in
        # failed_pin_run; the lifecycle lock records the terminal when up
        # takes it and when up releases it.
        for published in (False, True):
            with self.subTest(published=published):
                terminal: list[str] = []
                self.lock_events.clear()
                with self.lock_recording_the_terminal(terminal):
                    raised, output, mocks = self.failed_pin_run(
                        self.lock_events,
                        False,
                        published,
                        OSError(errno.ESRCH, "No such process"),
                        self.record_cleanup(self.lock_events),
                    )
                self.assertIsInstance(raised, SystemExit)
                assert isinstance(raised, SystemExit)
                self.assertEqual(raised.code, 1)
                mocks.stop.assert_called_once_with(
                    mocks.popen.return_value, **LOCKED_STOP
                )
                self.assertEqual(len(terminal), 2)
                # Nothing reached the terminal under the lock.
                self.assertEqual(terminal[1], terminal[0])
                self.assertIn(
                    "I: Starting 'ai-dev' \r\n"
                    "E: Container 'ai-dev' did not start: "
                    "'[Errno 3] No such process'\n",
                    output[len(terminal[1]) :],
                )

    def send_sigint(self, *_args: object, **_kwargs: object) -> None:
        """Send a real SIGINT to this process, as a Ctrl-C does.

        Each test catches each exception and checks its type: a stray
        KeyboardInterrupt would end the whole test run, not one test.
        """
        os.kill(os.getpid(), sandy.signal.SIGINT)

    def test_a_ctrl_c_right_after_the_start_stops_the_supervisor(self):
        # Regression test: a Ctrl-C after the start of the supervisor and
        # before the try that stops it (here in the restore of the OOM score
        # adjustment) left the supervisor running. Now up holds it back until
        # the try after the start, which stops the supervisor. Mocks: as in
        # up_mocks; the restore sends a real SIGINT to this process.
        instance = make_sandy()
        instance.workspace = None
        handler = sandy.signal.getsignal(sandy.signal.SIGINT)

        @contextmanager
        def oom_score_adj(_value: object) -> Iterator[None]:
            try:
                yield
            finally:
                self.send_sigint()

        self.oom_score_adj.side_effect = oom_score_adj
        with tempfile.TemporaryDirectory() as machine:
            with self.up_mocks(instance, machine) as mocks:
                with captured_output():
                    with self.assertRaises(BaseException) as raised:
                        instance.run_up(self.arguments(detach=False))
        self.assertIsInstance(raised.exception, KeyboardInterrupt)
        mocks.stop.assert_called_once_with(mocks.popen.return_value)
        self.create_marker.assert_called_once()
        self.exec.assert_not_called()
        self.assertIs(sandy.signal.getsignal(sandy.signal.SIGINT), handler)

    def test_a_ctrl_c_during_the_stop_of_a_failed_pin_does_not_cut_it(self):
        # Regression test: a Ctrl-C while up handled a failed pin (here in
        # the stop) cut the handling short, and up ended with a traceback in
        # place of its error. Now the steps run to their end, and up exits 1
        # with the error. Mocks: as in up_mocks; the pin fails, and the stop
        # sends a real SIGINT to this process.
        instance = make_sandy()
        instance.workspace = None
        handler = sandy.signal.getsignal(sandy.signal.SIGINT)
        self.pin_supervisor.side_effect = OSError(errno.ESRCH, "No such process")
        with tempfile.TemporaryDirectory() as machine:
            with self.up_mocks(instance, machine) as mocks:
                mocks.stop.side_effect = self.send_sigint
                with captured_output() as (stdout, _):
                    with self.assertRaises(BaseException) as raised:
                        instance.run_up(self.arguments(detach=True))
        self.assertIsInstance(raised.exception, SystemExit)
        assert isinstance(raised.exception, SystemExit)
        self.assertEqual(raised.exception.code, 1)
        mocks.stop.assert_called_once_with(mocks.popen.return_value, **LOCKED_STOP)
        self.assertIn(
            "E: Container 'ai-dev' did not start: '[Errno 3] No such process'\n",
            stdout.getvalue(),
        )
        self.assertIs(sandy.signal.getsignal(sandy.signal.SIGINT), handler)

    def test_a_ctrl_c_before_the_console_ends_the_console(self):
        # Regression test: a Ctrl-C after the container was ready and before
        # its console (here in the close of the up lock) ended up with the
        # container running and its up-console marker, so it never stopped.
        # Now up holds the SIGINT back until the console has started, where
        # it ends the console. Mocks: as in up_mocks; the close of the up lock
        # sends a real SIGINT to this process, and the console releases the
        # held SIGINT, as _exec does at its start.
        instance = make_sandy()
        instance.workspace = None
        handler = sandy.signal.getsignal(sandy.signal.SIGINT)
        self.up_lock.close.side_effect = self.send_sigint

        def console(*_args: object, sigint: object = None, **_kwargs: object) -> int:
            assert isinstance(sigint, sandy._DeferredSigint)
            sandy._DeferredSigint.release(sigint)
            return 0

        self.exec.side_effect = console
        with tempfile.TemporaryDirectory() as machine:
            with self.up_mocks(instance, machine) as mocks:
                with captured_output():
                    with self.assertRaises(BaseException) as raised:
                        instance.run_up(self.arguments(detach=False))
        self.assertIsInstance(raised.exception, KeyboardInterrupt)
        self.exec.assert_called_once()
        mocks.stop.assert_not_called()
        self.assertIs(sandy.signal.getsignal(sandy.signal.SIGINT), handler)

    def test_a_failed_cleanup_after_the_start_gives_back_sigint(self):
        # A cleanup step after a good start can fail while up holds SIGINT
        # back. Then up ends with that error, and SIGINT has its handler
        # again. Mocks: as in up_mocks; the close of the pinned pidfd closes
        # it, and then fails.
        instance = make_sandy()
        instance.workspace = None
        handler = sandy.signal.getsignal(sandy.signal.SIGINT)
        real_close = os.close

        def close(fd: int) -> None:
            real_close(fd)
            if self.pinned and fd == self.pinned[-1].pidfd:
                raise OSError(errno.EBADF, "Bad file descriptor")

        with tempfile.TemporaryDirectory() as machine:
            with self.up_mocks(instance, machine), patch.object(
                sandy.os, "close", side_effect=close
            ):
                with captured_output():
                    with self.assertRaises(OSError) as raised:
                        instance.run_up(self.arguments(detach=False))
        self.assertEqual(raised.exception.errno, errno.EBADF)
        self.exec.assert_not_called()
        self.assertIs(sandy.signal.getsignal(sandy.signal.SIGINT), handler)

    def test_up_stops_when_the_port_mapping_lock_stays_busy(self):
        # Regression test: up waited for the port mapping lock without a limit
        # while it held the lifecycle lock, so each attach failed after
        # LIFECYCLE_LOCK_TIMEOUT. Mocks: the port mapping lock (setUp), which
        # times out.
        self.assertLess(sandy.PORT_MAPPINGS_LOCK_TIMEOUT, sandy.LIFECYCLE_LOCK_TIMEOUT)
        self.port_lock_error = TimeoutError(
            "Timed out waiting for the Sandy port mapping lock"
        )
        instance = make_sandy()
        instance.workspace = None
        instance.network = make_network()
        instance.port_mappings = [("tcp", 8080, 80)]
        with tempfile.TemporaryDirectory() as machine:
            init_script = Path(machine) / "init.sh"
            init_script.write_text('CONTAINER_IP="10.200.1.10"\n')
            init_script.chmod(0o644)
            with self.up_mocks(instance, machine) as mocks, patch.object(
                instance, "_setup_port_forwarding_rules"
            ) as publish, patch.object(sandy.os, "fchown"):
                with captured_output() as (stdout, _):
                    with self.assertRaises(SystemExit) as exited:
                        instance.run_up(self.arguments(network="lenient", detach=False))
        self.assertEqual(exited.exception.code, 1)
        self.port_lock.assert_called_once_with(
            exclusive=True, timeout=sandy.PORT_MAPPINGS_LOCK_TIMEOUT
        )
        publish.assert_not_called()
        self.assertIn(
            "E: Could not publish the ports of 'ai-dev': Timed out waiting for "
            "the Sandy port mapping lock\n",
            stdout.getvalue(),
        )
        mocks.popen.assert_not_called()
        mocks.stop.assert_not_called()
        # The lifecycle lock is free again. The state did not change, so only
        # the cleanup of stale rules at the start ran.
        self.assertEqual(self.lock_events, ["enter", "exit"])
        self.stale_cleanup.assert_called_once_with("ai-dev")

    def test_up_limits_the_port_lock_wait_only_under_the_lifecycle_lock(self):
        # Regression test: up -d with no directories to mount holds no
        # lifecycle lock, but it also waited for the port mapping lock for at
        # most 5 seconds. So it failed while rm --cache held that lock, where
        # it had waited and started before. Mocks: the lifecycle lock and the
        # port mapping lock (setUp), the port setup, and the start (up_mocks).
        limit = sandy.PORT_MAPPINGS_LOCK_TIMEOUT
        publish = [f"port lock {limit}", "ports"]
        for label, detach, mount, expected in (
            # No process waits for an up without the lifecycle lock.
            ("up -d", True, False, ["port lock None", "ports", "port unlock"]),
            (
                "up -d with mounts",
                True,
                True,
                ["enter", *publish, "pending ai-dev", "port unlock", "exit"],
            ),
            (
                "up",
                False,
                False,
                ["enter", *publish, "marker ai-dev", "port unlock", "exit"],
            ),
        ):
            with self.subTest(label=label):
                events = self.lock_events
                events.clear()
                instance = make_sandy()
                instance.network = make_network()
                instance.port_mappings = [("tcp", 8080, 80)]
                with ExitStack() as stack:
                    if mount:
                        machine, _, _ = stack.enter_context(self.mount_dirs(instance))
                    else:
                        instance.workspace = None
                        machine = Path(
                            stack.enter_context(tempfile.TemporaryDirectory())
                        )
                    init_script = machine / "init.sh"
                    init_script.write_text('CONTAINER_IP="10.200.1.10"\n')
                    init_script.chmod(0o644)
                    stack.enter_context(self.up_mocks(instance, machine))
                    stack.enter_context(
                        patch.object(
                            instance,
                            "_setup_port_forwarding_rules",
                            side_effect=lambda ip: events.append("ports"),
                        )
                    )
                    stack.enter_context(patch.object(sandy.os, "fchown"))
                    stack.enter_context(captured_output())
                    instance.run_up(self.arguments(network="lenient", detach=detach))
                self.assertEqual(events, expected)

    def test_keepalive_open_is_not_awaited_before_ready(self):
        instance = make_sandy()
        instance.workspace = None
        self.wait_for_container_ready.return_value = False
        with tempfile.TemporaryDirectory() as machine, patch.object(
            instance, "_stop_failed_start"
        ):
            with self.assertRaises(SystemExit):
                self.run_detached_up(instance, machine)
        self.wait_for_keepalive_open.assert_not_called()

    def test_entry_setup_failure_stops_the_started_container(self):
        # Regression test for a setup error in the readiness probe, which
        # escaped as a traceback. Mocks: as in the not-ready test.
        for detach in (True, False):
            with self.subTest(detach=detach):
                instance = make_sandy()
                instance.workspace = None
                self.wait_for_container_ready.side_effect = sandy._EntrySetupError(
                    "Sandy script must be a regular file that only its owner can write"
                )
                self.exec.reset_mock()
                with tempfile.TemporaryDirectory() as machine, ExitStack() as stack:
                    stack.enter_context(
                        patch.object(
                            instance, "_is_container_running", return_value=None
                        )
                    )
                    stack.enter_context(
                        patch.object(instance, "_get_machine_dir", return_value=machine)
                    )
                    popen = stack.enter_context(
                        patch.object(sandy, "_run_secure_subprocess_popen")
                    )
                    stop = stack.enter_context(
                        patch.object(instance, "_stop_failed_start")
                    )
                    init = stack.enter_context(
                        patch.object(instance, "_run_init_script")
                    )
                    stdout, _ = stack.enter_context(captured_output())
                    with self.assertRaises(SystemExit) as exited:
                        instance.run_up(self.arguments(detach=detach))
                self.assertEqual(exited.exception.code, 1)
                stop.assert_called_once_with(popen.return_value)
                init.assert_not_called()
                self.exec.assert_not_called()
                self.assertIn(
                    "E: Could not prepare the container entry", stdout.getvalue()
                )

    def test_up_console_marker_failure_stops_the_started_container(self):
        for error, expected in (
            (TimeoutError("The container scope did not appear"), SystemExit),
            (KeyboardInterrupt(), KeyboardInterrupt),
        ):
            with self.subTest(error=type(error).__name__):
                instance = make_sandy()
                instance.workspace = None
                self.create_marker.side_effect = error
                self.wait_for_container_ready.reset_mock()
                with tempfile.TemporaryDirectory() as machine:
                    with patch.object(
                        instance, "_is_container_running", return_value=None
                    ), patch.object(
                        instance, "_get_machine_dir", return_value=machine
                    ), patch.object(
                        sandy, "_run_secure_subprocess_popen"
                    ) as popen, patch.object(
                        instance, "_stop_failed_start"
                    ) as stop:
                        with captured_output() as (stdout, _):
                            with self.assertRaises(expected):
                                instance.run_up(self.arguments(detach=False))
                # No ports, so no port removal and no wait for its lock.
                stop.assert_called_once_with(popen.return_value, **LOCKED_STOP)
                self.wait_for_container_ready.assert_not_called()
                if expected is SystemExit:
                    self.assertIn("did not start", stdout.getvalue())

    def test_init_failure_stops_the_started_container(self):
        instance = make_sandy()
        instance.workspace = None
        with tempfile.TemporaryDirectory() as machine:
            with patch.object(instance, "_is_container_running", return_value=None):
                with patch.object(instance, "_get_machine_dir", return_value=machine):
                    with patch.object(instance, "_remove_port_mappings_from_state"):
                        with patch.object(
                            sandy, "_run_secure_subprocess_popen"
                        ) as popen:
                            with patch.object(instance, "_stop_failed_start") as stop:
                                with patch.object(
                                    instance,
                                    "_run_init_script",
                                    side_effect=KeyboardInterrupt,
                                ):
                                    with captured_output():
                                        with self.assertRaises(KeyboardInterrupt):
                                            instance.run_up(self.arguments())
        stop.assert_called_once_with(popen.return_value)
        self.exec.assert_not_called()

    def test_console_status_is_the_exit_status_of_up(self):
        # The base ignored the status of the attached container. Mocks: as in
        # the detached host test; the console returns each status in turn.
        for status, expected in ((0, None), (19, 19), (-9, 128 + 9)):
            with self.subTest(status=status):
                instance = make_sandy()
                instance.workspace = None
                self.exec.reset_mock()
                self.exec.return_value = status
                with tempfile.TemporaryDirectory() as machine, ExitStack() as stack:
                    stack.enter_context(
                        patch.object(
                            instance, "_is_container_running", return_value=None
                        )
                    )
                    stack.enter_context(
                        patch.object(instance, "_remove_port_mappings_from_state")
                    )
                    stack.enter_context(
                        patch.object(instance, "_get_machine_dir", return_value=machine)
                    )
                    stack.enter_context(
                        patch.object(sandy, "_run_secure_subprocess_popen")
                    )
                    stack.enter_context(
                        patch.object(instance, "_run_init_script", return_value=False)
                    )
                    stack.enter_context(captured_output())
                    if expected is None:
                        instance.run_up(self.arguments(detach=False))
                    else:
                        with self.assertRaises(SystemExit) as exited:
                            instance.run_up(self.arguments(detach=False))
                        self.assertEqual(exited.exception.code, expected)
                self.exec.assert_called_once_with(
                    None, login_shell=True, console=True, sigint=ANY
                )
                self.assertIsInstance(
                    self.exec.call_args.kwargs["sigint"], sandy._DeferredSigint
                )

    def test_rejects_ports_with_host_network(self):
        instance = make_sandy()
        with patch.object(instance, "_is_container_running", return_value=None):
            with captured_output():
                with self.assertRaises(SystemExit):
                    instance.run_up(self.arguments(ports=["tcp:8080:80"]))
        # CLI values are validated before any host change.
        self.stale_cleanup.assert_not_called()

    def test_rejects_invalid_port_mapping(self):
        instance = make_sandy()
        with patch.object(instance, "_is_container_running", return_value=None):
            with captured_output():
                with self.assertRaises(SystemExit):
                    instance.run_up(
                        self.arguments(
                            network="lenient",
                            ports=["tcp:bad:80"],
                        )
                    )
        self.stale_cleanup.assert_not_called()

    def test_detached_host_command_has_security_flags(self):
        instance = make_sandy()
        instance.workspace = None
        with tempfile.TemporaryDirectory() as machine:
            with patch.object(instance, "_is_container_running", return_value=None):
                with patch.object(
                    instance,
                    "_remove_port_mappings_from_state",
                ):
                    with patch.object(
                        instance,
                        "_get_machine_dir",
                        return_value=machine,
                    ):
                        with patch.object(
                            sandy,
                            "_run_secure_subprocess_popen",
                        ) as popen:
                            with patch.object(
                                instance,
                                "_run_init_script",
                                return_value=False,
                            ):
                                with captured_output():
                                    instance.run_up(self.arguments())

        scope_command = popen.call_args.args[0]
        self.assertEqual(
            scope_command[: scope_command.index("systemd-nspawn")],
            [
                "systemd-run",
                "--scope",
                "--quiet",
                "--unit=sandy-ai-dev.scope",
                "--slice=sandy.slice",
                "--description=Sandy container ai-dev (detached)",
                "--property=Delegate=yes",
                "--property=OOMPolicy=continue",
                # 25% of the shared process limit; the CPU and memory limits
                # are those of sandy.slice.
                "--property=TasksMax=24576",
                "--property=MemorySwapMax=0",
                "--",
            ],
        )
        command = self.nspawn_command(scope_command)
        self.assertEqual(
            command[2:9],
            [
                "--machine=ai-dev",
                "--keep-unit",
                "--console=passive",
                f"--tmpfs=/tmp:mode=1777,size={512 * MIB}",
                "--as-pid2",
                "--timezone=bind",
                "--user=root",
            ],
        )
        self.assertEqual(
            command[-2:], ["/run/sandy/sandy-keepalive", "/run/sandy/keepalive.sh"]
        )
        self.assertIn("--private-users=pick", command)
        self.assertIn("--ephemeral", command)
        self.assertFalse(any(argument.startswith("--chdir") for argument in command))
        self.assertTrue(
            any(argument.startswith("--system-call-filter=") for argument in command)
        )
        self.assertRegex(command[1], r"^--directory=/proc/self/fd/[0-9]+$")
        # The keepalive directory is bound read-only and removed after start.
        keepalive = [a for a in command if a.endswith(":/run/sandy")]
        self.assertEqual(len(keepalive), 1)
        keepalive_dir = keepalive[0].removeprefix("--bind-ro=").split(":", 1)[0]
        self.assertTrue(
            keepalive_dir.startswith(f"{tempfile.gettempdir()}/sandy-keepalive-")
        )
        self.assertFalse(os.path.lexists(keepalive_dir))
        self.wait_for_container_ready.assert_called_once()
        self.exec.assert_not_called()
        self.machine_poweroff.assert_not_called()
        # up -d takes no lock and creates no up-console marker.
        self.assertEqual(self.lock_events, [])
        # Stale rules of this name go on every up, also without -p.
        self.stale_cleanup.assert_called_once_with("ai-dev")
        self.assertFalse(
            any(argument.startswith("--network-bridge=") for argument in command)
        )
        self.assertEqual(popen.call_args.kwargs["start_new_session"], True)
        self.assertEqual(len(popen.call_args.kwargs["pass_fds"]), 1)
        environment = popen.call_args.kwargs["env"]
        self.assertEqual(environment["HOME"], "/home/developer")
        self.assertEqual(environment["USER"], "developer")
        self.assertNotIn("SANDY_TEST_HOST_SECRET", environment)

    def test_lenient_network_adds_bridge_and_dedupes_ports(self):
        instance = make_sandy()
        instance.workspace = None
        instance.network = make_network()
        args = self.arguments(
            network="lenient",
            ports=["tcp:8080:80", "tcp:8080:81"],
            persistent=True,
        )
        with tempfile.TemporaryDirectory() as machine:
            with patch.object(instance, "_is_container_running", return_value=None):
                with patch.object(
                    instance,
                    "_get_machine_dir",
                    return_value=machine,
                ):
                    with patch.object(
                        instance,
                        "_setup_port_forwarding_rules",
                    ) as forwarding:
                        with patch.object(
                            sandy,
                            "_run_secure_subprocess_popen",
                        ) as popen:
                            with patch.object(
                                instance,
                                "_run_init_script",
                                return_value=False,
                            ):
                                with captured_output():
                                    instance.run_up(args)

        self.assertEqual(instance.port_mappings, [("tcp", 8080, 80)])
        # up -d with no directories to mount holds no lifecycle lock, so it
        # waits for the port mapping lock with no limit.
        self.port_lock.assert_called_once_with(exclusive=True, timeout=None)
        forwarding.assert_called_once_with(None)
        command = popen.call_args.args[0]
        self.assertIn("--network-bridge=sandybr0", command)
        self.assertNotIn("--ephemeral", command)

    def test_foreground_old_systemd_mounts_and_cleans_network_state(self):
        instance = make_sandy()
        instance.systemd_version = 249
        instance.network = make_network()
        instance.port_mappings = [("tcp", 8080, 80)]
        args = self.arguments(
            network="lenient",
            detach=False,
            persistent=False,
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            machine = root / "machine"
            host_workspace = root / "host-workspace"
            host_shared = root / "host-shared"
            container_home = machine / "home" / "developer"
            host_workspace.mkdir()
            host_shared.mkdir()
            (container_home / "workspace").mkdir(parents=True)
            (container_home / "shared").mkdir()
            init_script = machine / "init.sh"
            init_script.write_text('CONTAINER_IP="10.200.1.10"\n')
            init_script.chmod(0o644)
            instance.workspace = str(host_workspace)
            instance.shared = str(host_shared)

            with ExitStack() as stack:
                stack.enter_context(
                    patch.object(instance, "_is_container_running", return_value=None)
                )
                remove_state = stack.enter_context(
                    patch.object(instance, "_remove_port_mappings_from_state")
                )
                stack.enter_context(
                    patch.object(
                        instance, "_get_machine_dir", return_value=str(machine)
                    )
                )
                setup_forwarding = stack.enter_context(
                    patch.object(instance, "_setup_port_forwarding_rules")
                )
                init = stack.enter_context(
                    patch.object(instance, "_run_init_script", return_value=True)
                )
                popen = stack.enter_context(
                    patch.object(sandy, "_run_secure_subprocess_popen")
                )
                cleanup = stack.enter_context(
                    patch.object(instance, "_cleanup_port_forwarding_rules")
                )
                stack.enter_context(
                    patch.object(sandy.platform, "machine", return_value="unknown-cpu")
                )
                # The unknown architecture has no number for openat2, so the
                # check of the targets in the image opens them with os.open.
                open_target = stack.enter_context(
                    patch.object(
                        sandy,
                        "_openat2_no_links",
                        side_effect=lambda path, flags, root_fd: os.open(
                            path[1:], flags, dir_fd=root_fd
                        ),
                    )
                )
                fchown = stack.enter_context(patch.object(sandy.os, "fchown"))
                with captured_output() as (stdout, _):
                    instance.run_up(args)
            workspace = os.path.realpath(host_workspace)
            shared = os.path.realpath(host_shared)

        setup_forwarding.assert_called_once_with("10.200.1.10")
        init.assert_called_once_with(network_mode="lenient")
        # The console is an attach. _exec applies the last-attach rule, and
        # the stop removes the port forwarding rules.
        self.exec.assert_called_once_with(
            None, login_shell=True, console=True, sigint=ANY
        )
        self.assertIsInstance(
            self.exec.call_args.kwargs["sigint"], sandy._DeferredSigint
        )
        # The pending marker and the console marker exist before the lock is
        # released, in that order. The port mapping lock is held from the
        # publish until the supervisor is pinned with its markers.
        self.assertEqual(
            self.lock_events,
            [
                "enter",
                f"port lock {sandy.PORT_MAPPINGS_LOCK_TIMEOUT}",
                "pending ai-dev",
                "marker ai-dev",
                "port unlock",
                "exit",
            ],
        )
        self.machine_poweroff.assert_not_called()
        cleanup.assert_not_called()
        # up removes this name's stale rules and state once, at its start.
        self.stale_cleanup.assert_called_once_with("ai-dev")
        remove_state.assert_not_called()
        fchown.assert_called_once()
        self.assertEqual(
            fchown.call_args.args[1:],
            (sandy.CONTAINER_BASE_UID, sandy.CONTAINER_BASE_UID),
        )
        scope_command = popen.call_args.args[0]
        self.assertIn("--description=Sandy container ai-dev (attached)", scope_command)
        # Scope units accept OOMPolicy= only from systemd 253.
        self.assertFalse(any("OOMPolicy" in item for item in scope_command))
        command = self.nspawn_command(scope_command)
        environment = popen.call_args.kwargs["env"]
        self.assertEqual(environment["HOME"], "/home/developer")
        self.assertEqual(environment["USER"], "developer")
        self.assertIn(
            f"--private-users={sandy.CONTAINER_BASE_UID}:65536",
            command,
        )
        self.assertIn("--private-users-ownership=auto", command)
        # No nspawn bind for the directories: up mounts them after the start.
        self.assertFalse(any(item.startswith("--bind=") for item in command))
        self.assertEqual(
            self.plan_mount.call_args_list,
            [
                call("workspace", workspace, "/home/developer/workspace"),
                call("shared", shared, "/home/developer/shared"),
            ],
        )
        self.assertEqual(
            open_target.call_args_list,
            [
                call(
                    "/home/developer/workspace",
                    os.O_PATH | os.O_DIRECTORY,
                    root_fd=ANY,
                ),
                call("/home/developer/shared", os.O_PATH | os.O_DIRECTORY, root_fd=ANY),
            ],
        )
        self.wait_for_mounts.assert_called_once_with(
            (
                sandy.MountPlan(
                    "workspace", workspace, "/home/developer/workspace", 1, 2
                ),
                sandy.MountPlan("shared", shared, "/home/developer/shared", 1, 2),
            ),
            (1000, 1000),
            self.pinned[0],
            spinner_line_event=ANY,
            supervisor=popen.return_value,
        )
        self.assertFalse(any(item.startswith("--chdir") for item in command))
        self.assertRegex(command[1], r"^--directory=/proc/self/fd/[0-9]+$")
        bind_ro = [
            argument for argument in command if argument.startswith("--bind-ro=")
        ]
        self.assertEqual(len(bind_ro), 2)
        self.assertTrue(
            bind_ro[0].startswith(f"--bind-ro={tempfile.gettempdir()}/sandy-init-")
        )
        self.assertTrue(bind_ro[0].endswith("/init.sh:/init.sh"))
        bind_source = bind_ro[0].removeprefix("--bind-ro=").split(":", 1)[0]
        self.assertFalse(Path(bind_source).parent.exists())
        self.assertEqual(len(popen.call_args.kwargs["pass_fds"]), 1)
        self.assertIn("unknown architecture", stdout.getvalue())

    def test_modern_init_bind_uses_idmapped_read_only_mount(self):
        instance = make_sandy()
        instance.workspace = None
        args = self.arguments(network="host", persistent=True)
        with tempfile.TemporaryDirectory() as temp_dir:
            machine = Path(temp_dir)
            init_script = machine / "init.sh"
            init_script.write_text('CONTAINER_IP="10.200.1.10"\n')
            init_script.chmod(0o644)
            with patch.object(instance, "_is_container_running", return_value=None):
                with patch.object(instance, "_remove_port_mappings_from_state"):
                    with patch.object(
                        instance,
                        "_get_machine_dir",
                        return_value=str(machine),
                    ):
                        with patch.object(
                            sandy,
                            "_run_secure_subprocess_popen",
                        ) as popen:
                            with patch.object(
                                instance,
                                "_run_init_script",
                                return_value=False,
                            ):
                                with captured_output():
                                    instance.run_up(args)

        command = popen.call_args.args[0]
        bind_ro = [
            argument for argument in command if argument.startswith("--bind-ro=")
        ]
        self.assertEqual(len(bind_ro), 2)
        self.assertTrue(bind_ro[0].endswith("/init.sh:/init.sh:idmap"))
        # The keepalive bind has no idmap: its files are world-readable.
        self.assertTrue(bind_ro[1].endswith(":/run/sandy"))

    def test_init_bind_copy_is_cleaned_after_prelaunch_failure(self):
        instance = make_sandy()
        instance.workspace = None
        created_dirs = []
        opened_fds = []
        real_create_init_bind_copy = sandy._create_init_bind_copy

        def open_machine(path):
            machine_fd = os.open(path, sandy.DIRECTORY_OPEN_FLAGS)
            opened_fds.append(machine_fd)
            return machine_fd

        def create_init_bind_copy(*args, **kwargs):
            result = real_create_init_bind_copy(*args, **kwargs)
            created_dirs.append(result[0])
            return result

        with tempfile.TemporaryDirectory() as temp_dir:
            machine = Path(temp_dir)
            init_script = machine / "init.sh"
            init_script.write_text('CONTAINER_IP="10.200.1.10"\n')
            init_script.chmod(0o644)
            with patch.object(instance, "_is_container_running", return_value=None):
                with patch.object(
                    instance,
                    "_get_machine_dir",
                    return_value=str(machine),
                ):
                    with patch.object(
                        sandy,
                        "_open_verified_dir",
                        side_effect=open_machine,
                    ):
                        with patch.object(
                            sandy,
                            "_create_init_bind_copy",
                            side_effect=create_init_bind_copy,
                        ):
                            with patch.object(
                                sandy,
                                "_create_keepalive_dir",
                                side_effect=RuntimeError("keepalive failure"),
                            ):
                                with self.assertRaisesRegex(
                                    RuntimeError,
                                    "keepalive failure",
                                ):
                                    with captured_output():
                                        instance.run_up(
                                            self.arguments(
                                                network="host",
                                                persistent=True,
                                            )
                                        )

        self.assertEqual(len(created_dirs), 1)
        self.assertFalse(Path(created_dirs[0]).exists())
        self.assertEqual(len(opened_fds), 1)
        with self.assertRaises(OSError):
            os.fstat(opened_fds[0])

    def test_mount_validation_skips_missing_host_and_container_paths(self):
        instance = make_sandy()
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            machine = root / "machine"
            machine.mkdir()
            shared = root / "shared"
            shared.mkdir()
            instance.workspace = str(root / "missing-workspace")
            instance.shared = str(shared)
            with patch.object(instance, "_is_container_running", return_value=None):
                with patch.object(
                    instance,
                    "_remove_port_mappings_from_state",
                ):
                    with patch.object(
                        instance,
                        "_get_machine_dir",
                        return_value=str(machine),
                    ):
                        with patch.object(
                            sandy,
                            "_run_secure_subprocess_popen",
                        ) as popen:
                            with patch.object(
                                instance,
                                "_run_init_script",
                                return_value=False,
                            ):
                                with captured_output() as (stdout, _):
                                    instance.run_up(self.arguments())

        command = self.nspawn_command(popen.call_args.args[0])
        self.assertFalse(any(item.startswith("--chdir") for item in command))
        self.assertFalse(any(item.startswith("--bind=") for item in command))
        self.assertIn("skipping workspace mount", stdout.getvalue())
        self.assertIn("Skipping shared mount", stdout.getvalue())

    @contextmanager
    def up_mocks(self, instance, machine):
        """Mock the host boundaries of up; yield its popen and stop mocks."""
        with ExitStack() as stack:
            stack.enter_context(
                patch.object(instance, "_is_container_running", return_value=None)
            )
            stack.enter_context(
                patch.object(instance, "_remove_port_mappings_from_state")
            )
            stack.enter_context(
                patch.object(instance, "_get_machine_dir", return_value=str(machine))
            )
            popen = stack.enter_context(
                patch.object(sandy, "_run_secure_subprocess_popen")
            )
            stack.enter_context(
                patch.object(instance, "_run_init_script", return_value=False)
            )
            stop = stack.enter_context(patch.object(instance, "_stop_failed_start"))
            yield SimpleNamespace(popen=popen, stop=stop)

    @contextmanager
    def mount_dirs(self, instance):
        """Make host directories and an image that has both mount targets.

        Yield the machine directory and the real paths of the host directories.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            machine = root / "machine"
            for name in ("workspace", "shared"):
                (machine / "home" / "developer" / name).mkdir(parents=True)
            host_workspace = root / "host-workspace"
            host_shared = root / "host-shared"
            host_workspace.mkdir()
            host_shared.mkdir()
            instance.workspace = str(host_workspace)
            instance.shared = str(host_shared)
            yield (
                machine,
                os.path.realpath(host_workspace),
                os.path.realpath(host_shared),
            )

    def test_a_second_up_of_a_starting_name_fails_at_once(self):
        # Regression test: two ups of a name could both pass the first check.
        # The second then removed or replaced the port state of the first,
        # and built or started the same container.
        instance = make_sandy()
        self.acquire_up_lock.return_value = None
        with patch.object(instance, "_is_container_running") as running:
            with captured_output() as (stdout, _):
                with self.assertRaises(SystemExit) as exited:
                    instance.run_up(
                        self.arguments(network="lenient", ports=["tcp:8080:80"])
                    )
        self.assertEqual(exited.exception.code, 1)
        self.assertEqual(
            stdout.getvalue(), "E: Another up is starting container 'ai-dev'\n"
        )
        self.acquire_up_lock.assert_called_once_with("ai-dev")
        running.assert_not_called()
        self.supervisor_unit_loaded.assert_not_called()
        self.plan_mount.assert_not_called()
        self.set_shared_limits.assert_not_called()
        self.stale_cleanup.assert_not_called()
        self.assertEqual(self.lock_events, [])

    def test_up_checks_its_ports_before_it_takes_the_up_lock(self):
        instance = make_sandy()
        with captured_output() as (stdout, _):
            with self.assertRaises(SystemExit):
                instance.run_up(self.arguments(network="lenient", ports=["tcp:0:80"]))
        self.assertIn("E: Invalid port specification", stdout.getvalue())
        self.ensure_cache_dir.assert_not_called()
        self.acquire_up_lock.assert_not_called()

    def test_up_holds_the_up_lock_from_its_first_check_until_ready(self):
        for detach in (True, False):
            with self.subTest(detach=detach):
                instance = make_sandy()
                manager = MagicMock()
                self.up_lock.reset_mock()
                for name, mock in (
                    ("cache_dir", self.ensure_cache_dir),
                    ("up_lock", self.acquire_up_lock),
                    ("lock_file", self.up_lock),
                    ("plan", self.plan_mount),
                    ("limits", self.set_shared_limits),
                    ("stale", self.stale_cleanup),
                    ("mounts", self.wait_for_mounts),
                    ("ready", self.wait_for_container_ready),
                    ("console", self.exec),
                ):
                    mock.reset_mock()
                    manager.attach_mock(mock, name)
                with self.mount_dirs(instance) as (machine, _, _):
                    with self.up_mocks(instance, machine) as mocks:
                        manager.attach_mock(mocks.popen, "start")
                        with patch.object(
                            instance, "_existing_container_error", return_value=None
                        ) as check:
                            manager.attach_mock(check, "check")
                            with captured_output():
                                instance.run_up(self.arguments(detach=detach))
                order = [
                    entry[0]
                    for entry in manager.mock_calls
                    if entry[0]
                    in (
                        "cache_dir",
                        "up_lock",
                        "check",
                        "plan",
                        "limits",
                        "stale",
                        "start",
                        "mounts",
                        "ready",
                        "lock_file.close",
                        "console",
                    )
                ]
                # With directories to mount, up checks again under the
                # lifecycle lock, also with -d.
                expected = [
                    "cache_dir",
                    "up_lock",
                    "check",
                    "plan",
                    "plan",
                    "limits",
                    "stale",
                    "check",
                    "start",
                    "mounts",
                    "ready",
                    "lock_file.close",
                ]
                expected += [] if detach else ["console"]
                self.assertEqual(order, expected)

    def test_a_failed_start_keeps_the_up_lock_for_its_cleanup(self):
        # The cleanup of a failed start removes the port state of the name;
        # no other up of the name may run before it is done. The lock goes
        # when up exits.
        instance = make_sandy()
        instance.workspace = None
        self.wait_for_container_ready.return_value = False
        with tempfile.TemporaryDirectory() as machine:
            with self.up_mocks(instance, machine) as mocks:
                with captured_output():
                    with self.assertRaises(SystemExit):
                        instance.run_up(self.arguments())
        mocks.stop.assert_called_once_with(mocks.popen.return_value)
        self.up_lock.close.assert_not_called()

    def test_up_refuses_when_the_machine_query_does_not_answer(self):
        # Mocks: machinectl, which times out.
        instance = make_sandy()
        with patch.object(
            instance,
            "_is_container_running",
            side_effect=subprocess.TimeoutExpired(["machinectl"], 3),
        ):
            with captured_output() as (stdout, _):
                with self.assertRaises(SystemExit) as exited:
                    instance.run_up(self.arguments())
        self.assertEqual(exited.exception.code, 1)
        self.assertIn("E: Could not query machine 'ai-dev': ", stdout.getvalue())
        self.supervisor_unit_loaded.assert_not_called()
        self.set_shared_limits.assert_not_called()

    def test_up_refuses_when_the_machine_query_fails(self):
        # Mocks: the machine query, which fails with the error that
        # _is_container_running raises. The error line names the cause once.
        instance = make_sandy()
        with patch.object(
            instance,
            "_is_container_running",
            side_effect=sandy._MachineQueryError(
                "ai-dev", "Failed to connect to bus: Connection refused"
            ),
        ):
            with captured_output() as (stdout, _):
                with self.assertRaises(SystemExit) as exited:
                    instance.run_up(self.arguments())
        self.assertEqual(exited.exception.code, 1)
        self.assertIn(
            "E: Could not query machine 'ai-dev': "
            "'Failed to connect to bus: Connection refused'\n",
            stdout.getvalue(),
        )
        self.supervisor_unit_loaded.assert_not_called()
        self.set_shared_limits.assert_not_called()

    def test_mounts_are_checked_before_any_host_change(self):
        # The check of a directory comes before the first host change, the
        # shared limits.
        instance = make_sandy()
        manager = MagicMock()
        manager.attach_mock(self.plan_mount, "plan")
        manager.attach_mock(self.set_shared_limits, "limits")
        with self.mount_dirs(instance) as (machine, _, _):
            with self.up_mocks(instance, machine):
                with captured_output():
                    instance.run_up(self.arguments())
        self.assertEqual(
            [entry[0] for entry in manager.mock_calls], ["plan", "plan", "limits"]
        )

    def test_a_refused_directory_stops_up_before_any_host_change(self):
        instance = make_sandy()
        self.plan_mount.side_effect = sandy._MountError(
            "root owns the workspace directory"
        )
        with self.mount_dirs(instance) as (machine, workspace, _):
            with self.up_mocks(instance, machine) as mocks:
                with captured_output() as (stdout, _):
                    with self.assertRaises(SystemExit) as exited:
                        instance.run_up(self.arguments())
        self.assertEqual(exited.exception.code, 1)
        self.assertEqual(
            stdout.getvalue(),
            f"E: Cannot mount '{workspace}' as the workspace directory: "
            "root owns the workspace directory\n",
        )
        self.set_shared_limits.assert_not_called()
        self.stale_cleanup.assert_not_called()
        mocks.popen.assert_not_called()

    def test_detached_up_with_mounts_holds_the_lock_for_the_pending_marker(self):
        instance = make_sandy()
        events = []
        self.wait_for_mounts.side_effect = (
            lambda *a, **k: events.append("mounts") or True
        )
        self.wait_for_container_ready.side_effect = (
            lambda *a, **k: events.append("ready") or True
        )
        with self.mount_dirs(instance) as (machine, workspace, shared):
            with self.up_mocks(instance, machine) as mocks:
                with captured_output() as (stdout, _):
                    instance.run_up(self.arguments(detach=True))
        # No console, so no up-console marker; the pending marker still needs
        # the lock, and the cache directory holds the lock file.
        self.assertEqual(self.lock_events, ["enter", "pending ai-dev", "exit"])
        self.ensure_cache_dir.assert_called_once_with()
        # The mounts come before the readiness probe, which needs them.
        self.assertEqual(events, ["mounts", "ready"])
        self.wait_for_mounts.assert_called_once_with(
            (
                sandy.MountPlan(
                    "workspace", workspace, "/home/developer/workspace", 1, 2
                ),
                sandy.MountPlan("shared", shared, "/home/developer/shared", 1, 2),
            ),
            (1000, 1000),
            self.pinned[0],
            spinner_line_event=ANY,
            supervisor=mocks.popen.return_value,
        )
        self.read_image_user_ids.assert_called_once_with(ANY, "developer")
        command = self.nspawn_command(mocks.popen.call_args.args[0])
        self.assertFalse(any(item.startswith("--bind=") for item in command))
        self.assertIn("--private-users=pick", command)
        self.assertIn(
            f"I: Mounting '{workspace}' on '/home/developer/workspace'",
            stdout.getvalue(),
        )
        self.assertIn(
            f"I: Mounting '{shared}' on '/home/developer/shared'", stdout.getvalue()
        )

    def test_up_checks_the_name_again_under_the_lock(self):
        # Regression test: an up of a name passed the first checks while
        # another up started a container of that name, and then waited for
        # the lock. It started its own systemd-run, which failed, and still
        # made its marker in the other container's scope. Now it checks
        # again under the lock and starts nothing. Mocks: machined, systemd,
        # the start, and the lock.
        for label, running, loaded, message in (
            ("running", "123", False, "E: Container 'ai-dev' is already running"),
            ("scope", None, True, "E: Unit 'sandy-ai-dev.scope' already exists"),
        ):
            with self.subTest(label=label):
                self.lock_events.clear()
                self.pin_supervisor.reset_mock()
                self.pending_marker.reset_mock()
                self.supervisor_unit_loaded.side_effect = lambda name: (
                    loaded and "enter" in self.lock_events
                )
                instance = make_sandy()
                with self.mount_dirs(instance) as (machine, _, _):
                    with self.up_mocks(instance, machine) as mocks, patch.object(
                        instance,
                        "_is_container_running",
                        side_effect=lambda: (
                            running if "enter" in self.lock_events else None
                        ),
                    ):
                        with captured_output() as (stdout, _):
                            with self.assertRaises(SystemExit) as exited:
                                instance.run_up(self.arguments(detach=True))
                self.assertEqual(exited.exception.code, 1)
                # up refuses on a line of its own, before "Starting".
                self.assertTrue(
                    stdout.getvalue().endswith("\n" + message + "\n"),
                    stdout.getvalue(),
                )
                self.assertNotIn("I: Starting", stdout.getvalue())
                self.assertEqual(self.lock_events, ["enter", "exit"])
                mocks.popen.assert_not_called()
                mocks.stop.assert_not_called()
                self.pin_supervisor.assert_not_called()
                self.pending_marker.assert_not_called()
        self.supervisor_unit_loaded.side_effect = None

    def test_a_refused_up_publishes_no_port(self):
        # Regression test: an up that the check under the lock refused had
        # already published its ports, to the container of the other start.
        # The rules and the state stayed until that container stopped. Now
        # the ports come after the check, just before the start. Mocks:
        # machined, the start, the lock, and the port setup (the port
        # forwarding tests cover the rules themselves).
        events = self.lock_events
        for label, running, expected in (
            ("refused", "123", ["enter", "exit"]),
            (
                "started",
                None,
                [
                    "enter",
                    f"port lock {sandy.PORT_MAPPINGS_LOCK_TIMEOUT}",
                    "ports 10.200.1.10",
                    "popen",
                    "pending ai-dev",
                    "port unlock",
                    "exit",
                ],
            ),
        ):
            with self.subTest(label=label):
                events.clear()
                instance = make_sandy()
                instance.network = make_network()
                instance.port_mappings = [("tcp", 8080, 80)]
                with self.mount_dirs(instance) as (machine, _, _):
                    init_script = Path(machine) / "init.sh"
                    init_script.write_text('CONTAINER_IP="10.200.1.10"\n')
                    init_script.chmod(0o644)
                    with self.up_mocks(instance, machine) as mocks, patch.object(
                        instance,
                        "_setup_port_forwarding_rules",
                        side_effect=lambda ip: events.append(f"ports {ip}"),
                    ) as publish, patch.object(sandy.os, "fchown"), patch.object(
                        instance,
                        "_is_container_running",
                        side_effect=lambda: (running if "enter" in events else None),
                    ):
                        mocks.popen.side_effect = lambda *a, **k: (
                            events.append("popen") or MagicMock()
                        )
                        with captured_output():
                            try:
                                instance.run_up(
                                    self.arguments(network="lenient", detach=True)
                                )
                            except SystemExit as exited:
                                self.assertEqual(exited.code, 1)
                self.assertEqual(events, expected)
                if running:
                    publish.assert_not_called()
                    mocks.popen.assert_not_called()

    def test_up_closes_the_pinned_supervisor(self):
        # Regression test: no test checked that up closes the pidfd of its
        # supervisor. Without -d, up goes on as the console, so the pidfd
        # would stay open for the whole session: the case without -d checks
        # that the close comes before the console attach. Mocks: the start,
        # the markers, and the console (setUp). The pin opens a directory of
        # its own, and os.close records the file that it closes: up closes
        # other descriptors first, and the pin can reuse one of their numbers.
        closed = []
        real_close = os.close

        def close(fd):
            entry = os.fstat(fd)
            closed.append((fd, (entry.st_dev, entry.st_ino)))
            real_close(fd)

        with tempfile.TemporaryDirectory() as pin_dir:
            entry = os.stat(pin_dir)
            pin_file = (entry.st_dev, entry.st_ino)

            def pin(pid):
                fd = os.open(pin_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
                pinned = sandy.PinnedSupervisor(fd, pid)
                self.pinned.append(pinned)
                return pinned

            self.pin_supervisor.side_effect = pin
            # What up had closed when the console attach started.
            at_console: list = []
            self.exec.side_effect = lambda *a, **k: at_console.append(list(closed)) or 0
            for label, marker_error, detach in (
                ("started", None, True),
                ("marker failed", OSError("no scope"), True),
                ("console", None, False),
            ):
                with self.subTest(label=label):
                    self.pinned.clear()
                    closed.clear()
                    at_console.clear()
                    self.pending_marker.side_effect = marker_error
                    instance = make_sandy()
                    with self.mount_dirs(instance) as (machine, _, _):
                        with self.up_mocks(instance, machine), patch.object(
                            sandy.os, "close", side_effect=close
                        ):
                            with captured_output():
                                try:
                                    instance.run_up(self.arguments(detach=detach))
                                except SystemExit as exited:
                                    self.assertIsNotNone(marker_error)
                                    self.assertEqual(exited.code, 1)
                    self.assertEqual(len(self.pinned), 1)
                    pinned_file = (self.pinned[0].pidfd, pin_file)
                    self.assertIn(pinned_file, closed)
                    if detach:
                        self.assertEqual(at_console, [])
                    else:
                        self.assertEqual(len(at_console), 1)
                        self.assertIn(pinned_file, at_console[0])

    def test_up_shows_its_output_before_it_waits_for_the_lock(self):
        # Regression test: "Starting", which up printed with a flush before
        # the lock, moved after the check under the lock. With stdout in a
        # file, the lines before the lock then stayed in the buffer while up
        # waited, also the line that the E2E race case waits for. Mocks: the
        # lock (setUp) and the flush of the captured stdout.
        events = self.lock_events
        instance = make_sandy()
        with self.mount_dirs(instance) as (machine, _, _):
            with self.up_mocks(instance, machine):
                with captured_output() as (stdout, _):
                    stdout.flush = lambda: events.append(
                        "flush after limits"
                        if "I: Limits of this container" in stdout.getvalue()
                        else "flush"
                    )
                    instance.run_up(self.arguments(detach=True))
        self.assertLess(
            events.index("flush after limits"), events.index("enter"), events
        )

    def test_up_without_the_lock_does_not_check_again(self):
        # up -d without directories takes no lock; it makes no marker and no
        # mount that another start's scope could get.
        instance = make_sandy()
        instance.workspace = None
        with tempfile.TemporaryDirectory() as machine:
            with self.up_mocks(instance, machine), patch.object(
                instance, "_is_container_running", return_value=None
            ) as running:
                with captured_output():
                    instance.run_up(self.arguments(detach=True))
        running.assert_called_once_with()
        self.supervisor_unit_loaded.assert_called_once_with("ai-dev")
        self.assertEqual(len(self.pinned), 1)

    def test_detached_up_without_mounts_takes_only_the_up_lock(self):
        # Regression test: up -d without directories took no lock, so a
        # second up of the name could replace and then remove its port state.
        instance = make_sandy()
        instance.workspace = None
        with tempfile.TemporaryDirectory() as machine:
            with self.up_mocks(instance, machine):
                with captured_output():
                    instance.run_up(self.arguments(detach=True))
        self.assertEqual(self.lock_events, [])
        self.ensure_cache_dir.assert_called_once_with()
        self.acquire_up_lock.assert_called_once_with("ai-dev")
        self.up_lock.close.assert_called_once_with()
        self.wait_for_mounts.assert_not_called()
        self.read_image_user_ids.assert_not_called()

    def test_no_bind_for_the_directories_on_any_systemd_version(self):
        for version, private_users in (
            (249, f"--private-users={sandy.CONTAINER_BASE_UID}:65536"),
            (255, "--private-users=pick"),
        ):
            with self.subTest(version=version):
                instance = make_sandy()
                instance.systemd_version = version
                with self.mount_dirs(instance) as (machine, _, _):
                    with self.up_mocks(instance, machine) as mocks:
                        with captured_output():
                            instance.run_up(self.arguments())
                command = self.nspawn_command(mocks.popen.call_args.args[0])
                self.assertFalse(any(item.startswith("--bind=") for item in command))
                self.assertIn(private_users, command)

    def test_a_failed_mount_stops_the_container_and_reports_the_step(self):
        message = (
            "'/srv/w' on '/home/developer/workspace': "
            "move_mount failed: Invalid argument (errno 22)"
        )
        for detach in (True, False):
            with self.subTest(detach=detach):
                instance = make_sandy()
                self.wait_for_mounts.side_effect = sandy._MountError(message)
                self.wait_for_container_ready.reset_mock()
                self.exec.reset_mock()
                with self.mount_dirs(instance) as (machine, _, _):
                    with self.up_mocks(instance, machine) as mocks:
                        with captured_output() as (stdout, _):
                            with self.assertRaises(SystemExit) as exited:
                                instance.run_up(self.arguments(detach=detach))
                self.assertEqual(exited.exception.code, 1)
                mocks.stop.assert_called_once_with(mocks.popen.return_value)
                self.wait_for_container_ready.assert_not_called()
                self.exec.assert_not_called()
                self.assertIn(f"E: Could not mount {message}\n", stdout.getvalue())

    def test_mounts_that_do_not_finish_stop_the_container(self):
        for detach in (True, False):
            with self.subTest(detach=detach):
                instance = make_sandy()
                self.wait_for_mounts.return_value = False
                self.wait_for_container_ready.reset_mock()
                self.exec.reset_mock()
                with self.mount_dirs(instance) as (machine, _, _):
                    with self.up_mocks(instance, machine) as mocks:
                        mocks.popen.return_value.poll.return_value = None
                        with captured_output() as (stdout, _):
                            with self.assertRaises(SystemExit) as exited:
                                instance.run_up(self.arguments(detach=detach))
                self.assertEqual(exited.exception.code, 1)
                mocks.stop.assert_called_once_with(mocks.popen.return_value)
                self.wait_for_container_ready.assert_not_called()
                self.exec.assert_not_called()
                self.assertIn(
                    "E: Container 'ai-dev' did not become ready\n", stdout.getvalue()
                )

    def test_a_pending_marker_failure_stops_the_container(self):
        for detach in (True, False):
            with self.subTest(detach=detach):
                instance = make_sandy()
                self.pending_marker.side_effect = TimeoutError(
                    "The container scope did not appear"
                )
                self.create_marker.reset_mock()
                self.wait_for_mounts.reset_mock()
                with self.mount_dirs(instance) as (machine, _, _):
                    with self.up_mocks(instance, machine) as mocks:
                        with captured_output() as (stdout, _):
                            with self.assertRaises(SystemExit):
                                instance.run_up(self.arguments(detach=detach))
                # No ports, so no port removal and no wait for its lock.
                mocks.stop.assert_called_once_with(
                    mocks.popen.return_value, **LOCKED_STOP
                )
                # The console marker comes after the pending marker.
                self.create_marker.assert_not_called()
                self.wait_for_mounts.assert_not_called()
                self.assertIn("did not start", stdout.getvalue())

    def test_unreadable_image_user_ends_up_before_the_network_and_the_start(self):
        instance = make_sandy()
        self.read_image_user_ids.side_effect = ValueError(
            "Container user must have exactly one passwd entry"
        )
        with self.mount_dirs(instance) as (machine, _, _):
            with self.up_mocks(instance, machine) as mocks:
                with patch.object(sandy, "SandyNet") as network:
                    with captured_output() as (stdout, _):
                        with self.assertRaises(SystemExit) as exited:
                            instance.run_up(self.arguments(network="lenient"))
        self.assertEqual(exited.exception.code, 1)
        self.assertIn(
            "E: Could not read the uid and gid of 'developer' in the container "
            "image: ",
            stdout.getvalue(),
        )
        network.assert_not_called()
        mocks.popen.assert_not_called()
        self.assertEqual(self.lock_events, [])

    def test_build_and_missing_machine_are_reported(self):
        instance = make_sandy()
        with patch.object(instance, "_is_container_running", return_value=None):
            with patch.object(instance, "_remove_port_mappings_from_state"):
                with patch.object(instance, "_build") as build:
                    with patch.object(
                        instance,
                        "_get_machine_dir",
                        return_value="/missing",
                    ):
                        with patch.object(
                            sandy.os.path,
                            "exists",
                            return_value=False,
                        ):
                            with captured_output():
                                with self.assertRaises(SystemExit):
                                    instance.run_up(self.arguments(build=True))
        build.assert_called_once_with(None)

    def test_lenient_build_plans_network_and_configures_after_validation(self):
        instance = make_sandy()
        instance.workspace = None
        configured = make_network()
        planned = ("10.200.1.0", "10.200.1.0/24", "10.200.1.1")
        guest_network = ("10.200.1.0/24", "10.200.1.1")
        with tempfile.TemporaryDirectory() as temp_dir:
            machine = Path(temp_dir) / "machine"

            def build(planned_guest_network):
                self.assertIsNone(instance.network)
                self.assertEqual(planned_guest_network, guest_network)
                machine.mkdir()

            with patch.object(instance, "_is_container_running", return_value=None):
                with patch.object(instance, "_remove_port_mappings_from_state"):
                    with patch.object(
                        sandy,
                        "SandyNet",
                        return_value=configured,
                    ) as network_type:
                        network_type.preview_bridge_network.return_value = (
                            guest_network,
                            planned,
                        )
                        with patch.object(
                            instance, "_build", side_effect=build
                        ) as build:
                            with patch.object(
                                instance,
                                "_get_machine_dir",
                                return_value=str(machine),
                            ):
                                with patch.object(
                                    sandy, "_run_secure_subprocess_popen"
                                ):
                                    with patch.object(
                                        instance,
                                        "_run_init_script",
                                        return_value=False,
                                    ):
                                        with captured_output():
                                            instance.run_up(
                                                self.arguments(
                                                    build=True,
                                                    network="lenient",
                                                )
                                            )

        network_type.preview_bridge_network.assert_called_once_with()
        network_type.assert_called_once_with(planned)
        build.assert_called_once_with(guest_network)

    def test_lenient_build_existing_unsafe_image_rejects_before_network(self):
        instance = make_sandy()
        instance.workspace = None
        with tempfile.TemporaryDirectory() as temp_dir:
            machine = Path(temp_dir) / "machine"
            machine.mkdir()
            with patch.object(instance, "_is_container_running", return_value=None):
                with patch.object(
                    instance,
                    "_get_machine_dir",
                    return_value=str(machine),
                ):
                    with patch.object(
                        sandy,
                        "_open_verified_dir",
                        side_effect=PermissionError("unsafe image"),
                    ):
                        with patch.object(sandy, "SandyNet") as network_type:
                            with patch.object(
                                sandy,
                                "_run_secure_subprocess_popen",
                            ) as popen:
                                with captured_output() as (stdout, _):
                                    with self.assertRaises(SystemExit):
                                        instance.run_up(
                                            self.arguments(
                                                build=True,
                                                network="lenient",
                                            )
                                        )

        network_type.assert_not_called()
        popen.assert_not_called()
        self.assertIn("Unsafe machine image", stdout.getvalue())

    def test_rejects_unsafe_machine_image_before_start(self):
        instance = make_sandy()
        instance.workspace = None
        with patch.object(instance, "_is_container_running", return_value=None):
            with patch.object(instance, "_remove_port_mappings_from_state"):
                with patch.object(
                    instance,
                    "_get_machine_dir",
                    return_value="/var/lib/machines/sandy.ai-dev",
                ):
                    with patch.object(
                        sandy,
                        "_open_verified_dir",
                        side_effect=PermissionError(
                            "Machine image symlink targets the managed root"
                        ),
                    ):
                        with patch.object(
                            sandy,
                            "_run_secure_subprocess_popen",
                        ) as popen:
                            with captured_output() as (stdout, _):
                                with self.assertRaises(SystemExit):
                                    instance.run_up(self.arguments())

        popen.assert_not_called()
        self.assertIn("Unsafe machine image", stdout.getvalue())

    def test_rejects_init_script_symlink_before_start(self):
        instance = make_sandy()
        instance.workspace = None
        with tempfile.TemporaryDirectory() as temp_dir:
            machine = Path(temp_dir)
            (machine / "init.sh").symlink_to("/etc/passwd")
            with patch.object(instance, "_is_container_running", return_value=None):
                with patch.object(instance, "_remove_port_mappings_from_state"):
                    with patch.object(
                        instance,
                        "_get_machine_dir",
                        return_value=str(machine),
                    ):
                        with patch.object(
                            sandy,
                            "_run_secure_subprocess_popen",
                        ) as popen:
                            with captured_output() as (stdout, _):
                                with self.assertRaises(SystemExit):
                                    instance.run_up(self.arguments())

        popen.assert_not_called()
        self.assertIn("Unsafe machine image /init.sh", stdout.getvalue())

    def test_rejects_invalid_init_content_before_network_setup(self):
        instance = make_sandy()
        instance.workspace = None
        args = self.arguments(network="lenient")
        with tempfile.TemporaryDirectory() as temp_dir:
            machine = Path(temp_dir)
            init_script = machine / "init.sh"
            init_script.write_text('CONTAINER_IP="999.1.1.1"\n', encoding="utf-8")
            init_script.chmod(0o644)
            with patch.object(instance, "_is_container_running", return_value=None):
                with patch.object(
                    instance,
                    "_get_machine_dir",
                    return_value=str(machine),
                ):
                    with patch.object(
                        sandy.SandyNet,
                        "preview_bridge_network",
                    ) as preview:
                        with patch.object(
                            sandy.SandyNet,
                            "__init__",
                            return_value=None,
                        ) as network_init:
                            with patch.object(
                                sandy,
                                "_run_secure_subprocess_popen",
                            ) as popen:
                                with captured_output() as (stdout, _):
                                    with self.assertRaises(SystemExit):
                                        instance.run_up(args)

        preview.assert_not_called()
        network_init.assert_not_called()
        popen.assert_not_called()
        self.assertIn("Unsafe machine image /init.sh", stdout.getvalue())

    def test_rejects_out_of_network_init_before_network_setup(self):
        instance = make_sandy()
        instance.workspace = None
        args = self.arguments(network="lenient")
        planned_network = ("10.200.1.0", "10.200.1.0/24", "10.200.1.1")
        with tempfile.TemporaryDirectory() as temp_dir:
            machine = Path(temp_dir)
            init_script = machine / "init.sh"
            init_script.write_text('CONTAINER_IP="10.20.30.10"\n', encoding="utf-8")
            init_script.chmod(0o644)
            with patch.object(instance, "_is_container_running", return_value=None):
                with patch.object(
                    instance,
                    "_get_machine_dir",
                    return_value=str(machine),
                ):
                    with patch.object(
                        sandy.SandyNet,
                        "preview_bridge_network",
                        return_value=(("10.200.1.0/24", "10.200.1.1"), planned_network),
                    ) as preview:
                        with patch.object(
                            sandy.SandyNet,
                            "__init__",
                            return_value=None,
                        ) as network_init:
                            with patch.object(
                                sandy,
                                "_run_secure_subprocess_popen",
                            ) as popen:
                                with captured_output() as (stdout, _):
                                    with self.assertRaises(SystemExit):
                                        instance.run_up(args)

        preview.assert_called_once_with()
        network_init.assert_not_called()
        popen.assert_not_called()
        self.assertIn("outside the Sandy network", stdout.getvalue())

    def test_rejects_invalid_init_ip_before_port_forwarding_setup(self):
        instance = make_sandy()
        instance.workspace = None
        instance.network = make_network()
        args = self.arguments(
            network="lenient",
            ports=["tcp:8080:80"],
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            machine = Path(temp_dir)
            init_script = machine / "init.sh"
            init_script.write_text('CONTAINER_IP="10.20.30.10"\n', encoding="utf-8")
            init_script.chmod(0o644)
            with patch.object(instance, "_is_container_running", return_value=None):
                with patch.object(
                    instance,
                    "_get_machine_dir",
                    return_value=str(machine),
                ):
                    with patch.object(
                        instance,
                        "_setup_port_forwarding_rules",
                    ) as setup_forwarding:
                        with patch.object(
                            sandy,
                            "_run_secure_subprocess_popen",
                        ) as popen:
                            with captured_output() as (stdout, _):
                                with self.assertRaises(SystemExit):
                                    instance.run_up(args)

        setup_forwarding.assert_not_called()
        popen.assert_not_called()
        self.assertIn("Unsafe machine image /init.sh", stdout.getvalue())

    def test_lenient_network_is_constructed_and_detach_waits(self):
        instance = make_sandy()
        instance.workspace = None
        configured = make_network()
        with tempfile.TemporaryDirectory() as machine:
            with patch.object(instance, "_is_container_running", return_value=None):
                with patch.object(instance, "_remove_port_mappings_from_state"):
                    with patch.object(
                        sandy,
                        "SandyNet",
                        return_value=configured,
                    ) as network_type:
                        with patch.object(
                            instance,
                            "_get_machine_dir",
                            return_value=machine,
                        ):
                            with patch.object(
                                sandy,
                                "_run_secure_subprocess_popen",
                            ):
                                with patch.object(
                                    instance,
                                    "_run_init_script",
                                    return_value=True,
                                ):
                                    with captured_output() as (stdout, _):
                                        instance.run_up(
                                            self.arguments(network="lenient")
                                        )
        network_type.assert_called_once_with()
        self.assertIn(" done", stdout.getvalue())

    def test_host_network_ignores_preexisting_network_object(self):
        instance = make_sandy()
        instance.workspace = None
        instance.network = make_network()
        with tempfile.TemporaryDirectory() as machine:
            with patch.object(instance, "_is_container_running", return_value=None):
                with patch.object(instance, "_remove_port_mappings_from_state"):
                    with patch.object(
                        instance,
                        "_get_machine_dir",
                        return_value=machine,
                    ):
                        with patch.object(
                            sandy,
                            "_run_secure_subprocess_popen",
                        ):
                            with patch.object(
                                instance,
                                "_run_init_script",
                                return_value=False,
                            ):
                                with captured_output() as (stdout, _):
                                    instance.run_up(self.arguments())
        self.assertIn("ignoring existing bridge", stdout.getvalue())


class KeepaliveTests(unittest.TestCase):
    """The keepalive payload files on the host.

    Tests use real files in a private temporary directory. E2E tests must
    prove that nspawn binds them and that the payload runs.
    """

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        # Keep every keepalive directory of a test in its own tempdir.
        patcher = patch.object(
            sandy.tempfile, "gettempdir", return_value=self.tempdir.name
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = patch.object(sandy.tempfile, "tempdir", self.tempdir.name)
        patcher.start()
        self.addCleanup(patcher.stop)

    def write_script(self, content, mode=0o755):
        path = Path(self.tempdir.name) / "sandy-keepalive.sh"
        path.write_bytes(content)
        path.chmod(mode)
        return str(path)

    def test_read_keepalive_script_returns_the_repository_script(self):
        content = (PROJECT_DIR / "sandy-keepalive.sh").read_bytes()
        self.assertEqual(
            sandy._read_keepalive_script(self.write_script(content)), content
        )

    def test_read_keepalive_script_rejects_unsafe_scripts(self):
        cases = {
            "group-writable": (b"#!/bin/bash\n", 0o775),
            "world-writable": (b"#!/bin/bash\n", 0o757),
            "empty": (b"", 0o755),
            "too large": (b"#" * (sandy.KEEPALIVE_SCRIPT_MAX_BYTES + 1), 0o755),
            "not ASCII": ("# é\n".encode("utf-8"), 0o755),
            "NUL": (b"#!/bin/bash\n\x00", 0o755),
        }
        for label, (content, mode) in cases.items():
            with self.subTest(label=label):
                path = self.write_script(content, mode)
                with self.assertRaises(PermissionError):
                    sandy._read_keepalive_script(path)

    def test_read_keepalive_script_rejects_symlink_and_directory(self):
        target = self.write_script(b"#!/bin/bash\n")
        link = os.path.join(self.tempdir.name, "link.sh")
        os.symlink(target, link)
        with self.assertRaises(OSError):
            sandy._read_keepalive_script(link)
        with self.assertRaises(PermissionError):
            sandy._read_keepalive_script(self.tempdir.name)

    def test_create_keepalive_dir_holds_exactly_link_and_copy(self):
        directory = sandy._create_keepalive_dir(b"script\n")
        self.assertTrue(
            os.path.basename(directory).startswith(sandy.KEEPALIVE_DIR_PREFIX)
        )
        self.assertEqual(os.path.dirname(directory), self.tempdir.name)
        self.assertEqual(stat.S_IMODE(os.lstat(directory).st_mode), 0o755)
        self.assertEqual(
            sorted(os.listdir(directory)), ["keepalive.sh", "sandy-keepalive"]
        )
        link = os.path.join(directory, "sandy-keepalive")
        self.assertTrue(os.path.islink(link))
        self.assertEqual(os.readlink(link), "/bin/bash")
        copy = os.path.join(directory, "keepalive.sh")
        self.assertEqual(stat.S_IMODE(os.lstat(copy).st_mode), 0o644)
        self.assertEqual(Path(copy).read_bytes(), b"script\n")

    def test_create_keepalive_dir_removes_partial_directory(self):
        with patch.object(sandy.os, "write", return_value=0):
            with self.assertRaisesRegex(OSError, "no progress"):
                sandy._create_keepalive_dir(b"script\n")
        self.assertEqual(os.listdir(self.tempdir.name), [])

    def test_remove_keepalive_dir_removes_exact_entries(self):
        directory = sandy._create_keepalive_dir(b"script\n")
        sandy._remove_keepalive_dir(directory)
        self.assertFalse(os.path.lexists(directory))

    def test_remove_keepalive_dir_rejects_unexpected_paths(self):
        other = os.path.join(self.tempdir.name, "other-dir")
        os.mkdir(other)
        for path in (
            other,
            "/etc/sandy-keepalive-x",
            os.path.join(other, sandy.KEEPALIVE_DIR_PREFIX + "x"),
        ):
            with self.subTest(path=path):
                with self.assertRaisesRegex(PermissionError, "unexpected"):
                    sandy._remove_keepalive_dir(path)
        self.assertTrue(os.path.isdir(other))

    def test_remove_keepalive_dir_keeps_unexpected_entries(self):
        directory = sandy._create_keepalive_dir(b"script\n")
        extra = os.path.join(directory, "extra")
        Path(extra).write_text("x")
        with self.assertRaisesRegex(PermissionError, "unexpected entries"):
            sandy._remove_keepalive_dir(directory)
        self.assertTrue(os.path.exists(extra))
        self.assertTrue(os.path.lexists(os.path.join(directory, "sandy-keepalive")))

    def test_remove_keepalive_dir_rejects_unsafe_directory(self):
        directory = sandy._create_keepalive_dir(b"script\n")
        os.chmod(directory, 0o775)
        with self.assertRaisesRegex(PermissionError, "unsafe permissions"):
            sandy._remove_keepalive_dir(directory)
        os.chmod(directory, 0o755)
        with patch.object(sandy.os, "geteuid", return_value=12345):
            with self.assertRaisesRegex(PermissionError, "ownership"):
                sandy._remove_keepalive_dir(directory)
        link = os.path.join(self.tempdir.name, sandy.KEEPALIVE_DIR_PREFIX + "link")
        os.symlink(directory, link)
        with self.assertRaises(OSError):
            sandy._remove_keepalive_dir(link)
        self.assertTrue(os.path.isdir(directory))


class SupervisorScopeTests(unittest.TestCase):
    """The transient scope that runs nspawn.

    Tests mock _run_secure_subprocess. E2E tests must prove the unit layout
    and its properties on each systemd version.
    """

    def test_unit_name_and_description(self):
        self.assertEqual(sandy._supervisor_unit_name("ai-dev"), "sandy-ai-dev.scope")
        for name in ("", "Ai", "-x", "a" * 64, "a.b", "a/b"):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    sandy._supervisor_unit_name(name)
        self.assertEqual(
            sandy._supervisor_description("ai-dev", True),
            "Sandy container ai-dev (detached)",
        )
        self.assertEqual(
            sandy._supervisor_description("ai-dev", False),
            "Sandy container ai-dev (attached)",
        )

    def test_scope_argv_sets_oom_policy_only_from_systemd_253(self):
        prefix = [
            "systemd-run",
            "--scope",
            "--quiet",
            "--unit=sandy-ai-dev.scope",
            "--slice=sandy.slice",
            "--description=Sandy container ai-dev (attached)",
            "--property=Delegate=yes",
        ]
        limits = sandy.ResourceLimits(16384, 512 * MIB, -500)
        suffix = [
            "--property=TasksMax=16384",
            "--property=MemorySwapMax=0",
            "--",
        ]
        for version in (249, 252):
            with self.subTest(version=version):
                self.assertEqual(
                    sandy._supervisor_scope_argv("ai-dev", version, False, limits),
                    prefix + suffix,
                )
        for version in (253, 257):
            with self.subTest(version=version):
                self.assertEqual(
                    sandy._supervisor_scope_argv("ai-dev", version, False, limits),
                    prefix + ["--property=OOMPolicy=continue"] + suffix,
                )
        with self.assertRaises(ValueError):
            sandy._supervisor_scope_argv("Bad", 255, False, limits)

    def test_systemctl_show_value_runs_exact_command(self):
        result = SimpleNamespace(stdout="loaded\n")
        with patch.object(sandy, "_run_secure_subprocess", return_value=result) as run:
            self.assertEqual(
                sandy._systemctl_show_value("sandy-x.scope", "LoadState"), "loaded"
            )
        run.assert_called_once_with(
            ["systemctl", "show", "sandy-x.scope", "-p", "LoadState", "--value"],
            capture_output=True,
            text=True,
            check=True,
            timeout=sandy.QUERY_COMMAND_TIMEOUT,
        )

    def test_systemctl_show_value_rejects_malformed_output(self):
        for output in (
            "a\nb\n",
            "a\x1b[0m\n",
            "x" * (sandy.SYSTEMCTL_VALUE_MAX_LENGTH + 1),
        ):
            with self.subTest(output=output[:10]):
                with patch.object(
                    sandy,
                    "_run_secure_subprocess",
                    return_value=SimpleNamespace(stdout=output),
                ):
                    with self.assertRaises(ValueError):
                        sandy._systemctl_show_value("u.scope", "LoadState")
        error = subprocess.CalledProcessError(1, ["systemctl"])
        with patch.object(sandy, "_run_secure_subprocess", side_effect=error):
            with self.assertRaises(subprocess.CalledProcessError):
                sandy._systemctl_show_value("u.scope", "LoadState")

    def test_unit_loaded_states(self):
        for value, expected in (
            ("not-found", False),
            ("loaded", True),
            ("masked", True),
            ("bad-setting", True),
        ):
            with self.subTest(value=value):
                with patch.object(
                    sandy, "_systemctl_show_value", return_value=value
                ) as show:
                    self.assertIs(sandy._supervisor_unit_loaded("ai-dev"), expected)
                    self.assertIs(
                        sandy._supervisor_unit_loaded("ai-dev", timeout=0.5), expected
                    )
                self.assertEqual(
                    show.call_args_list,
                    [
                        call(
                            "sandy-ai-dev.scope",
                            "LoadState",
                            timeout=sandy.QUERY_COMMAND_TIMEOUT,
                        ),
                        call("sandy-ai-dev.scope", "LoadState", timeout=0.5),
                    ],
                )
        for value in ("", "Loaded", "not found", "x" * 40):
            with self.subTest(value=value):
                with patch.object(sandy, "_systemctl_show_value", return_value=value):
                    with self.assertRaises(ValueError):
                        sandy._supervisor_unit_loaded("ai-dev")


class StartFailureTests(unittest.TestCase):
    """What up does when the started container does not become ready.

    Tests mock the supervisor process, the readiness probe, and the port
    cleanup.
    """

    def test_wait_for_container_ready_stops_when_supervisor_exits(self):
        instance = make_sandy()
        supervisor = MagicMock()
        supervisor.poll.return_value = 127
        with patch.object(instance, "_run_as_root") as run_as_root:
            self.assertFalse(instance._wait_for_container_ready(supervisor=supervisor))
        run_as_root.assert_not_called()

    def test_report_failed_start_reports_exit_status(self):
        instance = make_sandy()
        supervisor = MagicMock()
        supervisor.poll.return_value = 127
        with captured_output() as (stdout, _):
            instance._report_failed_start(supervisor)
        self.assertIn("exited before it was ready (exit status 127)", stdout.getvalue())
        self.assertIn("/bin/bash and 'sleep'", stdout.getvalue())
        supervisor.poll.return_value = None
        with captured_output() as (stdout, _):
            instance._report_failed_start(supervisor)
        self.assertIn("did not become ready", stdout.getvalue())

    def test_stop_failed_start_terminates_then_removes_port_rules(self):
        instance = make_sandy()
        manager = MagicMock()
        manager.supervisor.poll.return_value = None
        with patch.object(
            instance, "_cleanup_port_mappings_for_container", manager.cleanup
        ):
            instance._stop_failed_start(manager.supervisor)
        self.assertEqual(
            manager.mock_calls,
            [
                call.supervisor.poll(),
                call.supervisor.terminate(),
                call.supervisor.wait(timeout=sandy.CONTAINER_STOP_TIMEOUT),
                call.cleanup("ai-dev"),
            ],
        )

    def test_stop_failed_start_kills_after_timeout(self):
        instance = make_sandy()
        manager = MagicMock()
        manager.supervisor.poll.return_value = None
        manager.supervisor.wait.side_effect = [
            subprocess.TimeoutExpired(["systemd-run"], 30),
            0,
        ]
        with patch.object(
            instance, "_cleanup_port_mappings_for_container", manager.cleanup
        ):
            instance._stop_failed_start(manager.supervisor)
        self.assertEqual(
            manager.mock_calls[1:],
            [
                call.supervisor.terminate(),
                call.supervisor.wait(timeout=sandy.CONTAINER_STOP_TIMEOUT),
                call.supervisor.kill(),
                call.supervisor.wait(timeout=sandy.CONTAINER_POWEROFF_TIMEOUT),
                call.cleanup("ai-dev"),
            ],
        )

    def test_stop_failed_start_gives_up_after_its_timeouts(self):
        # Regression test: after SIGKILL, the stop waited with no limit, and
        # the stop after a failed pin or marker waited up to 30 s under the
        # lifecycle lock. Mocks: the supervisor, which does not end, and the
        # port cleanup.
        instance = make_sandy()
        manager = MagicMock()
        manager.supervisor.pid = 4242
        manager.supervisor.poll.return_value = None
        manager.supervisor.wait.side_effect = subprocess.TimeoutExpired(
            ["systemd-run"], 2.5
        )
        with patch.object(
            instance, "_cleanup_port_mappings_for_container", manager.cleanup
        ):
            with captured_output() as (stdout, _):
                instance._stop_failed_start(manager.supervisor, **LOCKED_STOP)
        self.assertEqual(
            manager.mock_calls[1:],
            [
                call.supervisor.terminate(),
                call.supervisor.wait(timeout=sandy.CONTAINER_POWEROFF_TIMEOUT / 2),
                call.supervisor.kill(),
                call.supervisor.wait(timeout=sandy.CONTAINER_POWEROFF_TIMEOUT / 2),
            ],
        )
        self.assertEqual(
            stdout.getvalue(),
            "W: The supervisor of 'ai-dev' did not stop (PID 4242)\n",
        )

    def test_stop_failed_start_can_leave_the_ports(self):
        # A caller that removed the ports in the hold of the publish stops the
        # supervisor after the release. Mocks: the supervisor and the cleanup.
        instance = make_sandy()
        manager = MagicMock()
        manager.supervisor.poll.return_value = None
        with patch.object(
            instance, "_cleanup_port_mappings_for_container", manager.cleanup
        ):
            instance._stop_failed_start(manager.supervisor, remove_ports=False)
        manager.cleanup.assert_not_called()
        manager.supervisor.terminate.assert_called_once_with()

    def test_stop_failed_start_skips_exited_supervisor(self):
        instance = make_sandy()
        supervisor = MagicMock()
        supervisor.poll.return_value = 1
        with patch.object(instance, "_cleanup_port_mappings_for_container") as clean:
            instance._stop_failed_start(supervisor)
        supervisor.terminate.assert_not_called()
        clean.assert_called_once_with("ai-dev")


class AttachCgroupTests(unittest.TestCase):
    """Attach leaf cgroups in the container's scope.

    Tests use plain directories and regular files in place of cgroupfs, and
    mock the checks that need root. E2E tests must prove the real cgroup
    moves, cgroup.kill, and removal.
    """

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.root = Path(self.tempdir.name)
        self.unit = self.root / "sandy.slice" / "sandy-ai-dev.scope"
        self.unit.mkdir(parents=True)

    def fake_leaf(self, name=ATTACH_LEAF, events="populated 0\nfrozen 0\n"):
        leaf = self.unit / name
        leaf.mkdir()
        for filename in ("cgroup.kill", "cgroup.procs"):
            (leaf / filename).write_bytes(b"")
        (leaf / "cgroup.events").write_text(events)
        return leaf

    def root_fstat(self):
        """Report every directory as owned by root, as on cgroupfs."""
        real_fstat = os.fstat

        def fstat(fd):
            result = real_fstat(fd)
            return SimpleNamespace(st_uid=0, st_dev=result.st_dev)

        return patch.object(sandy.os, "fstat", side_effect=fstat)

    def open_unit(self):
        return os.open(self.unit, sandy.DIRECTORY_OPEN_FLAGS)

    def test_read_process_cgroup(self):
        proc = self.root / "proc"
        proc.mkdir()
        cases = {
            "0::/sandy.slice/sandy-ai-dev.scope/payload\n": (
                "/sandy.slice/sandy-ai-dev.scope/payload"
            ),
            "0::/\n": "/",
        }
        proc_fd = os.open(proc, sandy.DIRECTORY_OPEN_FLAGS)
        self.addCleanup(os.close, proc_fd)
        for text, expected in cases.items():
            with self.subTest(text=text):
                (proc / "cgroup").write_text(text)
                self.assertEqual(sandy._read_process_cgroup(proc_fd), expected)
        for text in (
            "",
            "0::/a",
            "0::relative\n",
            "1:name=systemd:/a\n0::/a\n",
            "0::/a\n0::/b\n",
            "0::/" + "a" * sandy.PROC_CGROUP_MAX_BYTES + "\n",
        ):
            with self.subTest(text=text[:30]):
                (proc / "cgroup").write_text(text)
                with self.assertRaisesRegex(ValueError, "cgroup v2"):
                    sandy._read_process_cgroup(proc_fd)

    def test_open_supervisor_cgroup_walks_without_symlinks(self):
        with patch.object(sandy, "CGROUP_ROOT", str(self.root)), self.root_fstat():
            fd = sandy._open_supervisor_cgroup("ai-dev")
        try:
            self.assertTrue(os.path.samestat(os.fstat(fd), self.unit.stat()))
        finally:
            os.close(fd)

        with patch.object(sandy, "CGROUP_ROOT", str(self.root)), self.root_fstat():
            with self.assertRaises(FileNotFoundError):
                sandy._open_supervisor_cgroup("other")
        with patch.object(sandy, "CGROUP_ROOT", str(self.root)):
            with self.assertRaises(ValueError):
                sandy._open_supervisor_cgroup("Bad")
            # Not owned by root: this test does not run as root.
            if os.geteuid() != 0:
                with self.assertRaisesRegex(PermissionError, "Unexpected cgroup"):
                    sandy._open_supervisor_cgroup("ai-dev")

        link_root = self.root / "link-root"
        (link_root / "sandy.slice").mkdir(parents=True)
        (link_root / "sandy.slice" / "sandy-ai-dev.scope").symlink_to(self.unit)
        with patch.object(sandy, "CGROUP_ROOT", str(link_root)), self.root_fstat():
            with self.assertRaises(OSError):
                sandy._open_supervisor_cgroup("ai-dev")

    def test_open_supervisor_cgroup_rejects_other_filesystem(self):
        real_fstat = os.fstat
        devices = iter((1, 2))

        def fstat(fd):
            _ = real_fstat(fd)
            return SimpleNamespace(st_uid=0, st_dev=next(devices))

        with patch.object(sandy, "CGROUP_ROOT", str(self.root)), patch.object(
            sandy.os, "fstat", side_effect=fstat
        ), patch.object(sandy.os, "close", wraps=os.close) as close:
            with self.assertRaisesRegex(PermissionError, "sandy.slice"):
                sandy._open_supervisor_cgroup("ai-dev")
        # The root and the slice descriptors are closed.
        self.assertEqual(close.call_count, 2)

    def test_cgroup_populated(self):
        leaf = self.fake_leaf()
        leaf_fd = os.open(leaf, sandy.DIRECTORY_OPEN_FLAGS)
        self.addCleanup(os.close, leaf_fd)
        for text, expected in (
            ("populated 0\nfrozen 0\n", False),
            ("populated 1\nfrozen 0\n", True),
        ):
            with self.subTest(text=text):
                (leaf / "cgroup.events").write_text(text)
                self.assertIs(sandy._cgroup_populated(leaf_fd), expected)
        for text in (
            "",
            "frozen 0\n",
            "populated 2\n",
            "populated 0\npopulated 1\n",
            "populated\n",
            "populated 0\n" + "x" * sandy.CGROUP_EVENTS_MAX_BYTES,
        ):
            with self.subTest(text=text[:20]):
                (leaf / "cgroup.events").write_text(text)
                with self.assertRaisesRegex(ValueError, "cgroup.events"):
                    sandy._cgroup_populated(leaf_fd)

    def test_write_cgroup_file_rejects_short_write(self):
        leaf = self.fake_leaf()
        leaf_fd = os.open(leaf, sandy.DIRECTORY_OPEN_FLAGS)
        self.addCleanup(os.close, leaf_fd)
        sandy._write_cgroup_file(leaf_fd, "cgroup.kill", b"1")
        self.assertEqual((leaf / "cgroup.kill").read_bytes(), b"1")
        with patch.object(sandy.os, "write", return_value=0):
            with self.assertRaisesRegex(OSError, "Short write"):
                sandy._write_cgroup_file(leaf_fd, "cgroup.kill", b"1")
        with self.assertRaises(FileNotFoundError):
            sandy._write_cgroup_file(leaf_fd, "cgroup.missing", b"1")

    def test_join_attach_leaf_creates_leaf_and_moves_this_process(self):
        real_mkdir = os.mkdir

        def mkdir(name, mode, dir_fd):
            real_mkdir(name, mode, dir_fd=dir_fd)
            for filename in ("cgroup.kill", "cgroup.procs"):
                (self.unit / name / filename).write_bytes(b"")

        with patch.object(
            sandy, "_open_supervisor_cgroup", side_effect=lambda _: self.open_unit()
        ), patch.object(sandy.os, "mkdir", side_effect=mkdir) as make:
            kill_fd = sandy._join_attach_leaf("ai-dev", ATTACH_LEAF)
        try:
            self.assertEqual(make.call_args.args[:2], (ATTACH_LEAF, 0o755))
            self.assertEqual(
                (self.unit / ATTACH_LEAF / "cgroup.procs").read_bytes(), b"0"
            )
            os.write(kill_fd, b"1")
            self.assertEqual(
                (self.unit / ATTACH_LEAF / "cgroup.kill").read_bytes(), b"1"
            )
            self.assertFalse(os.get_inheritable(kill_fd))
        finally:
            os.close(kill_fd)

    def test_join_attach_leaf_removes_leaf_when_move_fails(self):
        real_mkdir = os.mkdir

        def mkdir(name, mode, dir_fd):
            real_mkdir(name, mode, dir_fd=dir_fd)
            (self.unit / name / "cgroup.kill").write_bytes(b"")

        with patch.object(
            sandy, "_open_supervisor_cgroup", side_effect=lambda _: self.open_unit()
        ), patch.object(sandy.os, "mkdir", side_effect=mkdir):
            with patch.object(sandy.os, "rmdir", wraps=os.rmdir) as rmdir:
                with self.assertRaises(FileNotFoundError):
                    sandy._join_attach_leaf("ai-dev", ATTACH_LEAF)
        # The fake leaf still holds a file, so the rmdir fails; it is tried.
        rmdir.assert_called_once_with(ATTACH_LEAF, dir_fd=ANY)

    def test_join_attach_leaf_rejects_existing_leaf_and_bad_names(self):
        self.fake_leaf()
        with patch.object(
            sandy, "_open_supervisor_cgroup", side_effect=lambda _: self.open_unit()
        ):
            with self.assertRaises(FileExistsError):
                sandy._join_attach_leaf("ai-dev", ATTACH_LEAF)
            for leaf in ("payload", "attach-", "../attach-" + "0" * 32):
                with self.subTest(leaf=leaf):
                    with self.assertRaises(ValueError):
                        sandy._join_attach_leaf("ai-dev", leaf)
        self.assertEqual((self.unit / ATTACH_LEAF / "cgroup.procs").read_bytes(), b"")

    def test_end_attach_leaf_kills_waits_and_removes(self):
        leaf = self.fake_leaf(events="populated 1\n")
        polls = []

        def sleep(_seconds):
            polls.append(_seconds)
            (leaf / "cgroup.events").write_text("populated 0\n")

        unit_fd = self.open_unit()
        self.addCleanup(os.close, unit_fd)
        with patch.object(sandy.time, "sleep", side_effect=sleep), patch.object(
            sandy.os, "rmdir"
        ) as rmdir:
            sandy._end_attach_leaf(unit_fd, ATTACH_LEAF)
        self.assertEqual((leaf / "cgroup.kill").read_bytes(), b"1")
        self.assertEqual(polls, [sandy.ATTACH_LEAF_POLL_INTERVAL])
        rmdir.assert_called_once_with(ATTACH_LEAF, dir_fd=unit_fd)

    def test_end_attach_leaf_is_idempotent_and_times_out(self):
        unit_fd = self.open_unit()
        self.addCleanup(os.close, unit_fd)
        with patch.object(sandy.os, "rmdir") as rmdir:
            sandy._end_attach_leaf(unit_fd, ATTACH_LEAF)
        rmdir.assert_not_called()

        self.fake_leaf(events="populated 1\n")
        with patch.object(
            sandy.time, "monotonic", side_effect=[0, 0, 10]
        ), patch.object(sandy.time, "sleep"), patch.object(sandy.os, "rmdir") as rmdir:
            with self.assertRaisesRegex(TimeoutError, "did not become empty"):
                sandy._end_attach_leaf(unit_fd, ATTACH_LEAF)
        rmdir.assert_not_called()

        (self.unit / ATTACH_LEAF / "cgroup.events").write_text("populated 0\n")
        with patch.object(sandy.os, "rmdir", side_effect=FileNotFoundError):
            sandy._end_attach_leaf(unit_fd, ATTACH_LEAF)
        with patch.object(sandy.os, "rmdir", side_effect=OSError(errno.EBUSY, "x")):
            with self.assertRaises(OSError):
                sandy._end_attach_leaf(unit_fd, ATTACH_LEAF)
        with self.assertRaises(ValueError):
            sandy._end_attach_leaf(unit_fd, "payload")

    def test_end_attach_leaf_accepts_leaf_removed_meanwhile(self):
        # Regression: the last-session count of another attach removes an
        # empty leaf while its owner is still in cleanup (measured on 249).
        leaf = self.fake_leaf()
        unit_fd = self.open_unit()
        self.addCleanup(os.close, unit_fd)
        (leaf / "cgroup.kill").unlink()
        with patch.object(sandy.os, "rmdir") as rmdir:
            sandy._end_attach_leaf(unit_fd, ATTACH_LEAF)
        rmdir.assert_not_called()
        (leaf / "cgroup.kill").write_bytes(b"")
        (leaf / "cgroup.events").unlink()
        with patch.object(sandy.os, "rmdir") as rmdir:
            sandy._end_attach_leaf(unit_fd, ATTACH_LEAF)
        rmdir.assert_not_called()

    def test_remove_attach_leaf_skips_missing_scope(self):
        with patch.object(
            sandy, "_open_supervisor_cgroup", side_effect=FileNotFoundError
        ), patch.object(sandy, "_end_attach_leaf") as end:
            sandy._remove_attach_leaf("ai-dev", ATTACH_LEAF)
        end.assert_not_called()

        unit_fd = self.open_unit()
        with patch.object(
            sandy, "_open_supervisor_cgroup", return_value=unit_fd
        ), patch.object(
            sandy, "_end_attach_leaf", side_effect=TimeoutError("busy")
        ) as end, patch.object(
            sandy.os, "close", wraps=os.close
        ) as close:
            with self.assertRaises(TimeoutError):
                sandy._remove_attach_leaf("ai-dev", ATTACH_LEAF)
        end.assert_called_once_with(unit_fd, ATTACH_LEAF)
        close.assert_called_once_with(unit_fd)

    def test_up_console_marker_lifecycle(self):
        unit_fd = self.open_unit()
        self.addCleanup(os.close, unit_fd)
        self.assertFalse(sandy._up_console_marker_exists(unit_fd))
        # Mocks: the check that the scope holds the supervisor of this up.
        with patch.object(
            sandy, "_open_supervisor_cgroup", side_effect=lambda _: self.open_unit()
        ), patch.object(sandy, "_supervisor_in_scope", return_value=True):
            sandy._create_up_console_marker("ai-dev", PINNED_SUPERVISOR)
            # Creating it twice is not an error.
            sandy._create_up_console_marker("ai-dev", PINNED_SUPERVISOR)
        self.assertTrue((self.unit / "up-console").is_dir())
        self.assertTrue(sandy._up_console_marker_exists(unit_fd))
        sandy._remove_up_console_marker(unit_fd)
        sandy._remove_up_console_marker(unit_fd)
        self.assertFalse(sandy._up_console_marker_exists(unit_fd))
        # A file of that name is not the marker.
        (self.unit / "up-console").write_text("")
        self.assertFalse(sandy._up_console_marker_exists(unit_fd))

    def test_create_up_console_marker_waits_for_the_scope(self):
        opens = [FileNotFoundError(), FileNotFoundError(), None]

        def open_unit(_name):
            result = opens.pop(0)
            if result is not None:
                raise result
            return self.open_unit()

        # Mocks: the scope check and the pidfd of the supervisor.
        with patch.object(
            sandy, "_open_supervisor_cgroup", side_effect=open_unit
        ), patch.object(sandy.time, "sleep") as sleep, patch.object(
            sandy, "_supervisor_in_scope", return_value=True
        ), patch.object(
            sandy, "_pidfd_process_alive", return_value=True
        ):
            sandy._create_up_console_marker("ai-dev", PINNED_SUPERVISOR)
        self.assertEqual(
            sleep.call_args_list, [call(sandy.UP_CONSOLE_POLL_INTERVAL)] * 2
        )
        self.assertTrue((self.unit / "up-console").is_dir())

        with patch.object(
            sandy, "_open_supervisor_cgroup", side_effect=FileNotFoundError
        ), patch.object(sandy.time, "sleep"), patch.object(
            sandy.time, "monotonic", side_effect=[0, 1, 10]
        ), patch.object(
            sandy, "_pidfd_process_alive", return_value=True
        ):
            with self.assertRaisesRegex(TimeoutError, "did not appear"):
                sandy._create_up_console_marker("ai-dev", PINNED_SUPERVISOR)

    def test_new_attach_leaf_is_random_and_valid(self):
        first = sandy._new_attach_leaf()
        second = sandy._new_attach_leaf()
        self.assertRegex(first, sandy.ATTACH_LEAF_PATTERN)
        self.assertNotEqual(first, second)


class AttachLifecycleTests(unittest.TestCase):
    """The -d record, attach counting, hangups, and the last-attach rule.

    Tests mock systemctl, the lifecycle lock, the cgroup directory, signal
    handling, and the stop. E2E tests must prove the rule with real attaches.
    """

    def setUp(self):
        # The session's OOM report reads cgroupfs; OomReportTests cover it.
        memory_events = patch.object(
            sandy, "_container_memory_events", return_value=None
        )
        memory_events.start()
        self.addCleanup(memory_events.stop)

    def test_supervisor_started_attached_reads_the_exact_description(self):
        for value, expected in (
            ("Sandy container ai-dev (attached)", True),
            ("Sandy container ai-dev (detached)", False),
            ("sandy-ai-dev.scope", False),
            ("Sandy container other (attached)", False),
            ("Sandy container ai-dev (attached) ", False),
            ("", False),
        ):
            with self.subTest(value=value):
                with patch.object(
                    sandy, "_systemctl_show_value", return_value=value
                ) as show:
                    self.assertIs(
                        sandy._supervisor_started_attached("ai-dev"), expected
                    )
                show.assert_called_once_with("sandy-ai-dev.scope", "Description")

    def test_count_populated_attaches_counts_and_prunes(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            unit = Path(temp_dir)
            leaves = {
                "attach-" + "a" * 32: "populated 1\n",
                "attach-" + "b" * 32: "populated 0\n",
                "attach-" + "c" * 32: "populated 1\n",
                "payload": "populated 1\n",
                "supervisor": "populated 1\n",
                "attach-short": "populated 1\n",
            }
            for name, events in leaves.items():
                (unit / name).mkdir()
                (unit / name / "cgroup.events").write_text(events)
            unit_fd = os.open(unit, sandy.DIRECTORY_OPEN_FLAGS)
            try:
                with patch.object(sandy.os, "rmdir") as rmdir:
                    self.assertEqual(sandy._count_populated_attaches(unit_fd), 2)
                rmdir.assert_called_once_with("attach-" + "b" * 32, dir_fd=unit_fd)
                with patch.object(
                    sandy.os, "rmdir", side_effect=OSError(errno.EBUSY, "x")
                ):
                    self.assertEqual(sandy._count_populated_attaches(unit_fd), 2)
                (unit / ("attach-" + "a" * 32) / "cgroup.events").write_text("bad\n")
                with self.assertRaises(ValueError):
                    sandy._count_populated_attaches(unit_fd)
            finally:
                os.close(unit_fd)

    def test_count_populated_attaches_skips_leaf_removed_meanwhile(self):
        real_open = os.open

        def open_fd(path, flags, mode=0o777, *, dir_fd=None):
            if path.startswith("attach-"):
                raise FileNotFoundError(path)
            return real_open(path, flags, mode, dir_fd=dir_fd)

        with tempfile.TemporaryDirectory() as temp_dir:
            (Path(temp_dir) / ("attach-" + "a" * 32)).mkdir()
            unit_fd = os.open(temp_dir, sandy.DIRECTORY_OPEN_FLAGS)
            try:
                with patch.object(sandy.os, "open", side_effect=open_fd):
                    self.assertEqual(sandy._count_populated_attaches(unit_fd), 0)
            finally:
                os.close(unit_fd)

    def test_hangup_handlers_turn_signals_into_exception(self):
        previous = {
            signum: sandy.signal.getsignal(signum)
            for signum in sandy.ATTACH_HANGUP_SIGNALS
        }
        with patch.object(sandy.signal, "signal") as install:
            installed = {}
            install.side_effect = (
                lambda signum, handler: installed.setdefault(signum, handler)
                and previous[signum]
            )
            with self.assertRaises(sandy._AttachHangup) as raised:
                with sandy._attach_hangup_handlers():
                    installed[sandy.signal.SIGHUP](sandy.signal.SIGHUP, None)
        self.assertEqual(raised.exception.signum, sandy.signal.SIGHUP)
        # After a hangup both signals are ignored and stay ignored.
        self.assertIn(
            call(sandy.signal.SIGTERM, sandy.signal.SIG_IGN), install.call_args_list
        )
        self.assertEqual(install.call_args_list[-1].args[1], sandy.signal.SIG_IGN)

    def test_hangup_handlers_restore_previous_handlers(self):
        with patch.object(sandy.signal, "signal", return_value="old") as install:
            with sandy._attach_hangup_handlers():
                pass
        self.assertEqual(
            install.call_args_list[2:],
            [call(sandy.signal.SIGHUP, "old"), call(sandy.signal.SIGTERM, "old")],
        )
        with patch.object(sandy.signal, "signal", return_value="old") as install:
            with self.assertRaises(RuntimeError):
                with sandy._attach_hangup_handlers():
                    raise RuntimeError("attach failed")
        self.assertEqual(install.call_count, 4)

    def test_hangup_handlers_do_nothing_outside_main_thread(self):
        with patch.object(sandy.signal, "signal") as install:
            thread = threading.Thread(
                target=lambda: sandy._attach_hangup_handlers().__enter__()
            )
            thread.start()
            thread.join()
        install.assert_not_called()

    @contextmanager
    def rule_mocks(
        self,
        attached: object = True,
        remaining: object = 0,
        unit_error=None,
        marker: object = False,
    ):
        manager = MagicMock()

        @contextmanager
        def lock():
            manager.lock_enter()
            try:
                yield
            finally:
                manager.lock_exit()

        manager.attached.return_value = attached
        manager.open_unit.return_value = 70
        if unit_error is not None:
            manager.open_unit.side_effect = unit_error
        manager.count.return_value = remaining
        manager.marker.return_value = marker
        # The stop works unless a test says otherwise.
        manager.poweroff.return_value = True
        instance = make_sandy()
        with patch.object(sandy, "_lifecycle_lock", lock), patch.object(
            sandy, "_up_console_marker_exists", manager.marker
        ), patch.object(
            sandy, "_remove_up_console_marker", manager.remove_marker
        ), patch.object(
            sandy, "_supervisor_started_attached", manager.attached
        ), patch.object(
            sandy, "_open_supervisor_cgroup", manager.open_unit
        ), patch.object(
            sandy, "_count_populated_attaches", manager.count
        ), patch.object(
            sandy.os, "close", manager.close
        ), patch.object(
            sandy.signal, "pthread_sigmask", manager.sigmask
        ), patch.object(
            instance, "_machine_poweroff", manager.poweroff
        ):
            yield instance, manager

    def test_last_attach_stops_container_under_lock(self):
        with self.rule_mocks() as (instance, manager):
            with captured_output() as (stdout, _):
                instance._stop_if_last_attach()
        self.assertEqual(
            manager.mock_calls,
            [
                call.sigmask(sandy.signal.SIG_BLOCK, sandy.ATTACH_HANGUP_SIGNALS),
                call.lock_enter(),
                call.open_unit("ai-dev"),
                call.count(70),
                call.marker(70),
                call.close(70),
                call.attached("ai-dev"),
                call.poweroff(**LAST_ATTACH_STOP),
                call.lock_exit(),
                call.sigmask(sandy.signal.SIG_UNBLOCK, sandy.ATTACH_HANGUP_SIGNALS),
            ],
        )
        self.assertIn("no session is attached", stdout.getvalue())

    def test_last_attach_rule_keeps_container_running(self):
        cases = (
            # up -d, another description, or no scope.
            ({"attached": False}, "poweroff"),
            ({"unit_error": FileNotFoundError()}, "count"),
            ({"remaining": 1}, "attached"),
            # The console has not exited yet (for example, up is starting).
            ({"marker": True}, "attached"),
        )
        for overrides, not_called in cases:
            with self.subTest(overrides=overrides):
                with self.rule_mocks(**overrides) as (instance, manager):
                    instance._stop_if_last_attach()
                getattr(manager, not_called).assert_not_called()
                manager.poweroff.assert_not_called()
                manager.lock_exit.assert_called_once_with()
                self.assertEqual(
                    manager.sigmask.call_args_list[-1],
                    call(sandy.signal.SIG_UNBLOCK, sandy.ATTACH_HANGUP_SIGNALS),
                )

    def test_last_attach_rule_counts_on_detached_containers(self):
        # Regression: empty leaves after SIGKILL stayed on -d containers,
        # because the rule returned before the count (measured).
        with self.rule_mocks(attached=False) as (instance, manager):
            instance._stop_if_last_attach()
        manager.count.assert_called_once_with(70)
        manager.remove_marker.assert_not_called()

    def test_console_exit_removes_marker_before_count(self):
        with self.rule_mocks() as (instance, manager):
            with captured_output():
                instance._stop_if_last_attach(console=True)
        names = [entry[0] for entry in manager.mock_calls]
        self.assertLess(names.index("remove_marker"), names.index("count"))
        manager.remove_marker.assert_called_once_with(70)
        manager.poweroff.assert_called_once_with(**LAST_ATTACH_STOP)

    def test_console_hangup_removes_marker_without_stop(self):
        with self.rule_mocks() as (instance, manager):
            instance._end_up_console()
        manager.remove_marker.assert_called_once_with(70)
        manager.close.assert_called_once_with(70)
        manager.count.assert_not_called()
        manager.poweroff.assert_not_called()
        for error, warned in (
            (FileNotFoundError(), False),
            (PermissionError("x"), True),
        ):
            with self.subTest(error=type(error).__name__):
                with self.rule_mocks(unit_error=error) as (instance, manager):
                    with captured_output() as (stdout, _):
                        instance._end_up_console()
                manager.remove_marker.assert_not_called()
                self.assertEqual("W: Could not update" in stdout.getvalue(), warned)

    def test_last_attach_rule_warns_on_errors(self):
        for target, error in (
            ("open_unit", PermissionError("Unexpected cgroup directory")),
            ("attached", subprocess.CalledProcessError(1, ["systemctl"])),
            ("count", ValueError("Malformed cgroup.events\x1b")),
        ):
            with self.subTest(target=target):
                with self.rule_mocks() as (instance, manager):
                    getattr(manager, target).side_effect = error
                    with captured_output() as (stdout, _):
                        instance._stop_if_last_attach()
                manager.poweroff.assert_not_called()
                manager.lock_exit.assert_called_once_with()
                self.assertIn("W: Could not check the sessions", stdout.getvalue())
                self.assertNotIn("\x1b", stdout.getvalue())

    def test_last_attach_rule_keeps_the_container_when_the_port_lock_stays_busy(
        self,
    ):
        # Regression test: the stop after the last session waited for the
        # port mapping lock with no limit under the lifecycle lock. While
        # another process held the port mapping lock (for example, rm
        # --cache), each attach, to any container, failed after
        # LIFECYCLE_LOCK_TIMEOUT. Now the stop waits for at most
        # PORT_MAPPINGS_LOCK_TIMEOUT, and the container keeps running with its
        # ports. Mocks: the lifecycle lock, the cgroup checks, and the
        # poweroff, which times out on the port mapping lock before any change.
        self.assertLess(sandy.PORT_MAPPINGS_LOCK_TIMEOUT, sandy.LIFECYCLE_LOCK_TIMEOUT)
        with self.rule_mocks() as (instance, manager):
            manager.poweroff.side_effect = TimeoutError(
                "Timed out waiting for the Sandy port mapping lock"
            )
            with captured_output() as (stdout, _):
                instance._stop_if_last_attach()
        manager.poweroff.assert_called_once_with(**LAST_ATTACH_STOP)
        manager.lock_exit.assert_called_once_with()
        self.assertEqual(
            manager.sigmask.call_args_list[-1],
            call(sandy.signal.SIG_UNBLOCK, sandy.ATTACH_HANGUP_SIGNALS),
        )
        self.assertEqual(
            stdout.getvalue(),
            "I: Stopping 'ai-dev': no session is attached\n"
            "W: Did not stop 'ai-dev': the port mapping lock stayed busy\n"
            "   Stop it with: sandy --container ai-dev down\n",
        )

    def test_last_attach_stop_names_down_when_the_stop_fails(self):
        # The stop under the lifecycle lock is short, so it can give up: the
        # container did not stop in time, or a machinectl command of the stop
        # did not answer. Both name the down command, and the second one says
        # what failed, not "Could not check the sessions". Mocks: as above.
        no_answer = subprocess.TimeoutExpired(["machinectl", "poweroff", "ai-dev"], 2.5)
        for name, stopped, error, warning in (
            ("did not stop", False, None, ""),
            (
                "no answer",
                None,
                no_answer,
                "W: Could not stop 'ai-dev': "
                "\"Command '['machinectl', 'poweroff', 'ai-dev']' timed out "
                'after 2.5 seconds"\n',
            ),
        ):
            with self.subTest(name=name):
                with self.rule_mocks() as (instance, manager):
                    manager.poweroff.return_value = stopped
                    manager.poweroff.side_effect = error
                    with captured_output() as (stdout, _):
                        instance._stop_if_last_attach()
                manager.poweroff.assert_called_once_with(**LAST_ATTACH_STOP)
                manager.lock_exit.assert_called_once_with()
                self.assertEqual(
                    stdout.getvalue(),
                    "I: Stopping 'ai-dev': no session is attached\n"
                    f"{warning}"
                    "   Stop it with: sandy --container ai-dev down\n",
                )

    def test_last_attach_rule_lock_timeout_warns(self):
        # A timeout of the lifecycle lock is not one of the port mapping
        # lock: the warning names the session check, not a stop that the
        # port mapping lock kept from running. Mocks: the lifecycle lock,
        # which times out, the signal mask, and the poweroff.
        instance = make_sandy()
        with patch.object(
            sandy, "_lifecycle_lock", side_effect=TimeoutError("busy")
        ), patch.object(sandy.signal, "pthread_sigmask") as sigmask, patch.object(
            instance, "_machine_poweroff"
        ) as poweroff:
            with captured_output() as (stdout, _):
                instance._stop_if_last_attach()
        poweroff.assert_not_called()
        self.assertEqual(
            stdout.getvalue(), "W: Could not check the sessions of 'ai-dev': 'busy'\n"
        )
        self.assertEqual(sigmask.call_count, 2)

    def test_exec_applies_rule_after_normal_exit_only(self):
        instance = make_sandy()
        instance.workspace = None

        @contextmanager
        def helper_command(request):
            yield ["helper"], 5

        with patch.object(
            instance, "_is_container_running", return_value="123"
        ), patch.object(
            instance, "_entry_helper_command", side_effect=helper_command
        ), patch.object(
            instance, "_run_container_interactive", return_value=3
        ), patch.object(
            instance, "_stop_if_last_attach"
        ) as rule:
            self.assertEqual(instance._exec("true"), 3)
        rule.assert_called_once_with(console=False)

        with patch.object(
            instance, "_is_container_running", return_value="123"
        ), patch.object(
            instance, "_entry_helper_command", side_effect=helper_command
        ), patch.object(
            instance,
            "_run_container_interactive",
            side_effect=sandy._AttachHangup(sandy.signal.SIGHUP),
        ), patch.object(
            instance, "_stop_if_last_attach"
        ) as rule:
            with self.assertRaises(SystemExit) as exited:
                instance._exec("true")
        self.assertEqual(exited.exception.code, 128 + sandy.signal.SIGHUP)
        rule.assert_not_called()

    def test_exec_reports_entry_setup_errors(self):
        # Regression test for entry setup errors that escaped as a traceback.
        # Mocks: the running check, the cache directory, the script open (it
        # fails as for a group-writable script), the session, and the
        # last-attach rule.
        error = PermissionError(
            "Sandy script must be a regular file that only its owner can write\x1b"
        )
        for console in (False, True):
            with self.subTest(console=console):
                instance = make_sandy()
                instance.workspace = None
                with patch.object(
                    instance, "_is_container_running", return_value="123"
                ), patch.object(instance, "_ensure_cache_dir"), patch.object(
                    sandy, "_open_entry_script", side_effect=error
                ), patch.object(
                    instance, "_run_container_interactive"
                ) as session, patch.object(
                    instance, "_stop_if_last_attach"
                ) as rule:
                    with captured_output() as (stdout, _):
                        with self.assertRaises(SystemExit) as exited:
                            instance._exec(None, login_shell=True, console=console)
                self.assertEqual(exited.exception.code, 1)
                self.assertIn(
                    "E: Could not prepare the container entry", stdout.getvalue()
                )
                self.assertNotIn("\x1b", stdout.getvalue())
                session.assert_not_called()
                # A console that did not start is handled as a console exit.
                if console:
                    rule.assert_called_once_with(console=True)
                else:
                    rule.assert_not_called()

    def test_each_other_end_of_the_up_console_is_a_console_exit(self):
        # Regression test: when the console of up without -d ended in another
        # way than an exit, a hangup, or an entry setup error, the up-console
        # marker stayed, and the container never stopped at its last attach
        # exit. Mocks: the machine query, the helper command, the session,
        # the end after a hangup, and the last-attach rule.
        @contextmanager
        def helper_command(request):
            yield ["helper"], 5

        no_answer = subprocess.TimeoutExpired(["machinectl"], 3)
        failed = sandy._MachineQueryError("ai-dev", "Connection refused")
        helper_error = OSError(errno.EMFILE, "Too many open files")
        interrupt = KeyboardInterrupt()
        # (name, leader, query error, helper error, session error, expected)
        cases: tuple[
            tuple[
                str,
                str | None,
                BaseException | None,
                BaseException | None,
                BaseException | None,
                BaseException | type[BaseException],
            ],
            ...,
        ] = (
            ("no answer", None, no_answer, None, None, no_answer),
            ("failed query", None, failed, None, None, failed),
            ("not running", None, None, None, None, SystemExit),
            ("invalid entry", "abc", None, None, None, SystemExit),
            ("helper error", "123", None, helper_error, None, helper_error),
            ("interrupt", "123", None, None, interrupt, interrupt),
        )
        for name, leader, query_error, helper_failure, session_error, expected in cases:
            for console in (True, False):
                with self.subTest(name=name, console=console):
                    instance = make_sandy()
                    instance.workspace = None
                    with patch.object(
                        instance,
                        "_is_container_running",
                        side_effect=query_error,
                        return_value=leader,
                    ), patch.object(
                        instance,
                        "_entry_helper_command",
                        side_effect=helper_failure or helper_command,
                    ), patch.object(
                        instance,
                        "_run_container_interactive",
                        side_effect=session_error,
                        return_value=0,
                    ), patch.object(
                        instance, "_end_up_console"
                    ) as end, patch.object(
                        instance, "_stop_if_last_attach"
                    ) as rule:
                        with captured_output():
                            with self.assertRaises(BaseException) as raised:
                                instance._exec(None, login_shell=True, console=console)
                    if isinstance(expected, BaseException):
                        self.assertIs(raised.exception, expected)
                    else:
                        self.assertIsInstance(raised.exception, expected)
                    end.assert_not_called()
                    if console:
                        rule.assert_called_once_with(console=True)
                    else:
                        rule.assert_not_called()

    def test_the_console_ends_at_once_on_a_held_ctrl_c(self):
        # up holds a Ctrl-C back from the end of its start until the console
        # has started. It ends the console there, before the query, and that
        # is a console exit. Mocks: the query and the last-attach rule; the
        # SIGINT is real.
        instance = make_sandy()
        handler = sandy.signal.getsignal(sandy.signal.SIGINT)
        self.addCleanup(sandy.signal.signal, sandy.signal.SIGINT, handler)
        held = sandy._DeferredSigint()
        held.hold()
        try:
            os.kill(os.getpid(), sandy.signal.SIGINT)
            sandy.time.sleep(0)
        except KeyboardInterrupt:
            self.fail("The SIGINT was not held back")
        with patch.object(instance, "_is_container_running") as running, patch.object(
            instance, "_stop_if_last_attach"
        ) as rule:
            with self.assertRaises(BaseException) as raised:
                instance._exec(None, login_shell=True, console=True, sigint=held)
        self.assertIsInstance(raised.exception, KeyboardInterrupt)
        running.assert_not_called()
        rule.assert_called_once_with(console=True)
        self.assertIs(sandy.signal.getsignal(sandy.signal.SIGINT), handler)

    def test_up_console_exit_and_hangup_end_the_console_once(self):
        # Mocks: as above. A normal exit is one console exit. A hangup only
        # removes the marker, so no stop follows it.
        @contextmanager
        def helper_command(request):
            yield ["helper"], 5

        hangup = sandy._AttachHangup(sandy.signal.SIGHUP)
        for name, session_error, rule_calls, end_calls in (
            ("exit", None, [call(console=True)], 0),
            ("hangup", hangup, [], 1),
        ):
            with self.subTest(name=name):
                instance = make_sandy()
                instance.workspace = None
                with patch.object(
                    instance, "_is_container_running", return_value="123"
                ), patch.object(
                    instance, "_entry_helper_command", side_effect=helper_command
                ), patch.object(
                    instance,
                    "_run_container_interactive",
                    side_effect=session_error,
                    return_value=0,
                ), patch.object(
                    instance, "_end_up_console"
                ) as end, patch.object(
                    instance, "_stop_if_last_attach"
                ) as rule:
                    try:
                        instance._exec(None, login_shell=True, console=True)
                    except SystemExit:
                        pass
                self.assertEqual(rule.call_args_list, rule_calls)
                self.assertEqual(end.call_count, end_calls)


class DeferredSigintTests(unittest.TestCase):
    """A SIGINT held back in a short section of up.

    Each test sends a real SIGINT to this process; the held section records
    it. The handler of SIGINT is the same after each test.
    """

    def setUp(self):
        self.handler = signal_handler = sandy.signal.getsignal(sandy.signal.SIGINT)
        self.addCleanup(sandy.signal.signal, sandy.signal.SIGINT, signal_handler)

    def send_sigint(self) -> None:
        """Send a SIGINT that the section must hold back.

        A KeyboardInterrupt here would end the whole test run, so it fails
        this test.
        """
        try:
            os.kill(os.getpid(), sandy.signal.SIGINT)
            # Let the handler of the signal run here.
            sandy.time.sleep(0)
        except KeyboardInterrupt:
            self.fail("The SIGINT was not held back")

    def test_a_held_sigint_acts_at_the_release(self):
        held = sandy._DeferredSigint()
        held.hold()
        self.send_sigint()
        # Nothing happens until the release.
        with self.assertRaises(KeyboardInterrupt):
            held.release()
        self.assertIs(sandy.signal.getsignal(sandy.signal.SIGINT), self.handler)
        # A second release does nothing.
        held.release()

    def test_a_release_with_no_sigint_or_with_discard_raises_nothing(self):
        for discard in (False, True):
            with self.subTest(discard=discard):
                held = sandy._DeferredSigint()
                held.hold()
                held.hold()
                if discard:
                    self.send_sigint()
                held.release(discard=discard)
                self.assertIs(sandy.signal.getsignal(sandy.signal.SIGINT), self.handler)

    def test_an_ignored_sigint_stays_ignored(self):
        sandy.signal.signal(sandy.signal.SIGINT, sandy.signal.SIG_IGN)
        held = sandy._DeferredSigint()
        held.hold()
        self.send_sigint()
        held.release()
        self.assertEqual(
            sandy.signal.getsignal(sandy.signal.SIGINT), sandy.signal.SIG_IGN
        )

    def test_another_thread_holds_nothing(self):
        # Only the main thread can change a handler.
        held = sandy._DeferredSigint()
        errors: list[BaseException] = []

        def run() -> None:
            try:
                held.hold()
                held.release()
            except BaseException as exc:  # the test reports each error
                errors.append(exc)

        thread = threading.Thread(target=run)
        thread.start()
        thread.join(10)
        self.assertEqual(errors, [])
        self.assertIs(sandy.signal.getsignal(sandy.signal.SIGINT), self.handler)


class OomReportTests(unittest.TestCase):
    """memory.events of the scope and the slice, and the OOM kill report.

    The cgroup tree is a temporary directory; a patched fstat reports root
    ownership, as on cgroupfs. E2E tests prove the counters with real kills.
    """

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.root = Path(self.tempdir.name)
        self.slice = self.root / "sandy.slice"
        self.unit = self.slice / "sandy-ai-dev.scope"
        self.unit.mkdir(parents=True)
        real_fstat = os.fstat

        def fstat(fd):
            return SimpleNamespace(st_uid=0, st_dev=real_fstat(fd).st_dev)

        for patcher in (
            patch.object(sandy, "CGROUP_ROOT", str(self.root)),
            patch.object(sandy.os, "fstat", side_effect=fstat),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def events_text(self, oom=0, oom_kill=0):
        return (
            f"low 0\nhigh 0\nmax 7\noom {oom}\noom_kill {oom_kill}\noom_group_kill 0\n"
        )

    def test_read_cgroup_counters(self):
        (self.unit / "memory.events").write_text(self.events_text(2, 3))
        fd = os.open(self.unit, sandy.DIRECTORY_OPEN_FLAGS)
        self.addCleanup(os.close, fd)
        self.assertEqual(
            sandy._read_cgroup_counters(fd, "memory.events"),
            {
                "low": 0,
                "high": 0,
                "max": 7,
                "oom": 2,
                "oom_kill": 3,
                "oom_group_kill": 0,
            },
        )
        for text in (
            "oom 1 2\n",
            "oom -1\n",
            "OOM 1\n",
            "oom\t1\n",
            "oom 1" + "0" * 20 + "\n",
            "\x1b[31m 1\n",
            "x" * 4097,
        ):
            with self.subTest(text=text[:20]):
                (self.unit / "memory.events").write_text(text)
                with self.assertRaises(ValueError):
                    sandy._read_cgroup_counters(fd, "memory.events")
        (self.unit / "memory.events").write_text("")
        self.assertEqual(sandy._read_cgroup_counters(fd, "memory.events"), {})

    def test_container_memory_events(self):
        # The slice's own count is in memory.events.local; its memory.events
        # also counts the events inside each container.
        (self.slice / "memory.events").write_text(self.events_text(oom=7, oom_kill=9))
        (self.slice / "memory.events.local").write_text(
            self.events_text(oom=5, oom_kill=0)
        )
        (self.unit / "memory.events").write_text(self.events_text(oom=2, oom_kill=3))
        self.assertEqual(
            sandy._container_memory_events("ai-dev"), sandy.MemoryEvents(3, 2, 5)
        )
        # A missing counter is 0.
        (self.unit / "memory.events").write_text("oom_kill 4\n")
        self.assertEqual(
            sandy._container_memory_events("ai-dev"), sandy.MemoryEvents(4, 0, 5)
        )

    def test_container_memory_events_is_none_when_unknown(self):
        (self.slice / "memory.events.local").write_text(self.events_text())
        (self.unit / "memory.events").write_text(self.events_text())
        # No scope, a malformed file, or a missing file: no report.
        self.assertIsNone(sandy._container_memory_events("other"))
        (self.unit / "memory.events").write_text("oom x\n")
        self.assertIsNone(sandy._container_memory_events("ai-dev"))
        (self.unit / "memory.events").unlink()
        self.assertIsNone(sandy._container_memory_events("ai-dev"))
        (self.unit / "memory.events").write_text(self.events_text())
        (self.slice / "memory.events.local").unlink()
        self.assertIsNone(sandy._container_memory_events("ai-dev"))
        with patch.object(sandy, "CGROUP_ROOT", str(self.root / "missing")):
            self.assertIsNone(sandy._container_memory_events("ai-dev"))

    def test_container_memory_events_closes_its_descriptors(self):
        (self.slice / "memory.events.local").write_text(self.events_text())
        (self.unit / "memory.events").write_text("oom x\n")
        real_close = os.close
        closed = []

        def close(fd):
            closed.append(fd)
            real_close(fd)

        real_open = os.open
        opened = []

        def tracking_open(*args, **kwargs):
            fd = real_open(*args, **kwargs)
            opened.append(fd)
            return fd

        with patch.object(sandy.os, "open", side_effect=tracking_open), patch.object(
            sandy.os, "close", side_effect=close
        ):
            self.assertIsNone(sandy._container_memory_events("ai-dev"))
        self.assertEqual(sorted(opened), sorted(closed))

    def report(self, before, after):
        instance = make_sandy()
        with patch.object(sandy, "_container_memory_events", return_value=after):
            with captured_output() as (stdout, _):
                instance._report_oom_kills(before)
        return stdout.getvalue()

    def test_report_names_the_limit_that_was_reached(self):
        before = sandy.MemoryEvents(1, 1, 4)
        shared = (
            "   The Sandy containers reached the memory limit that they share. "
            "Stop other containers, start less work at a time, or raise the "
            "limit with: sandy update --shared -m SIZE\n"
        )
        own = "   The container reached a memory limit of its own\n"
        self.assertEqual(
            self.report(before, sandy.MemoryEvents(4, 1, 5)),
            "W: The kernel ended 3 processes in 'ai-dev' during this session "
            "because memory ran out\n" + shared,
        )
        # A limit of the scope, or one that container root set inside.
        self.assertEqual(
            self.report(before, sandy.MemoryEvents(2, 2, 4)),
            "W: The kernel ended 1 process in 'ai-dev' during this session because "
            "memory ran out\n" + own,
        )
        # Both limits were reached during the session: name both.
        self.assertEqual(
            self.report(before, sandy.MemoryEvents(3, 2, 5)),
            "W: The kernel ended 2 processes in 'ai-dev' during this session "
            "because memory ran out\n" + shared + own,
        )
        self.assertEqual(
            self.report(before, sandy.MemoryEvents(3, 1, 4)),
            "W: The kernel ended 2 processes in 'ai-dev' during this session "
            "because memory ran out\n"
            "   The host ran out of memory\n",
        )

    def test_report_is_silent_without_new_kills_or_counters(self):
        events = sandy.MemoryEvents(1, 1, 1)
        for before, after in (
            (events, events),
            (events, sandy.MemoryEvents(1, 2, 2)),
            # A new scope with the same name restarts the counters.
            (sandy.MemoryEvents(5, 0, 0), sandy.MemoryEvents(0, 0, 0)),
            (None, events),
            (events, None),
        ):
            with self.subTest(before=before, after=after):
                self.assertEqual(self.report(before, after), "")


class UpdateCommandTests(unittest.TestCase):
    """sandy update: validation, the systemctl call, and errors.

    Mocks: host facts, the running check, systemctl queries, the subprocess
    wrapper, and _set_shared_limits (SharedLimitTests cover it). E2E tests
    prove the change of a running scope and of sandy.slice.
    """

    def start_patch(self, target: object, name: str, value: object) -> MagicMock:
        patcher = patch.object(target, name, return_value=value)
        self.addCleanup(patcher.stop)
        return patcher.start()

    def setUp(self):
        self.read_host_facts = self.start_patch(sandy, "_read_host_facts", HOST_FACTS)
        self.supervisor_unit_loaded = self.start_patch(
            sandy, "_supervisor_unit_loaded", True
        )
        self.live = self.start_patch(sandy, "_read_live_group_limits", DEFAULT_GROUP)
        self.systemctl = self.start_patch(sandy, "_run_secure_subprocess", None)
        self.set_shared_limits = self.start_patch(
            sandy.Sandy,
            "_set_shared_limits",
            (DEFAULT_GROUP, sandy.SavedGroupLimits()),
        )
        self.instance = make_sandy()
        running = patch.object(self.instance, "_is_container_running", return_value="9")
        self.running = running.start()
        self.addCleanup(running.stop)

    def update(self, **overrides):
        values = {
            "container": None,
            "shared_limits": False,
            "cpuset_cpus": None,
            "memory": None,
            "pids_limit": None,
            "reset": False,
        }
        values.update(overrides)
        with captured_output() as (stdout, _):
            try:
                self.instance.run_update(SimpleNamespace(**values))
            except SystemExit as exc:
                return exc.code, stdout.getvalue()
        return 0, stdout.getvalue()

    def test_update_sets_the_process_limit_of_the_running_scope(self):
        for pids_limit, value in ((512, "512"), (-1, "infinity")):
            with self.subTest(pids_limit=pids_limit):
                self.systemctl.reset_mock()
                status, output = self.update(pids_limit=pids_limit)
                self.assertEqual(status, 0)
                self.systemctl.assert_called_once_with(
                    [
                        "systemctl",
                        "set-property",
                        "--runtime",
                        "sandy-ai-dev.scope",
                        f"TasksMax={value}",
                    ],
                    check=True,
                )
                self.assertEqual(output, f"I: Updated 'ai-dev': TasksMax={value}\n")
        self.set_shared_limits.assert_not_called()

    def test_update_warns_above_the_shared_process_limit(self):
        status, output = self.update(pids_limit=98305)
        self.assertEqual(status, 0)
        self.assertIn(
            "W: --pids-limit 98305 is above the process limit that all Sandy "
            "containers share (98304), which applies too\n",
            output,
        )
        self.systemctl.assert_called_once()
        # No warning without a shared process limit.
        self.live.return_value = DEFAULT_GROUP._replace(tasks_max=None)
        status, output = self.update(pids_limit=98305)
        self.assertNotIn("W: ", output)

    def test_update_rejects_before_any_change(self):
        for overrides, message in (
            ({}, "E: update needs --pids-limit, or --shared to change the limits"),
            (
                {"memory": GIB, "pids_limit": 5},
                "E: --memory needs --shared: a container has no CPU or memory limit "
                "of its own",
            ),
            (
                {"cpuset_cpus": (1,), "memory": GIB, "reset": True},
                "E: --cpuset-cpus, --memory, --reset need --shared",
            ),
        ):
            with self.subTest(overrides=overrides):
                status, output = self.update(**overrides)
                self.assertEqual(status, 1)
                self.assertIn(message, output)
        self.running.assert_not_called()
        self.systemctl.assert_not_called()

    def test_update_needs_a_running_container_and_its_scope(self):
        self.running.return_value = None
        status, output = self.update(pids_limit=100)
        self.assertEqual(
            (status, output), (1, "E: Container 'ai-dev' not found or not running\n")
        )
        self.running.return_value = "9"
        self.supervisor_unit_loaded.return_value = False
        status, output = self.update(pids_limit=100)
        self.assertEqual(
            (status, output), (1, "E: Unit 'sandy-ai-dev.scope' does not exist\n")
        )
        self.supervisor_unit_loaded.side_effect = subprocess.CalledProcessError(
            1, ["systemctl"]
        )
        status, output = self.update(pids_limit=100)
        self.assertEqual(status, 1)
        self.assertIn("E: Could not query unit 'sandy-ai-dev.scope'", output)
        self.supervisor_unit_loaded.side_effect = None
        self.supervisor_unit_loaded.return_value = True
        self.live.side_effect = ValueError("Malformed limits of sandy.slice")
        status, output = self.update(pids_limit=100)
        self.assertEqual(
            (status, output),
            (1, "E: Could not query sandy.slice: 'Malformed limits of sandy.slice'\n"),
        )
        self.systemctl.assert_not_called()

    def test_update_reports_a_failed_change(self):
        # Measured: set-property on a stopped scope fails and writes nothing.
        self.systemctl.side_effect = subprocess.CalledProcessError(1, ["systemctl"])
        status, output = self.update(pids_limit=100)
        self.assertEqual(status, 1)
        self.assertIn("E: Could not update 'sandy-ai-dev.scope'", output)

    def test_update_shared_saves_and_sets_the_given_limits(self):
        saved = sandy.SavedGroupLimits((0, 1), 8 * GIB, None)
        self.set_shared_limits.return_value = (
            sandy.GroupLimits((0, 1), 8 * GIB, 98304),
            saved,
        )
        status, output = self.update(
            shared_limits=True, cpuset_cpus=(0, 1), memory=8 * GIB
        )
        self.assertEqual(status, 0)
        self.set_shared_limits.assert_called_once_with(
            HOST_FACTS, {"cpus": (0, 1), "memory_max": 8 * GIB}, reset=False
        )
        self.assertEqual(
            output,
            "I: Limits of all Sandy containers: CPUs 0-1 (saved), memory 8.0 GiB "
            "(saved), 98304 tasks\n",
        )
        # It needs no running container.
        self.running.assert_not_called()
        self.systemctl.assert_not_called()
        self.set_shared_limits.reset_mock()
        self.assertEqual(self.update(shared_limits=True, pids_limit=-1)[0], 0)
        self.set_shared_limits.assert_called_once_with(
            HOST_FACTS, {"tasks_max": -1}, reset=False
        )
        self.set_shared_limits.reset_mock()
        self.assertEqual(self.update(shared_limits=True, reset=True)[0], 0)
        self.set_shared_limits.assert_called_once_with(HOST_FACTS, {}, reset=True)

    def test_update_shared_rejects_before_any_change(self):
        for overrides, message in (
            (
                {"container": "ai-dev", "memory": GIB},
                "E: update --shared cannot be used with --container",
            ),
            ({}, "E: update --shared needs at least one of --cpuset-cpus"),
            (
                {"reset": True, "pids_limit": 5},
                "E: --reset cannot be used with --cpuset-cpus, --memory, or "
                "--pids-limit",
            ),
            (
                {"cpuset_cpus": (7, 8)},
                "E: --cpuset-cpus must name online CPUs; the online CPUs are 0-7",
            ),
        ):
            with self.subTest(overrides=overrides):
                status, output = self.update(shared_limits=True, **overrides)
                self.assertEqual(status, 1)
                self.assertIn(message, output)
        self.set_shared_limits.assert_not_called()
        self.systemctl.assert_not_called()


class SharedLimitTests(unittest.TestCase):
    """The saved shared limits: lock, file, defaults, and the slice change.

    The cache directory is a temporary directory: a patched
    _open_verified_parent anchors the managed paths there. Mocks: the
    systemctl query and change of sandy.slice. E2E tests prove the systemd
    and kernel values.
    """

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.cache = Path(self.tempdir.name)

        def open_parent(path):
            if os.path.dirname(path) != "/managed/sandy.__cache":
                raise AssertionError(f"Unexpected managed path {path}")
            return (
                os.open(self.cache, sandy.DIRECTORY_OPEN_FLAGS),
                os.path.basename(path),
            )

        self.events = []
        self.live = DEFAULT_GROUP._replace(memory_max=None)
        for patcher in (
            patch.object(sandy, "_open_verified_parent", side_effect=open_parent),
            patch.object(
                sandy.Sandy, "_get_cache_dir", return_value="/managed/sandy.__cache"
            ),
            patch.object(sandy.Sandy, "_ensure_cache_dir"),
            patch.object(
                sandy,
                "_read_live_group_limits",
                side_effect=lambda: self.events.append("show") or self.live,
            ),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        apply_patcher = patch.object(
            sandy,
            "_apply_group_limits",
            side_effect=lambda group: self.events.append(("apply", group)),
        )
        self.apply = apply_patcher.start()
        self.addCleanup(apply_patcher.stop)
        self.instance = make_sandy()

    @property
    def saved_file(self) -> Path:
        return self.cache / "shared_limits.json"

    def set_limits(self, changes=None, reset=False):
        with captured_output() as (stdout, _):
            try:
                result = self.instance._set_shared_limits(HOST_FACTS, changes, reset)
            except SystemExit as exc:
                return exc.code, stdout.getvalue()
        return result, stdout.getvalue()

    def test_defaults_without_a_saved_file(self):
        result, output = self.set_limits()
        self.assertEqual(result, (DEFAULT_GROUP, sandy.SavedGroupLimits()))
        self.assertEqual(output, "")
        self.assertEqual(self.events, ["show", ("apply", DEFAULT_GROUP)])
        # up saves nothing; the lock inode stays.
        self.assertFalse(self.saved_file.exists())
        lock = self.cache / "shared_limits.lock"
        self.assertEqual(stat.S_IMODE(lock.stat().st_mode), 0o600)

    def test_a_slice_with_the_limits_is_not_changed(self):
        self.live = DEFAULT_GROUP
        result, _ = self.set_limits()
        self.assertEqual(result, (DEFAULT_GROUP, sandy.SavedGroupLimits()))
        self.assertEqual(self.events, ["show"])

    def test_saved_values_replace_the_defaults(self):
        self.saved_file.write_text('{"cpus":"0-1","tasks":-1,"unknown":1}\n')
        self.saved_file.chmod(0o600)
        result, _ = self.set_limits()
        group = sandy.GroupLimits((0, 1), 12 * GIB, None)
        self.assertEqual(result, (group, sandy.SavedGroupLimits((0, 1), None, -1)))
        self.assertEqual(self.events, ["show", ("apply", group)])
        # Reading does not rewrite the file.
        self.assertIn("unknown", self.saved_file.read_text())

    def recorded_write(self):
        real_write = sandy._write
        return patch.object(
            sandy,
            "_write",
            side_effect=lambda *a, **k: self.events.append("write")
            or real_write(*a, **k),
        )

    def test_changes_are_set_then_saved(self):
        self.saved_file.write_text('{"cpus":"0-1"}\n')
        self.saved_file.chmod(0o600)
        with self.recorded_write():
            result, output = self.set_limits({"memory_max": 0, "tasks_max": 4096})
        group = sandy.GroupLimits((0, 1), None, 4096)
        self.assertEqual(result, (group, sandy.SavedGroupLimits((0, 1), 0, 4096)))
        self.assertEqual(output, "")
        self.assertEqual(self.events, ["show", ("apply", group), "write"])
        self.assertEqual(
            self.saved_file.read_text(), '{"cpus":"0-1","memory":0,"tasks":4096}\n'
        )
        self.assertEqual(stat.S_IMODE(self.saved_file.stat().st_mode), 0o600)

    def test_reset_saves_no_values_even_over_a_malformed_file(self):
        self.saved_file.write_text("{")
        self.saved_file.chmod(0o600)
        result, _ = self.set_limits(reset=True)
        self.assertEqual(result, (DEFAULT_GROUP, sandy.SavedGroupLimits()))
        self.assertEqual(self.saved_file.read_text(), "{}\n")

    def test_a_malformed_file_stops_before_any_change(self):
        for text, message in (
            ("{", "The saved shared limits are not valid JSON"),
            ('{"cpus":"8-9"}', "The saved shared CPUs 8-9 are not all online"),
        ):
            with self.subTest(text=text):
                self.events.clear()
                self.saved_file.write_text(text)
                self.saved_file.chmod(0o600)
                for changes in (None, {"memory_max": 0}):
                    status, output = self.set_limits(changes)
                    self.assertEqual(status, 1)
                    self.assertEqual(
                        output,
                        f"E: {message}. Reset them with: sandy update --shared "
                        "--reset\n",
                    )
                self.assertEqual(self.events, [])
                self.assertEqual(self.saved_file.read_text(), text)

    def test_an_unsafe_saved_file_stops_before_any_change(self):
        self.saved_file.write_text("{}\n")
        self.saved_file.chmod(0o644)
        status, output = self.set_limits()
        self.assertEqual(status, 1)
        self.assertIn("E: Could not read the saved shared limits: ", output)
        self.assertIn("unsafe permissions", output)
        self.assertEqual(self.events, [])

    def test_a_failed_slice_change_saves_nothing(self):
        for error in (
            subprocess.CalledProcessError(1, ["systemctl"]),
            OSError("no systemctl"),
            ValueError("Malformed limits of sandy.slice"),
        ):
            with self.subTest(error=type(error).__name__):
                self.apply.side_effect = error
                status, output = self.set_limits({"memory_max": 8 * GIB})
                self.assertEqual(status, 1)
                self.assertIn("E: Could not set the limits of sandy.slice: ", output)
                self.assertFalse(self.saved_file.exists())

    def test_a_failed_save_is_reported(self):
        with patch.object(sandy, "_write", side_effect=OSError(errno.ENOSPC, "full")):
            status, output = self.set_limits({"memory_max": 0})
        self.assertEqual(status, 1)
        self.assertEqual(
            output,
            "E: Could not save the shared limits: '[Errno 28] full'\n"
            "   They apply now, but the next up sets the saved limits again\n",
        )

    def test_the_lock_is_held_from_the_read_to_the_save(self):
        # Mocks: flock records its operations next to the other events.
        real_flock = sandy.fcntl.flock

        def flock(fd, operation):
            self.events.append(("flock", operation))
            return real_flock(fd, operation)

        with patch.object(sandy.fcntl, "flock", side_effect=flock):
            with self.recorded_write():
                self.set_limits({"tasks_max": 64})
        self.assertEqual(
            [event if isinstance(event, str) else event[0] for event in self.events],
            ["flock", "show", "apply", "write", "flock"],
        )
        self.assertEqual(self.events[0], ("flock", sandy.fcntl.LOCK_EX))
        self.assertEqual(self.events[-1], ("flock", sandy.fcntl.LOCK_UN))


if __name__ == "__main__":
    unittest.main()
