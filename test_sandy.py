#!/usr/bin/env python3

"""Unit tests for the extensionless ``sandy`` CLI script."""

import argparse
import importlib.machinery
import importlib.util
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import ExitStack, contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, call, mock_open, patch

PROJECT_DIR = Path(__file__).resolve().parent
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

    def test_log_sanitization_removes_control_characters(self):
        message = "safe\nforged\rline\tvalue\x00\x7f"
        self.assertEqual(sandy._sanitize_log_output(message), "safeforgedlinevalue")
        self.assertEqual(sandy._sanitize_log_output(123), "123")


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

    def test_run_wrapper_sanitizes_called_process_error(self):
        error = subprocess.CalledProcessError(
            2,
            ["tool"],
            output="ordinary output",
            stderr="bad\nforged",
        )
        with patch.object(sandy.subprocess, "run", side_effect=error):
            with self.assertRaises(subprocess.CalledProcessError) as raised:
                sandy._run_secure_subprocess(["tool"])

        self.assertEqual(raised.exception.stderr, "badforged")
        self.assertEqual(raised.exception.stdout, "ordinary output")

    def test_popen_wrapper_forces_shell_false(self):
        process = MagicMock()
        with patch.object(sandy.subprocess, "Popen", return_value=process) as popen:
            result = sandy._run_secure_subprocess_popen(["tool"], stdin=None)

        self.assertIs(result, process)
        popen.assert_called_once_with(["tool"], stdin=None, shell=False)

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
                master_read=None,
                stdin_read=callback,
            )
        with self.assertRaises(ValueError):
            sandy._run_secure_subprocess_pty(
                ["tool"],
                master_read=callback,
                stdin_read=None,
            )


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
                                                master_read=MagicMock(
                                                    side_effect=OSError
                                                ),
                                                stdin_read=MagicMock(),
                                            )
        self.assertEqual(result, -1)

    def test_child_pty_reports_exec_failure(self):
        with patch.object(sandy.pty, "fork", return_value=(0, 10)):
            with patch.object(
                sandy.os,
                "execvp",
                side_effect=OSError("missing"),
            ):
                with patch.object(
                    sandy.os,
                    "_exit",
                    side_effect=RuntimeError("child exited"),
                ) as child_exit:
                    with captured_output() as (_, stderr):
                        with self.assertRaisesRegex(
                            RuntimeError,
                            "child exited",
                        ):
                            sandy._run_secure_subprocess_pty(
                                ["missing"],
                                master_read=MagicMock(),
                                stdin_read=MagicMock(),
                            )
        child_exit.assert_called_once_with(1)
        self.assertIn("Failed to execute missing", stderr.getvalue())


class ParserTests(unittest.TestCase):
    def parse(self, *arguments):
        with patch.object(sys, "argv", ["sandy", *arguments]):
            return sandy.parse_args_custom()

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
            with patch.object(sandy, "_verify_safe_dir"):
                with patch.object(sandy, "Sandy", return_value=instance):
                    sandy.main()
        return instance

    def test_safe_directory_is_verified_between_parsing_and_construction(self):
        args = self.make_args("status")
        instance = MagicMock(container="ai-dev", user="developer")
        events = []

        def parse_arguments():
            events.append("parse")
            return args

        def verify_directory(path):
            events.append(("verify", path))

        def create_instance():
            events.append("construct")
            return instance

        with patch.object(
            sandy,
            "parse_args_custom",
            side_effect=parse_arguments,
        ):
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
            events[:3],
            ["parse", ("verify", sandy.SYSTEMD_MACHINES), "construct"],
        )
        verify.assert_called_once_with(sandy.SYSTEMD_MACHINES)

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
        instance = self.run_main(args)
        instance._exec.assert_called_once_with(None, login_shell=True)


class FilesystemSafetyTests(unittest.TestCase):
    def safe_stat(self, *, uid=0, gid=0, mode=stat.S_IFDIR | 0o755, ino=1):
        return SimpleNamespace(
            st_uid=uid,
            st_gid=gid,
            st_mode=mode,
            st_dev=1,
            st_ino=ino,
        )

    def test_verify_safe_dir_rejects_outside_managed_root(self):
        with patch.object(sandy, "SYSTEMD_MACHINES", "/safe"):
            with self.assertRaises(ValueError):
                sandy._verify_safe_dir("/unsafe/container")

    def test_verify_safe_dir_accepts_owned_non_writable_components(self):
        safe = self.safe_stat()
        with patch.object(sandy, "SYSTEMD_MACHINES", "/safe"):
            with patch.object(sandy.os.path, "realpath", side_effect=lambda p: p):
                with patch.object(sandy.os, "open", side_effect=[10, 11, 12]):
                    with patch.object(
                        sandy.os,
                        "fstat",
                        side_effect=[safe, safe, safe, safe],
                    ):
                        with patch.object(sandy.os, "stat", return_value=safe):
                            with patch.object(sandy.os, "close") as close:
                                sandy._verify_safe_dir("/safe/container")
        self.assertTrue(close.called)

    def test_verify_safe_dir_rejects_unsafe_ownership_and_permissions(self):
        cases = [
            self.safe_stat(uid=1000),
            self.safe_stat(gid=1000),
            self.safe_stat(mode=stat.S_IFDIR | 0o777),
        ]
        for unsafe in cases:
            with self.subTest(unsafe=unsafe):
                root = self.safe_stat()
                with patch.object(sandy, "SYSTEMD_MACHINES", "/safe"):
                    with patch.object(
                        sandy.os.path,
                        "realpath",
                        side_effect=lambda p: p,
                    ):
                        with patch.object(sandy.os, "open", side_effect=[10, 11]):
                            with patch.object(
                                sandy.os,
                                "fstat",
                                side_effect=[root, unsafe],
                            ):
                                with patch.object(sandy.os, "close"):
                                    with self.assertRaises(PermissionError):
                                        sandy._verify_safe_dir("/safe")

    def test_verify_safe_dir_rejects_unsafe_root_and_non_directory(self):
        root_cases = [
            self.safe_stat(uid=1000),
            self.safe_stat(mode=stat.S_IFDIR | 0o777),
        ]
        for unsafe_root in root_cases:
            with self.subTest(root=unsafe_root):
                with patch.object(sandy, "SYSTEMD_MACHINES", "/safe"):
                    with patch.object(
                        sandy.os.path,
                        "realpath",
                        side_effect=lambda path: path,
                    ):
                        with patch.object(sandy.os, "open", return_value=10):
                            with patch.object(
                                sandy.os,
                                "fstat",
                                return_value=unsafe_root,
                            ):
                                with patch.object(sandy.os, "close"):
                                    with self.assertRaises(PermissionError):
                                        sandy._verify_safe_dir("/safe")

        root = self.safe_stat()
        regular_file = self.safe_stat(mode=stat.S_IFREG | 0o644)
        with patch.object(sandy, "SYSTEMD_MACHINES", "/safe"):
            with patch.object(
                sandy.os.path,
                "realpath",
                side_effect=lambda path: path,
            ):
                with patch.object(sandy.os, "open", side_effect=[10, 11]):
                    with patch.object(
                        sandy.os,
                        "fstat",
                        side_effect=[root, regular_file],
                    ):
                        with patch.object(sandy.os, "close"):
                            with self.assertRaises(PermissionError):
                                sandy._verify_safe_dir("/safe")

    def test_verify_safe_dir_detects_inode_mismatch(self):
        safe = self.safe_stat(ino=1)
        mismatch = self.safe_stat(ino=2)
        with patch.object(sandy, "SYSTEMD_MACHINES", "/safe"):
            with patch.object(sandy.os.path, "realpath", side_effect=lambda p: p):
                with patch.object(sandy.os, "open", side_effect=[10, 11]):
                    with patch.object(
                        sandy.os,
                        "fstat",
                        side_effect=[safe, safe, safe],
                    ):
                        with patch.object(sandy.os, "stat", return_value=mismatch):
                            with patch.object(sandy.os, "close"):
                                with self.assertRaises(PermissionError):
                                    sandy._verify_safe_dir("/safe")

    def test_rmtree_never_removes_managed_root(self):
        with patch.object(sandy, "SYSTEMD_MACHINES", "/safe"):
            with patch.object(sandy.os.path, "realpath", side_effect=lambda p: p):
                with self.assertRaises(ValueError):
                    sandy._rmtree("/safe")

    def test_rmtree_verifies_before_removal(self):
        with patch.object(sandy, "_verify_safe_dir") as verify:
            with patch.object(sandy.shutil, "rmtree") as rmtree:
                sandy._rmtree("/var/lib/machines/sandy.test")

        verify.assert_called_once_with("/var/lib/machines/sandy.test")
        rmtree.assert_called_once_with("/var/lib/machines/sandy.test")

    def test_mkdir_verifies_parent_and_result(self):
        with patch.object(sandy, "_verify_safe_dir") as verify:
            with patch.object(sandy.os, "mkdir") as mkdir:
                sandy._mkdir("/var/lib/machines/sandy.test")

        self.assertEqual(
            verify.call_args_list,
            [
                call("/var/lib/machines"),
                call("/var/lib/machines/sandy.test"),
            ],
        )
        mkdir.assert_called_once_with(
            "/var/lib/machines/sandy.test",
            mode=0o700,
        )

    def test_write_verifies_parent_and_sets_mode(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "state"
            with patch.object(sandy, "_verify_safe_dir") as verify:
                sandy._write(str(path), "safe content", mode=0o640)

            self.assertEqual(path.read_text(), "safe content")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)
            verify.assert_called_once_with(temp_dir)


class GuestFileTests(unittest.TestCase):
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
            return (
                path == sandy.SYSTEMD_MACHINES
                or path == "/var/lib/machines/sandy.old/init.sh"
            )

        opened = mock_open(read_data='CONTAINER_IP="10.20.30.10"\n')
        with patch.object(sandy, "_write", side_effect=record_write):
            with patch.object(sandy.os.path, "exists", side_effect=exists):
                with patch.object(
                    sandy.glob,
                    "glob",
                    return_value=["/var/lib/machines/sandy.old"],
                ):
                    with patch("builtins.open", opened):
                        with captured_output():
                            sandy._create_guest_files(
                                "/machine",
                                "test-box",
                                "10.20.30.0/24",
                                "10.20.30.1",
                            )

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
                        side_effect=ValueError("invalid"),
                    ):
                        with captured_output():
                            sandy._create_guest_files(
                                "/machine",
                                "test-box",
                                "10.20.30.0/24",
                                "10.20.30.1",
                            )
        self.assertEqual(write.call_count, 1)

        directories = [
            "/var/lib/machines/sandy.__cache",
            "/var/lib/machines/sandy.missing",
            "/var/lib/machines/sandy.unreadable",
        ]

        def exists(path):
            if path.endswith("sandy.missing/init.sh"):
                return False
            return True

        opened = mock_open()
        opened.side_effect = OSError("unreadable")
        with patch.object(sandy.os.path, "exists", side_effect=exists):
            with patch.object(sandy.glob, "glob", return_value=directories):
                with patch("builtins.open", opened):
                    with patch.object(sandy, "_write") as write:
                        with captured_output():
                            sandy._create_guest_files(
                                "/machine",
                                "test-box",
                                "10.20.30.0/24",
                                "10.20.30.1",
                            )
        self.assertIn('CONTAINER_IP="10.20.30.10"', write.call_args.args[1])

    def test_create_guest_files_reports_exhausted_address_pool(self):
        directories = [
            f"/var/lib/machines/sandy.container-{number}" for number in range(10, 254)
        ]

        def open_init(path, *_args, **_kwargs):
            container = Path(path).parent.name
            number = int(container.rsplit("-", 1)[1])
            return io.StringIO(f'CONTAINER_IP="10.20.30.{number}"\n')

        with patch.object(sandy.os.path, "exists", return_value=True):
            with patch.object(sandy.glob, "glob", return_value=directories):
                with patch("builtins.open", side_effect=open_init):
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
        self.assertIn("setfacl", stdout.getvalue())

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
            ([True, True, False], "setup-container.sh"),
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

    def test_get_host_uid(self):
        instance = make_sandy()
        with tempfile.TemporaryDirectory() as temp_dir:
            passwd = Path(temp_dir) / "sandy.test" / "etc" / "passwd"
            passwd.parent.mkdir(parents=True)
            passwd.write_text(
                "root:x:0:0::/root:/bin/bash\n"
                "developer:x:1000:1000::/home/developer:/bin/bash\n"
            )
            with patch.object(sandy, "SYSTEMD_MACHINES", temp_dir):
                self.assertEqual(
                    instance._get_host_uid("test"),
                    sandy.CONTAINER_BASE_UID + 1000,
                )

    def test_get_host_uid_rejects_missing_user(self):
        instance = make_sandy()
        with tempfile.TemporaryDirectory() as temp_dir:
            passwd = Path(temp_dir) / "sandy.test" / "etc" / "passwd"
            passwd.parent.mkdir(parents=True)
            passwd.write_text("root:x:0:0::/root:/bin/bash\n")
            with patch.object(sandy, "SYSTEMD_MACHINES", temp_dir):
                with self.assertRaises(ValueError):
                    instance._get_host_uid("test")

    def test_get_host_uid_rejects_missing_passwd_file(self):
        instance = make_sandy()
        with patch.object(sandy.os.path, "exists", return_value=False):
            with self.assertRaisesRegex(ValueError, "passwd file not found"):
                instance._get_host_uid("test")

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

    def test_running_container_enumeration_skips_cache(self):
        instance = make_sandy()
        paths = [
            "/var/lib/machines/sandy.one",
            "/var/lib/machines/sandy.two",
            "/var/lib/machines/sandy.__cache",
        ]
        with patch.object(sandy.os.path, "exists", return_value=True):
            with patch.object(sandy.glob, "glob", return_value=paths):
                with patch.object(
                    instance,
                    "_is_container_running",
                    side_effect=lambda name: "123" if name == "one" else None,
                ):
                    self.assertEqual(
                        instance._get_running_sandy_containers(),
                        ["one"],
                    )

        with patch.object(sandy.os.path, "exists", return_value=False):
            self.assertEqual(instance._get_running_sandy_containers(), [])


class AclTests(unittest.TestCase):
    def test_acl_setup_skips_irrelevant_paths_and_new_systemd(self):
        instance = make_sandy()
        with patch.object(sandy, "_run_secure_subprocess") as run:
            instance._setfacl("", "test")
            with patch.object(sandy.os.path, "exists", return_value=False):
                instance._setfacl("/missing", "test")
            instance.systemd_version = 250
            with patch.object(sandy.os.path, "exists", return_value=True):
                instance._setfacl("/workspace", "test")
        run.assert_not_called()

    def test_acl_setup_handles_missing_container_user(self):
        instance = make_sandy()
        instance.systemd_version = 249
        with patch.object(sandy.os.path, "exists", return_value=True):
            with patch.object(
                instance,
                "_get_host_uid",
                side_effect=ValueError("missing user"),
            ):
                with captured_output() as (stdout, _):
                    instance._setfacl("/workspace", "test")
        self.assertIn("missing user", stdout.getvalue())

    def test_acl_setup_reuses_existing_acl(self):
        instance = make_sandy()
        instance.systemd_version = 249
        existing = SimpleNamespace(stdout="user:1001000:rwx\n")
        with patch.object(sandy.os.path, "exists", return_value=True):
            with patch.object(
                instance,
                "_get_host_uid",
                return_value=1001000,
            ):
                with patch.object(
                    sandy,
                    "_run_secure_subprocess",
                    return_value=existing,
                ) as run:
                    instance._setfacl("/workspace", "test")
        run.assert_called_once_with(
            ["getfacl", "-n", "/workspace"],
            capture_output=True,
            text=True,
            check=True,
        )

    def test_acl_setup_prints_manual_commands_without_sudo_uid(self):
        instance = make_sandy()
        instance.systemd_version = 249
        missing_acl = SimpleNamespace(stdout="")
        with patch.object(sandy.os.path, "exists", return_value=True):
            with patch.object(
                instance,
                "_get_host_uid",
                return_value=1001000,
            ):
                with patch.object(
                    sandy,
                    "_run_secure_subprocess",
                    return_value=missing_acl,
                ):
                    with patch.dict(
                        sandy.os.environ,
                        {"SUDO_UID": "invalid"},
                        clear=True,
                    ):
                        with captured_output() as (stdout, _):
                            instance._setfacl("/workspace", "test")
        self.assertIn("SUDO_UID not set", stdout.getvalue())
        self.assertIn("setfacl -R -m u:1001000:rwX", stdout.getvalue())

    def test_acl_setup_decline_does_not_modify_acl(self):
        instance = make_sandy()
        instance.systemd_version = 249
        getfacl_error = subprocess.CalledProcessError(1, ["getfacl"])
        with patch.object(sandy.os.path, "exists", return_value=True):
            with patch.object(
                instance,
                "_get_host_uid",
                return_value=1001000,
            ):
                with patch.object(
                    sandy,
                    "_run_secure_subprocess",
                    side_effect=getfacl_error,
                ) as run:
                    with patch.object(instance, "_confirm", return_value=False):
                        with patch.dict(
                            sandy.os.environ,
                            {"SUDO_UID": "1000"},
                            clear=True,
                        ):
                            with captured_output():
                                instance._setfacl("/workspace", "test")
        self.assertEqual(run.call_count, 1)

    def test_acl_setup_drops_privileges_for_both_acl_commands(self):
        instance = make_sandy()
        instance.systemd_version = 249
        getfacl = SimpleNamespace(stdout="")
        failed = SimpleNamespace(returncode=1, stderr="denied")
        succeeded = SimpleNamespace(returncode=0, stderr="")
        with patch.object(sandy.os.path, "exists", return_value=True):
            with patch.object(
                instance,
                "_get_host_uid",
                return_value=1001000,
            ):
                with patch.object(
                    sandy,
                    "_run_secure_subprocess",
                    side_effect=[getfacl, failed, succeeded],
                ) as run:
                    with patch.object(instance, "_confirm", return_value=True):
                        with patch.dict(
                            sandy.os.environ,
                            {"SUDO_UID": "1000"},
                            clear=True,
                        ):
                            with captured_output() as (stdout, _):
                                instance._setfacl("/workspace", "test")

        self.assertEqual(run.call_count, 3)
        recursive = run.call_args_list[1].args[0]
        default = run.call_args_list[2].args[0]
        privilege_prefix = [
            "setpriv",
            "--reuid=1000",
            "--regid=1000",
            "--clear-groups",
            "--",
        ]
        self.assertEqual(recursive[:5], privilege_prefix)
        self.assertEqual(default[:5], privilege_prefix)
        self.assertIn("Failed to add ACL", stdout.getvalue())


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
            path = Path(temp_dir) / "ports.json"
            with patch.object(
                instance,
                "_get_port_mappings_path",
                return_value=str(path),
            ):
                with instance._port_mapping_lock(exclusive=False) as handle:
                    self.assertIsNone(handle)

                with patch.object(instance, "_ensure_cache_dir"):
                    with instance._port_mapping_lock(
                        exclusive=True,
                        create=True,
                    ) as handle:
                        self.assertIsNotNone(handle)
                        handle.write("{}")
            self.assertEqual(path.read_text(), "{}")

    def test_port_mapping_lock_tolerates_unlock_failure(self):
        instance = make_sandy()
        handle = MagicMock()
        handle.fileno.return_value = 10
        opened = MagicMock(return_value=handle)
        with patch.object(
            instance,
            "_get_port_mappings_path",
            return_value="/cache/ports.json",
        ):
            with patch("builtins.open", opened):
                with patch.object(
                    sandy.fcntl,
                    "flock",
                    side_effect=[None, OSError("unlock failed")],
                ):
                    with instance._port_mapping_lock(exclusive=False) as locked:
                        self.assertIs(locked, handle)
        handle.close.assert_called_once_with()

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

        @contextmanager
        def locked():
            yield io.StringIO("{}")

        with patch.object(
            instance,
            "_get_port_mappings_path",
            return_value="/cache/ports.json",
        ):
            with patch.object(sandy.os.path, "exists", return_value=True):
                with patch.object(
                    instance,
                    "_port_mapping_lock",
                    return_value=locked(),
                ):
                    with patch.object(
                        instance,
                        "_persist_port_mapping_state",
                    ) as persist:
                        instance._clear_port_mapping_state()
        persist.assert_called_once_with({})

        with patch.object(
            instance,
            "_get_port_mappings_path",
            return_value="/cache/ports.json",
        ):
            with patch.object(sandy.os.path, "exists", return_value=False):
                with patch.object(
                    instance,
                    "_port_mapping_lock",
                ) as lock:
                    instance._clear_port_mapping_state()
        lock.assert_not_called()

        @contextmanager
        def missing_handle():
            yield None

        with patch.object(
            instance,
            "_get_port_mappings_path",
            return_value="/cache/ports.json",
        ):
            with patch.object(sandy.os.path, "exists", return_value=True):
                with patch.object(
                    instance,
                    "_port_mapping_lock",
                    return_value=missing_handle(),
                ):
                    with patch.object(
                        instance,
                        "_persist_port_mapping_state",
                    ) as persist:
                        instance._clear_port_mapping_state()
        persist.assert_not_called()

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

    def test_ensure_network_ready_reuses_or_constructs_network(self):
        instance = make_sandy()
        instance.network = make_network()
        with patch.object(sandy, "SandyNet") as network_type:
            self.assertTrue(instance._ensure_network_ready())
        network_type.assert_not_called()

        instance.network = None
        configured = make_network()
        with patch.object(sandy, "SandyNet", return_value=configured):
            self.assertTrue(instance._ensure_network_ready())

        unconfigured = make_network()
        unconfigured.configured = False
        instance.network = None
        with patch.object(sandy, "SandyNet", return_value=unconfigured):
            self.assertFalse(instance._ensure_network_ready())

    def test_cleanup_port_state_handles_incomplete_state(self):
        instance = make_sandy()
        cases = (
            ([], None, True, ""),
            ([{"invalid": True}], None, True, ""),
            (
                [
                    {
                        "proto": "tcp",
                        "host_port": 8080,
                        "container_port": 80,
                    }
                ],
                None,
                True,
                "Could not determine IP",
            ),
            (
                [
                    {
                        "proto": "tcp",
                        "host_port": 8080,
                        "container_port": 80,
                        "ip": "10.20.30.10",
                    }
                ],
                None,
                False,
                "Could not initialize network",
            ),
        )
        for stored, discovered_ip, network_ready, message in cases:
            with self.subTest(message=message, stored=stored):
                with patch.object(
                    instance,
                    "_remove_port_mappings_from_state",
                    return_value=stored,
                ):
                    with patch.object(
                        instance,
                        "_get_container_ip",
                        return_value=discovered_ip,
                    ):
                        with patch.object(
                            instance,
                            "_ensure_network_ready",
                            return_value=network_ready,
                        ):
                            with captured_output() as (stdout, _):
                                instance._cleanup_port_mappings_for_container("target")
                if message:
                    self.assertIn(message, stdout.getvalue())

    def test_cleanup_port_state_dispatches_nftables(self):
        instance = make_sandy()
        instance.network = make_network()
        instance.network.firewall_backend = "nftables"
        stored = [
            {
                "proto": "tcp",
                "host_port": 8080,
                "container_port": 80,
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
                "_cleanup_port_forwarding_nft",
            ) as cleanup:
                instance._cleanup_port_mappings_for_container("target")
        cleanup.assert_called_once_with("10.20.30.10")


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
        cached.assert_called_once_with("/cache/key.tar", "/machine")
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
        fresh.assert_called_once_with("/machine", False)

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
        fresh.assert_called_once_with("/machine", True)

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
            archive = cache / "cache.tar"
            directory = cache / "partial"
            state.write_text("{}")
            archive.write_text("archive")
            directory.mkdir()
            (directory / "file").write_text("partial")
            with patch.object(instance, "_get_cache_dir", return_value=temp_dir):
                with patch.object(
                    instance,
                    "_get_port_mappings_path",
                    return_value=str(state),
                ):
                    with patch.object(sandy, "_rmtree") as rmtree:
                        self.assertTrue(instance._clear_cache_contents())
            self.assertTrue(state.exists())
            self.assertFalse(archive.exists())
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
                            sandy.os.path,
                            "samefile",
                            side_effect=FileNotFoundError,
                        ):
                            self.assertFalse(instance._clear_cache_contents())

    def test_new_machine_from_cache_restores_identity_and_network(self):
        instance = make_sandy()
        instance.network = make_network()
        instance.network._ensure_gateway = MagicMock(return_value=True)
        success = SimpleNamespace(returncode=0)
        with patch.object(sandy, "_verify_safe_dir") as verify:
            with patch.object(sandy, "_mkdir") as mkdir:
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
        self.assertEqual(run.call_count, 2)
        extract = run.call_args_list[0].args[0]
        self.assertEqual(extract[:4], ["tar", "--extract", "--file", "/cache/key.tar"])
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
            with patch.object(sandy, "_verify_safe_dir") as verify:
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
        written_content = write.call_args.args[1]
        self.assertIn("user=developer", written_content)
        self.assertNotIn("%%MACHINE_USER%%", written_content)
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
            with patch.object(sandy, "_verify_safe_dir"):
                with patch.object(sandy.os.path, "exists", return_value=True):
                    with patch.object(sandy, "_write") as write:
                        with captured_output():
                            instance._new_machine_from_scratch("/machine")
        self.assertEqual(run.call_count, 2)
        write.assert_not_called()

    def test_purge_cache_all_outcomes(self):
        instance = make_sandy()
        cases = (
            (False, False, False, "No cache directory"),
            (True, True, True, "except port mapping state"),
            (True, False, False, "Purged cache directory"),
            (True, False, True, "retained only port mapping state"),
        )
        for cache_exists, removed, state_exists, message in cases:
            with self.subTest(message=message):
                with patch.object(
                    instance,
                    "_get_cache_dir",
                    return_value="/cache",
                ):
                    with patch.object(
                        instance,
                        "_get_port_mappings_path",
                        return_value="/cache/ports.json",
                    ):
                        with patch.object(
                            sandy.os.path,
                            "exists",
                            side_effect=[cache_exists, state_exists],
                        ):
                            with patch.object(
                                instance,
                                "_clear_cache_contents",
                                return_value=removed,
                            ):
                                with patch.object(sandy, "_rmtree") as rmtree:
                                    with captured_output() as (stdout, _):
                                        instance._purge_cache()
                self.assertIn(message, stdout.getvalue())
                if cache_exists and not removed and not state_exists:
                    rmtree.assert_called_once_with("/cache")


class ExecutionTests(unittest.TestCase):
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
        )

        with patch.object(
            sandy,
            "_run_secure_subprocess",
            side_effect=subprocess.CalledProcessError(1, ["machinectl"]),
        ):
            self.assertIsNone(instance._is_container_running())

    def test_machine_poweroff_cleans_state_first(self):
        instance = make_sandy()
        with patch.object(instance, "_is_container_running", return_value="123"):
            with patch.object(
                instance,
                "_cleanup_port_mappings_for_container",
            ) as cleanup:
                with patch.object(sandy, "_run_secure_subprocess") as run:
                    instance._machine_poweroff()
        cleanup.assert_called_once_with("ai-dev")
        self.assertEqual(
            [entry.args[0] for entry in run.call_args_list],
            [
                ["machinectl", "poweroff", "ai-dev"],
                ["machinectl", "terminate", "ai-dev"],
            ],
        )

    def test_exec_builds_nsenter_command_and_quotes_workdir(self):
        instance = make_sandy()
        with patch.object(instance, "_is_container_running", return_value="123"):
            with patch.object(
                instance,
                "_get_machine_dir",
                return_value="/machine",
            ):
                with patch.object(sandy.os.path, "isdir", return_value=True):
                    with patch.object(
                        instance,
                        "_run_container_interactive",
                    ) as interactive:
                        instance._exec("printf safe")

        command = interactive.call_args.args[0]
        self.assertEqual(command[:6], ["nsenter", "-t", "123", "-a", "--", "su"])
        self.assertIn("cd /home/developer/workspace && printf safe", command[-1])
        self.assertIn("script -qec", command[-1])

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

    def test_exec_login_shell(self):
        instance = make_sandy()
        instance.workspace = None
        with patch.object(instance, "_is_container_running", return_value="123"):
            with patch.object(instance, "_run_container_interactive") as interactive:
                instance._exec(None, login_shell=True)
        self.assertIn("exec bash --login", interactive.call_args.args[0][-1])

    def test_exec_as_root_validates_and_runs(self):
        instance = make_sandy()
        result = SimpleNamespace(returncode=0)
        with patch.object(instance, "_is_container_running", return_value="123"):
            with patch.object(
                sandy,
                "_run_secure_subprocess",
                return_value=result,
            ) as run:
                self.assertIs(instance._exec_as_root("/init.sh"), result)
        run.assert_called_once_with(
            ["nsenter", "-t", "123", "-a", "--", "sh", "-c", "/init.sh"]
        )

        with captured_output():
            with self.assertRaises(SystemExit):
                instance._exec_as_root("")

    def test_interactive_wrapper_wires_callbacks_and_finishes_spinner(self):
        instance = make_sandy()
        spinner = threading.Event()

        def run_pty(command, *, master_read, stdin_read):
            self.assertEqual(command, ["tool"])
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
                        spinner_line_event=spinner,
                    ),
                    7,
                )
        self.assertTrue(spinner.is_set())

    def test_wait_for_container_ready_retries(self):
        instance = make_sandy()
        result = SimpleNamespace(returncode=0)
        with patch.object(
            instance,
            "_is_container_running",
            side_effect=[None, "123"],
        ):
            with patch.object(
                sandy,
                "_run_secure_subprocess",
                return_value=result,
            ):
                with patch("time.sleep") as sleep:
                    self.assertTrue(instance._wait_for_container_ready())
        sleep.assert_called_once_with(1)

    def test_get_container_ip(self):
        instance = make_sandy()
        with tempfile.TemporaryDirectory() as temp_dir:
            init_script = Path(temp_dir) / "init.sh"
            init_script.write_text('CONTAINER_IP="10.20.30.10"\n')
            with patch.object(instance, "_get_machine_dir", return_value=temp_dir):
                self.assertEqual(instance._get_container_ip(), "10.20.30.10")
            init_script.write_text("no address")
            with patch.object(instance, "_get_machine_dir", return_value=temp_dir):
                self.assertIsNone(instance._get_container_ip())

    def test_run_init_script_conditions_and_success(self):
        instance = make_sandy()
        self.assertFalse(instance._run_init_script(network_mode="host"))
        instance.network = make_network()
        result = SimpleNamespace(returncode=0)
        with patch.object(instance, "_get_machine_dir", return_value="/machine"):
            with patch.object(sandy.os.path, "exists", return_value=True):
                with patch.object(
                    instance,
                    "_wait_for_container_ready",
                    return_value=True,
                ):
                    with patch.object(
                        instance,
                        "_exec_as_root",
                        return_value=result,
                    ) as execute:
                        with captured_output():
                            self.assertTrue(instance._run_init_script())
        execute.assert_called_once_with("/init.sh")

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

        with patch.object(instance, "_is_container_running", return_value=None):
            with captured_output():
                with self.assertRaises(SystemExit):
                    instance._exec_as_root("true")

    def test_interactive_wrapper_handles_io_errors_and_pty_failure(self):
        instance = make_sandy()
        spinner = threading.Event()

        def run_pty(_command, *, master_read, stdin_read):
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
                    spinner_line_event=spinner,
                )
        self.assertTrue(spinner.is_set())

    def test_wait_for_container_ready_handles_failures_and_spinner_stop(self):
        instance = make_sandy()
        spinner = threading.Event()
        spinner.clear()

        def stop_spinner(_seconds):
            spinner.set()

        result = SimpleNamespace(returncode=1)
        with patch.object(
            instance,
            "_is_container_running",
            side_effect=["123", "123", "123"],
        ):
            with patch.object(
                sandy,
                "_run_secure_subprocess",
                side_effect=[
                    subprocess.TimeoutExpired(["true"], 5),
                    result,
                    SimpleNamespace(returncode=0),
                ],
            ):
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
            with patch.object(sandy.os.path, "exists", return_value=False):
                self.assertIsNone(instance._get_container_ip())

            with patch.object(sandy.os.path, "exists", return_value=True):
                with patch(
                    "builtins.open",
                    side_effect=OSError("denied"),
                ):
                    with captured_output() as (stdout, _):
                        self.assertIsNone(instance._get_container_ip())
        self.assertIn("Could not read container IP", stdout.getvalue())

    def test_run_init_script_skips_or_reports_readiness_failure(self):
        instance = make_sandy()
        self.assertFalse(instance._run_init_script())

        instance.network = make_network()
        with patch.object(
            instance,
            "_get_machine_dir",
            return_value="/machine",
        ):
            with patch.object(sandy.os.path, "exists", return_value=False):
                self.assertFalse(instance._run_init_script())

            with patch.object(sandy.os.path, "exists", return_value=True):
                with patch.object(
                    instance,
                    "_wait_for_container_ready",
                    return_value=False,
                ):
                    with captured_output() as (stdout, _):
                        self.assertTrue(instance._run_init_script())
        self.assertIn("not ready", stdout.getvalue())

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
                    "_wait_for_container_ready",
                    return_value=True,
                ):
                    with patch.object(
                        instance,
                        "_exec_as_root",
                        return_value=failed,
                    ):
                        with captured_output() as (stdout, _):
                            self.assertTrue(instance._run_init_script())
        self.assertIn("script failed", stdout.getvalue())


class PortForwardingTests(unittest.TestCase):
    def configured_instance(self, backend="iptables"):
        instance = make_sandy()
        instance.port_mappings = [("tcp", 8080, 80)]
        instance.network = make_network()
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
        self.assertEqual(
            [entry.args[0] for entry in instance.network._run_nft.call_args_list],
            ["add", "add", "add", "insert", "insert"],
        )

        instance.network._run_nft.reset_mock()
        with captured_output():
            self.assertTrue(instance._cleanup_port_forwarding_nft("10.20.30.10"))
        self.assertEqual(instance.network._run_nft.call_count, 5)
        self.assertTrue(
            all(
                entry.args[0] == "delete"
                for entry in instance.network._run_nft.call_args_list
            )
        )

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
        for method_name in (
            "_setup_port_forwarding_ipt",
            "_setup_port_forwarding_nft",
            "_cleanup_port_forwarding_ipt",
            "_cleanup_port_forwarding_nft",
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
            "_cleanup_port_forwarding_nft",
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
                with captured_output():
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
        with patch.object(instance, "_exec") as execute:
            instance.run_bash(args)
        execute.assert_called_once_with(None, login_shell=True)

        args = SimpleNamespace(bash_args=["--", "-c", "echo", "safe"])
        with patch.object(instance, "_exec") as execute:
            instance.run_bash(args)
        execute.assert_called_once_with("echo safe")

    def test_run_bash_rejects_only_c_flag(self):
        instance = make_sandy()
        with captured_output():
            with self.assertRaises(SystemExit):
                instance.run_bash(SimpleNamespace(bash_args=["-c"]))

    def test_run_exec_strips_separator_and_requires_command(self):
        instance = make_sandy()
        with patch.object(instance, "_exec") as execute:
            instance.run_exec(SimpleNamespace(exec_command=["--", "python3", "-V"]))
        execute.assert_called_once_with("python3 -V")

        with captured_output():
            with self.assertRaises(SystemExit):
                instance.run_exec(SimpleNamespace(exec_command=[]))

    def test_status_uses_machinectl(self):
        instance = make_sandy()
        with patch.object(sandy, "_run_secure_subprocess") as run:
            instance.run_status()
        run.assert_called_once_with(
            ["machinectl", "status", "--no-pager", "--full", "ai-dev"]
        )

    def test_list_sorts_and_reports_status(self):
        instance = make_sandy()
        paths = [
            "/var/lib/machines/sandy.zed",
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
        self.assertLess(output.index("alpha"), output.index("zed"))

    def test_down_powers_off(self):
        instance = make_sandy()
        with patch.object(instance, "_machine_poweroff") as poweroff:
            instance.run_down(SimpleNamespace())
        poweroff.assert_called_once_with()


class RemovalTests(unittest.TestCase):
    def test_remove_machine_dir_confirmation_and_success(self):
        instance = make_sandy()
        path = "/var/lib/machines/sandy.test"
        with patch.object(instance, "_confirm", return_value=False):
            with patch.object(sandy, "_rmtree") as rmtree:
                with captured_output():
                    instance._remove_machine_dir(path)
        rmtree.assert_not_called()

        with patch.object(instance, "_confirm", return_value=True):
            with patch.object(sandy, "_rmtree") as rmtree:
                with captured_output():
                    instance._remove_machine_dir(path)
        rmtree.assert_called_once_with(path)

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


class RunUpTests(unittest.TestCase):
    def arguments(self, **overrides):
        values = {
            "ports": None,
            "network": "host",
            "build": False,
            "persistent": False,
            "detach": True,
        }
        values.update(overrides)
        return SimpleNamespace(**values)

    def test_rejects_running_container(self):
        instance = make_sandy()
        with patch.object(instance, "_is_container_running", return_value="123"):
            with captured_output():
                with self.assertRaises(SystemExit):
                    instance.run_up(self.arguments())

    def test_rejects_ports_with_host_network(self):
        instance = make_sandy()
        with patch.object(instance, "_is_container_running", return_value=None):
            with captured_output():
                with self.assertRaises(SystemExit):
                    instance.run_up(self.arguments(ports=["tcp:8080:80"]))

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

        command = popen.call_args.args[0]
        self.assertIn("--private-users=pick", command)
        self.assertIn("--ephemeral", command)
        self.assertIn("--chdir=/home/developer", command)
        self.assertTrue(
            any(argument.startswith("--system-call-filter=") for argument in command)
        )
        self.assertFalse(
            any(argument.startswith("--network-bridge=") for argument in command)
        )
        self.assertEqual(popen.call_args.kwargs["start_new_session"], True)

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
        forwarding.assert_called_once_with()
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
            (machine / "init.sh").write_text("#!/bin/sh\n")
            instance.workspace = str(host_workspace)
            instance.shared = str(host_shared)

            with patch.object(instance, "_is_container_running", return_value=None):
                with patch.object(
                    instance,
                    "_remove_port_mappings_from_state",
                ) as remove_state:
                    with patch.object(
                        instance,
                        "_get_machine_dir",
                        return_value=str(machine),
                    ):
                        with patch.object(
                            instance,
                            "_setup_port_forwarding_rules",
                        ) as setup_forwarding:
                            with patch.object(instance, "_setfacl") as setfacl:
                                with patch.object(
                                    instance,
                                    "_run_init_script",
                                    return_value=True,
                                ) as init:
                                    with patch.object(
                                        instance,
                                        "_run_container_interactive",
                                    ) as interactive:
                                        with patch.object(
                                            instance,
                                            "_cleanup_port_forwarding_rules",
                                        ) as cleanup:
                                            with patch.object(
                                                sandy.platform,
                                                "machine",
                                                return_value="unknown-cpu",
                                            ):
                                                with captured_output() as (
                                                    stdout,
                                                    _,
                                                ):
                                                    instance.run_up(args)

        setup_forwarding.assert_called_once_with()
        self.assertEqual(setfacl.call_count, 2)
        init.assert_called_once()
        cleanup.assert_called_once_with()
        self.assertEqual(remove_state.call_count, 2)
        self.assertEqual(
            remove_state.call_args_list,
            [call("ai-dev"), call("ai-dev")],
        )
        command = interactive.call_args.args[0]
        self.assertIn(
            f"--private-users={sandy.CONTAINER_BASE_UID}:65536",
            command,
        )
        self.assertIn("--private-users-ownership=auto", command)
        self.assertIn(
            f"--bind={host_workspace}:/home/developer/workspace",
            command,
        )
        self.assertIn(
            f"--bind={host_shared}:/home/developer/shared",
            command,
        )
        self.assertIn("--chdir=/home/developer/workspace", command)
        self.assertIn(
            f"--bind-ro={machine}/init.sh:/init.sh",
            command,
        )
        self.assertIn("unknown architecture", stdout.getvalue())

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

        command = popen.call_args.args[0]
        self.assertIn("--chdir=/home/developer", command)
        self.assertFalse(any(item.startswith("--bind=") for item in command))
        self.assertIn("skipping workspace mount", stdout.getvalue())
        self.assertIn("Skipping shared mount", stdout.getvalue())

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
        build.assert_called_once_with()

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


if __name__ == "__main__":
    unittest.main()
