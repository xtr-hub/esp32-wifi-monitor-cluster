"""Detached process control for headless capture.

`capture start --background` has to survive the terminal that launched it. On
Windows there is no fork, so the child is started with DETACHED_PROCESS and its
own log file; on POSIX it uses a double-fork-free approach by starting the child
in a new session with its output redirected.

State lives in a small run directory so any later command can find the process:

    <run-dir>/capture.pid      pid of the detached collector
    <run-dir>/capture.log      its stdout/stderr
    <run-dir>/capture.json     what it was started with

The pid file alone is not trusted: a stale pid could belong to a different
process after a reboot, so the recorded command line is checked before signalling.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path

DEFAULT_RUN_DIR = Path(".wimon")
MARKER = "wimon-capture"          # appears in the child command line


@dataclass
class CaptureState:
    pid: int
    started_at: str
    argv: list[str]
    log: str
    run_dir: str


def _pid_path(run_dir: Path) -> Path:
    return run_dir / "capture.pid"


def _state_path(run_dir: Path) -> Path:
    return run_dir / "capture.json"


def _log_path(run_dir: Path) -> Path:
    return run_dir / "capture.log"


def _command_line_of(pid: int) -> str | None:
    """Best-effort command line for a pid, or None when it is gone.

    Used to avoid killing an unrelated process that reused a stale pid.
    """
    if sys.platform == "win32":
        try:
            completed = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                 f"(Get-CimInstance Win32_Process -Filter 'ProcessId={pid}').CommandLine"],
                capture_output=True, text=True, timeout=15,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        text = completed.stdout.strip()
        return text or None
    try:
        return Path(f"/proc/{pid}/cmdline").read_text().replace("\0", " ")
    except OSError:
        try:
            os.kill(pid, 0)
        except OSError:
            return None
        return None


def is_running(run_dir: Path = DEFAULT_RUN_DIR) -> tuple[bool, int | None]:
    """Return (running, pid). A stale pid file counts as not running."""
    pid_file = _pid_path(run_dir)
    try:
        pid = int(pid_file.read_text(encoding="ascii").strip())
    except (OSError, ValueError):
        return False, None
    command = _command_line_of(pid)
    if command is None:
        return False, pid
    # The child runs the same interpreter with "capture start" in its argv.
    if "capture" not in command or "start" not in command:
        return False, pid
    return True, pid


def read_state(run_dir: Path = DEFAULT_RUN_DIR) -> CaptureState | None:
    try:
        data = json.loads(_state_path(run_dir).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    try:
        return CaptureState(**data)
    except TypeError:
        return None


def start_detached(
    cli_path: Path,
    collector_args: list[str],
    run_dir: Path = DEFAULT_RUN_DIR,
) -> tuple[bool, str]:
    """Launch the collector detached. Returns (started, message)."""
    running, pid = is_running(run_dir)
    if running:
        return False, f"capture already running (pid {pid})"

    run_dir.mkdir(parents=True, exist_ok=True)
    log = _log_path(run_dir)
    argv = [
        sys.executable, str(cli_path),
        "capture", "start", "--foreground",
        *collector_args,
    ]

    # Truncate the log so each run is self-contained.
    log.write_text("", encoding="utf-8")
    handle = open(log, "ab")
    try:
        kwargs: dict = {
            "stdin": subprocess.DEVNULL,
            "stdout": handle,
            "stderr": handle,
            "cwd": str(Path.cwd()),
            "close_fds": True,
        }
        if sys.platform == "win32":
            # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP: no console, and Ctrl+C
            # in the launching terminal does not reach the child.
            kwargs["creationflags"] = 0x00000008 | 0x00000200
        else:
            kwargs["start_new_session"] = True
        process = subprocess.Popen(argv, **kwargs)
    except OSError as error:
        handle.close()
        return False, f"cannot start collector: {error}"
    finally:
        try:
            handle.close()
        except OSError:
            pass

    _pid_path(run_dir).write_text(f"{process.pid}\n", encoding="ascii")
    state = CaptureState(
        pid=process.pid,
        started_at=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        argv=collector_args,
        log=str(log),
        run_dir=str(run_dir),
    )
    _state_path(run_dir).write_text(
        json.dumps(asdict(state), indent=2), encoding="utf-8"
    )

    # Give it a moment to fail fast on a port conflict.
    time.sleep(0.7)
    if process.poll() is not None:
        tail = ""
        try:
            tail = log.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            pass
        return False, f"collector exited immediately:\n{tail}"
    return True, f"capture started detached (pid {process.pid}), log: {log}"


def stop(run_dir: Path = DEFAULT_RUN_DIR, timeout: float = 8.0) -> tuple[bool, str]:
    """Stop the detached collector. Returns (stopped, message)."""
    running, pid = is_running(run_dir)
    if not running:
        return False, "capture is not running"
    assert pid is not None

    try:
        if sys.platform == "win32":
            subprocess.run(
                ["taskkill", "/PID", str(pid), "/T", "/F"],
                capture_output=True, timeout=15,
            )
        else:
            os.kill(pid, signal.SIGTERM)
    except (OSError, subprocess.SubprocessError) as error:
        return False, f"cannot signal pid {pid}: {error}"

    deadline = time.time() + timeout
    while time.time() < deadline:
        if _command_line_of(pid) is None:
            _cleanup(run_dir)
            return True, f"capture stopped (pid {pid})"
        time.sleep(0.2)

    return False, f"pid {pid} did not exit within {timeout:.0f}s"


def _cleanup(run_dir: Path) -> None:
    for path in (_pid_path(run_dir), _state_path(run_dir)):
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass


def log_tail(run_dir: Path = DEFAULT_RUN_DIR, lines: int = 20) -> str:
    try:
        text = _log_path(run_dir).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    return "\n".join(text.splitlines()[-lines:])
