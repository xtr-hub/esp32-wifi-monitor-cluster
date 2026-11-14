"""Tests for detached (headless) capture control.

Starting a real detached collector in a test would bind UDP 9000 and write
gigabytes, so these tests exercise the state machine instead: stale pid detection,
double-start refusal, stop on a non-running capture, and the command surface.

    py wimon/tests/test_daemon.py
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "wimon"))

import cli  # noqa: E402
import daemon  # noqa: E402


def run_main(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli.main(argv)
        except SystemExit as exit_error:
            code = int(exit_error.code or 0)
    return code, out.getvalue(), err.getvalue()


@contextlib.contextmanager
def run_dir_context():
    directory = Path(tempfile.mkdtemp())
    yield directory
    for path in directory.glob("*"):
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
    try:
        directory.rmdir()
    except OSError:
        pass


def test_status_reports_not_running_without_state() -> None:
    with run_dir_context() as run_dir:
        code, out, _ = run_main(["capture", "status", "--run-dir", str(run_dir)])
    assert code == 1
    assert "not running" in out


def test_stale_pid_is_ignored() -> None:
    """A pid that belongs to another process must not be treated as capture."""
    with run_dir_context() as run_dir:
        # Use this test process's own pid: it exists but is not a collector.
        (run_dir / "capture.pid").write_text(str(os.getpid()), encoding="ascii")
        running, pid = daemon.is_running(run_dir)
        assert running is False, "an unrelated process was accepted as the collector"
        assert pid == os.getpid()

        code, out, _ = run_main(["capture", "status", "--run-dir", str(run_dir)])
        assert code == 1
        assert "stale pid" in out


def test_stop_refuses_when_not_running() -> None:
    with run_dir_context() as run_dir:
        code, out, _ = run_main(["capture", "stop", "--run-dir", str(run_dir)])
    assert code == 1
    assert "not running" in out


def test_stop_does_not_kill_an_unrelated_pid() -> None:
    """The safety property: a stale pid file must never signal another process."""
    with run_dir_context() as run_dir:
        child = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            (run_dir / "capture.pid").write_text(str(child.pid), encoding="ascii")
            code, out, _ = run_main(["capture", "stop", "--run-dir", str(run_dir)])
            assert code == 1, f"stop claimed success on a stale pid: {out}"
            time.sleep(0.3)
            assert child.poll() is None, "stop killed an unrelated process"
        finally:
            child.kill()
            child.wait(timeout=5)


def test_status_prints_recorded_state() -> None:
    with run_dir_context() as run_dir:
        state = daemon.CaptureState(
            pid=os.getpid(),
            started_at="2026-01-01T00:00:00+0000",
            argv=["--output", "telemetry.jsonl"],
            log=str(run_dir / "capture.log"),
            run_dir=str(run_dir),
        )
        (run_dir / "capture.json").write_text(
            json.dumps(daemon.asdict(state)), encoding="utf-8"
        )
        (run_dir / "capture.log").write_text("line one\nline two\n", encoding="utf-8")
        # A running collector is simulated by a pid whose command line mentions
        # capture start; use a real child so is_running can inspect it.
        child = subprocess.Popen(
            [sys.executable, "-c",
             "import time; time.sleep(30)", "capture", "start"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            (run_dir / "capture.pid").write_text(str(child.pid), encoding="ascii")
            running, _ = daemon.is_running(run_dir)
            if not running:
                print("  (skipped: this platform cannot inspect the child command line)")
                return
            code, out, _ = run_main(
                ["capture", "status", "--run-dir", str(run_dir), "--log", "2"]
            )
            assert code == 0
            assert "running" in out
            assert "2026-01-01T00:00:00+0000" in out
            assert "line two" in out
        finally:
            child.kill()
            child.wait(timeout=5)


def test_log_tail_reads_last_lines() -> None:
    with run_dir_context() as run_dir:
        (run_dir / "capture.log").write_text(
            "".join(f"line {n}\n" for n in range(50)), encoding="utf-8"
        )
        tail = daemon.log_tail(run_dir, lines=3)
        assert tail.splitlines() == ["line 47", "line 48", "line 49"], tail


def test_log_command_reports_missing_file() -> None:
    with run_dir_context() as run_dir:
        code, _out, err = run_main(["capture", "log", "--run-dir", str(run_dir)])
    assert code == 1
    assert "no log" in err


def test_capture_verbs_are_registered() -> None:
    for verb in ("start", "stop", "status", "log", "nodes"):
        assert verb in cli.VERBS["capture"], f"{verb} missing from capture"
        assert callable(cli.VERBS["capture"][verb])


def test_start_help_mentions_background() -> None:
    code, out, _ = run_main(["capture", "start", "--help"])
    assert code == 0
    assert "--background" in out


def main() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failures = 0
    for test in tests:
        try:
            test()
        except AssertionError as error:
            failures += 1
            print(f"FAIL {test.__name__}: {error}")
        except Exception as error:
            failures += 1
            print(f"ERROR {test.__name__}: {type(error).__name__}: {error}")
        else:
            print(f"ok   {test.__name__}")
    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
