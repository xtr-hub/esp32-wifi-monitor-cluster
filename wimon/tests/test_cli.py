"""Tests for the command-line front end and the node HTTP client.

The CLI must dispatch `noun verb` correctly and forward arguments untouched;
every module's main() must also still work standalone. None of these tests need
network access: the node client is exercised against a local HTTP server bound to
an ephemeral port.

    py wimon/tests/test_cli.py
"""

from __future__ import annotations

import contextlib
import io
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "wimon"))

import cli  # noqa: E402


def run_main(argv: list[str]) -> tuple[int, str, str]:
    """Call cli.main with captured stdout/stderr."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli.main(argv)
        except SystemExit as exit_error:
            code = int(exit_error.code or 0)
    return code, out.getvalue(), err.getvalue()


# --------------------------------------------------------------------------
# dispatch
# --------------------------------------------------------------------------
def test_split_keeps_noun_and_verb_separate() -> None:
    head, tail = cli._split(["frames", "show", "a.pcap", "--ports", "1"])
    assert head == ["frames", "show"], head
    assert tail == ["a.pcap", "--ports", "1"], tail


def test_split_stops_at_first_flag() -> None:
    head, tail = cli._split(["node", "status", "--node", "aa"])
    assert head == ["node", "status"], head
    assert tail == ["--node", "aa"], tail


def test_no_arguments_prints_help() -> None:
    code, out, _ = run_main([])
    assert code == 0
    assert "capture" in out and "frames" in out and "node" in out


def test_version() -> None:
    code, out, _ = run_main(["--version"])
    assert code == 0
    assert "wimon" in out


def test_unknown_noun_is_rejected() -> None:
    code, _, err = run_main(["nonsense"])
    assert code == 2, code
    assert "unknown noun" in err


def test_unknown_verb_is_rejected() -> None:
    code, _, err = run_main(["frames", "nonsense"])
    assert code == 2, code
    assert "unknown command" in err


def test_noun_without_verb_explains_verbs() -> None:
    code, _, err = run_main(["capture"])
    assert code == 2, code
    assert "start" in err and "nodes" in err


def test_dispatches_to_the_right_handler() -> None:
    """Replace a verb and confirm the CLI reaches it with its own arguments."""
    received: list[list[str]] = []
    original = cli.VERBS["frames"]["show"]
    cli.VERBS["frames"]["show"] = lambda argv: (received.append(argv), 0)[1]
    try:
        code, _, _ = run_main(["frames", "show", "a.pcap", "--ports", "4039"])
    finally:
        cli.VERBS["frames"]["show"] = original
    assert code == 0
    assert received == [["a.pcap", "--ports", "4039"]], received


def test_every_registered_verb_is_callable() -> None:
    for noun, verbs in cli.VERBS.items():
        for verb, handler in verbs.items():
            assert callable(handler), f"{noun} {verb} is not callable"


# --------------------------------------------------------------------------
# capture nodes
# --------------------------------------------------------------------------
def write_telemetry(path: Path) -> None:
    rows = [
        {"node": "aa:bb:cc:dd:ee:01", "name": "n1", "type": "status",
         "ip": "10.0.0.11", "received_at": "2026-01-01T00:00:00+00:00"},
        # A later frames report for the same node has no IP and must not erase it.
        {"node": "aa:bb:cc:dd:ee:01", "name": "n1", "type": "frames",
         "channels": [{"channel": 157}], "received_at": "2026-01-01T00:00:05+00:00"},
        {"node": "aa:bb:cc:dd:ee:02", "name": "n2", "type": "frames",
         "channels": [{"channel": 36}], "received_at": "2026-01-01T00:00:02+00:00"},
        {"node": "aa:bb:cc:dd:ee:02", "name": "n2", "type": "status",
         "ip": "10.0.0.12", "received_at": "2026-01-01T00:00:03+00:00"},
    ]
    path.write_text(
        "\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8"
    )


def test_capture_nodes_merges_status_and_frames() -> None:
    import tempfile

    directory = Path(tempfile.mkdtemp())
    telemetry = directory / "telemetry.jsonl"
    write_telemetry(telemetry)
    code, out, _ = run_main(["capture", "nodes", "--telemetry", str(telemetry)])
    assert code == 0, code
    # Both nodes keep their IP even though a frames report arrived later.
    assert "10.0.0.11" in out, out
    assert "10.0.0.12" in out, out


def test_capture_nodes_json_output() -> None:
    import tempfile

    directory = Path(tempfile.mkdtemp())
    telemetry = directory / "telemetry.jsonl"
    write_telemetry(telemetry)
    code, out, _ = run_main(["capture", "nodes", "--telemetry", str(telemetry), "--json"])
    assert code == 0
    data = json.loads(out)
    assert len(data) == 2
    assert any(row.get("ip") == "10.0.0.11" for row in data)


def test_capture_nodes_missing_file() -> None:
    code, _, err = run_main(["capture", "nodes", "--telemetry", "does-not-exist.jsonl"])
    assert code == 1
    assert "no telemetry file" in err


# --------------------------------------------------------------------------
# node client against a local server
# --------------------------------------------------------------------------
class _Handler(BaseHTTPRequestHandler):
    status_payload = {"node": "aa:bb", "name": "test", "ip": "127.0.0.1",
                      "channel": 157, "max_kbps": 64, "collector_ip": "10.0.0.1",
                      "collector_port": 9000, "hostname": "x.local"}
    last_body: bytes | None = None
    last_token: str | None = None

    def do_GET(self):  # noqa: N802 - required by BaseHTTPRequestHandler
        body = json.dumps(self.status_payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        type(self).last_body = self.rfile.read(length)
        type(self).last_token = self.headers.get("X-OTA-Token")
        body = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # silence the test output
        pass


@contextlib.contextmanager
def local_server():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()


def test_node_status_reads_status() -> None:
    import node

    with local_server() as port:
        code, out, _ = run_main(["node", "status", "127.0.0.1", "--port", str(port)])
    assert code == 0, code
    assert "test" in out and "157" in out


def test_node_config_requires_token_for_writes() -> None:
    import tempfile

    import node

    directory = Path(tempfile.mkdtemp())
    config = directory / "sdkconfig"
    config.write_text('CONFIG_MONITOR_OTA_TOKEN="secret-token"\n', encoding="utf-8")
    with local_server() as port:
        code, _, err = run_main([
            "node", "config", "127.0.0.1", "--port", str(port),
            "--config-file", str(config), "--max-kbps", "32",
        ])
    assert code == 0, (code, err)
    assert _Handler.last_token == "secret-token"
    assert json.loads(_Handler.last_body or b"{}") == {"max_kbps": 32}


def test_node_config_rejects_missing_token_file() -> None:
    code, _, err = run_main([
        "node", "config", "127.0.0.1", "--config-file", "no-such-sdkconfig",
        "--max-kbps", "32",
    ])
    assert code == 2, code
    assert "cannot read" in err


def test_node_status_reports_unreachable_host() -> None:
    # Port 1 on loopback refuses immediately on all platforms used here.
    code, _, err = run_main(["node", "status", "127.0.0.1", "--port", "1", "--timeout", "1"])
    assert code == 1, code
    assert "FAILED" in err


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
