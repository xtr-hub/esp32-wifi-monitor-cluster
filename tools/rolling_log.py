#!/usr/bin/env python3
"""Run a decoder while keeping bounded, size-rotated text logs."""

import argparse
import logging
from logging.handlers import RotatingFileHandler
import subprocess
import sys
import threading
from pathlib import Path


def _file_logger(name: str, path: Path, max_bytes: int, backups: int) -> logging.Logger:
    path.parent.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    handler = RotatingFileHandler(
        path, maxBytes=max_bytes, backupCount=backups, encoding="utf-8", delay=True
    )
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    return logger


def _drain_stderr(pipe, logger: logging.Logger) -> None:
    for line in iter(pipe.readline, ""):
        logger.error(line.rstrip("\r\n"))
    pipe.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log-file", required=True, type=Path)
    parser.add_argument("--error-file", required=True, type=Path)
    parser.add_argument("--max-bytes", type=int, default=1_048_576)
    parser.add_argument("--backups", type=int, default=2)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if args.max_bytes < 1024:
        parser.error("--max-bytes must be at least 1024")
    if args.backups < 1:
        parser.error("--backups must be at least 1")
    if not command:
        parser.error("a decoder command must follow --")

    output_logger = _file_logger("esp32-decoder-output", args.log_file, args.max_bytes, args.backups)
    error_logger = _file_logger("esp32-decoder-error", args.error_file, args.max_bytes, args.backups)
    process = None
    try:
        process = subprocess.Popen(
            [sys.executable, *command],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        stderr_thread = threading.Thread(
            target=_drain_stderr, args=(process.stderr, error_logger), daemon=True
        )
        stderr_thread.start()
        for line in iter(process.stdout.readline, ""):
            output_logger.info(line.rstrip("\r\n"))
        process.stdout.close()
        return_code = process.wait()
        stderr_thread.join()
        if return_code:
            error_logger.error("decoder exited with status %s", return_code)
        return return_code
    except Exception as error:
        error_logger.exception("decoder runner failed: %s", error)
        if process and process.poll() is None:
            process.kill()
            process.wait()
        return 1
    finally:
        for logger in (output_logger, error_logger):
            for handler in logger.handlers[:]:
                handler.close()
                logger.removeHandler(handler)


if __name__ == "__main__":
    raise SystemExit(main())
