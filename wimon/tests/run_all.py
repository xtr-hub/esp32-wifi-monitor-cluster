#!/usr/bin/env python3
"""Run every wimon test suite.

    py wimon/tests/run_all.py            # all suites
    py wimon/tests/run_all.py privacy    # only suites whose name matches

Each suite is a plain Python module exposing test_* functions and a main(), so
no test framework is required. The runner reports per-suite totals and exits
non-zero if anything failed.
"""

from __future__ import annotations

import importlib
import sys
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
SUITES = ["frames", "privacy", "decoder", "events", "daemon", "cli"]


def run_suite(name: str) -> tuple[int, int, list[str]]:
    """Return (passed, total, failure messages) for one suite module."""
    module_name = f"test_{name}"
    try:
        module = importlib.import_module(module_name)
    except Exception:
        return 0, 0, [f"could not import {module_name}:\n{traceback.format_exc()}"]

    tests = [value for key, value in sorted(vars(module).items())
             if key.startswith("test_") and callable(value)]
    passed = 0
    failures: list[str] = []
    for test in tests:
        try:
            test()
        except AssertionError as error:
            failures.append(f"{name}.{test.__name__}: {error}")
        except Exception as error:
            failures.append(
                f"{name}.{test.__name__}: {type(error).__name__}: {error}"
            )
        else:
            passed += 1
    return passed, len(tests), failures


def main() -> int:
    selected = SUITES
    if len(sys.argv) > 1:
        wanted = sys.argv[1:]
        selected = [name for name in SUITES if any(w in name for w in wanted)]
        if not selected:
            print(f"no suite matches {wanted}; suites: {', '.join(SUITES)}")
            return 2

    sys.path.insert(0, str(HERE))
    total_passed = total_tests = 0
    all_failures: list[str] = []

    for name in selected:
        passed, total, failures = run_suite(name)
        total_passed += passed
        total_tests += total
        all_failures.extend(failures)
        status = "ok" if not failures else "FAIL"
        print(f"{status:>4}  {name:<8} {passed}/{total}")

    if all_failures:
        print("\nfailures:")
        for message in all_failures:
            print(f"  - {message}")
        print(f"\n{total_passed}/{total_tests} passed")
        return 1

    print(f"\n{total_passed}/{total_tests} passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
