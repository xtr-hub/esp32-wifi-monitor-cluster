#!/usr/bin/env sh
# wimon launcher for macOS and Linux.
#
# Resolves the repository root so the default data paths (captures/,
# telemetry.jsonl, sdkconfig) behave the same as the Windows launcher.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$here"

exec "${PYTHON:-python3}" wimon/cli.py "$@"
