#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec "${PYTHON_BIN:-python3}" "$SCRIPT_DIR/../tools/publish_result.py" "$@"
