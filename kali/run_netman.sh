#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR"
VENV_DIR="$PROJECT_DIR/.venv"
PYTHON_BIN="$VENV_DIR/bin/python"
PIP_BIN="$VENV_DIR/bin/pip"
REQ_FILE="$PROJECT_DIR/requirements.txt"
APP_FILE="$PROJECT_DIR/gui_test.py"

cd "$PROJECT_DIR"

if [[ ! -f "$PYTHON_BIN" ]]; then
  echo "[+] Creating local virtual environment..."
  python3 -m venv "$VENV_DIR"
fi

if [[ -f "$REQ_FILE" ]]; then
  echo "[+] Ensuring dependencies from requirements.txt are installed..."
  "$PIP_BIN" install -r "$REQ_FILE" >/dev/null
else
  echo "[!] requirements.txt not found. Skipping dependency install."
fi

echo "[+] Launching NetMan..."
exec "$PYTHON_BIN" "$APP_FILE"
