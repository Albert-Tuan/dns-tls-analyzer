#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
if [[ ! -x .venv/bin/python ]]; then
  echo 'Run first: python3 -m venv .venv && .venv/bin/python -m pip install -r requirements-lock.txt' >&2
  exit 2
fi
exec .venv/bin/python -m scripts.run_all
