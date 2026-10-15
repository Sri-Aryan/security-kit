#!/usr/bin/env bash
# SecurityKit static scan: runs Semgrep with the sk-api rules and prints candidate JSON.
#
#   bash run_static.sh [project_dir]
#
# Prints {"semgrep":"missing",...} (exit 0) if Semgrep is not installed, so the agent can fall
# back to manual review. Runs fully offline: --metrics=off, local rules only.
set -u

TARGET="${1:-.}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RULES="$HERE/../rules/api.yml"

if command -v python3 >/dev/null 2>&1 && python3 -c 'import sys; sys.exit(sys.version_info[0] != 3)' 2>/dev/null; then
  PY=python3
elif command -v python >/dev/null 2>&1; then
  PY=python
else
  echo '{"semgrep":"error","results":[],"error":"Python 3 not found"}'
  exit 0
fi

if ! command -v semgrep >/dev/null 2>&1; then
  echo '{"semgrep":"missing","results":[],"hint":"pip install semgrep (or brew install semgrep), then re-run"}'
  exit 0
fi

if [ ! -d "$TARGET" ]; then
  echo "{\"semgrep\":\"error\",\"results\":[],\"error\":\"not a directory: $TARGET\"}"
  exit 0
fi

OUT="$(mktemp)"
ERR="$(mktemp)"
trap 'rm -f "$OUT" "$ERR"' EXIT

semgrep scan \
  --config "$RULES" \
  --json --quiet \
  --metrics=off --disable-version-check \
  --no-git-ignore \
  --exclude node_modules --exclude .git --exclude vendor --exclude dist --exclude build \
  --exclude .venv --exclude venv --exclude __pycache__ --exclude .securitykit \
  --exclude .claude --exclude .codex --exclude '*.min.js' --exclude coverage \
  --timeout 30 --max-target-bytes 2000000 \
  "$TARGET" >"$OUT" 2>"$ERR"

"$PY" "$HERE/semgrep_to_candidates.py" --root "$TARGET" --stderr-file "$ERR" "$OUT"
