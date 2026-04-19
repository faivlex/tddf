#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SUITE="${1:-}"
REVISION="${2:-0.1.35}"

case "$SUITE" in
  banking|workspace|slack|travel)
    ;;
  *)
    printf 'usage: %s {banking|workspace|slack|travel} [revision]\n' "$0" >&2
    exit 2
    ;;
esac

OUT_DIR="$ROOT/.tddf/agentdojo/$SUITE"
REGISTRY="$OUT_DIR/registry.yaml"
CONFIG="$OUT_DIR/hermes-$SUITE.yaml"
LOG_DIR="$OUT_DIR/logs"
STAMP="$(date +%Y%m%dT%H%M%S)"
LOG="$LOG_DIR/$SUITE-$STAMP.log"

mkdir -p "$OUT_DIR" "$LOG_DIR"

cat >"$CONFIG" <<EOF
target:
  kind: hermes
  cwd: $ROOT
  env: {}
  hermes:
    command_prefix:
      - hermes
    toolsets:
      - hermes-cli
      - file
    extra_args:
      - "--quiet"
      - "--max-turns"
      - "8"
    use_temp_home: true
    inject_mcp_config: true
scenarios_from_registry:
  - registry.yaml
output:
  artifacts_dir: artifacts
  write_json: true
  write_junit: true
run:
  timeout_seconds: 180
EOF

printf 'suite: %s\nrevision: %s\nconfig: %s\nlog: %s\n\n' \
  "$SUITE" "$REVISION" "$CONFIG" "$LOG"

cd "$ROOT"

uv run tddf import agentdojo \
  --suite "$SUITE" \
  --revision "$REVISION" \
  --output "$REGISTRY"

uv run tddf validate --config "$CONFIG"

time uv run tddf run \
  --config "$CONFIG" \
  --fail-severity critical \
  2>&1 | tee "$LOG"

printf '\nfinished: %s\n' "$LOG"
