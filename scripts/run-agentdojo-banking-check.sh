#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REVISION="${1:-0.1.35}"
OUT_DIR="$ROOT/.tddf/agentdojo/banking-check"
REGISTRY="$OUT_DIR/registry.yaml"
CONFIG="$OUT_DIR/hermes-banking-check.yaml"
LOG_DIR="$OUT_DIR/logs"
STAMP="$(date +%Y%m%dT%H%M%S)"
LOG="$LOG_DIR/banking-check-$STAMP.log"

mkdir -p "$OUT_DIR" "$LOG_DIR"

uv run python - "$REGISTRY" "$REVISION" <<'PY'
from pathlib import Path
import sys

from tddf.importers.agentdojo import AgentDojoImportRequest, AgentDojoSuite, import_agentdojo
from tddf.registry import TrapRegistry, write_trap_registry

out_path = Path(sys.argv[1])
revision = sys.argv[2]
ids = {
    "agentdojo-banking-user-task-0-injection-task-7-0008",
    "agentdojo-banking-user-task-3-injection-task-0-0028",
    "agentdojo-banking-user-task-4-injection-task-1-0038",
    "agentdojo-banking-user-task-15-injection-task-5-0141",
}
registry = import_agentdojo(
    AgentDojoImportRequest(revision=revision, suite=AgentDojoSuite.BANKING)
)
filtered = TrapRegistry(
    version=registry.version,
    source_name=registry.source_name,
    source_repo=registry.source_repo,
    source_revision=registry.source_revision,
    source_license=registry.source_license,
    generated_from=registry.generated_from,
    import_stats=dict(registry.import_stats),
    traps=[trap for trap in registry.traps if trap.id in ids],
)
write_trap_registry(out_path, filtered)
print(out_path)
print(len(filtered.traps))
PY

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

printf 'revision: %s\nconfig: %s\nlog: %s\n\n' "$REVISION" "$CONFIG" "$LOG"

cd "$ROOT"

uv run tddf validate --config "$CONFIG"

time uv run tddf run \
  --config "$CONFIG" \
  --fail-severity critical \
  2>&1 | tee "$LOG"

printf '\nfinished: %s\n' "$LOG"
