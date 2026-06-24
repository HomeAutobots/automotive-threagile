#!/usr/bin/env bash
# Validate the model YAML parses and (optionally) the generated attack-paths merge.
set -euo pipefail
MODEL="${1:-model/threagile.yaml}"
python3 - "$MODEL" <<'PY'
import sys, yaml
m = yaml.safe_load(open(sys.argv[1]))
ta = m.get("technical_assets", {}) or {}
cl = sum(len(a.get("communication_links") or {}) for a in ta.values())
print(f"OK: {sys.argv[1]} parses — {len(ta)} technical assets, {cl} communication links, "
      f"{len(m.get('data_assets', {}) or {})} data assets, "
      f"{len(m.get('trust_boundaries', {}) or {})} trust boundaries")
PY
