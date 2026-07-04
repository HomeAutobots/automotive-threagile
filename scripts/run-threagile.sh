#!/usr/bin/env bash
# Thin wrapper around the Threagile Docker image.
# Usage: scripts/run-threagile.sh [model.yaml] [output_dir]
#
# Findings merge: for the default model, this merges the two generated
# individual_risk_categories blocks -- model/attack-paths.yaml (multi-hop paths +
# chokepoints, from attack_path_analyzer.py) and model/rules-findings.yaml (the custom
# risk rules, from rules_runner.py) -- into a combined model so BOTH appear in the same
# report. Both files carry a top-level `individual_risk_categories:` key, so they can't
# just be concatenated (duplicate key); a small Python step merges the category maps.
# (The released image silently ignores Threagile's `includes:` key, hence this merge.)
#
# NOTE: the official threagile/threagile image (v1.0.0, build 20240730113903) uses
# FLAG-style args (-model / -output / -verbose), NOT subcommands. An invocation like
# `threagile analyze --model ...` is silently mis-parsed (the flag parser stops at the
# `analyze` positional, ignores the flags, and falls back to the default ./threagile.yaml).
# `--user` makes the mounted output dir writable by the container on rootful-Docker Linux
# (and is harmless on Docker Desktop). (Verified against the official image.)
#
# The image is PINNED BY DIGEST for reproducibility (an unpinned `:latest` drifts and
# would silently change findings). This digest is what `threagile/threagile:latest`
# (== tag 0.9.1) resolved to; override with THREAGILE_IMAGE to bump it deliberately.
set -euo pipefail
MODEL="${1:-model/threagile.yaml}"
OUT="${2:-output}"
THREAGILE_IMAGE="${THREAGILE_IMAGE:-threagile/threagile@sha256:abb9eccb111a2059c4876759a24245db02ad295b1608d3a4634ec250f38d9640}"
mkdir -p "$OUT"

RUN_MODEL="$MODEL"
if [ "$MODEL" = "model/threagile.yaml" ]; then
  RUN_MODEL="${OUT}/combined-model.yaml"
  python3 - "$RUN_MODEL" <<'PY'
import os, sys, yaml
model = yaml.safe_load(open("model/threagile.yaml"))
irc = {}
for f in ("model/attack-paths.yaml", "model/rules-findings.yaml"):
    if os.path.isfile(f):
        irc.update((yaml.safe_load(open(f)) or {}).get("individual_risk_categories") or {})
if irc:
    model["individual_risk_categories"] = irc
yaml.safe_dump(model, open(sys.argv[1], "w"), sort_keys=False, width=10_000, allow_unicode=True)
print(f"Merged {len(irc)} risk categories (attack paths + custom rules) into {sys.argv[1]}")
PY
fi

docker run --rm --user "$(id -u):$(id -g)" -v "$(pwd):/app/work" "$THREAGILE_IMAGE" \
  -model "/app/work/${RUN_MODEL}" -output "/app/work/${OUT}" -verbose
echo "Artifacts written to ${OUT}/ (report.pdf, data-flow-diagram.png, risks.xlsx, risks.json)"
