#!/usr/bin/env bash
# Thin wrapper around the Threagile Docker image.
# Usage: scripts/run-threagile.sh [model.yaml] [output_dir]
#
# Multi-hop merge: if the default model is used and model/attack-paths.yaml exists
# (produced by library/analyzer/attack_path_analyzer.py), this concatenates the model with that
# file into a combined model so the analyzer's individual_risk_categories (attack paths +
# chokepoints) appear in the same report. The analyzer output only adds a top-level
# `individual_risk_categories:` block that the base model lacks, so concatenation is valid
# YAML. (The released image silently ignores Threagile's `includes:` key, hence this merge.)
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
if [ "$MODEL" = "model/threagile.yaml" ] && [ -f model/attack-paths.yaml ]; then
  RUN_MODEL="${OUT}/combined-model.yaml"
  { cat model/threagile.yaml; echo; cat model/attack-paths.yaml; } > "$RUN_MODEL"
  echo "Merged model/attack-paths.yaml into ${RUN_MODEL}"
fi

docker run --rm --user "$(id -u):$(id -g)" -v "$(pwd):/app/work" "$THREAGILE_IMAGE" \
  -model "/app/work/${RUN_MODEL}" -output "/app/work/${OUT}" -verbose
echo "Artifacts written to ${OUT}/ (report.pdf, data-flow-diagram.png, risks.xlsx, risks.json)"
