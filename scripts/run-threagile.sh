#!/usr/bin/env bash
# Thin wrapper around the Threagile Docker image.
# Usage: scripts/run-threagile.sh [model.yaml] [output_dir]
#
# NOTE: the official threagile/threagile image (v1.0.0, build 20240730113903) uses
# FLAG-style args (-model / -output / -verbose), NOT subcommands. An invocation like
# `threagile analyze --model ...` is silently mis-parsed (the flag parser stops at the
# `analyze` positional, ignores the flags, and falls back to the default ./threagile.yaml).
# (Verified against the official threagile/threagile image.)
# On rootful-Docker Linux hosts the output dir must be writable by the container user;
# add `--user "$(id -u):$(id -g)"` if you hit a permission-denied panic.
set -euo pipefail
MODEL="${1:-model/threagile.yaml}"
OUT="${2:-output}"
mkdir -p "$OUT"
docker run --rm -v "$(pwd):/app/work" threagile/threagile \
  -model "/app/work/${MODEL}" -output "/app/work/${OUT}" -verbose
echo "Artifacts written to ${OUT}/ (report.pdf, data-flow-diagram.png, risks.xlsx, risks.json)"
