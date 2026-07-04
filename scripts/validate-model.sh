#!/usr/bin/env bash
# Thin wrapper around scripts/validate_model.py (the real, unit-tested validator).
# Validates a Threagile model: parse + referential integrity + enum values + vocab drift.
# Usage: scripts/validate-model.sh [model.yaml]   (default: model/threagile.yaml)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
exec python3 "$HERE/validate_model.py" "${1:-model/threagile.yaml}"
