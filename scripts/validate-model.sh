#!/usr/bin/env bash
# Validate the model YAML parses and (optionally) the generated attack-paths merge.
set -euo pipefail
MODEL="${1:-model/threagile.yaml}"
python3 - "$MODEL" <<'PY'
import sys, yaml


# Threagile's Go YAML parser rejects duplicate mapping keys, but PyYAML silently keeps
# the last one. Detect duplicates here so this fast check matches Threagile's strictness.
class StrictLoader(yaml.SafeLoader):
    pass


def _no_dup_keys(loader, node, deep=False):
    seen = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            raise ValueError(
                f"duplicate key {key!r} at line {key_node.start_mark.line + 1}"
            )
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep)


StrictLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _no_dup_keys
)

m = yaml.load(open(sys.argv[1]), Loader=StrictLoader)
ta = m.get("technical_assets", {}) or {}
cl = sum(len(a.get("communication_links") or {}) for a in ta.values())
print(f"OK: {sys.argv[1]} parses — {len(ta)} technical assets, {cl} communication links, "
      f"{len(m.get('data_assets', {}) or {})} data assets, "
      f"{len(m.get('trust_boundaries', {}) or {})} trust boundaries")
PY
