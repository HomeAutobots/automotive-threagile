#!/usr/bin/env bash
# Validate the model YAML: parses cleanly AND is referentially self-consistent.
#
# Checks (all ERRORS fail the build; WARNINGS are printed but do not fail):
#   - parses, with no duplicate mapping keys (Threagile's Go parser rejects these)
#   - every communication-link `target` resolves to a technical-asset id
#   - every tag USED on an asset or link is declared in `tags_available`
#   - every data-asset id referenced (processed/stored/sent/received) exists
#   - every trust-boundary `technical_assets_inside` id resolves to an asset
#   - no technical asset is inside more than one trust boundary (ERROR)
#   - each IN-SCOPE technical asset is inside exactly one trust boundary (WARNING if 0)
set -euo pipefail
MODEL="${1:-model/threagile.yaml}"
python3 - "$MODEL" <<'PY'
import sys, yaml

MODEL = sys.argv[1]


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

m = yaml.load(open(MODEL), Loader=StrictLoader)
ta = m.get("technical_assets", {}) or {}
da = m.get("data_assets", {}) or {}
tb = m.get("trust_boundaries", {}) or {}
tags_avail = set(m.get("tags_available", []) or [])

asset_ids = {a["id"] for a in ta.values()}
data_ids = {d["id"] for d in da.values()}

errors, warnings = [], []

# 1) communication-link targets resolve
for name, a in ta.items():
    for lname, l in (a.get("communication_links") or {}).items():
        tgt = l.get("target")
        if tgt not in asset_ids:
            errors.append(f"link {a['id']!r} -> {lname!r}: target {tgt!r} is not a technical-asset id")

# 2) every USED tag is declared in tags_available
for name, a in ta.items():
    for t in (a.get("tags") or []):
        if t not in tags_avail:
            errors.append(f"asset {a['id']!r}: tag {t!r} not declared in tags_available")
    for lname, l in (a.get("communication_links") or {}).items():
        for t in (l.get("tags") or []):
            if t not in tags_avail:
                errors.append(f"link {a['id']!r} -> {l.get('target')!r}: tag {t!r} not declared in tags_available")
for name, d in da.items():
    for t in (d.get("tags") or []):
        if t not in tags_avail:
            errors.append(f"data-asset {d['id']!r}: tag {t!r} not declared in tags_available")

# 3) referenced data-asset ids exist
for name, a in ta.items():
    for field in ("data_assets_processed", "data_assets_stored"):
        for did in (a.get(field) or []):
            if did not in data_ids:
                errors.append(f"asset {a['id']!r}.{field}: data-asset {did!r} does not exist")
    for lname, l in (a.get("communication_links") or {}).items():
        for field in ("data_assets_sent", "data_assets_received"):
            for did in (l.get(field) or []):
                if did not in data_ids:
                    errors.append(f"link {a['id']!r} -> {l.get('target')!r}.{field}: data-asset {did!r} does not exist")

# 4) trust-boundary membership
membership = {}
for bname, b in tb.items():
    for aid in (b.get("technical_assets_inside") or []):
        if aid not in asset_ids:
            errors.append(f"trust-boundary {b.get('id')!r}: member {aid!r} is not a technical-asset id")
        membership.setdefault(aid, []).append(b.get("id"))

for aid, boundaries in membership.items():
    if len(boundaries) > 1:
        errors.append(f"asset {aid!r} is inside {len(boundaries)} trust boundaries {boundaries} (expected at most 1)")

oos = {a["id"] for a in ta.values() if a.get("out_of_scope")}
for a in ta.values():
    if a["id"] not in membership and a["id"] not in oos:
        warnings.append(f"in-scope asset {a['id']!r} is not inside any trust boundary")

for w in warnings:
    print(f"WARN: {w}", file=sys.stderr)
if errors:
    for e in errors:
        print(f"ERROR: {e}", file=sys.stderr)
    print(f"\nFAIL: {MODEL} — {len(errors)} referential error(s), {len(warnings)} warning(s)", file=sys.stderr)
    sys.exit(1)

cl = sum(len(a.get("communication_links") or {}) for a in ta.values())
print(f"OK: {MODEL} parses and is referentially consistent — {len(ta)} technical assets, "
      f"{cl} communication links, {len(da)} data assets, {len(tb)} trust boundaries, "
      f"{len(warnings)} warning(s)")
PY
