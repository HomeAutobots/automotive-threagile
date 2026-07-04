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

# Vocabulary-drift guard: the model's tags_available must match the canonical
# library/tags.yaml (the library contract). Only enforced for the shipped model,
# and only when the library file is present (adopters may vendor it elsewhere).
import os
# library/tags.yaml sits next to model/ at the repo root (model/threagile.yaml ->
# ../library/tags.yaml). Resolve relative to MODEL so cwd does not matter.
_lib_tags = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(MODEL))),
                         "library", "tags.yaml")
if os.path.basename(MODEL) == "threagile.yaml" and os.path.isfile(_lib_tags):
    canon = set((yaml.safe_load(open(_lib_tags)) or {}).get("tags", []) or [])
    missing = canon - tags_avail
    extra = tags_avail - canon
    if missing or extra:
        if missing:
            print(f"ERROR: tags in library/tags.yaml but NOT in model tags_available: {sorted(missing)}", file=sys.stderr)
        if extra:
            print(f"ERROR: tags in model tags_available but NOT in library/tags.yaml: {sorted(extra)}", file=sys.stderr)
        print("FAIL: model tags_available has drifted from library/tags.yaml", file=sys.stderr)
        sys.exit(1)

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

# 5) field values are valid Threagile enums (a typo like `mision-critical` passes the
#    fast parse + referential checks and only fails later in the slow Docker job).
_CIA = {"archive", "operational", "important", "critical", "mission-critical"}
_CONF = {"public", "internal", "restricted", "confidential", "strictly-confidential"}
_USAGE = {"business", "devops"}
ASSET_ENUMS = {
    "type": {"external-entity", "process", "datastore"},
    "size": {"system", "service", "application", "component"},
    "machine": {"physical", "virtual", "container", "serverless"},
    "encryption": {"none", "transparent", "data-with-symmetric-shared-key",
                   "data-with-asymmetric-shared-key", "data-with-enduser-individual-key"},
    "usage": _USAGE, "confidentiality": _CONF, "integrity": _CIA, "availability": _CIA,
}
DATA_ENUMS = {
    "usage": _USAGE, "quantity": {"very-few", "few", "many", "very-many"},
    "confidentiality": _CONF, "integrity": _CIA, "availability": _CIA,
}
LINK_ENUMS = {
    "authentication": {"none", "credentials", "session-id", "token",
                       "client-certificate", "two-factor", "externalized"},
    "authorization": {"none", "technical-user", "enduser-identity-propagation"},
    "usage": _USAGE,
}
BOUNDARY_TYPES = {"network-on-prem", "network-dedicated-hoster", "network-virtual-lan",
                  "network-cloud-provider", "network-cloud-security-group",
                  "network-policy-namespace-isolation", "execution-environment"}


def _check_enums(kind, ident, obj, enums):
    for field, valid in enums.items():
        v = obj.get(field)
        if v is not None and v not in valid:
            errors.append(f"{kind} {ident!r}: {field}={v!r} not a valid Threagile value")


for name, a in ta.items():
    _check_enums("asset", a["id"], a, ASSET_ENUMS)
    for lname, l in (a.get("communication_links") or {}).items():
        _check_enums("link", f"{a['id']}->{l.get('target')}", l, LINK_ENUMS)
for name, d in da.items():
    _check_enums("data-asset", d["id"], d, DATA_ENUMS)
for bname, b in tb.items():
    if b.get("type") is not None and b["type"] not in BOUNDARY_TYPES:
        errors.append(f"trust-boundary {b.get('id')!r}: type={b['type']!r} not a valid Threagile value")

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
