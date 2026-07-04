#!/usr/bin/env python3
"""Validate a Threagile model: parse + referential integrity + enum values + vocab drift.

Importable (``validate(path)`` returns ``(errors, warnings)``) so the checks are unit
tested, and runnable as a CLI (``python3 validate_model.py [model.yaml]``). The thin
``validate-model.sh`` wrapper calls this. Checks (ERRORS fail; WARNINGS only print):
  - parses, with no duplicate mapping keys (Threagile's Go parser rejects these)
  - every communication-link `target` resolves to a technical-asset id
  - every tag USED on an asset/link/data-asset is declared in `tags_available`
  - every referenced data-asset id (processed/stored/sent/received) exists
  - every trust-boundary member id resolves; no asset in >1 boundary (ERROR),
    in-scope asset in 0 boundaries (WARNING)
  - field values are valid Threagile enums
  - the model's `tags_available` matches the canonical library/tags.yaml (for the
    shipped model/threagile.yaml, when library/tags.yaml is present)
"""
from __future__ import annotations

import os
import sys

import yaml

# ---- enum vocabularies ------------------------------------------------------
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
# Role/domain tags -- the tag-driven rules key on these; an internet-exposed compute
# asset lacking one is silently uncovered (model-lint warning).
ROLE_TAGS = {"safety-critical", "ecu", "gateway", "zone-controller", "connectivity",
             "infotainment", "telematics", "adas", "powertrain", "chassis", "body", "charging"}


class StrictLoader(yaml.SafeLoader):
    """Rejects duplicate mapping keys, matching Threagile's Go parser (PyYAML keeps
    the last silently)."""


def _no_dup_keys(loader, node, deep=False):
    seen = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            raise ValueError(f"duplicate key {key!r} at line {key_node.start_mark.line + 1}")
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep)


StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _no_dup_keys)


def load_model(path: str) -> dict:
    with open(path) as f:
        return yaml.load(f, Loader=StrictLoader)


def _check_enums(kind: str, ident: str, obj: dict, enums: dict, errors: list) -> None:
    for field, valid in enums.items():
        v = obj.get(field)
        if v is not None and v not in valid:
            errors.append(f"{kind} {ident!r}: {field}={v!r} not a valid Threagile value")


def vocab_drift_error(model_path: str, m: dict) -> str | None:
    """The shipped model's tags_available must match the canonical library/tags.yaml.
    Returns an error string, or None (only enforced for model/threagile.yaml when the
    library file is present)."""
    lib_tags = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(model_path))),
                            "library", "tags.yaml")
    if os.path.basename(model_path) != "threagile.yaml" or not os.path.isfile(lib_tags):
        return None
    canon = set((yaml.safe_load(open(lib_tags)) or {}).get("tags", []) or [])
    used = set(m.get("tags_available", []) or [])
    missing, extra = canon - used, used - canon
    if not (missing or extra):
        return None
    parts = []
    if missing:
        parts.append(f"in library/tags.yaml but NOT in tags_available: {sorted(missing)}")
    if extra:
        parts.append(f"in tags_available but NOT in library/tags.yaml: {sorted(extra)}")
    return "tags_available has drifted from library/tags.yaml — " + "; ".join(parts)


def validate(model_path: str) -> tuple[list, list]:
    """Return (errors, warnings). A non-empty errors list means the model is invalid."""
    m = load_model(model_path)
    ta = m.get("technical_assets", {}) or {}
    da = m.get("data_assets", {}) or {}
    tb = m.get("trust_boundaries", {}) or {}
    tags_avail = set(m.get("tags_available", []) or [])
    asset_ids = {a["id"] for a in ta.values()}
    data_ids = {d["id"] for d in da.values()}
    errors: list = []
    warnings: list = []

    # 1) communication-link targets resolve
    for a in ta.values():
        for lname, link in (a.get("communication_links") or {}).items():
            if link.get("target") not in asset_ids:
                errors.append(f"link {a['id']!r} -> {lname!r}: target {link.get('target')!r} is not a technical-asset id")

    # 2) every USED tag is declared
    for a in ta.values():
        for t in (a.get("tags") or []):
            if t not in tags_avail:
                errors.append(f"asset {a['id']!r}: tag {t!r} not declared in tags_available")
        for link in (a.get("communication_links") or {}).values():
            for t in (link.get("tags") or []):
                if t not in tags_avail:
                    errors.append(f"link {a['id']!r} -> {link.get('target')!r}: tag {t!r} not declared in tags_available")
    for d in da.values():
        for t in (d.get("tags") or []):
            if t not in tags_avail:
                errors.append(f"data-asset {d['id']!r}: tag {t!r} not declared in tags_available")

    # 3) referenced data-asset ids exist
    for a in ta.values():
        for field in ("data_assets_processed", "data_assets_stored"):
            for did in (a.get(field) or []):
                if did not in data_ids:
                    errors.append(f"asset {a['id']!r}.{field}: data-asset {did!r} does not exist")
        for link in (a.get("communication_links") or {}).values():
            for field in ("data_assets_sent", "data_assets_received"):
                for did in (link.get(field) or []):
                    if did not in data_ids:
                        errors.append(f"link {a['id']!r} -> {link.get('target')!r}.{field}: data-asset {did!r} does not exist")

    # 4) trust-boundary membership
    membership: dict = {}
    for b in tb.values():
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

    # 5) enum values
    for a in ta.values():
        _check_enums("asset", a["id"], a, ASSET_ENUMS, errors)
        for link in (a.get("communication_links") or {}).values():
            _check_enums("link", f"{a['id']}->{link.get('target')}", link, LINK_ENUMS, errors)
    for d in da.values():
        _check_enums("data-asset", d["id"], d, DATA_ENUMS, errors)
    for b in tb.values():
        if b.get("type") is not None and b["type"] not in BOUNDARY_TYPES:
            errors.append(f"trust-boundary {b.get('id')!r}: type={b['type']!r} not a valid Threagile value")

    # 6) model-lint: an internet-exposed process asset with no role/domain tag gets
    #    silently missed by the tag-driven rules -- warn so the tagging gap is visible.
    for a in ta.values():
        if (a.get("internet") and a.get("type") == "process"
                and not a.get("out_of_scope") and not (set(a.get("tags") or []) & ROLE_TAGS)):
            warnings.append(f"internet-exposed asset {a['id']!r} has no role/domain tag "
                            f"(rules key on role tags -- it may be silently uncovered)")

    return errors, warnings


def main(argv: list) -> int:
    model_path = argv[1] if len(argv) > 1 else "model/threagile.yaml"
    m = load_model(model_path)

    drift = vocab_drift_error(model_path, m)
    if drift:
        print(f"ERROR: {drift}", file=sys.stderr)
        print(f"FAIL: {model_path} — vocabulary drift", file=sys.stderr)
        return 1

    errors, warnings = validate(model_path)
    for w in warnings:
        print(f"WARN: {w}", file=sys.stderr)
    if errors:
        for e in errors:
            print(f"ERROR: {e}", file=sys.stderr)
        print(f"\nFAIL: {model_path} — {len(errors)} referential error(s), {len(warnings)} warning(s)", file=sys.stderr)
        return 1

    ta = m.get("technical_assets", {}) or {}
    cl = sum(len(a.get("communication_links") or {}) for a in ta.values())
    print(f"OK: {model_path} parses and is referentially consistent — {len(ta)} technical assets, "
          f"{cl} communication links, {len(m.get('data_assets', {}) or {})} data assets, "
          f"{len(m.get('trust_boundaries', {}) or {})} trust boundaries, {len(warnings)} warning(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
