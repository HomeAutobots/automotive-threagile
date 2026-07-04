#!/usr/bin/env python3
"""Evaluate the custom YAML risk rules in Python and emit individual_risk_categories.

The released Threagile image does not auto-load external YAML risk rules (it ignores
`includes:` and exposes no rules flag), so the 16 rules under library/custom-risk-rules/
are harness-validated but produce zero findings in the shipped report. This runner closes
that gap: it emits their findings as an `individual_risk_categories` block that
run-threagile.sh merges into the report -- the same mechanism as attack-paths.yaml.

Design: rule METADATA (id/title/severity/description/...) is loaded FROM the YAML files
(single source of truth); only the MATCH logic is ported to Python (one predicate per
rule, translated directly from each rule's `match:` block). The YAML rules remain the
harness-validated spec; a committed rules-findings.yaml + CI drift check guards this
runner, and the cmd/script harness independently validates the YAML rules on the fixture.
"""
from __future__ import annotations

import glob
import os
import sys

import yaml

# ---- severity (mirrors the analyzer / Threagile bucketing) ------------------
_LW = {"unlikely": 1, "likely": 2, "very-likely": 3, "frequent": 4}
_IW = {"low": 1, "medium": 2, "high": 3, "very-high": 4}


def calculate_severity(likelihood: str, impact: str) -> str:
    score = _LW[likelihood] * _IW[impact]
    if score >= 12:
        return "critical"
    if score >= 8:
        return "high"
    if score >= 4:
        return "elevated"
    if score >= 2:
        return "medium"
    return "low"


# ---- model helpers ----------------------------------------------------------
BUS = {"can", "can-fd", "lin", "flexray"}
REAL_AUTH = {"credentials", "session-id", "token", "client-certificate",
             "two-factor", "externalized"}
ENCRYPTED_PROTO = {"https", "wss", "binary-encrypted", "text-encrypted",
                   "ssh", "ssh-tunnel", "sftp", "scp", "ftps"}
EXPOSED = {"connectivity", "telematics", "infotainment", "external", "v2x"}
SAFETY_DOMAIN = {"safety-critical", "powertrain", "chassis"}
FILTER = {"gateway", "zone-controller"}


def _t(x) -> set:
    return set(x.get("tags") or [])


def _no_auth(link: dict) -> bool:
    return (link.get("authentication") or "none") not in REAL_AUTH


def _links(a: dict):
    return (a.get("communication_links") or {}).values()


class Ctx:
    """Precomputed lookups shared by the matchers."""
    def __init__(self, model: dict):
        self.assets = model.get("technical_assets") or {}
        self.by_id = {a["id"]: a for a in self.assets.values()}
        das = (model.get("data_assets") or {}).values()
        self.key_material = {d["id"] for d in das if "key-material" in (d.get("tags") or [])}
        self.firmware = {d["id"] for d in das if "firmware-image" in (d.get("tags") or [])}

    def target_tags(self, link: dict) -> set:
        return _t(self.by_id.get(link.get("target"), {}))

    def holds(self, a: dict, ids: set) -> bool:
        held = set(a.get("data_assets_processed") or []) | set(a.get("data_assets_stored") or [])
        return bool(held & ids)


# ---- match predicates (one per rule, translated from each `match:` block) ----
def _m_unauth_safety_bus(a, c):
    return any((_t(lk) & BUS) and _no_auth(lk)
               and ("safety-critical" in _t(a) or "safety-critical" in c.target_tags(lk))
               for lk in _links(a))


def _m_missing_secoc(a, c):
    return any((_t(lk) & BUS) and (lk.get("authentication") or "none") != "credentials"
               and ("safety-critical" in _t(a) or "safety-critical" in c.target_tags(lk))
               for lk in _links(a))


def _m_cross_domain(a, c):
    if not (_t(a) & EXPOSED) or (_t(a) & FILTER):
        return False
    return any(_no_auth(lk) and (c.target_tags(lk) & SAFETY_DOMAIN)
               and not (c.target_tags(lk) & FILTER) for lk in _links(a))


def _m_gateway_bridge(a, c):
    return bool(_t(a) & FILTER) and any(_no_auth(lk) for lk in _links(a))


def _m_internet_unencrypted(a, c):
    return (a.get("internet") and (_t(a) & {"ecu", "telematics", "infotainment"})
            and (a.get("encryption") or "none") == "none")


def _m_internet_no_secure_boot(a, c):
    return (a.get("internet")
            and (_t(a) & {"ecu", "telematics", "infotainment", "connectivity"})
            and "secure-boot" not in _t(a))


def _m_unauth_diagnostics(a, c):
    return any((_t(lk) & {"obd-ii", "doip"}) and _no_auth(lk) for lk in _links(a))


def _m_debug_port(a, c):
    return any("physical" in _t(lk) and _no_auth(lk) for lk in _links(a))


def _m_unencrypted_ota(a, c):
    return any("ota" in _t(lk) and not lk.get("vpn")
               and (lk.get("protocol") or "") not in ENCRYPTED_PROTO for lk in _links(a))


def _m_iso15118_server_only(a, c):
    return any("iso15118" in _t(lk) and "tls-mutual" not in _t(lk)
               and (lk.get("authentication") or "none") != "client-certificate"
               for lk in _links(a))


def _m_someip_unauth(a, c):
    return any("some-ip" in _t(lk) and _no_auth(lk) for lk in _links(a))


def _m_no_redundancy(a, c):
    return "safety-critical" in _t(a) and not a.get("redundant")


def _m_relay_passive_entry(a, c):
    return any((_t(lk) & {"uwb", "bluetooth"}) and "body" in c.target_tags(lk)
               and "distance-bounding" not in _t(lk) for lk in _links(a))


def _m_unprotected_key_storage(a, c):
    return c.holds(a, c.key_material) and "hsm" not in _t(a)


def _m_removable_media(a, c):
    return any("removable-media" in _t(lk) and _no_auth(lk) for lk in _links(a))


def _m_unverified_firmware(a, c):
    return c.holds(a, c.firmware) and "firmware-signing" not in _t(a)


MATCHERS = {
    "unauthenticated-safety-bus-link": _m_unauth_safety_bus,
    "missing-secoc-on-safety-bus": _m_missing_secoc,
    "cross-domain-link-no-filter": _m_cross_domain,
    "unauthenticated-gateway-bridge": _m_gateway_bridge,
    "internet-exposed-ecu-unencrypted": _m_internet_unencrypted,
    "internet-exposed-ecu-no-secure-boot": _m_internet_no_secure_boot,
    "reachable-unauthenticated-diagnostics": _m_unauth_diagnostics,
    "reachable-debug-port": _m_debug_port,
    "unencrypted-ota-channel": _m_unencrypted_ota,
    "iso15118-server-only-tls": _m_iso15118_server_only,
    "unauthenticated-someip-service-link": _m_someip_unauth,
    "safety-function-without-redundancy": _m_no_redundancy,
    "relay-vulnerable-passive-entry": _m_relay_passive_entry,
    "unprotected-key-storage": _m_unprotected_key_storage,
    "removable-media-ingress": _m_removable_media,
    "unverified-firmware-update": _m_unverified_firmware,
}

_RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "custom-risk-rules")
_CAT_FIELDS = ("description", "impact", "asvs", "cheat_sheet", "action", "mitigation",
               "check", "function", "stride", "detection_logic", "risk_assessment",
               "false_positives")


def load_rules(rules_dir: str = _RULES_DIR) -> dict:
    """Load each rule YAML's metadata, keyed by rule id. Skips any without a matcher."""
    rules = {}
    for path in sorted(glob.glob(os.path.join(rules_dir, "*.yaml"))):
        r = yaml.safe_load(open(path))
        if not r or r.get("id") not in MATCHERS:
            continue
        rules[r["id"]] = r
    return rules


def _clean(s):
    return " ".join(str(s).split()) if s is not None else s


def run(model: dict, rules_dir: str = _RULES_DIR) -> dict:
    """Evaluate all rules against the model, return an individual_risk_categories dict."""
    ctx = Ctx(model)
    rules = load_rules(rules_dir)
    categories = {}
    for rid, rule in rules.items():
        matcher = MATCHERS[rid]
        data = rule.get("risk", {}).get("data", {})
        likelihood = data.get("exploitation_likelihood", "likely")
        impact = data.get("exploitation_impact", "medium")
        breach = data.get("data_breach_probability", "possible")
        title_tpl = data.get("title", "")
        risks = {}
        for name, a in ctx.assets.items():
            if a.get("out_of_scope") or not matcher(a, ctx):
                continue
            title = title_tpl.replace("{tech_asset.title}", name).replace("{tech_asset.id}", a["id"])
            risks[title] = {
                "severity": calculate_severity(likelihood, impact),
                "exploitation_likelihood": likelihood,
                "exploitation_impact": impact,
                "data_breach_probability": breach,
                "data_breach_technical_assets": [a["id"]],
                "most_relevant_technical_asset": a["id"],
            }
        if not risks:
            continue
        cat = {"id": rid}
        for f in _CAT_FIELDS:
            if rule.get(f) is not None:
                cat[f] = _clean(rule[f])
        cat["model_failure_possible_reason"] = False
        if rule.get("cwe") is not None:
            cat["cwe"] = rule["cwe"]
        cat["risks_identified"] = risks
        categories[rule.get("title", rid)] = cat
    return {"individual_risk_categories": categories}


def main(argv: list) -> int:
    model_path = argv[1] if len(argv) > 1 else "model/threagile.yaml"
    out_path = "rules-findings.yaml"
    if "--out" in argv:
        out_path = argv[argv.index("--out") + 1]
    model = yaml.safe_load(open(model_path))
    out = run(model)
    with open(out_path, "w") as f:
        yaml.safe_dump(out, f, sort_keys=False, default_flow_style=False,
                       width=10_000, allow_unicode=True)
    n = sum(len(c["risks_identified"]) for c in out["individual_risk_categories"].values())
    print(f"Wrote {out_path} ({n} findings across "
          f"{len(out['individual_risk_categories'])} rule categories)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
