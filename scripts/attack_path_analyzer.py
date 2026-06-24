#!/usr/bin/env python3
"""
Attack-path analyzer for Threagile models.

It is NOT a separate threat model. It reads the SAME threagile.yaml, builds an
attacker-reachability graph from the technical assets and communication links
already declared in it, runs graph analysis Threagile's per-asset rule engine
cannot express (multi-hop reachability + chokepoint / min-cut), and writes the
findings back as `individual_risk_categories` so they appear in the normal
Threagile report alongside every native risk.

Usage:
    python attack_path_analyzer.py <model.yaml> [--out attack-paths.yaml] [--cutoff 8]
"""

import argparse
import sys
import yaml
import networkx as nx

# ---- Tunable policy ---------------------------------------------------------
# Which tags mark a "crown jewel" we must keep attackers away from.
CROWN_JEWEL_TAGS = {"safety-critical"}

# Weakness ranking for authentication on a hop (lower = weaker = easier pivot).
AUTH_RANK = {
    "none": 0, "credentials": 1, "session-id": 1, "token": 2,
    "externalized": 2, "client-certificate": 3, "two-factor": 4,
}
LIKELIHOOD_W = {"unlikely": 1, "likely": 2, "very-likely": 3, "frequent": 4}
IMPACT_W = {"low": 1, "medium": 2, "high": 3, "very-high": 4}


def calculate_severity(likelihood: str, impact: str) -> str:
    """Approximates Threagile's likelihood x impact -> severity bucketing.
    Threagile recomputes severity for its own rules; for individual risk
    categories we set it explicitly, so we mirror the combination here."""
    score = LIKELIHOOD_W[likelihood] * IMPACT_W[impact]
    if score >= 12:
        return "critical"
    if score >= 8:
        return "high"
    if score >= 4:
        return "elevated"
    if score >= 2:
        return "medium"
    return "low"


# ---- Model -> graph ---------------------------------------------------------
def load_model(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def build_reachability_graph(model: dict) -> nx.Graph:
    """Build an UNDIRECTED graph keyed by technical-asset id.

    Undirected on purpose: a Threagile communication link records DATA-FLOW
    direction (in a vehicle, telemetry mostly flows UP toward the head unit and
    cloud), but compromising a node grants an attacker use of its links in
    BOTH directions. Following only outgoing data-flow edges would make the
    downward command-injection path invisible. Swap to a DiGraph with reverse
    edges if you need to honour true unidirectional gateways/diodes.
    """
    g = nx.Graph()
    assets = model.get("technical_assets", {}) or {}

    for title, a in assets.items():
        aid = a["id"]
        g.add_node(
            aid,
            title=title,
            tags=set(a.get("tags") or []),
            internet=bool(a.get("internet")),
            out_of_scope=bool(a.get("out_of_scope")),
            confidentiality=a.get("confidentiality", "internal"),
            integrity=a.get("integrity", "operational"),
            availability=a.get("availability", "operational"),
        )

    for a in assets.values():
        src = a["id"]
        for link_name, link in (a.get("communication_links") or {}).items():
            dst = link["target"]
            auth = link.get("authentication", "none")
            # Collapse parallel links to the weakest authentication seen.
            if g.has_edge(src, dst):
                if AUTH_RANK.get(auth, 0) < AUTH_RANK.get(g[src][dst]["auth"], 9):
                    g[src][dst].update(auth=auth, label=link_name)
            else:
                g.add_edge(src, dst, auth=auth,
                           protocol=link.get("protocol", "unknown-protocol"),
                           label=link_name)
    return g


def entries(g: nx.Graph) -> list:
    """In-scope, internet-exposed assets = the remote attacker's footholds."""
    return [n for n, d in g.nodes(data=True)
            if d["internet"] and not d["out_of_scope"]]


def crown_jewels(g: nx.Graph) -> list:
    return [n for n, d in g.nodes(data=True)
            if d["tags"] & CROWN_JEWEL_TAGS and not d["out_of_scope"]]


# ---- Analysis ---------------------------------------------------------------
def weakest_auth_on_path(g: nx.Graph, path: list) -> str:
    worst = "two-factor"
    for u, v in zip(path, path[1:]):
        a = g[u][v]["auth"]
        if AUTH_RANK.get(a, 9) < AUTH_RANK.get(worst, 9):
            worst = a
    return worst


def score_path(g: nx.Graph, path: list, jewel: str) -> dict:
    hops = len(path) - 1
    worst_auth = weakest_auth_on_path(g, path)
    # Likelihood: unauthenticated hops + short paths raise it.
    if worst_auth == "none":
        likelihood = "very-likely" if hops <= 3 else "likely"
    elif AUTH_RANK[worst_auth] <= 1:
        likelihood = "likely"
    else:
        likelihood = "unlikely"
    # Impact: driven by the target's integrity rating (safety actuation).
    impact = "very-high" if g.nodes[jewel]["integrity"] in (
        "mission-critical", "critical") else "high"
    return {
        "hops": hops,
        "weakest_auth": worst_auth,
        "exploitation_likelihood": likelihood,
        "exploitation_impact": impact,
        "severity": calculate_severity(likelihood, impact),
    }


def analyze(g: nx.Graph, cutoff: int) -> dict:
    srcs, jewels = entries(g), crown_jewels(g)
    paths, chokepoint_tally = [], {}

    for s in srcs:
        for j in jewels:
            if s == j or not nx.has_path(g, s, j):
                continue
            shortest = nx.shortest_path(g, s, j)
            all_paths = list(nx.all_simple_paths(g, s, j, cutoff=cutoff))
            paths.append({
                "entry": s, "jewel": j,
                "shortest": shortest,
                "num_paths": len(all_paths),
                **score_path(g, shortest, j),
            })
            # Minimum node cut = fewest nodes whose removal severs s->j.
            # (s and j are excluded from the cut by definition.)
            try:
                for node in nx.minimum_node_cut(g, s, j):
                    chokepoint_tally.setdefault(node, set()).add(j)
            except nx.NetworkXError:
                pass  # s,j adjacent -> no internal chokepoint

    return {"paths": paths, "chokepoints": chokepoint_tally,
            "entries": srcs, "jewels": jewels}


# ---- Emit individual_risk_categories ---------------------------------------
def _path_str(g, path):
    return " -> ".join(g.nodes[n]["title"] for n in path)


def emit_risks(g: nx.Graph, result: dict) -> dict:
    risks_identified = {}
    for p in result["paths"]:
        title = (f"<b>Attack path</b> {_path_str(g, p['shortest'])} "
                 f"[{p['hops']}h, {p['num_paths']} path(s), weakest auth {p['weakest_auth']}]")
        risks_identified[title] = {
            "severity": p["severity"],
            "exploitation_likelihood": p["exploitation_likelihood"],
            "exploitation_impact": p["exploitation_impact"],
            "data_breach_probability": "possible",
            "data_breach_technical_assets": [p["jewel"]],
            "most_relevant_technical_asset": p["jewel"],
        }

    choke = {}
    for node, jewels in sorted(result["chokepoints"].items(),
                               key=lambda kv: -len(kv[1])):
        nt = g.nodes[node]["title"]
        title = (f"<b>Chokepoint</b> {nt} gates {len(jewels)} "
                 f"safety-critical path(s)")
        choke[title] = {
            "severity": "critical" if len(jewels) >= 2 else "high",
            "exploitation_likelihood": "likely",
            "exploitation_impact": "very-high",
            "data_breach_probability": "possible",
            "data_breach_technical_assets": sorted(jewels),
            "most_relevant_technical_asset": node,
        }

    categories = {}
    if risks_identified:
        categories["Multi-Hop Attack Path To Safety-Critical ECU"] = {
            "id": "attack-path-to-safety-critical-ecu",
            "description": "An internet-exposed asset can reach a safety-critical "
                           "ECU across one or more intermediate nodes/buses.",
            "impact": "Remote attacker can inject control messages affecting "
                      "vehicle safety functions (steering, braking, transmission).",
            "asvs": "V1 - Architecture, Design and Threat Modeling",
            "cheat_sheet": "https://cheatsheetseries.owasp.org/cheatsheets/"
                           "Attack_Surface_Analysis_Cheat_Sheet.html",
            "action": "Network Segmentation",
            "mitigation": "Enforce authenticated gateways between connectivity and "
                          "safety domains; filter CAN IDs; add secure boot on bridges.",
            "check": "Is every path from an external interface to a safety ECU "
                     "broken by an authenticated, filtering boundary?",
            "function": "architecture",
            "stride": "elevation-of-privilege",
            "detection_logic": "Graph reachability from internet-exposed in-scope "
                               "assets to assets tagged safety-critical.",
            "risk_assessment": "Severity from path length, weakest hop auth, and "
                               "target integrity rating.",
            "false_positives": "Paths broken by controls not modelled as links "
                               "(e.g. physical air-gap) may be false positives.",
            "model_failure_possible_reason": False,
            "cwe": 923,
            "risks_identified": risks_identified,
        }
    if choke:
        categories["Attack-Path Chokepoint"] = {
            "id": "attack-path-chokepoint",
            "description": "A single node lies on every modelled path between an "
                           "external interface and safety-critical ECUs.",
            "impact": "Compromise of this one node yields control over multiple "
                      "safety-critical functions.",
            "asvs": "V1 - Architecture, Design and Threat Modeling",
            "cheat_sheet": "https://cheatsheetseries.owasp.org/cheatsheets/"
                           "Attack_Surface_Analysis_Cheat_Sheet.html",
            "action": "Defense in Depth",
            "mitigation": "Harden the chokepoint and add a second independent "
                          "control so it is not a single point of compromise.",
            "check": "Is the chokepoint hardened and monitored?",
            "function": "architecture",
            "stride": "elevation-of-privilege",
            "detection_logic": "Minimum node cut between internet-exposed assets "
                               "and safety-critical assets.",
            "risk_assessment": "Critical when the node gates 2+ safety-critical ECUs.",
            "false_positives": "None expected.",
            "model_failure_possible_reason": False,
            "cwe": 1188,
            "risks_identified": choke,
        }
    return {"individual_risk_categories": categories}


def print_summary(g, result):
    print(f"  entries (internet-exposed): "
          f"{[g.nodes[n]['title'] for n in result['entries']]}")
    print(f"  crown jewels (safety-critical): "
          f"{[g.nodes[n]['title'] for n in result['jewels']]}\n")
    for p in result["paths"]:
        print(f"  [{p['severity'].upper():8}] {g.nodes[p['jewel']]['title']:18} "
              f"<- {p['hops']} hops, {p['num_paths']} path(s), "
              f"weakest auth={p['weakest_auth']}")
        print(f"             {_path_str(g, p['shortest'])}")
    print("\n  chokepoints (min node cut):")
    for node, jewels in sorted(result["chokepoints"].items(),
                               key=lambda kv: -len(kv[1])):
        print(f"    {g.nodes[node]['title']} gates {len(jewels)} jewel path(s)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("model")
    ap.add_argument("--out", default="attack-paths.yaml")
    ap.add_argument("--cutoff", type=int, default=8)
    args = ap.parse_args()

    g = build_reachability_graph(load_model(args.model))
    print(f"Graph: {g.number_of_nodes()} nodes, {g.number_of_edges()} edges")
    result = analyze(g, args.cutoff)
    print_summary(g, result)

    out = emit_risks(g, result)
    with open(args.out, "w") as f:
        # width very high so long risk-title keys stay on one line (a wrapped
        # multi-line key would force YAML's explicit "? key / : value" form).
        yaml.safe_dump(out, f, sort_keys=False, default_flow_style=False,
                       width=10_000, allow_unicode=True)
    print(f"\nWrote {args.out} "
          f"({sum(len(c['risks_identified']) for c in out['individual_risk_categories'].values())} "
          f"risks across {len(out['individual_risk_categories'])} categories)")


if __name__ == "__main__":
    sys.exit(main())
