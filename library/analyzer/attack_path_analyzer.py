#!/usr/bin/env python3
"""
Attack-path analyzer for Threagile models.

It is NOT a separate threat model. It reads the SAME threagile.yaml, builds an
attacker-reachability graph from the technical assets and communication links
already declared in it, runs graph analysis Threagile's per-asset rule engine
cannot express (multi-hop reachability + chokepoint / min-cut), and writes the
findings back as `individual_risk_categories` so they appear in the normal
Threagile report alongside every native risk.

Graph direction
---------------
By DEFAULT the reachability graph is UNDIRECTED (``nx.Graph``): compromising a
node grants an attacker use of every link on that node in both directions, and
the emitted output is exactly what it has always been.

Pass ``--directed`` to build a ``nx.DiGraph`` instead. For every communication
link the analyzer then adds the FORWARD edge (source -> target) AND a REVERSE
edge (target -> source) -- because owning a node lets the attacker drive its
links either way -- EXCEPT when the link is a true one-way diode. A link is
treated as a diode (forward edge only, no reverse edge) when it is marked
``readonly: true`` OR carries a ``diode`` tag. Reachability and pathfinding then
follow directed paths, so a diode can sever a path that the undirected graph
would have found. Everything downstream (entries, crown jewels, per-hop
technique tagging, scoring, emit) works on either graph type.

Usage:
    python library/analyzer/attack_path_analyzer.py <model.yaml> [--out attack-paths.yaml]
        [--cutoff 8] [--directed]
"""

import argparse
import collections
import sys
import yaml
import networkx as nx

# ---- Tunable policy ---------------------------------------------------------
# Which tags mark a "crown jewel" we must keep attackers away from.
CROWN_JEWEL_TAGS = {"safety-critical"}

# Tags that make an IN-SCOPE, non-internet asset an attacker ENTRY point via
# PHYSICAL access: the OBD-II connector, the JTAG/UART debug port, removable
# media. Physical access is a precondition, so these seed at one likelihood
# bucket BELOW a remote (internet) entry (see score_path). Configurable on the
# CLI via --entry-tags; empty => remote entries only. (R9, docs/research/15.)
PHYSICAL_ENTRY_TAGS = {"physical", "obd-ii", "removable-media"}
# SENSOR spoofing: a perception sensor whose physical input an adversary can
# manipulate (camera phantom/projection, lidar/radar spoofing, adversarial
# patches -- R2, docs/research/08). No network foothold and no physical touch,
# but specialised equipment + line-of-sight, so scored like a physical entry
# (one bucket below remote). The sensor feeds the ADAS crown jewel one hop away.
SENSOR_ENTRY_TAGS = {"sensor-spoofable"}
# All non-remote entry markers (physical + sensor). entry_kind distinguishes them.
NON_REMOTE_ENTRY_TAGS = PHYSICAL_ENTRY_TAGS | SENSOR_ENTRY_TAGS

# Weakness ranking for authentication on a hop (lower = weaker = easier pivot).
AUTH_RANK = {
    "none": 0, "credentials": 1, "session-id": 1, "token": 2,
    "externalized": 2, "client-certificate": 3, "two-factor": 4,
}
# Path likelihood tops out at very-likely: score_path never emits `frequent`, so it
# is omitted here rather than left as a dead top bucket. (A future path-breadth
# escalation could reintroduce a 4th bucket -- see IMPROVEMENTS.md Phase 4.)
LIKELIHOOD_W = {"unlikely": 1, "likely": 2, "very-likely": 3}
IMPACT_W = {"low": 1, "medium": 2, "high": 3, "very-high": 4}
# Ordering for taking the max severity across a set of paths (chokepoints).
SEVERITY_ORDER = ["low", "medium", "elevated", "high", "critical"]


def _sev_rank(severity: str) -> int:
    return SEVERITY_ORDER.index(severity)

# ---- Per-hop technique tagging (SELF-CONTAINED) -----------------------------
# These are public taxonomy IDs hand-curated from frameworks/atm/{tactics,
# crosswalk}.yaml and frameworks/attack/{techniques,crosswalk}.yaml. They are
# EMBEDDED on purpose: the analyzer must run in CI WITHOUT the (gitignored)
# frameworks/ tree, so nothing here is read from disk at runtime.
#
# ATT&CK IDs verified against attack.mitre.org ICS/Enterprise/Mobile (v19.1).
# ATM IDs verified against the Auto-ISAC ATM STIX 2.1 export.
#
# Each entry: (att&ck technique ids, ATM technique ids, ATM tactic id).
# A hop is classified by its ROLE in the path (entry/pivot/bus/target) and the
# tags on the node (or the edge into it); the first matching rule wins.

# Bus-link tags that mark an in-vehicle fieldbus hop.
BUS_TAGS = {"can", "can-fd", "lin", "flexray", "sent"}
# Backbone-link tags that mark an automotive-Ethernet / SOME-IP service hop.
ETHERNET_TAGS = {"ethernet", "some-ip"}
# Node tags that mark a pivot (domain/zonal bridge).
PIVOT_TAGS = {"gateway", "zone-controller"}

# Entry-hop rules: ordered; first whose trigger tags intersect the node tags wins.
ENTRY_RULES = [
    # (trigger tags, att&ck ids, att&ck names, ATM ids, ATM names, ATM tactic)
    (
        {"v2x", "gnss", "sensor-spoofable"},
        ["T0860"], ["Wireless Compromise"],
        ["ATM-T0003", "ATM-T0004"],
        ["Manipulate Communications", "Analog Sensor Attacks"],
        "ATM-TA0001",
    ),
    (
        {"obd-ii", "physical"},
        ["T0883"], ["Internet Accessible Device"],
        ["ATM-T0010"], ["Aftermarket, Customer, or Dealer Equipment"],
        "ATM-TA0002",
    ),
    (
        {"cellular", "telematics", "charging", "ota"},
        ["T0883"], ["Internet Accessible Device"],
        ["ATM-T0012"], ["Exploit via Radio Interface"],
        "ATM-TA0002",
    ),
    (
        {"bluetooth", "wifi", "uwb", "connectivity"},
        ["T0860"], ["Wireless Compromise"],
        ["ATM-T0012"], ["Exploit via Radio Interface"],
        "ATM-TA0002",
    ),
]

# Pivot hop (intermediate gateway / zone-controller node).
PIVOT_TECH = (
    ["T0867", "T0866"],
    ["Lateral Tool Transfer", "Exploitation of Remote Services"],
    ["ATM-T0051", "ATM-T0052"],
    ["Bridge Vehicle Networks", "Exploit ECU for Lateral Movement"],
    "ATM-TA0009",
)

# Bus hop (edge into the next node tagged with a fieldbus).
BUS_TECH = (
    ["T1692.001", "T0849"],
    ["Command Message", "Masquerading"],
    ["ATM-T0070"],
    ["Modify Bus Message"],
    "ATM-TA0013",
)

# Backbone hop (edge into the next node over automotive Ethernet / SOME-IP):
# service-layer adversary-in-the-middle + sniffing + lateral movement across the
# switched backbone, distinct from a fieldbus (CAN) bus hop.
ETHERNET_TECH = (
    ["T0830"], ["Adversary-in-the-Middle"],
    ["ATM-T0052", "ATM-T0038"],
    ["Exploit ECU for Lateral Movement", "Network Sniffing"],
    "ATM-TA0009",  # Lateral Movement
)

# Target hop (terminal safety-critical node).
TARGET_TECH = (
    ["T0831", "T0880"],
    ["Manipulation of Control", "Loss of Safety"],
    ["ATM-T0070", "ATM-T0068"],
    ["Modify Bus Message", "CAN Bus Denial of Service"],
    "ATM-TA0013",
)

# Key-theft hop: emitted on a node that HOLDS key material (a data asset tagged
# `key-material`) AND must forge
# across an AUTHENTICATED onward link (so stealing keys is a real step). The
# hsm control defeats it. (Persistence techniques are intentionally NOT emitted
# yet -- see the spec's "key-theft now, persistence later" decision.)
KEYTHEFT_TECH = (
    ["T1552"], ["Unsecured Credentials"],
    ["ATM-T0039", "ATM-T0040"], ["ECU Credential Dumping", "Unsecured Credentials"],
    "ATM-TA0007",  # Credential Access
)

# ---- ECU hardening controls (node tags that break attack chains) ------------
# Each control tag -> the technique IDs (ATT&CK or ATM) it defeats, and whether
# the effect is "soft" (raise attacker cost -> lower likelihood) or "hard"
# (cryptographic/root-of-trust -> floor likelihood). The defeats sets are pinned
# to the technique IDs this analyzer actually emits per hop (see ENTRY_RULES,
# PIVOT_TECH, KEYTHEFT_TECH above) -- if an ID here is never emitted on any hop,
# the control is inert.
CONTROL_CATALOG = {
    # soft -- defense-in-depth on the node's firmware/runtime
    "binary-hardening":         {"effect": "soft", "defeats": {"T0883", "T0860", "T0866"}},
    "memory-protection":        {"effect": "soft", "defeats": {"T0866", "T0867"}},
    "attack-surface-reduction": {"effect": "soft", "defeats": {"T0883", "T0860"}},
    # ids is DETECT-ONLY, so it earns NO success-likelihood credit (empty defeats
    # => inert). AUTOSAR IdsM/IdsR report events; they do not block or drop (R10,
    # docs/research/12: 6 primary specs, zero prevent/block language). Stealthy
    # bus-off evades it outright (WeepingCAN 0% detection; CANnon error patterns
    # indistinguishable from natural faults -- R11, docs/research/11). Detection is
    # a separate axis this likelihood model does not score; inline enforcement
    # (SecOC) is already modeled via link authentication, not here.
    "ids":                      {"effect": "soft", "defeats": set()},
    # sensor-plausibility defeats discrete sensor injection (ATM-T0003/T0004). It
    # does NOT protect against KF-MSF gradual-drift GNSS spoofing: FusionRipper
    # (Shen et al., USENIX Sec 2020) exploits the fusion weighting itself, so
    # cross-modal redundancy is the attack vector, not a defense (R2b,
    # docs/research/22). Credit here is for discrete-injection detection only.
    "sensor-plausibility":      {"effect": "soft", "defeats": {"ATM-T0003", "ATM-T0004"}},
    # anti-rollback is SOFT, not a crypto root-of-trust: SUIT's sequence number "is
    # not a firmware version field" (RFC 9124 4.3.1) and Aktualizr's rollback check
    # is SQLite-backed and wipeable (R6b, docs/research/20). Inert today (its
    # techniques are not emitted); soft classification prevents future over-credit
    # once the rollback class is wired.
    "anti-rollback":            {"effect": "soft", "defeats": {"T0800", "ATM-T0021", "ATM-T0054"}},
    # hard -- hsm is ACTIVE: the key-theft hop (KEYTHEFT_TECH) is emitted in
    # tag_path, so hsm floors likelihood on paths that must forge across an
    # authenticated link. secure-boot/firmware-signing stay inert until the
    # analyzer emits their techniques (persistence -- later work).
    "hsm":                      {"effect": "hard", "defeats": {"ATM-T0039", "ATM-T0040", "T1552"}},
    "secure-boot":              {"effect": "hard", "defeats": {"T1542", "T0857"}},
    "firmware-signing":         {"effect": "hard", "defeats": {"T1693", "T0843"}},
}

# The full firmware-hardening image (all three present) is what earns -2.
FIRMWARE_HARDENING_SET = {"binary-hardening", "memory-protection", "attack-surface-reduction"}

# Likelihood ladder, weakest first; "lowering" steps toward index 0 (the floor).
# Tops out at very-likely (see LIKELIHOOD_W) -- score_path never starts above it.
LADDER = ["unlikely", "likely", "very-likely"]


def _lower(likelihood: str, buckets: int) -> str:
    """Step a likelihood down the ladder by N buckets, clamped at the floor."""
    i = LADDER.index(likelihood)
    return LADDER[max(0, i - buckets)]


def match_hop_controls(node_tags: set, hop_techs: set) -> dict:
    """Controls on this node that defeat a technique used at this hop.

    Returns {"hard": [tags], "soft": [tags]} (sorted, deterministic).
    """
    hard: list[str] = []
    soft: list[str] = []
    for tag in sorted(node_tags):
        ctl = CONTROL_CATALOG.get(tag)
        if not ctl or not (set(ctl["defeats"]) & hop_techs):
            continue
        (hard if ctl["effect"] == "hard" else soft).append(tag)
    return {"hard": hard, "soft": soft}

# ---- Path-realism weighting (SELF-CONTAINED) --------------------------------
# Auto-ISAC ATM "campaigns" (ATM-Pxxxx) are documented, real-world vehicle
# attacks; each is linked (STIX 'uses' relationships) to the ATM techniques it
# actually exercised. We embed that campaign<->technique evidence so a modeled
# attack path can be WEIGHTED by whether real attacks have chained the same
# techniques -- separating empirically-demonstrated paths from purely
# theoretical ones. Extracted from the Auto-ISAC ATM STIX 2.1 export: the 11
# campaigns that carry technique links, covering 37 of 77 techniques. EMBEDDED
# like the per-hop tags above -- nothing is read from the (gitignored)
# frameworks/ tree at runtime, so this still runs in CI.
ATM_CAMPAIGN_NAMES = {
    "ATM-P0006": "Experimental Security Assessment of BMW Cars",
    "ATM-P0016": "Losing the Car Keys",
    "ATM-P0020": "Hacking a Tesla Model S",
    "ATM-P0038": "Drive It Like You Hacked It",
    "ATM-P0082": "NFC Relay Attack on Tesla Model Y",
    "ATM-P0083": "Comprehensive Experimental Analyses of Automotive Attack Surfaces",
    "ATM-P0088": "There Will Be Glitches",
    "ATM-P0141": "Exploiting Wi-Fi Stack on Tesla Model S",
    "ATM-P0175": "Driving Down the Rabbit Hole",
    "ATM-P0193": "Unlocking the Drive",
    "ATM-P0198": "Jailbreaking an Electric Vehicle in 2023",
}
# ATM technique id -> the real campaigns that exercised it.
ATM_TECHNIQUE_CAMPAIGNS = {
    "ATM-T0002": ["ATM-P0141"],
    "ATM-T0003": ["ATM-P0038"],
    "ATM-T0006": ["ATM-P0175"],
    "ATM-T0007": ["ATM-P0082"],
    "ATM-T0008": ["ATM-P0006"],
    "ATM-T0009": ["ATM-P0038"],
    "ATM-T0010": ["ATM-P0083", "ATM-P0088"],
    "ATM-T0011": ["ATM-P0020"],
    "ATM-T0012": ["ATM-P0006", "ATM-P0083", "ATM-P0141", "ATM-P0175"],
    "ATM-T0013": ["ATM-P0006", "ATM-P0083"],
    "ATM-T0016": ["ATM-P0088"],
    "ATM-T0018": ["ATM-P0006"],
    "ATM-T0022": ["ATM-P0083"],
    "ATM-T0025": ["ATM-P0141", "ATM-P0193"],
    "ATM-T0026": ["ATM-P0006"],
    "ATM-T0028": ["ATM-P0088", "ATM-P0198"],
    "ATM-T0031": ["ATM-P0006"],
    "ATM-T0033": ["ATM-P0088"],
    "ATM-T0038": ["ATM-P0016", "ATM-P0038", "ATM-P0083", "ATM-P0175"],
    "ATM-T0040": ["ATM-P0016"],
    "ATM-T0042": ["ATM-P0006"],
    "ATM-T0043": ["ATM-P0038", "ATM-P0175"],
    "ATM-T0044": ["ATM-P0006"],
    "ATM-T0047": ["ATM-P0006"],
    "ATM-T0051": ["ATM-P0006"],
    "ATM-T0053": ["ATM-P0141"],
    "ATM-T0054": ["ATM-P0083"],
    "ATM-T0055": ["ATM-P0088"],
    "ATM-T0059": ["ATM-P0175"],
    "ATM-T0062": ["ATM-P0006"],
    "ATM-T0063": ["ATM-P0038"],
    "ATM-T0064": ["ATM-P0083"],
    "ATM-T0065": ["ATM-P0016", "ATM-P0083", "ATM-P0141"],
    "ATM-T0067": ["ATM-P0006"],
    "ATM-T0071": ["ATM-P0006", "ATM-P0083"],
    "ATM-T0076": ["ATM-P0141"],
    "ATM-T0077": ["ATM-P0083"],
}

# ---- Entry-corroboration (post-2023 demonstrated FOOTHOLDS) ------------------
# SEPARATE from ATM_TECHNIQUE_CAMPAIGNS above. Those weight the CHAIN (techniques
# a single real campaign chained all the way to the jewel). This weights the
# ENTRY hop ONLY: publicly demonstrated 2024-2025 exploits that popped an
# internet/RF-exposed component. The load-bearing finding of docs/research/06 is
# a NEGATIVE -- NONE of these demos pivoted from the exposed component into an
# in-vehicle bus or a safety function -- so this must NEVER raise a path's
# realism label or its severity above the structural baseline. Its ONLY scoring
# effect: a demonstrated foothold cannot be discounted by the entry node's OWN
# firmware-hardening soft controls (Pwn2Own popped those hardened units), so the
# entry hop's soft-control credit is dropped (see node_control_adjustment). The
# device RCEs have no canonical ATM/ATT&CK technique of their own; they
# corroborate the entry technique the analyzer already tags for that interface
# (T0883/T0860 + ATM-T0012). The cloud-API campaigns (Kia/Subaru) are MITRE
# ATT&CK *Enterprise* (T1190/T1078/T1213) -- out of this analyzer's ICS/ATM chain
# scope, recorded here as metadata only. All IDs verified vs frameworks/ 2026-07-01.
ENTRY_CAMPAIGN_NAMES = {
    "P2O-AUTO-2024": "Pwn2Own Automotive 2024 (Tesla modem root, IVI, EV chargers)",
    "P2O-AUTO-2025": "Pwn2Own Automotive 2025 (IVI, EV chargers, Automotive Grade Linux)",
    "KIA-DEALER-2024": "Kia dealer-portal telematics authz bypass -> remote command",
    "SUBARU-STARLINK-2025": "Subaru STARLINK admin account takeover -> remote command",
}
# Entry-interface trigger tag -> the demonstrated campaigns that popped it. Keyed
# by the SAME node tags ENTRY_RULES trigger on, so a path's entry node is matched
# by tag. Only interfaces with a 2024-2025 public exploit appear; absence == "no
# public exploit -> entry prior unchanged". Kept deliberately narrow: generic
# bluetooth/wifi/uwb/connectivity and the v2x/gnss sensor surfaces are NOT here
# (no 2024-2025 foothold demo in the corpus; sensor spoofing is R2, not R1).
ENTRY_CORROBORATION = {
    "cellular":     ["P2O-AUTO-2024"],                          # Tesla Modem baseband root
    "telematics":   ["P2O-AUTO-2024", "KIA-DEALER-2024",        # modem + backend command
                     "SUBARU-STARLINK-2025"],                   # injection reaching the vehicle
    "infotainment": ["P2O-AUTO-2024", "P2O-AUTO-2025"],         # Tesla IVI; Sony/Alpine/Kenwood
    # NO "charging": the Pwn2Own EV-charger RCEs popped the off-board EVSE
    # (ChargePoint/JuiceBox/Autel/Tesla Wall Connector), NOT the vehicle-side
    # charge-port controller (EVCC). Crediting the in-vehicle EVCC entry hop with
    # those results is a category error -- no vehicle-side EVCC foothold has been
    # demonstrated (R8, docs/research/14). The EVCC keeps its ordinary entry prior.
}


def entry_corroboration(node_tags: set) -> dict | None:
    """Post-2023 demonstrated-foothold evidence for an entry node, or None.

    Unions the campaigns of every entry-interface tag on the node. ENTRY-ONLY:
    this never feeds path_realism (see the ENTRY_CORROBORATION comment). Returns
    ``{"tier": "demonstrated", "campaigns": [ids...]}`` (campaigns deduped,
    deterministic) or ``None`` when no public 2024-2025 exploit corroborates the
    interface -- in which case the entry prior is left unchanged.
    """
    campaigns = []
    for tag in sorted(node_tags):
        for c in ENTRY_CORROBORATION.get(tag, ()):
            if c not in campaigns:
                campaigns.append(c)
    if not campaigns:
        return None
    return {"tier": "demonstrated", "campaigns": campaigns}


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


def _is_diode(link: dict) -> bool:
    """A link is a one-way diode when readonly or explicitly tagged 'diode'."""
    return bool(link.get("readonly")) or ("diode" in set(link.get("tags") or []))


def _add_or_merge_edge(g, src, dst, link_name, link):
    """Add an edge src->dst (or, undirected, src<->dst), collapsing parallels.

    Parallel links between the same ordered pair collapse to the WEAKEST
    authentication seen and UNION their tags, so an edge carries every bus it
    represents. For a DiGraph this is per-direction; ``has_edge`` is direction-
    aware, which is exactly what we want for the forward/reverse split.
    """
    auth = link.get("authentication", "none")
    tags = set(link.get("tags") or [])
    if g.has_edge(src, dst):
        g[src][dst]["tags"] |= tags
        if AUTH_RANK.get(auth, 0) < AUTH_RANK.get(g[src][dst]["auth"], 9):
            g[src][dst].update(auth=auth, label=link_name)
    else:
        g.add_edge(src, dst, auth=auth,
                   protocol=link.get("protocol", "unknown-protocol"),
                   label=link_name, tags=set(tags))


def build_reachability_graph(model: dict, directed: bool = False):
    """Build a graph keyed by technical-asset id.

    Undirected by default (``directed=False``): a Threagile communication link
    records DATA-FLOW direction (in a vehicle, telemetry mostly flows UP toward
    the head unit and cloud), but compromising a node grants an attacker use of
    its links in BOTH directions. Following only outgoing data-flow edges would
    make the downward command-injection path invisible.

    With ``directed=True`` the graph is a ``nx.DiGraph``: each link adds the
    forward edge AND a reverse edge (compromise grants the link both ways),
    EXCEPT true diodes (``readonly: true`` or a ``diode`` tag), which add the
    forward edge only. This honours real unidirectional gateways/diodes.
    """
    g = nx.DiGraph() if directed else nx.Graph()
    assets = model.get("technical_assets", {}) or {}
    # Data-asset ids tagged `key-material` -> a node that holds one is a key-theft
    # target (see tag_path). Matching the reserved TAG rather than a fixed id keeps
    # this portable across vehicle models (library/data-asset-taxonomy.yaml).
    g.graph["key_material_ids"] = {
        d["id"] for d in (model.get("data_assets") or {}).values()
        if "key-material" in (d.get("tags") or [])
    }

    for title, a in assets.items():
        aid = a["id"]
        data_held = (set(a.get("data_assets_processed") or [])
                     | set(a.get("data_assets_stored") or []))
        g.add_node(
            aid,
            title=title,
            tags=set(a.get("tags") or []),
            internet=bool(a.get("internet")),
            out_of_scope=bool(a.get("out_of_scope")),
            confidentiality=a.get("confidentiality", "internal"),
            integrity=a.get("integrity", "operational"),
            availability=a.get("availability", "operational"),
            data_held=data_held,
        )

    for a in assets.values():
        src = a["id"]
        for link_name, link in (a.get("communication_links") or {}).items():
            dst = link["target"]
            # Forward edge always exists.
            _add_or_merge_edge(g, src, dst, link_name, link)
            # For a DiGraph add the reverse edge too, unless the link is a
            # diode. (For an undirected Graph the edge is already bidirectional,
            # and we deliberately ignore the diode flag to preserve the
            # historical default behaviour and emitted output.)
            if directed and not _is_diode(link):
                _add_or_merge_edge(g, dst, src, link_name, link)
    return g


def edge_bus_tags(g: nx.Graph, u: str, v: str) -> set:
    """Fieldbus tags governing the u<->v edge.

    Prefers explicit link tags. When a link carries no tags (e.g. the minimal
    Jeep demo model), fall back to inferring a CAN hop from a binary-protocol
    edge between two in-vehicle (non-internet) nodes that both carry ECU/bridge
    tags. This keeps bus hops visible without inventing tags for off-bus edges.
    """
    e = g[u][v]
    explicit = e["tags"] & BUS_TAGS
    if explicit:
        return explicit
    in_vehicle_tags = {"ecu", "gateway", "zone-controller", "safety-critical"}
    nu, nv = g.nodes[u], g.nodes[v]
    if (e.get("protocol") == "binary"
            and not nu["internet"] and not nv["internet"]
            and (nu["tags"] & in_vehicle_tags) and (nv["tags"] & in_vehicle_tags)):
        return {"can"}
    return set()


def entries(g: nx.Graph, physical_entry_tags: set = NON_REMOTE_ENTRY_TAGS) -> list:
    """In-scope attacker footholds: internet-exposed (remote) PLUS assets carrying
    a non-remote entry tag -- physical (OBD-II / debug / removable media) or sensor
    (a spoofable perception sensor). Physical access and sensor spoofing are both
    first-class automotive threats, so those surfaces produce paths too."""
    return [n for n, d in g.nodes(data=True)
            if not d["out_of_scope"]
            and (d["internet"] or (d["tags"] & physical_entry_tags))]


def entry_kind(g: nx.Graph, node: str) -> str:
    """'remote' (internet-exposed), 'sensor' (spoofable perception sensor), or
    'physical' (OBD-II/debug/removable-media). Non-remote entries are scored one
    likelihood bucket lower (access/equipment precondition)."""
    d = g.nodes[node]
    if d["internet"]:
        return "remote"
    if d["tags"] & SENSOR_ENTRY_TAGS:
        return "sensor"
    return "physical"


def crown_jewels(g: nx.Graph) -> list:
    return [n for n, d in g.nodes(data=True)
            if d["tags"] & CROWN_JEWEL_TAGS and not d["out_of_scope"]]


# ---- Per-hop technique classification --------------------------------------
def _entry_tech(node_tags: set):
    for trig, ax_ids, ax_names, atm_ids, atm_names, atm_ta in ENTRY_RULES:
        if node_tags & trig:
            return (list(ax_ids), list(ax_names),
                    list(atm_ids), list(atm_names), atm_ta)
    return None


def tag_path(g: nx.Graph, path: list, jewel: str) -> list:
    """Annotate each NODE in the path with technique IDs by its role.

    Returns one dict per node (hop), each with attack_ids/atm_ids/atm_tactic
    (lists may be empty when no rule matches -> hop intentionally untagged).
    A node can accumulate several roles (e.g. the terminal node reached over a
    CAN edge is both a bus hop and the target hop); IDs are merged, order kept,
    duplicates dropped.
    """
    hops = []
    for i, node in enumerate(path):
        ndata = g.nodes[node]
        ntags = ndata["tags"]
        ax_ids, ax_names, atm_ids, atm_names = [], [], [], []
        atm_tactics = []

        def add(ax_i, ax_n, atm_i, atm_n, atm_ta):
            for x, n in zip(ax_i, ax_n):
                if x not in ax_ids:
                    ax_ids.append(x)
                    ax_names.append(n)
            for x, n in zip(atm_i, atm_n):
                if x not in atm_ids:
                    atm_ids.append(x)
                    atm_names.append(n)
            if atm_ta not in atm_tactics:
                atm_tactics.append(atm_ta)

        is_first = i == 0
        is_last = node == jewel and i == len(path) - 1
        # Entry hop: first node, internet-exposed OR a non-remote entry (physical:
        # OBD-II/debug/removable-media -> ATM-T0010; sensor: sensor-spoofable ->
        # ATM-T0003/T0004 analog sensor attack, via the same ENTRY_RULE as v2x/gnss).
        if is_first and (ndata["internet"] or (ntags & NON_REMOTE_ENTRY_TAGS)):
            t = _entry_tech(ntags)
            if t:
                add(*t)
        # Bus hop: the edge INTO this node is a fieldbus link.
        if i > 0 and edge_bus_tags(g, path[i - 1], node):
            add(*BUS_TECH)
        # Backbone hop: the edge INTO this node is automotive-Ethernet / SOME-IP.
        if i > 0 and (g[path[i - 1]][node]["tags"] & ETHERNET_TAGS):
            add(*ETHERNET_TECH)
        # Pivot hop: intermediate gateway / zone-controller.
        if not is_first and not is_last and (ntags & PIVOT_TAGS):
            add(*PIVOT_TECH)
        # Target hop: terminal safety-critical node.
        if is_last and ("safety-critical" in ntags):
            add(*TARGET_TECH)
        # Key-theft hop: node holds a `key-material`-tagged data asset AND must
        # forge across an authenticated onward link (so stealing keys is a step).
        # hsm defeats it. (Abstraction limit: treats any held key material as the
        # key for any authenticated onward link; over-claims if the node holds keys
        # unrelated to that link.)
        if i < len(path) - 1:
            nxt = path[i + 1]
            if ((ndata["data_held"] & g.graph.get("key_material_ids", set()))
                    and g[node][nxt]["auth"] != "none"):
                add(*KEYTHEFT_TECH)

        hops.append({
            "node": node,
            "title": ndata["title"],
            "attack_ids": ax_ids,
            "attack_names": ax_names,
            "atm_ids": atm_ids,
            "atm_names": atm_names,
            "atm_tactics": atm_tactics,
        })
    return hops


def _attack_chain(hops: list) -> str:
    return " -> ".join("/".join(h["attack_ids"]) if h["attack_ids"] else "-"
                       for h in hops)


def _atm_chain(hops: list) -> str:
    return " -> ".join("/".join(h["atm_ids"]) if h["atm_ids"] else "-"
                       for h in hops)


def _atm_tactic_chain(hops: list) -> str:
    return " -> ".join("/".join(h["atm_tactics"]) if h["atm_tactics"] else "-"
                       for h in hops)


# ---- Path-realism weighting -------------------------------------------------
def path_realism(hops: list) -> dict:
    """Weight a path by real-world corroboration from ATM campaigns.

    Collects the distinct ATM techniques tagged along the path and finds which
    documented ATM campaigns (ATM-Pxxxx) exercised them. ``best_overlap`` is the
    most of THIS path's techniques that any SINGLE real campaign chained
    together -- >=2 means a documented attack followed a materially similar
    chain (strong corroboration), 1 means individual techniques are attested but
    no single campaign chained them, 0 means no campaign evidence (theoretical).
    """
    techs = []
    for h in hops:
        for t in h["atm_ids"]:
            if t not in techs:
                techs.append(t)
    overlap: collections.Counter = collections.Counter()
    for t in techs:
        for c in ATM_TECHNIQUE_CAMPAIGNS.get(t, ()):
            overlap[c] += 1
    ranked = sorted(overlap.items(), key=lambda kv: (-kv[1], kv[0]))
    best = ranked[0][1] if ranked else 0
    label = ("corroborated" if best >= 2
             else "partially-corroborated" if best == 1
             else "theoretical")
    return {
        "label": label,
        "best_overlap": best,
        "campaigns": ranked,  # [(campaign_id, overlap), ...] strongest first
        "techniques_total": len(techs),
        "techniques_corroborated": sum(
            1 for t in techs if t in ATM_TECHNIQUE_CAMPAIGNS),
    }


def _realism_str(r: dict, top: int = 3) -> str:
    """Compact realism annotation for the risk title (campaign IDs only)."""
    if not r["campaigns"]:
        return f"realism: {r['label']}"
    ids = ", ".join(c for c, _ in r["campaigns"][:top])
    return (f"realism: {r['label']} "
            f"({r['techniques_corroborated']}/{r['techniques_total']} techniques "
            f"attested; {ids})")


def _entry_corroboration_str(ec: dict, entry_kind: str = "remote") -> str:
    """Entry-hop corroboration annotation for the risk title (campaign IDs only).

    ``ec`` is the ``entry_corroboration`` dict (or None) from the path's control
    adjustment. Reported SEPARATELY from realism: it grades the entry FOOTHOLD,
    not the chain (docs/research/06). A physical-access entry is flagged as such
    (it is scored one likelihood bucket lower; no remote foothold needed).
    """
    if entry_kind == "physical":
        return ("entry: physical access required (OBD-II / debug / removable "
                "media); scored one bucket below a remote entry")
    if entry_kind == "sensor":
        return ("entry: sensor spoofing (adversarial perception input -- camera/"
                "lidar/radar; demonstrated, R2); scored one bucket below a remote entry")
    if not ec:
        return "entry: no public 2024-2025 exploit (prior unchanged)"
    return f"entry: {ec['tier']} foothold ({', '.join(ec['campaigns'])})"


def _controls_str(adj: dict) -> str:
    """Compact annotation of which node controls fired and the net effect."""
    fired = [f"{m['node']}:{'/'.join(m['hard'] + m['soft'])}"
             for m in adj["matches"] if (m["hard"] or m["soft"])]
    suppressed = [f"{m['node']}:{'/'.join(m['soft_suppressed'])}"
                  for m in adj["matches"] if m.get("soft_suppressed")]
    if not fired and not suppressed:
        return "controls: none matched"
    effect = ("floored (hard control)" if adj["hard"]
              else f"-{adj['soft_buckets']} likelihood" if adj["soft_buckets"]
              else "no net effect")
    head = (f"controls: {', '.join(fired)} ({effect})" if fired
            else f"controls: none credited ({effect})")
    if suppressed:
        head += (f"; entry-hardening not credited on demonstrated foothold: "
                 f"{', '.join(suppressed)}")
    return head


# ---- Analysis ---------------------------------------------------------------
def weakest_auth_on_path(g: nx.Graph, path: list) -> str:
    worst = "two-factor"
    for u, v in zip(path, path[1:]):
        a = g[u][v]["auth"]
        if AUTH_RANK.get(a, 9) < AUTH_RANK.get(worst, 9):
            worst = a
    return worst


def node_control_adjustment(g: nx.Graph, path: list, hops_tagged: list) -> dict:
    """Per-hop control matches -> a likelihood adjustment.

    Returns {"hard": bool, "soft_buckets": 0|1|2, "matches": [per-hop dicts],
    "entry_corroboration": dict|None}.
    soft = -1 per hop with >=1 soft match; -2 only when a hop's node carries the
    COMPLETE firmware-hardening set AND at least one of those controls matched
    that hop (i.e. we're at a code-exec/priv-esc step). Path value = max across
    hops, capped at 2. Any hard match -> floor (handled by the caller).

    Exception -- demonstrated entry foothold: if the ENTRY node (hop 0) is a
    demonstrated 2024-2025 foothold (entry_corroboration), its OWN soft controls
    are NOT credited on the entry hop. Real teams popped exactly those hardened
    interfaces (Pwn2Own), so crediting the entry node's firmware-hardening there
    would over-discount an empirically-easy foothold (docs/research/06). The
    dropped controls are recorded per-hop as ``soft_suppressed`` for transparency.
    Hard (crypto root-of-trust) controls were NOT shown defeated at entry, so
    they still floor; downstream pivot/target controls are untouched.
    """
    assert len(path) == len(hops_tagged), "hops_tagged must align with path"
    entry_demo = entry_corroboration(g.nodes[path[0]]["tags"]) if path else None
    any_hard = False
    soft_buckets = 0
    matches = []
    for i, (node, hop) in enumerate(zip(path, hops_tagged)):
        ntags = g.nodes[node]["tags"]
        hop_techs = set(hop["attack_ids"]) | set(hop["atm_ids"])
        m = match_hop_controls(ntags, hop_techs)
        rec = {"node": node, **m}
        if m["hard"]:
            any_hard = True
        if m["soft"]:
            if i == 0 and entry_demo:
                rec["soft_suppressed"] = m["soft"]
                rec["soft"] = []            # not credited on a demonstrated entry
            else:
                full_fh = (FIRMWARE_HARDENING_SET <= ntags
                           and bool(FIRMWARE_HARDENING_SET & set(m["soft"])))
                soft_buckets = max(soft_buckets, 2 if full_fh else 1)
        matches.append(rec)
    return {"hard": any_hard, "soft_buckets": soft_buckets, "matches": matches,
            "entry_corroboration": entry_demo}


def score_path(g: nx.Graph, path: list, jewel: str, hops_tagged: list | None = None,
               entry_kind: str = "remote") -> dict:
    hops = len(path) - 1
    worst_auth = weakest_auth_on_path(g, path)
    # Likelihood: unauthenticated hops + short paths raise it.
    if worst_auth == "none":
        likelihood = "very-likely" if hops <= 3 else "likely"
    elif AUTH_RANK[worst_auth] <= 1:
        likelihood = "likely"
    else:
        likelihood = "unlikely"
    # Non-remote entries (physical access, or sensor spoofing) are gated on a
    # proximity/equipment precondition -> one bucket below an equivalent remote path.
    if entry_kind in ("physical", "sensor"):
        likelihood = _lower(likelihood, 1)
    base_likelihood = likelihood
    # Node hardening controls break the chain: lower (soft) or floor (hard).
    if hops_tagged is None:
        hops_tagged = tag_path(g, path, jewel)
    adj = node_control_adjustment(g, path, hops_tagged)
    if adj["hard"]:
        likelihood = "unlikely"            # floor; risk retained, never erased
    elif adj["soft_buckets"]:
        likelihood = _lower(likelihood, adj["soft_buckets"])
    # Impact: driven by the target's integrity rating (safety actuation).
    impact = "very-high" if g.nodes[jewel]["integrity"] in (
        "mission-critical", "critical") else "high"
    return {
        "hops": hops,
        "weakest_auth": worst_auth,
        "base_likelihood": base_likelihood,
        "exploitation_likelihood": likelihood,
        "exploitation_impact": impact,
        "severity": calculate_severity(likelihood, impact),
        "control_adjustment": adj,
    }


def analyze(g: nx.Graph, cutoff: int,
            physical_entry_tags: set = PHYSICAL_ENTRY_TAGS) -> dict:
    srcs, jewels = sorted(entries(g, physical_entry_tags)), sorted(crown_jewels(g))
    paths: list = []
    chokepoint_tally: dict = {}
    truncated = 0  # (entry,jewel) pairs whose only path(s) exceed --cutoff hops

    for s in srcs:
        kind = entry_kind(g, s)
        for j in jewels:
            if s == j or not nx.has_path(g, s, j):
                continue
            shortest = nx.shortest_path(g, s, j)
            all_paths = list(nx.all_simple_paths(g, s, j, cutoff=cutoff))
            if not all_paths:
                # a path exists (has_path) but every one is longer than cutoff:
                # num_paths would read 0 despite reachability -- flag it.
                truncated += 1
            hops_tagged = tag_path(g, shortest, j)
            pscore = score_path(g, shortest, j, hops_tagged, entry_kind=kind)
            paths.append({
                "entry": s, "jewel": j,
                "entry_kind": kind,
                "shortest": shortest,
                "num_paths": len(all_paths),
                "hops_tagged": hops_tagged,
                "realism": path_realism(hops_tagged),
                **pscore,
            })
            # Minimum node cut = fewest nodes whose removal severs s->j.
            # (s and j are excluded from the cut by definition.) A chokepoint's
            # severity is the WORST severity among the paths it gates (not a fixed
            # constant), so it can't over- or under-state the risk it funnels.
            try:
                for node in nx.minimum_node_cut(g, s, j):
                    rec = chokepoint_tally.setdefault(node, {"jewels": set(), "worst": None})
                    rec["jewels"].add(j)
                    if rec["worst"] is None or _sev_rank(pscore["severity"]) > _sev_rank(rec["worst"]["severity"]):
                        rec["worst"] = pscore
            except nx.NetworkXError:
                pass  # s,j adjacent -> no internal chokepoint

    return {"paths": paths, "chokepoints": chokepoint_tally,
            "entries": srcs, "jewels": jewels,
            "cutoff": cutoff, "truncated_pairs": truncated}


# ---- Emit individual_risk_categories ---------------------------------------
def _path_str(g, path):
    return " -> ".join(g.nodes[n]["title"] for n in path)


def emit_risks(g: nx.Graph, result: dict) -> dict:
    risks_identified = {}
    for p in result["paths"]:
        hops = p["hops_tagged"]
        title = (f"<b>Attack path</b> {_path_str(g, p['shortest'])} "
                 f"[{p['hops']}h, {p['num_paths']} path(s), weakest auth {p['weakest_auth']}] "
                 f"| ATT&CK: {_attack_chain(hops)} "
                 f"| ATM: {_atm_chain(hops)} "
                 f"| {_realism_str(p['realism'])} "
                 f"| {_entry_corroboration_str(p['control_adjustment']['entry_corroboration'], p['entry_kind'])} "
                 f"| {_controls_str(p['control_adjustment'])}")
        risks_identified[title] = {
            "severity": p["severity"],
            "exploitation_likelihood": p["exploitation_likelihood"],
            "exploitation_impact": p["exploitation_impact"],
            "data_breach_probability": "possible",
            "data_breach_technical_assets": [p["jewel"]],
            "most_relevant_technical_asset": p["jewel"],
        }

    choke = {}
    # Sort by paths-gated (desc) then node id (asc) so ties are deterministic
    # regardless of the min-cut set's iteration order.
    for node, rec in sorted(result["chokepoints"].items(),
                            key=lambda kv: (-len(kv[1]["jewels"]), kv[0])):
        jewels, worst = rec["jewels"], rec["worst"]
        nt = g.nodes[node]["title"]
        title = (f"<b>Chokepoint</b> {nt} gates {len(jewels)} "
                 f"safety-critical path(s) (worst gated severity: {worst['severity']})")
        choke[title] = {
            # A chokepoint is as severe as the worst path it gates -- not a fixed
            # constant. Breadth (how many paths) drives sort order + the title, not severity.
            "severity": worst["severity"],
            "exploitation_likelihood": worst["exploitation_likelihood"],
            "exploitation_impact": worst["exploitation_impact"],
            "data_breach_probability": "possible",
            "data_breach_technical_assets": sorted(jewels),
            "most_relevant_technical_asset": node,
        }

    categories = {}
    if risks_identified:
        categories["Multi-Hop Attack Path To Safety-Critical ECU"] = {
            "id": "attack-path-to-safety-critical-ecu",
            "description": "An internet-exposed OR physically-accessible "
                           "(OBD-II / debug port / removable media) asset can reach "
                           "a safety-critical ECU across one or more intermediate "
                           "nodes/buses. Physical-access entries are scored one "
                           "likelihood bucket below an equivalent remote entry. "
                           "Each risk title carries the per-hop technique chain: "
                           "the 'ATT&CK:' and 'ATM:' arrows are aligned hop-by-hop "
                           "with the path's '->' node chain (one entry per node, "
                           "'/' separates co-occurring techniques on a hop, '-' "
                           "means that hop matched no mapping rule). ATT&CK IDs are "
                           "MITRE ATT&CK v19.1 (ICS); ATM IDs are Auto-ISAC ATM "
                           "technique IDs. Roles: entry=Initial Access, "
                           "gateway/zone=Lateral Movement, fieldbus edge=Modify Bus "
                           "Message, terminal=Affect Vehicle Function. The trailing "
                           "'realism:' tag weights the path by real-world evidence: it "
                           "names the documented Auto-ISAC ATM campaigns (ATM-Pxxxx) "
                           "that exercised the path's techniques. 'corroborated' = a "
                           "single real attack chained 2+ of these techniques; "
                           "'partially-corroborated' = individual techniques are "
                           "attested but not chained in one campaign; 'theoretical' = "
                           "no campaign evidence (informational, does not change "
                           "severity). The 'entry:' tag grades the FOOTHOLD only, "
                           "kept separate from chain realism: 'demonstrated foothold' "
                           "names post-2023 public exploits (Pwn2Own Automotive 2024/"
                           "2025, Kia/Subaru telematics) that popped that exposed "
                           "interface -- none of which pivoted to a bus/safety function "
                           "(docs/research/06), so it never raises realism or severity; "
                           "its one effect is that the entry node's own firmware-"
                           "hardening is not credited as a likelihood discount on a "
                           "demonstrably-poppable interface.",
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
            "detection_logic": ("Graph reachability from internet-exposed OR "
                                "physical-entry (OBD-II/debug/removable-media) "
                                "in-scope assets to assets tagged safety-critical. "
                                f"Simple paths are enumerated up to {result['cutoff']} "
                                "hops (--cutoff); longer paths reach the target but are "
                                "not counted, so a path count of 0 means 'none within "
                                "the cutoff', not 'unreachable'."),
            "risk_assessment": "Severity from path length, weakest hop auth, and "
                               "target integrity rating; physical-access entries "
                               "start one likelihood bucket lower than remote.",
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


def path_mitigation_hint(g, path: list, chokepoints: dict) -> str:
    """One-line, concrete hardening hint naming WHERE to break this path.

    Prefers a chokepoint that actually lies on this path (the min-cut node the
    whole path funnels through); else the first gateway/zone-controller hop;
    else the first intermediate node. Names the fix, not just the node.
    """
    interior = path[1:-1] if len(path) > 2 else path[1:]
    target = None
    # 1) a gating chokepoint sitting on this very path.
    on_path_choke = [n for n in interior if n in chokepoints]
    if on_path_choke:
        target = on_path_choke[0]
    # 2) first gateway / zone-controller hop.
    if target is None:
        for n in interior:
            if g.nodes[n]["tags"] & PIVOT_TAGS:
                target = n
                break
    # 3) fall back to the first intermediate hop.
    if target is None and interior:
        target = interior[0]
    if target is None:
        return ("mitigate: place an authenticated, message-filtering boundary "
                "between the external interface and the safety-critical ECU")
    return (f"mitigate: insert an authenticated, CAN-ID-filtering gateway at "
            f"{g.nodes[target]['title']} (SecOC + secure boot) to break this path")


def print_summary(g, result):
    print(f"  entries (remote + physical): "
          f"{[g.nodes[n]['title'] for n in result['entries']]}")
    print(f"  crown jewels (safety-critical): "
          f"{[g.nodes[n]['title'] for n in result['jewels']]}\n")
    for p in result["paths"]:
        hops = p["hops_tagged"]
        print(f"  [{p['severity'].upper():8}] {g.nodes[p['jewel']]['title']:18} "
              f"<- {p['hops']} hops, {p['num_paths']} path(s), "
              f"weakest auth={p['weakest_auth']}")
        print(f"             {_path_str(g, p['shortest'])}")
        print(f"      ATT&CK:  {_attack_chain(hops)}")
        print(f"      ATM:     {_atm_chain(hops)}")
        print(f"      ATM-TA:  {_atm_tactic_chain(hops)}")
        r = p["realism"]
        lead = (f" -- top: {r['campaigns'][0][0]} "
                f"{ATM_CAMPAIGN_NAMES.get(r['campaigns'][0][0], '')}"
                if r["campaigns"] else "")
        print(f"      realism: {r['label']} "
              f"({r['techniques_corroborated']}/{r['techniques_total']} "
              f"techniques attested){lead}")
        print(f"      {path_mitigation_hint(g, p['shortest'], result['chokepoints'])}")
    print("\n  chokepoints (min node cut):")
    for node, rec in sorted(result["chokepoints"].items(),
                            key=lambda kv: (-len(kv[1]["jewels"]), kv[0])):
        print(f"    {g.nodes[node]['title']} gates {len(rec['jewels'])} jewel path(s) "
              f"(worst gated: {rec['worst']['severity']})")
    if result.get("truncated_pairs"):
        print(f"\n  NOTE: {result['truncated_pairs']} reachable (entry,jewel) pair(s) "
              f"have no path within --cutoff {result['cutoff']} hops (num_paths reads 0 "
              f"for them; raise --cutoff to enumerate).")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("model")
    ap.add_argument("--out", default="attack-paths.yaml")
    ap.add_argument("--cutoff", type=int, default=8)
    ap.add_argument(
        "--entry-tags", default="physical,obd-ii,removable-media,sensor-spoofable",
        help="Comma-separated tags that make an in-scope, non-internet asset an "
             "attacker entry point: physical access (OBD-II/debug/removable media) "
             "and sensor spoofing (sensor-spoofable). Pass an empty string for "
             "remote (internet-exposed) entries only.")
    ap.add_argument(
        "--directed", action="store_true",
        help="Build a directed reachability graph (DiGraph). Each link gets a "
             "forward AND reverse edge, except diodes (readonly:true or a "
             "'diode' tag), which stay forward-only. Default is undirected.")
    args = ap.parse_args()

    g = build_reachability_graph(load_model(args.model), directed=args.directed)
    print(f"Graph: {g.number_of_nodes()} nodes, {g.number_of_edges()} edges")
    physical_entry_tags = {t.strip() for t in args.entry_tags.split(",") if t.strip()}
    result = analyze(g, args.cutoff, physical_entry_tags=physical_entry_tags)
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
