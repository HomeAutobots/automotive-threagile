"""Unit tests for scripts/attack_path_analyzer.py.

All models are small INLINE dicts (no external files, no frameworks/ tree).
Tests are deterministic and import the analyzer as a module.
"""

import importlib.util
import pathlib

import networkx as nx

# ---- Import the analyzer as a module by path (it lives in scripts/) ----------
_ANALYZER = (
    pathlib.Path(__file__).resolve().parent.parent
    / "scripts" / "attack_path_analyzer.py"
)
_spec = importlib.util.spec_from_file_location("attack_path_analyzer", _ANALYZER)
apa = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(apa)


# ---- Tiny model builders -----------------------------------------------------
def _asset(aid, *, tags=None, internet=False, out_of_scope=False,
           integrity="operational", links=None, data_processed=None,
           data_stored=None):
    return {
        "id": aid,
        "tags": tags or [],
        "internet": internet,
        "out_of_scope": out_of_scope,
        "integrity": integrity,
        "communication_links": links or {},
        "data_assets_processed": data_processed or [],
        "data_assets_stored": data_stored or [],
    }


def _link(target, *, auth="none", protocol="binary", tags=None,
          readonly=False):
    return {
        "target": target,
        "authentication": auth,
        "protocol": protocol,
        "tags": tags or [],
        "readonly": readonly,
    }


def _three_node_model():
    """internet head-unit -> gateway -> safety-critical ECU (telemetry up)."""
    return {
        "technical_assets": {
            "Head Unit": _asset(
                "head-unit", tags=["telematics", "connectivity"],
                internet=True, integrity="important"),
            "Gateway": _asset(
                "gw", tags=["gateway"], integrity="critical",
                links={"To HU": _link("head-unit", protocol="binary")}),
            "Brake ECU": _asset(
                "brake-ecu", tags=["ecu", "safety-critical", "chassis"],
                integrity="mission-critical",
                links={"Status": _link("gw", protocol="binary",
                                       tags=["can"])}),
        }
    }


# ---- build_reachability_graph ------------------------------------------------
def test_graph_nodes_and_edges():
    g = apa.build_reachability_graph(_three_node_model())
    assert isinstance(g, nx.Graph) and not g.is_directed()
    assert set(g.nodes) == {"head-unit", "gw", "brake-ecu"}
    assert g.has_edge("gw", "head-unit")
    assert g.has_edge("brake-ecu", "gw")


def test_edge_tags_unioned():
    model = {
        "technical_assets": {
            "A": _asset("a", links={
                "l1": _link("b", tags=["can"]),
            }),
            "B": _asset("b", links={
                "l2": _link("a", tags=["can-fd"]),
            }),
        }
    }
    g = apa.build_reachability_graph(model)
    # Undirected: the two links collapse onto one edge, tags unioned.
    assert g["a"]["b"]["tags"] == {"can", "can-fd"}


def test_parallel_link_weakest_auth_collapse():
    model = {
        "technical_assets": {
            "A": _asset("a", links={
                "strong": _link("b", auth="client-certificate"),
                "weak": _link("b", auth="none"),
            }),
            "B": _asset("b"),
        }
    }
    g = apa.build_reachability_graph(model)
    assert g["a"]["b"]["auth"] == "none"


# ---- entries / crown_jewels --------------------------------------------------
def test_entries_only_inscope_internet():
    model = {
        "technical_assets": {
            "Exposed": _asset("exposed", internet=True),
            "ExposedOOS": _asset("oos", internet=True, out_of_scope=True),
            "Internal": _asset("internal", internet=False),
        }
    }
    g = apa.build_reachability_graph(model)
    assert apa.entries(g) == ["exposed"]


def test_crown_jewels_only_safety_critical():
    model = {
        "technical_assets": {
            "Safety": _asset("safety", tags=["safety-critical"]),
            "SafetyOOS": _asset("soos", tags=["safety-critical"],
                                out_of_scope=True),
            "Body": _asset("body", tags=["ecu", "body"]),
        }
    }
    g = apa.build_reachability_graph(model)
    assert apa.crown_jewels(g) == ["safety"]


# ---- pathfinding via analyze -------------------------------------------------
def test_analyze_finds_expected_path():
    g = apa.build_reachability_graph(_three_node_model())
    result = apa.analyze(g, cutoff=8)
    assert result["entries"] == ["head-unit"]
    assert result["jewels"] == ["brake-ecu"]
    assert len(result["paths"]) == 1
    p = result["paths"][0]
    assert p["shortest"] == ["head-unit", "gw", "brake-ecu"]
    assert p["hops"] == 2
    assert p["weakest_auth"] == "none"
    assert p["num_paths"] == 1


def test_analyze_finds_chokepoint():
    g = apa.build_reachability_graph(_three_node_model())
    result = apa.analyze(g, cutoff=8)
    # The gateway is the sole node between entry and jewel -> min node cut.
    assert "gw" in result["chokepoints"]
    assert result["chokepoints"]["gw"] == {"brake-ecu"}


# ---- technique tagging (tag_path) --------------------------------------------
def test_tag_path_roles():
    g = apa.build_reachability_graph(_three_node_model())
    path = ["head-unit", "gw", "brake-ecu"]
    hops = apa.tag_path(g, path, "brake-ecu")

    # Entry hop: telematics/connectivity -> Exploit via Radio Interface.
    assert "T0883" in hops[0]["attack_ids"]
    assert "ATM-T0012" in hops[0]["atm_ids"]

    # Pivot hop: gateway -> lateral movement.
    assert "T0867" in hops[1]["attack_ids"]
    assert "ATM-T0051" in hops[1]["atm_ids"]

    # Target hop: terminal safety-critical reached over a CAN edge -> both
    # the bus technique and the affect-vehicle-function technique.
    assert "T0831" in hops[2]["attack_ids"]      # Manipulation of Control
    assert "T1692.001" in hops[2]["attack_ids"]  # Command Message (bus hop)
    assert "ATM-TA0013" in hops[2]["atm_tactics"]


# ---- path-realism weighting --------------------------------------------------
def test_realism_corroborated_when_one_campaign_chains_two():
    # ATM-P0006 exercised BOTH ATM-T0012 (entry) and ATM-T0051 (pivot), so a
    # path tagged with both is 'corroborated' (best_overlap >= 2).
    hops = [
        {"atm_ids": ["ATM-T0012"]},
        {"atm_ids": ["ATM-T0051", "ATM-T0052"]},
        {"atm_ids": ["ATM-T0070", "ATM-T0068"]},
    ]
    r = apa.path_realism(hops)
    assert r["label"] == "corroborated"
    assert r["best_overlap"] >= 2
    assert r["campaigns"][0][0] == "ATM-P0006"  # strongest first
    # T0012 + T0051 are attested; T0052/T0070/T0068 are not.
    assert r["techniques_corroborated"] == 2
    assert r["techniques_total"] == 5


def test_realism_partial_when_no_single_campaign_chains():
    # Two techniques attested, but by DIFFERENT campaigns (no overlap >= 2).
    # ATM-T0011 -> ATM-P0020 only; ATM-T0007 -> ATM-P0082 only.
    hops = [{"atm_ids": ["ATM-T0011"]}, {"atm_ids": ["ATM-T0007"]}]
    r = apa.path_realism(hops)
    assert r["label"] == "partially-corroborated"
    assert r["best_overlap"] == 1


def test_realism_theoretical_when_no_evidence():
    # ATM-T0070/T0068 carry no campaign evidence in the export.
    r = apa.path_realism([{"atm_ids": ["ATM-T0070", "ATM-T0068"]}])
    assert r["label"] == "theoretical"
    assert r["best_overlap"] == 0
    assert r["campaigns"] == []


def test_realism_embedded_tables_consistent():
    # Every campaign referenced by a technique must have a display name embedded
    # (so the summary/title never references an unknown campaign id).
    referenced = {c for cs in apa.ATM_TECHNIQUE_CAMPAIGNS.values() for c in cs}
    assert referenced <= set(apa.ATM_CAMPAIGN_NAMES)


def test_analyze_attaches_realism():
    g = apa.build_reachability_graph(_three_node_model())
    p = apa.analyze(g, cutoff=8)["paths"][0]
    assert "realism" in p and p["realism"]["label"] in (
        "corroborated", "partially-corroborated", "theoretical")


# ---- calculate_severity boundary cases --------------------------------------
def test_calculate_severity_boundaries():
    # very-likely (3) x very-high (4) = 12 -> critical
    assert apa.calculate_severity("very-likely", "very-high") == "critical"
    # likely (2) x high (3) = 6 -> elevated
    assert apa.calculate_severity("likely", "high") == "elevated"
    # unlikely (1) x low (1) = 1 -> low
    assert apa.calculate_severity("unlikely", "low") == "low"
    # unlikely (1) x medium (2) = 2 -> medium
    assert apa.calculate_severity("unlikely", "medium") == "medium"


# ---- directed mode: diode severs an undirected path -------------------------
def _diode_model(readonly=False, diode_tag=False):
    """entry -> sensor, and ECU -> sensor (telemetry up, diode).

    Undirected: entry can reach the ECU via the sensor. Directed honouring the
    diode: the ECU->sensor link has no reverse edge, so the attacker cannot get
    from the sensor back down to the ECU -> no path.
    """
    tags = ["diode"] if diode_tag else []
    return {
        "technical_assets": {
            "Entry": _asset("entry", internet=True,
                            links={"poll": _link("sensor")}),
            "Sensor": _asset("sensor", tags=["ecu"]),
            "Safety ECU": _asset(
                "ecu", tags=["safety-critical"],
                integrity="mission-critical",
                links={"telemetry": _link("sensor", readonly=readonly,
                                          tags=tags)}),
        }
    }


def test_directed_readonly_diode_removes_path():
    model = _diode_model(readonly=True)

    g_undir = apa.build_reachability_graph(model, directed=False)
    assert nx.has_path(g_undir, "entry", "ecu")

    g_dir = apa.build_reachability_graph(model, directed=True)
    assert g_dir.is_directed()
    # Forward edge ecu->sensor exists; reverse sensor->ecu does NOT (diode).
    assert g_dir.has_edge("ecu", "sensor")
    assert not g_dir.has_edge("sensor", "ecu")
    assert not nx.has_path(g_dir, "entry", "ecu")

    # And the analysis surfaces the difference: a path undirected, none directed.
    assert len(apa.analyze(g_undir, cutoff=8)["paths"]) == 1
    assert len(apa.analyze(g_dir, cutoff=8)["paths"]) == 0


def test_directed_diode_tag_removes_path():
    g_dir = apa.build_reachability_graph(
        _diode_model(diode_tag=True), directed=True)
    assert not g_dir.has_edge("sensor", "ecu")
    assert not nx.has_path(g_dir, "entry", "ecu")


def test_directed_non_diode_keeps_reverse_edge():
    # Same shape but the up-link is neither readonly nor diode-tagged: the
    # reverse edge IS added, so the directed graph still finds the path.
    g_dir = apa.build_reachability_graph(_diode_model(), directed=True)
    assert g_dir.has_edge("sensor", "ecu")
    assert nx.has_path(g_dir, "entry", "ecu")


# ---- mitigation hint ---------------------------------------------------------
def test_mitigation_hint_names_chokepoint_gateway():
    g = apa.build_reachability_graph(_three_node_model())
    result = apa.analyze(g, cutoff=8)
    hint = apa.path_mitigation_hint(
        g, result["paths"][0]["shortest"], result["chokepoints"])
    assert "mitigate:" in hint
    assert "Gateway" in hint  # the gateway/chokepoint on this path


# ---- ECU hardening controls: catalog + matching ------------------------------
def test_match_hop_controls_soft_and_hard():
    # entry technique T0883 is defeated by binary-hardening (soft);
    # key-theft ATM-T0039 is defeated by hsm (hard).
    soft = apa.match_hop_controls({"binary-hardening"}, {"T0883"})
    assert soft == {"hard": [], "soft": ["binary-hardening"]}
    hard = apa.match_hop_controls({"hsm"}, {"ATM-T0039"})
    assert hard == {"hard": ["hsm"], "soft": []}


def test_match_hop_controls_no_intersection_is_empty():
    # sensor-plausibility defeats ATM-T0003/4 only; a pivot hop (T0866) -> no match.
    assert apa.match_hop_controls({"sensor-plausibility"}, {"T0866"}) == {
        "hard": [], "soft": []}


def test_match_hop_controls_joint_and_sorted():
    # one hard + two soft, all matching their hop techniques; soft list sorted.
    result = apa.match_hop_controls(
        {"hsm", "memory-protection", "binary-hardening"},
        {"ATM-T0039", "T0883", "T0866"})
    assert result == {"hard": ["hsm"],
                      "soft": ["binary-hardening", "memory-protection"]}


def test_lower_likelihood_steps_and_floors():
    assert apa._lower("very-likely", 1) == "likely"
    assert apa._lower("very-likely", 2) == "unlikely"
    assert apa._lower("likely", 2) == "unlikely"      # clamps at floor
    assert apa._lower("unlikely", 1) == "unlikely"    # never below floor


# ---- key-theft hop: node holds crypto-material + authenticated onward link ---
def test_graph_loads_data_held():
    model = {"technical_assets": {
        "Mid": _asset("mid", data_processed=["crypto-material"])}}
    g = apa.build_reachability_graph(model)
    assert g.nodes["mid"]["data_held"] == {"crypto-material"}


def test_graph_data_held_unions_processed_and_stored():
    model = {"technical_assets": {
        "N": _asset("n", data_processed=["a"], data_stored=["b"])}}
    g = apa.build_reachability_graph(model)
    assert g.nodes["n"]["data_held"] == {"a", "b"}


def _keytheft_model(onward_auth):
    """entry(internet) -> mid(holds crypto-material) -> brake; the mid->brake
    link auth varies so we can test the 'authenticated onward link' condition."""
    return {"technical_assets": {
        "Entry": _asset("entry", tags=["telematics", "connectivity"],
                        internet=True, integrity="important"),
        "Mid": _asset("mid", tags=["gateway"], integrity="critical",
                      data_processed=["crypto-material"],
                      links={"up": _link("entry")}),
        "Brake": _asset("brake-ecu", tags=["ecu", "safety-critical"],
                        integrity="mission-critical",
                        links={"cmd": _link("mid", auth=onward_auth, tags=["can-fd"])}),
    }}


def test_keytheft_tag_emitted_when_onward_link_authenticated():
    g = apa.build_reachability_graph(_keytheft_model("credentials"))
    hops = apa.tag_path(g, ["entry", "mid", "brake-ecu"], "brake-ecu")
    mid = next(h for h in hops if h["node"] == "mid")
    assert "ATM-T0039" in mid["atm_ids"]


def test_keytheft_tag_absent_when_onward_link_unauthenticated():
    g = apa.build_reachability_graph(_keytheft_model("none"))
    hops = apa.tag_path(g, ["entry", "mid", "brake-ecu"], "brake-ecu")
    mid = next(h for h in hops if h["node"] == "mid")
    assert "ATM-T0039" not in mid["atm_ids"]


# ---- node-control adjustment in score_path -----------------------------------
def _control_model(entry_tags, gw_tags):
    """internet entry -> gateway(gw_tags) -> brake; weakest auth none."""
    return {"technical_assets": {
        "Entry": _asset("entry", tags=["telematics", "connectivity"] + entry_tags,
                        internet=True, integrity="important"),
        "GW": _asset("gw", tags=["gateway"] + gw_tags, integrity="critical",
                     links={"up": _link("entry")}),
        "Brake": _asset("brake-ecu", tags=["ecu", "safety-critical"],
                        integrity="mission-critical",
                        links={"cmd": _link("gw", tags=["can-fd"])}),
    }}


def _score(model):
    g = apa.build_reachability_graph(model)
    path = ["entry", "gw", "brake-ecu"]
    return apa.score_path(g, path, "brake-ecu", apa.tag_path(g, path, "brake-ecu"))


def test_no_controls_keeps_base_critical():
    s = _score(_control_model([], []))
    assert s["base_likelihood"] == "very-likely"
    assert s["exploitation_likelihood"] == "very-likely"
    assert s["severity"] == "critical"


def test_one_soft_control_drops_one_bucket():
    # binary-hardening on the entry node defeats the entry technique T0883.
    s = _score(_control_model(["binary-hardening"], []))
    assert s["exploitation_likelihood"] == "likely"
    assert s["severity"] == "high"


def test_two_soft_not_full_trio_still_one_bucket():
    # gw pivot emits T0866/T0867; binary-hardening + memory-protection both
    # match, but attack-surface-reduction is absent -> not the full trio -> -1.
    s = _score(_control_model([], ["binary-hardening", "memory-protection"]))
    assert s["exploitation_likelihood"] == "likely"


def test_full_firmware_hardening_set_drops_two_buckets():
    s = _score(_control_model([], ["binary-hardening", "memory-protection",
                                   "attack-surface-reduction"]))
    assert s["exploitation_likelihood"] == "unlikely"
    assert s["severity"] == "elevated"


def test_control_with_no_matching_technique_has_no_effect():
    # sensor-plausibility defeats ATM-T0003/4, never emitted on this path.
    s = _score(_control_model([], ["sensor-plausibility"]))
    assert s["exploitation_likelihood"] == "very-likely"
    assert s["control_adjustment"]["soft_buckets"] == 0


def test_hsm_hard_match_floors_likelihood():
    g = apa.build_reachability_graph(_keytheft_model("credentials"))
    g.nodes["mid"]["tags"].add("hsm")
    path = ["entry", "mid", "brake-ecu"]
    s = apa.score_path(g, path, "brake-ecu", apa.tag_path(g, path, "brake-ecu"))
    assert s["base_likelihood"] == "very-likely"
    assert s["exploitation_likelihood"] == "unlikely"   # floored, not below
    assert s["control_adjustment"]["hard"] is True
