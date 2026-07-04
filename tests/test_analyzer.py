"""Unit tests for library/analyzer/attack_path_analyzer.py.

All models are small INLINE dicts (no external files, no frameworks/ tree).
Tests are deterministic and import the analyzer as a module.
"""

import importlib.util
import pathlib

import networkx as nx

# ---- Import the analyzer as a module by path (it lives in library/analyzer/) --
_ANALYZER = (
    pathlib.Path(__file__).resolve().parent.parent
    / "library" / "analyzer" / "attack_path_analyzer.py"
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
    assert result["chokepoints"]["gw"]["jewels"] == {"brake-ecu"}


def test_chokepoint_severity_tracks_worst_gated_path():
    # A chokepoint's severity is derived from the worst path it gates, not a fixed
    # constant. The gateway here gates the (entry -> brake) path, so its emitted
    # severity must equal that path's severity (Phase 1 fix).
    g = apa.build_reachability_graph(_three_node_model())
    result = apa.analyze(g, cutoff=8)
    gated_sev = result["chokepoints"]["gw"]["worst"]["severity"]
    path_sev = next(p["severity"] for p in result["paths"] if p["jewel"] == "brake-ecu")
    assert gated_sev == path_sev
    out = apa.emit_risks(g, result)
    choke = out["individual_risk_categories"]["Attack-Path Chokepoint"]["risks_identified"]
    assert all(v["severity"] == gated_sev for v in choke.values())


def test_likelihood_scale_tops_at_very_likely():
    # `frequent` was dead in path scoring; the scale is 3 buckets now.
    assert "frequent" not in apa.LIKELIHOOD_W
    assert apa.LADDER == ["unlikely", "likely", "very-likely"]


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


def _keytheft_model(onward_auth, key_da_id="crypto-material"):
    """entry(internet) -> mid(holds key material) -> brake; the mid->brake link
    auth varies so we can test the 'authenticated onward link' condition. The key
    data asset is matched by its `key-material` TAG, not its id -- key_da_id can be
    any name to prove portability."""
    return {
        "data_assets": {"Keys": {"id": key_da_id, "tags": ["key-material"]}},
        "technical_assets": {
            "Entry": _asset("entry", tags=["telematics", "connectivity"],
                            internet=True, integrity="important"),
            "Mid": _asset("mid", tags=["gateway"], integrity="critical",
                          data_processed=[key_da_id],
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


def test_keytheft_matches_key_material_tag_not_a_fixed_id():
    # Portability: the key-theft hop fires on ANY data asset tagged `key-material`,
    # regardless of its id -- so an adopter can name it whatever they like.
    g = apa.build_reachability_graph(
        _keytheft_model("credentials", key_da_id="my-oem-signing-keys"))
    assert g.graph["key_material_ids"] == {"my-oem-signing-keys"}
    hops = apa.tag_path(g, ["entry", "mid", "brake-ecu"], "brake-ecu")
    mid = next(h for h in hops if h["node"] == "mid")
    assert "ATM-T0039" in mid["atm_ids"]
    # an UNtagged data asset of the same id would NOT trigger key-theft
    g2 = apa.build_reachability_graph({
        "data_assets": {"D": {"id": "plain", "tags": []}},
        "technical_assets": {
            "Entry": _asset("entry", tags=["telematics"], internet=True),
            "Mid": _asset("mid", tags=["gateway"], data_processed=["plain"],
                          links={"up": _link("entry")}),
            "Brake": _asset("brake-ecu", tags=["ecu", "safety-critical"],
                            links={"cmd": _link("mid", auth="credentials", tags=["can-fd"])}),
        }})
    assert g2.graph["key_material_ids"] == set()
    hops2 = apa.tag_path(g2, ["entry", "mid", "brake-ecu"], "brake-ecu")
    assert "ATM-T0039" not in next(h for h in hops2 if h["node"] == "mid")["atm_ids"]


# ---- node-control adjustment in score_path -----------------------------------
def _control_model(entry_tags, gw_tags, entry_base=("telematics", "connectivity")):
    """internet entry -> gateway(gw_tags) -> brake; weakest auth none.

    entry_base sets the entry interface. The default 'telematics' is a
    DEMONSTRATED 2024-2025 foothold (R1), so entry-hop soft controls are NOT
    credited there; pass a non-demonstrated interface (e.g. ('connectivity',)) to
    exercise ordinary entry-hop soft crediting.
    """
    return {"technical_assets": {
        "Entry": _asset("entry", tags=list(entry_base) + entry_tags,
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


def test_soft_control_on_demonstrated_entry_not_credited():
    # binary-hardening on the entry node defeats the entry technique T0883, BUT
    # the entry is a demonstrated 2024-2025 foothold (telematics): Pwn2Own popped
    # exactly such hardened units, so the entry-hop soft credit is dropped (R1,
    # docs/research/06). Likelihood stays at the structural baseline.
    s = _score(_control_model(["binary-hardening"], []))
    assert s["exploitation_likelihood"] == "very-likely"
    adj = s["control_adjustment"]
    assert adj["soft_buckets"] == 0
    assert adj["entry_corroboration"]["tier"] == "demonstrated"
    assert adj["matches"][0]["soft_suppressed"] == ["binary-hardening"]
    assert adj["matches"][0]["soft"] == []


def test_soft_control_on_ordinary_entry_still_credited():
    # Same soft control on a NON-demonstrated entry interface (connectivity has no
    # 2024-2025 foothold exploit in the corpus) -> the entry-hop credit stands.
    s = _score(_control_model(["binary-hardening"], [], entry_base=("connectivity",)))
    assert s["exploitation_likelihood"] == "likely"
    assert s["severity"] == "high"
    adj = s["control_adjustment"]
    assert adj["entry_corroboration"] is None
    assert adj["soft_buckets"] == 1


def test_two_soft_not_full_trio_still_one_bucket():
    # gw pivot emits T0866/T0867; binary-hardening + memory-protection both
    # match, but attack-surface-reduction is absent -> not the full trio -> -1.
    s = _score(_control_model([], ["binary-hardening", "memory-protection"]))
    assert s["exploitation_likelihood"] == "likely"


def test_full_firmware_hardening_set_drops_two_buckets():
    # The -2 gate is the full trio PRESENT on the node plus >=1 trio control
    # matching THIS hop's techniques (here binary-hardening/memory-protection
    # match the gw pivot) -- NOT all three matching this hop's techniques
    # (attack-surface-reduction never matches a pivot hop, and need not).
    s = _score(_control_model([], ["binary-hardening", "memory-protection",
                                   "attack-surface-reduction"]))
    assert s["exploitation_likelihood"] == "unlikely"
    assert s["severity"] == "elevated"


def test_ids_is_detect_only_and_earns_no_likelihood_credit():
    # ids is detect-only (R10/R11): on a gateway pivot hop where it once matched
    # ATM-T0051/T0052 + T0866/T0867, it now earns NO success-likelihood credit.
    # Stealthy bus-off (WeepingCAN/CANnon) evades it; detection is not modeled.
    assert apa.CONTROL_CATALOG["ids"]["defeats"] == set()
    assert apa.match_hop_controls(
        {"gateway", "ids"},
        {"T0866", "T0867", "ATM-T0051", "ATM-T0052"}) == {"hard": [], "soft": []}
    s = _score(_control_model([], ["ids"]))
    assert s["exploitation_likelihood"] == "very-likely"   # unchanged from base
    assert s["control_adjustment"]["soft_buckets"] == 0


def test_backbone_ethernet_hop_tags_aitm_lateral_sniffing():
    # An automotive-Ethernet / SOME-IP edge into a node emits the backbone tech
    # set: AitM (T0830) + lateral movement (ATM-T0052) + sniffing (ATM-T0038),
    # distinct from a fieldbus CAN bus hop. Pure enrichment, no severity effect (R3).
    model = {"technical_assets": {
        "Entry": _asset("entry", tags=["connectivity"], internet=True,
                        integrity="important",
                        links={"eth": _link("gw", tags=["ethernet", "some-ip"])}),
        "GW": _asset("gw", tags=["gateway"], integrity="critical"),
    }}
    g = apa.build_reachability_graph(model)
    hops = apa.tag_path(g, ["entry", "gw"], "gw")
    assert "T0830" in hops[1]["attack_ids"]
    assert {"ATM-T0052", "ATM-T0038"} <= set(hops[1]["atm_ids"])


def test_entries_include_physical_and_exclude_out_of_scope():
    # Physical surfaces (OBD-II / debug) are in-scope entries; a remote asset is
    # too; an out-of-scope removable-media stub is not. Empty --entry-tags =>
    # remote entries only. (R9)
    model = {"technical_assets": {
        "Remote": _asset("remote", tags=["telematics"], internet=True,
                         links={"l": _link("gw", tags=["ethernet"])}),
        "OBD": _asset("obd-port", tags=["obd-ii", "physical"],
                      links={"l": _link("gw")}),
        "OOS": _asset("usb", tags=["physical"], out_of_scope=True,
                      links={"l": _link("gw")}),
        "GW": _asset("gw", tags=["gateway"], integrity="critical"),
    }}
    g = apa.build_reachability_graph(model)
    ent = set(apa.entries(g))
    assert {"remote", "obd-port"} <= ent
    assert "usb" not in ent                       # out_of_scope excluded
    assert apa.entry_kind(g, "remote") == "remote"
    assert apa.entry_kind(g, "obd-port") == "physical"
    assert set(apa.entries(g, physical_entry_tags=set())) == {"remote"}


def test_physical_entry_scored_one_bucket_below_remote():
    # The SAME path scored from a physical entry is exactly one likelihood bucket
    # below the remote scoring (physical access is a precondition). (R9)
    g = apa.build_reachability_graph(_control_model([], []))
    path = ["entry", "gw", "brake-ecu"]
    ht = apa.tag_path(g, path, "brake-ecu")
    remote = apa.score_path(g, path, "brake-ecu", ht, entry_kind="remote")
    physical = apa.score_path(g, path, "brake-ecu", ht, entry_kind="physical")
    assert apa.LADDER.index(physical["exploitation_likelihood"]) == \
        apa.LADDER.index(remote["exploitation_likelihood"]) - 1


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


def test_hard_and_soft_both_present_stays_floored():
    # hsm (hard, key-theft) AND binary-hardening (soft) on the same mid node:
    # the hard floor must take precedence over the soft -1 (if/elif ordering).
    g = apa.build_reachability_graph(_keytheft_model("credentials"))
    g.nodes["mid"]["tags"].update({"hsm", "binary-hardening"})
    path = ["entry", "mid", "brake-ecu"]
    s = apa.score_path(g, path, "brake-ecu", apa.tag_path(g, path, "brake-ecu"))
    assert s["control_adjustment"]["hard"] is True
    assert s["exploitation_likelihood"] == "unlikely"


# ---- R1: entry-corroboration (demonstrated 2024-2025 footholds) -------------
def test_entry_corroboration_unions_and_dedupes():
    # TCU carries both 'cellular' and 'telematics'; campaigns union, deduped,
    # deterministic (sorted tag order, insertion-ordered campaigns).
    ec = apa.entry_corroboration({"telematics", "cellular", "ecu"})
    assert ec["tier"] == "demonstrated"
    assert ec["campaigns"] == [
        "P2O-AUTO-2024", "KIA-DEALER-2024", "SUBARU-STARLINK-2025"]


def test_entry_corroboration_none_for_undemonstrated_interface():
    # Generic RF surfaces and the sensor surfaces are deliberately excluded:
    # no 2024-2025 foothold demo (sensor spoofing is R2, not R1).
    assert apa.entry_corroboration({"connectivity", "bluetooth", "uwb"}) is None
    assert apa.entry_corroboration({"v2x", "gnss"}) is None
    assert apa.entry_corroboration({"ecu", "gateway"}) is None
    # charging is excluded (R8): the Pwn2Own EV-charger RCEs popped the off-board
    # EVSE, not the in-vehicle EVCC -- no vehicle-side charge-controller foothold.
    assert apa.entry_corroboration({"charging", "ecu"}) is None
    # the genuine remote footholds still corroborate.
    assert apa.entry_corroboration({"cellular"})["tier"] == "demonstrated"
    assert apa.entry_corroboration({"telematics"})["tier"] == "demonstrated"


def test_entry_campaign_ids_are_documented():
    # Every campaign referenced by the map must have a human-readable name.
    for camps in apa.ENTRY_CORROBORATION.values():
        for c in camps:
            assert c in apa.ENTRY_CAMPAIGN_NAMES, f"{c} has no ENTRY_CAMPAIGN_NAMES entry"


def test_entry_corroboration_never_leaks_into_realism():
    # A demonstrated ENTRY must not change CHAIN realism (entries != chains,
    # docs/research/06): the entry campaign IDs must never appear among the
    # realism campaigns, which are derived only from ATM_TECHNIQUE_CAMPAIGNS.
    g = apa.build_reachability_graph(_control_model([], []))
    p = apa.analyze(g, cutoff=10)["paths"][0]
    assert p["control_adjustment"]["entry_corroboration"]["tier"] == "demonstrated"
    realism_ids = {c for c, _ in p["realism"]["campaigns"]}
    assert not (realism_ids & set(apa.ENTRY_CAMPAIGN_NAMES))


def test_demonstrated_entry_suppression_leaves_hard_floor_intact():
    # Suppressing the entry hop's SOFT credit must not disturb a hard floor from
    # a downstream node: hsm on 'mid' still floors even though the entry
    # (telematics) is a demonstrated foothold.
    g = apa.build_reachability_graph(_keytheft_model("credentials"))
    g.nodes["mid"]["tags"].add("hsm")
    path = ["entry", "mid", "brake-ecu"]
    s = apa.score_path(g, path, "brake-ecu", apa.tag_path(g, path, "brake-ecu"))
    assert s["control_adjustment"]["entry_corroboration"]["tier"] == "demonstrated"
    assert s["control_adjustment"]["hard"] is True
    assert s["exploitation_likelihood"] == "unlikely"


def test_emit_title_carries_entry_corroboration_and_suppression():
    # The emitted path-risk title must name the demonstrated foothold AND report
    # the entry hardening that was not credited.
    g = apa.build_reachability_graph(_control_model(["binary-hardening"], []))
    emitted = apa.emit_risks(g, apa.analyze(g, cutoff=10))
    titles = list(emitted["individual_risk_categories"]
                  ["Multi-Hop Attack Path To Safety-Critical ECU"]["risks_identified"])
    assert titles, "expected at least one path risk"
    t = titles[0]
    assert "entry: demonstrated foothold" in t
    assert "P2O-AUTO-2024" in t
    assert "entry-hardening not credited on demonstrated foothold" in t
    assert "binary-hardening" in t


def test_emit_title_marks_undemonstrated_entry_unchanged():
    g = apa.build_reachability_graph(
        _control_model([], [], entry_base=("connectivity",)))
    emitted = apa.emit_risks(g, apa.analyze(g, cutoff=10))
    titles = list(emitted["individual_risk_categories"]
                  ["Multi-Hop Attack Path To Safety-Critical ECU"]["risks_identified"])
    assert titles
    assert all("entry: no public 2024-2025 exploit (prior unchanged)" in t
               for t in titles)


def test_emit_risks_title_names_fired_controls():
    # Two soft controls on the gw pivot fire against its lateral-movement
    # techniques; the emitted path-risk title must name the controls.
    g = apa.build_reachability_graph(
        _control_model([], ["binary-hardening", "memory-protection"]))
    result = apa.analyze(g, cutoff=10)
    emitted = apa.emit_risks(g, result)
    titles = list(
        emitted["individual_risk_categories"]
        ["Multi-Hop Attack Path To Safety-Critical ECU"]["risks_identified"]
    )
    assert any("binary-hardening" in t for t in titles)


# ---- honesty guard: active controls fire, inert controls never do -----------
def test_active_vs_inert_controls_match_emitted_techniques():
    # Union of every technique ID the analyzer can emit on a hop.
    emitted = set()
    for rule in apa.ENTRY_RULES:
        _, ax_ids, _, atm_ids, _, _ = rule
        emitted |= set(ax_ids) | set(atm_ids)
    for tup in (apa.PIVOT_TECH, apa.BUS_TECH, apa.TARGET_TECH, apa.KEYTHEFT_TECH,
                apa.ETHERNET_TECH):
        ax_ids, _, atm_ids, _, _ = tup
        emitted |= set(ax_ids) | set(atm_ids)

    active = {"binary-hardening", "memory-protection", "attack-surface-reduction",
              "sensor-plausibility", "hsm"}
    # ids is detect-only (empty defeats); anti-rollback/secure-boot/firmware-signing
    # defeat techniques the analyzer does not emit yet -- all inert by design.
    inert = {"ids", "secure-boot", "firmware-signing", "anti-rollback"}

    # Every active control must defeat at least one emitted technique.
    for tag in active:
        assert apa.CONTROL_CATALOG[tag]["defeats"] & emitted, \
            f"active control {tag} matches no emitted technique"
    # Inert controls must defeat NO emitted technique (no silent firing).
    for tag in inert:
        assert not (apa.CONTROL_CATALOG[tag]["defeats"] & emitted), \
            f"inert control {tag} unexpectedly matches an emitted technique"
