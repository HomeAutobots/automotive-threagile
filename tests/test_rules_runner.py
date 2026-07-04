"""Unit tests for library/analyzer/rules_runner.py.

Per-matcher positive/negative fidelity (each rule fires on its intended shape and
skips the control) plus a real-model sanity check. The YAML rules are independently
validated by the cmd/script harness; these guard the Python port of the match logic.
"""
import importlib.util
import pathlib

import yaml

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_RR = _ROOT / "library" / "analyzer" / "rules_runner.py"
_spec = importlib.util.spec_from_file_location("rules_runner", _RR)
rr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rr)


def _asset(aid, *, tags=None, internet=False, oos=False, redundant=None,
           encryption=None, processed=None, links=None):
    a = {"id": aid, "tags": tags or [], "internet": internet,
         "out_of_scope": oos, "communication_links": links or {},
         "data_assets_processed": processed or []}
    if redundant is not None:
        a["redundant"] = redundant
    if encryption is not None:
        a["encryption"] = encryption
    return a


def _link(target, *, auth="none", protocol="binary", tags=None, vpn=False):
    return {"target": target, "authentication": auth, "protocol": protocol,
            "tags": tags or [], "vpn": vpn}


def _ctx(assets, data_assets=None):
    model = {"technical_assets": {a["id"]: a for a in assets},
             "data_assets": data_assets or {}}
    return rr.Ctx(model)


def _match(rid, asset, assets, data_assets=None):
    return rr.MATCHERS[rid](asset, _ctx(assets, data_assets))


# ---- per-matcher fidelity ----------------------------------------------------
def test_unauth_safety_bus_link():
    ecu = _asset("brake", tags=["safety-critical"])
    hit = _asset("zc", links={"c": _link("brake", auth="none", tags=["can-fd"])})
    miss = _asset("zc2", links={"c": _link("brake", auth="credentials", tags=["can-fd"])})
    assert _match("unauthenticated-safety-bus-link", hit, [ecu, hit])
    assert not _match("unauthenticated-safety-bus-link", miss, [ecu, miss])


def test_missing_secoc_is_broader_than_unauth():
    ecu = _asset("brake", tags=["safety-critical"])
    # token auth is NOT SecOC -> missing-secoc fires, unauth-bus does not.
    tok = _asset("zc", links={"c": _link("brake", auth="token", tags=["can-fd"])})
    assert _match("missing-secoc-on-safety-bus", tok, [ecu, tok])
    assert not _match("unauthenticated-safety-bus-link", tok, [ecu, tok])
    secoc = _asset("zc2", links={"c": _link("brake", auth="credentials", tags=["can-fd"])})
    assert not _match("missing-secoc-on-safety-bus", secoc, [ecu, secoc])


def test_cross_domain_link_no_filter():
    safety = _asset("brake", tags=["safety-critical"])
    hit = _asset("tcu", tags=["telematics"],
                 links={"d": _link("brake", auth="none", tags=["ethernet"])})
    # a gateway source is a filtering boundary -> excluded even if it links to safety.
    gw = _asset("gw", tags=["telematics", "gateway"],
                links={"d": _link("brake", auth="none")})
    assert _match("cross-domain-link-no-filter", hit, [safety, hit])
    assert not _match("cross-domain-link-no-filter", gw, [safety, gw])


def test_gateway_bridge_unauth():
    hit = _asset("gw", tags=["gateway"], links={"b": _link("x", auth="none")})
    miss = _asset("gw2", tags=["gateway"], links={"b": _link("x", auth="credentials")})
    plain = _asset("ecu", tags=["ecu"], links={"b": _link("x", auth="none")})
    assert _match("unauthenticated-gateway-bridge", hit, [hit])
    assert not _match("unauthenticated-gateway-bridge", miss, [miss])
    assert not _match("unauthenticated-gateway-bridge", plain, [plain])


def test_internet_exposed_no_secure_boot():
    hit = _asset("tcu", tags=["telematics"], internet=True)
    miss = _asset("tcu2", tags=["telematics", "secure-boot"], internet=True)
    offline = _asset("ecu", tags=["ecu"], internet=False)
    assert _match("internet-exposed-ecu-no-secure-boot", hit, [hit])
    assert not _match("internet-exposed-ecu-no-secure-boot", miss, [miss])
    assert not _match("internet-exposed-ecu-no-secure-boot", offline, [offline])


def test_unencrypted_ota_channel():
    hit = _asset("cloud", links={"o": _link("tcu", protocol="text", tags=["ota"])})
    tls = _asset("cloud2", links={"o": _link("tcu", protocol="https", tags=["ota"])})
    vpn = _asset("cloud3", links={"o": _link("tcu", protocol="text", tags=["ota"], vpn=True)})
    assert _match("unencrypted-ota-channel", hit, [hit])
    assert not _match("unencrypted-ota-channel", tls, [tls])
    assert not _match("unencrypted-ota-channel", vpn, [vpn])


def test_iso15118_server_only_tls():
    body = _asset("evse", tags=[])
    hit = _asset("evcc", links={"c": _link("evse", tags=["iso15118"], auth="none")})
    mutual = _asset("evcc2", links={"c": _link("evse", tags=["iso15118", "tls-mutual"])})
    assert _match("iso15118-server-only-tls", hit, [body, hit])
    assert not _match("iso15118-server-only-tls", mutual, [body, mutual])


def test_relay_vulnerable_passive_entry():
    bodyctl = _asset("bcm", tags=["body"])
    hit = _asset("key", links={"r": _link("bcm", tags=["uwb", "bluetooth"])})
    ranged = _asset("key2", links={"r": _link("bcm", tags=["uwb", "distance-bounding"])})
    assert _match("relay-vulnerable-passive-entry", hit, [bodyctl, hit])
    assert not _match("relay-vulnerable-passive-entry", ranged, [bodyctl, ranged])


def test_unprotected_key_storage_matches_key_material_tag():
    da = {"Keys": {"id": "keys", "tags": ["key-material"]}}
    hit = _asset("hsm-less", processed=["keys"])
    safe = _asset("with-hsm", tags=["hsm"], processed=["keys"])
    assert _match("unprotected-key-storage", hit, [hit], da)
    assert not _match("unprotected-key-storage", safe, [safe], da)


def test_unverified_firmware_matches_firmware_image_tag():
    da = {"FW": {"id": "fw", "tags": ["firmware-image"]}}
    hit = _asset("receiver", processed=["fw"])
    signed = _asset("signed", tags=["firmware-signing"], processed=["fw"])
    assert _match("unverified-firmware-update", hit, [hit], da)
    assert not _match("unverified-firmware-update", signed, [signed], da)


def test_safety_function_without_redundancy():
    hit = _asset("bms", tags=["safety-critical"])
    ok = _asset("brake", tags=["safety-critical"], redundant=True)
    assert _match("safety-function-without-redundancy", hit, [hit])
    assert not _match("safety-function-without-redundancy", ok, [ok])


# ---- real-model sanity -------------------------------------------------------
def test_runner_on_real_model_is_sane():
    model = yaml.safe_load(open(_ROOT / "model" / "threagile.yaml"))
    out = rr.run(model)
    cats = out["individual_risk_categories"]
    # every emitted category is a known rule id, with >=1 finding, referencing real assets
    ids = {a["id"] for a in (model["technical_assets"]).values()}
    for cat in cats.values():
        assert cat["id"] in rr.MATCHERS
        assert cat["risks_identified"]
        for r in cat["risks_identified"].values():
            assert r["most_relevant_technical_asset"] in ids
    # redundancy rule finds exactly the safety-critical assets lacking redundant:true
    red = next(c for c in cats.values() if c["id"] == "safety-function-without-redundancy")
    sc = [a for a in model["technical_assets"].values()
          if "safety-critical" in (a.get("tags") or []) and not a.get("redundant")
          and not a.get("out_of_scope")]
    assert len(red["risks_identified"]) == len(sc)


def test_out_of_scope_assets_never_match():
    da = {"Keys": {"id": "keys", "tags": ["key-material"]}}
    oos = _asset("x", processed=["keys"], oos=True)
    model = {"technical_assets": {"X": oos}, "data_assets": da}
    out = rr.run(model)
    assert out["individual_risk_categories"] == {}
