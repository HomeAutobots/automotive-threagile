"""Unit tests for scripts/validate_model.py (the model validator)."""
import importlib.util
import pathlib

import yaml

_VM = pathlib.Path(__file__).resolve().parent.parent / "scripts" / "validate_model.py"
_spec = importlib.util.spec_from_file_location("validate_model", _VM)
vm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(vm)


def _valid_model():
    return {
        "tags_available": ["gateway", "safety-critical", "ecu", "can-fd"],
        "data_assets": {
            "Cmd": {"id": "cmd", "confidentiality": "internal",
                    "integrity": "mission-critical", "availability": "mission-critical"},
        },
        "technical_assets": {
            "GW": {"id": "gw", "type": "process", "tags": ["gateway"],
                   "integrity": "critical",
                   "communication_links": {
                       "to ecu": {"target": "ecu", "authentication": "none",
                                  "tags": ["can-fd"], "data_assets_sent": ["cmd"]}}},
            "ECU": {"id": "ecu", "type": "process", "tags": ["ecu", "safety-critical"],
                    "integrity": "mission-critical", "data_assets_processed": ["cmd"]},
        },
        "trust_boundaries": {
            "B1": {"id": "b1", "type": "network-virtual-lan",
                   "technical_assets_inside": ["gw"]},
            "B2": {"id": "b2", "type": "network-virtual-lan",
                   "technical_assets_inside": ["ecu"]},
        },
    }


def _validate(tmp_path, model):
    p = tmp_path / "m.yaml"
    p.write_text(yaml.safe_dump(model))
    return vm.validate(str(p))


def test_valid_model_has_no_errors(tmp_path):
    errors, warnings = _validate(tmp_path, _valid_model())
    assert errors == []
    assert warnings == []


def test_dangling_link_target_is_an_error(tmp_path):
    m = _valid_model()
    m["technical_assets"]["GW"]["communication_links"]["to ecu"]["target"] = "ghost"
    errors, _ = _validate(tmp_path, m)
    assert any("is not a technical-asset id" in e for e in errors)


def test_undeclared_tag_is_an_error(tmp_path):
    m = _valid_model()
    m["technical_assets"]["GW"]["tags"].append("undeclared-tag")
    errors, _ = _validate(tmp_path, m)
    assert any("not declared in tags_available" in e for e in errors)


def test_missing_data_asset_is_an_error(tmp_path):
    m = _valid_model()
    m["technical_assets"]["ECU"]["data_assets_processed"] = ["nonexistent"]
    errors, _ = _validate(tmp_path, m)
    assert any("does not exist" in e for e in errors)


def test_asset_in_two_boundaries_is_an_error(tmp_path):
    m = _valid_model()
    m["trust_boundaries"]["B2"]["technical_assets_inside"] = ["ecu", "gw"]
    errors, _ = _validate(tmp_path, m)
    assert any("inside 2 trust boundaries" in e for e in errors)


def test_invalid_enum_value_is_an_error(tmp_path):
    m = _valid_model()
    m["technical_assets"]["ECU"]["integrity"] = "mision-critical"  # typo
    errors, _ = _validate(tmp_path, m)
    assert any("not a valid Threagile value" in e for e in errors)


def test_inscope_asset_without_boundary_is_a_warning(tmp_path):
    m = _valid_model()
    m["trust_boundaries"]["B2"]["technical_assets_inside"] = []  # ecu now orphaned
    errors, warnings = _validate(tmp_path, m)
    assert errors == []
    assert any("not inside any trust boundary" in w for w in warnings)


def test_out_of_scope_asset_without_boundary_is_silent(tmp_path):
    m = _valid_model()
    m["technical_assets"]["ECU"]["out_of_scope"] = True
    m["trust_boundaries"]["B2"]["technical_assets_inside"] = []
    errors, warnings = _validate(tmp_path, m)
    assert errors == [] and warnings == []


def test_duplicate_keys_rejected(tmp_path):
    # StrictLoader must reject duplicate mapping keys like Threagile's Go parser.
    p = tmp_path / "dup.yaml"
    p.write_text("technical_assets:\n  A: {id: a}\n  A: {id: b}\n")
    try:
        vm.load_model(str(p))
        assert False, "expected duplicate-key ValueError"
    except ValueError as e:
        assert "duplicate key" in str(e)
