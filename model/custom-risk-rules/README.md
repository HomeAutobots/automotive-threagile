# Custom Threagile risk rules (YAML)

Per-asset / per-link automotive risk rules in Threagile's YAML script language (no Go).

- Follow Threagile's reference pattern `pkg/risks/scripts/accidental-secret-leak.yaml`
  (four-section `risk:` block: `id`, `match`, `data`, `utils`).
- Match on this project's **tags** (see `tags_available` in `model/threagile.yaml`), not
  invented protocol/technology enums.
- **Test** with Threagile's `cmd/script` harness:
  `go run cmd/script/main.go -script <rule>.yaml` against a representative parsed model.
- **Caveat:** production config-based auto-loading of YAML rules is unconfirmed upstream.
  For findings that must ship in the report, emit them as `individual_risk_categories` in
  the model instead. Keep multi-hop / topology logic out of rules — that is
  `scripts/attack_path_analyzer.py`'s job.

## Authored rules (harness-validated)

| Rule file | Flags | STRIDE / CWE |
|---|---|---|
| `unauthenticated-safety-bus-link.yaml` | In-scope asset that originates a CAN/CAN FD/LIN/FlexRay link with no authentication where the link target (or the asset itself) is `safety-critical` — i.e. forgeable actuation frames on a safety bus. | tampering / CWE-306 |
| `internet-exposed-ecu-unencrypted.yaml` | In-scope `internet: true` asset tagged `ecu`/`telematics`/`infotainment` with no encryption — sensitive connected-vehicle data exposed in transit/at rest. | information-disclosure / CWE-319 |
| `reachable-unauthenticated-diagnostics.yaml` | In-scope asset that originates an `obd-ii` or `doip` link with no authentication — an unauthenticated UDS diagnostic/flashing surface. | elevation-of-privilege / CWE-1188 |

Each rule references the relevant Auto-ISAC ATM / MITRE ATT&CK technique IDs in its
`description`.

### Implementation note (DSL gotcha)
In the **parsed** model, enum fields with a zero-value default are dropped by
`omitempty` when marshalled to the rule engine's map. So `authentication: none`,
`encryption: none`, and `internet: false` are *absent*, not present-as-"none".
`true:`/`false:` only accept real booleans, and `equal: second: none` never matches an
absent field. These rules therefore detect "none" as the **absence of any real value**
via `not-equal` against every real enum value (for `authentication`/`encryption`) and use
`true: "{tech_asset.internet}"` (true only when the bool is present/true).

## Test command (local; run from inside the Threagile source tree)

```sh
# Threagile source is cloned at /tmp/threagile-src; the harness reads test/parsed-model.yaml
cp model/custom-risk-rules/test/parsed-model.yaml /tmp/threagile-src/test/parsed-model.yaml
cd /tmp/threagile-src
go run cmd/script/main.go -script <abs-path>/model/custom-risk-rules/<rule>.yaml
```

`test/parsed-model.yaml` is a small automotive fixture in Threagile's **parsed** format
(not the input format). It contains positive cases and negative controls so each rule can
be confirmed to fire on the intended asset and skip the controls:

- `chassis-zone-controller` — unauth CAN-FD link to safety-critical brake ECU → fires
  rule 1. `safe-chassis-gateway` (authenticated link to a safety ECU) is the negative
  control and must NOT fire.
- `telematics-unit` — `internet: true`, encryption none, tagged telematics → fires rule 2.
  `infotainment-offline` (`internet: false`) is the negative control.
- `obd-tester` — unauth `obd-ii` and `doip` links → fires rule 3.

Validated results: rule 1 -> `chassis-zone-controller` only; rule 2 -> `telematics-unit`
only; rule 3 -> `obd-tester` only.

## Caveat (still applies)

Production auto-loading of these YAML rules is **unconfirmed** upstream. They are authored
and harness-validated only. For findings that must ship in the report, emit them as
`individual_risk_categories` in the model rather than relying on auto-load.

## Deferred candidate rules

`unencrypted-ota-channel` and `iso15118-server-only-tls` are deferred: both hinge on
fields not represented in our parsed model (an OTA-update flag / per-link directionality
of TLS), so they would require inventing fields outside the tag vocabulary. A
`reachable-debug-port` rule is effectively covered by
`reachable-unauthenticated-diagnostics` (OBD-II/DoIP). A
`internet-exposed-ecu-no-secure-boot` rule is dropped because secure-boot is not modeled
(per the no-invented-fields constraint).
