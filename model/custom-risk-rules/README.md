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
| `missing-secoc-on-safety-bus.yaml` | In-scope asset that originates a CAN/CAN FD/LIN/FlexRay link reaching a `safety-critical` target (or the asset itself is safety-critical) where authentication is NOT `credentials` (SecOC = AES-CMAC + freshness). Broader than the unauthenticated-safety-bus rule: also flags safety-bus links carrying some other auth (e.g. `token`) but no SecOC. | tampering / CWE-345 |
| `cross-domain-link-no-filter.yaml` | In-scope asset tagged with an exposure tag (`connectivity`/`telematics`/`infotainment`/`external`/`v2x`) that originates a no-auth link to a `safety-critical`/`powertrain`/`chassis` target where neither endpoint is a `gateway`/`zone-controller` — an exposed domain reaching safety without an authenticated filtering boundary. | elevation-of-privilege / CWE-923 |
| `unauthenticated-gateway-bridge.yaml` | In-scope asset tagged `gateway` or `zone-controller` (a segmentation enforcement point) that originates a communication link with no authentication — the bridge forwards traffic across a boundary without authenticating it, weakening segmentation. Distinct from `cross-domain-link-no-filter` (which fires when NEITHER endpoint is a gateway/zone, i.e. a missing filter); this fires precisely when the bridging node IS the gateway/zone but its link is unauthenticated (a filter present but not authenticating). | elevation-of-privilege / CWE-306 |
| `reachable-debug-port.yaml` | In-scope asset that originates a communication link tagged `physical` with no authentication — a hardware debug/test interface (JTAG/UART) left reachable without an authenticated secure-debug unlock. Distinct from `reachable-unauthenticated-diagnostics` (logical OBD-II/DoIP/UDS surface); this covers the silicon-level hardware debug surface. | elevation-of-privilege / CWE-1191 |
| `internet-exposed-ecu-no-secure-boot.yaml` | In-scope `internet: true` asset tagged as on-board compute (`ecu`/`telematics`/`infotainment`/`connectivity`) that does NOT carry the `secure-boot` tag — an externally reachable compute node lacking a verified boot chain / immutable root of trust, so a remote compromise can be turned into a persistent boot-time implant. | tampering / CWE-1326 |

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
  `unauthenticated-safety-bus-link`. `safe-chassis-gateway` now sends a SecOC link
  (`authentication: credentials`) to a safety ECU and is the negative control — it must
  NOT fire the safety-bus or SecOC rules.
- `telematics-unit` — `internet: true`, encryption none, tagged telematics → fires
  `internet-exposed-ecu-unencrypted`. `infotainment-offline` (`internet: false`) is the
  negative control.
- `obd-tester` — unauth `obd-ii` and `doip` links → fires
  `reachable-unauthenticated-diagnostics`.
- `token-auth-zone` — CAN-FD link to a safety steering ECU with `authentication: token`
  (NOT SecOC) → fires `missing-secoc-on-safety-bus` but NOT
  `unauthenticated-safety-bus-link`, proving the SecOC rule is the broader of the two.
  `safe-chassis-gateway` (`authentication: credentials` = SecOC) is the SecOC negative
  control.
- `rogue-telematics` — `connectivity`/`telematics` source with a DIRECT no-auth CAN-FD
  link straight to the safety-critical brake ECU, where neither endpoint is a
  gateway/zone-controller → fires `cross-domain-link-no-filter`. It is given a real
  encryption value (`data-with-symmetric-shared-key`) so it does NOT also trip the
  internet-encryption rule. Negative controls for the cross-domain rule: `telematics-unit`
  (its only safety-ward link goes THROUGH the `chassis-zone-controller`, a gatewayed hop)
  and `safe-chassis-gateway` (source itself is a gateway) must NOT fire.
- `chassis-zone-controller` (tagged `zone-controller`/`gateway`) also fires
  `unauthenticated-gateway-bridge`: a segmentation point originating a no-auth link.
  `safe-chassis-gateway` is the negative control — its bridging link uses
  `authentication: credentials`, so it must NOT fire.
- `debug-interface` — in-scope ECU originating a `physical`-tagged no-auth JTAG/UART debug
  link → fires `reachable-debug-port`. `secure-debug-port` is the negative control: its
  `physical`-tagged debug link requires `authentication: client-certificate` (an
  authenticated secure-debug unlock), so it must NOT fire. Both carry only the `physical`
  link tag (no fieldbus/diagnostic tag), so they do not trip the safety-bus, SecOC, or
  diagnostics rules.
- `connected-ecu-no-secure-boot` — in-scope `internet: true` compute node tagged
  `connectivity`/`ecu`/`external` WITHOUT the `secure-boot` tag → fires
  `internet-exposed-ecu-no-secure-boot` (no immutable root of trust for boot).
  `secure-boot-ecu` is the negative control: same exposure but it carries the `secure-boot`
  tag, so it must NOT fire. Both use `encryption: data-with-symmetric-shared-key`, so they do
  not also trip `internet-exposed-ecu-unencrypted`. The pre-existing internet-facing assets
  `telematics-unit` and `rogue-telematics` are given the `secure-boot` tag so they do NOT
  fire this rule either; that tag does not affect their other documented matches.

Validated results: `unauthenticated-safety-bus-link` -> `chassis-zone-controller`,
`rogue-telematics`; `internet-exposed-ecu-unencrypted` -> `telematics-unit` only;
`reachable-unauthenticated-diagnostics` -> `obd-tester` only; `missing-secoc-on-safety-bus`
-> `chassis-zone-controller`, `token-auth-zone`, `rogue-telematics` (skips
`safe-chassis-gateway`); `cross-domain-link-no-filter` -> `rogue-telematics` only (skips
`telematics-unit` and `safe-chassis-gateway`); `unauthenticated-gateway-bridge` ->
`chassis-zone-controller` only (skips `safe-chassis-gateway`); `reachable-debug-port` ->
`debug-interface` only (skips `secure-debug-port`); `internet-exposed-ecu-no-secure-boot`
-> `connected-ecu-no-secure-boot` only (skips `secure-boot-ecu`, `telematics-unit`,
`rogue-telematics`, and the internet-`false` `infotainment-offline`).

## Caveat (still applies)

Production auto-loading of these YAML rules is **unconfirmed** upstream. They are authored
and harness-validated only. For findings that must ship in the report, emit them as
`individual_risk_categories` in the model rather than relying on auto-load.

## Deferred candidate rules

`unencrypted-ota-channel` and `iso15118-server-only-tls` are deferred: both hinge on
fields not represented in our parsed model (an OTA-update flag / per-link directionality
of TLS), so they would require inventing fields outside the tag vocabulary.

`internet-exposed-ecu-no-secure-boot` is now authored: the model carries a `secure-boot`
asset tag (assets that implement verified/secure boot carry it), so "lacks secure boot" is
expressed within the tag vocabulary as the absence of that tag, with no invented fields.

`reachable-debug-port` (hardware JTAG/UART debug surface, modeled via the `physical` link
tag) is now authored as a distinct rule from `reachable-unauthenticated-diagnostics`
(logical OBD-II/DoIP/UDS surface); the two cover different attack surfaces and do not
overlap on the fixture.
