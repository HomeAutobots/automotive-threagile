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
| `unencrypted-ota-channel.yaml` | In-scope asset that originates a communication link tagged `ota` whose transport is not encrypted — `protocol` is not one of the encrypted protocols (`https`/`wss`/`binary-encrypted`/`text-encrypted`/`ssh`/`ssh-tunnel`/`sftp`/`scp`/`ftps`) and the link is not `vpn: true`. A cleartext OTA channel exposes the firmware payload and removes transport-layer MITM protection for software/firmware updates. Keys on the existing `ota` link tag, so no new model field is needed. | tampering / CWE-319 |
| `iso15118-server-only-tls.yaml` | In-scope asset that originates a communication link tagged `iso15118` (EV↔EVSE Plug & Charge) that is NOT mutual TLS — it lacks the `tls-mutual` tag and its authentication is not `client-certificate`. Server-only TLS (ISO 15118-2; marked explicitly with `tls-server-only`) leaves the charging session without mutual authentication and open to adversary-in-the-middle. Per-link TLS directionality is modeled via the `tls-server-only`/`tls-mutual` link tags. | spoofing / CWE-295 |
| `unauthenticated-someip-service-link.yaml` | In-scope asset that originates a communication link tagged `some-ip` with no authentication — service-oriented Automotive Ethernet (SOME/IP / SOME/IP-SD) has no built-in auth, so an unauthenticated link permits spoofed service offers, RPC/event injection, service-graph discovery, and lateral movement across zonal/domain boundaries. Fills the Ethernet Discovery/Lateral-Movement gap left by the CAN-focused safety-bus rules. | elevation-of-privilege / CWE-306 |
| `safety-function-without-redundancy.yaml` | In-scope asset tagged `safety-critical` that is not modeled `redundant: true` — a single point of failure with no fail-operational fallback, so one denial-of-service action (bus flood, ECU crash, sensor jam) removes the function. Fills the availability/DoS gap none of the other (integrity/auth) rules cover. | denial-of-service / CWE-400 |
| `relay-vulnerable-passive-entry.yaml` | In-scope asset that originates a short-range (`uwb`/`bluetooth`) link to a `body`-tagged access controller that does NOT carry the `distance-bounding` tag — passive entry/start without secure ranging is relay-attack vulnerable. Keys on absence of distance bounding, NOT authentication, because crypto auth does not stop a relay (the legitimate exchange is simply forwarded). | spoofing / CWE-290 |
| `unprotected-key-storage.yaml` | In-scope asset that processes/stores the `crypto-material` data asset (long-term keys/certs) but does NOT carry the `hsm` tag — key material held without hardware-backed storage is dumpable on code-exec or physical access, breaking every trust it anchors (firmware signing, backend auth, SecOC, secure boot, V2X). | information-disclosure / CWE-320 |
| `removable-media-ingress.yaml` | In-scope asset that originates a `removable-media`-tagged (USB/SD) link with no authentication — a media interface that parses untrusted content without signature/sandbox validation is both an initial-access vector (malformed-file parser exploit) and a data-exfiltration channel. | tampering / CWE-345 |

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
- `ota-backend-cleartext` — in-scope asset whose `ota`-tagged firmware-distribution link
  uses a cleartext `protocol` (`unknown-protocol`) → fires `unencrypted-ota-channel`, even
  though the link is `client-certificate` authenticated (authentication ≠ transport
  confidentiality). `ota-backend-tls` is the negative control: the same `ota`-tagged link
  over `https` must NOT fire.
- `evcc-server-only` — in-scope EVCC originating an `iso15118`-tagged Plug & Charge link
  tagged `tls-server-only` with authentication none → fires `iso15118-server-only-tls`
  (server-only TLS, no mutual authentication). `evcc-mutual-tls` is the negative control:
  the same `iso15118` link tagged `tls-mutual` with `authentication: client-certificate`
  must NOT fire. Both carry only the `charging`/`iso15118`/`tls-*` tags (no fieldbus/safety
  tag), so they trip no other rule.
- `someip-ecu` — in-scope ECU originating a `some-ip`-tagged service link with authentication
  none → fires `unauthenticated-someip-service-link` (spoofable SOME/IP-SD / RPC, lateral
  movement). `someip-secure` is the negative control: the same `some-ip` link carried over
  mutual TLS (`authentication: client-certificate`) must NOT fire. Both are tagged only
  `ecu`/`ethernet` (no exposure/gateway/safety tag), so they trip no other rule.
- `nonredundant-inverter` — in-scope `safety-critical` asset with no `redundant: true` →
  fires `safety-function-without-redundancy` (single-point DoS exposure). `redundant-actuator`
  is the negative control: same safety-critical tag but modeled `redundant: true`, so it must
  NOT fire. Neither originates a link, so they trip no bus/diagnostic rule.
- `keyfob-relay` — fob originating a `uwb`/`bluetooth` link to the `body`-tagged
  `body-access-controller` with no `distance-bounding` tag → fires
  `relay-vulnerable-passive-entry` even though the link is `credentials`-authenticated (crypto
  auth does not stop a relay). `keyfob-ranged` is the negative control: its `uwb` access link
  carries `distance-bounding`, so it must NOT fire.
- `keystore-no-hsm` — in-scope ECU that processes the `crypto-material` data asset with no
  `hsm` tag → fires `unprotected-key-storage` (keys not in hardware-backed storage). It uses a
  real `encryption` value and the `secure-boot` tag, so it trips neither internet-exposed rule.
  `keystore-hsm` is the negative control: same key holding but carries the `hsm` tag, so it must
  NOT fire.
- `media-host` — in-scope IVI originating a `removable-media`-tagged USB/SD link with
  authentication none → fires `removable-media-ingress` (untrusted-media ingress/exfil).
  `media-host-validated` is the negative control: its removable-media link uses authentication
  `client-certificate` (signed/validated content), so it must NOT fire.

Validated results: `unauthenticated-safety-bus-link` -> `chassis-zone-controller`,
`rogue-telematics`; `internet-exposed-ecu-unencrypted` -> `telematics-unit` only;
`reachable-unauthenticated-diagnostics` -> `obd-tester` only; `missing-secoc-on-safety-bus`
-> `chassis-zone-controller`, `token-auth-zone`, `rogue-telematics` (skips
`safe-chassis-gateway`); `cross-domain-link-no-filter` -> `rogue-telematics` only (skips
`telematics-unit` and `safe-chassis-gateway`); `unauthenticated-gateway-bridge` ->
`chassis-zone-controller` only (skips `safe-chassis-gateway`); `reachable-debug-port` ->
`debug-interface` only (skips `secure-debug-port`); `internet-exposed-ecu-no-secure-boot`
-> `connected-ecu-no-secure-boot` only (skips `secure-boot-ecu`, `telematics-unit`,
`rogue-telematics`, and the internet-`false` `infotainment-offline`);
`unencrypted-ota-channel` -> `ota-backend-cleartext` only (skips the `https` `ota-backend-tls`);
`iso15118-server-only-tls` -> `evcc-server-only` only (skips the mutual-TLS `evcc-mutual-tls`);
`unauthenticated-someip-service-link` -> `someip-ecu` only (skips the mutual-TLS `someip-secure`);
`safety-function-without-redundancy` -> `nonredundant-inverter` (and the other safety-critical
fixture assets) but NOT `redundant-actuator` (modeled `redundant: true`);
`relay-vulnerable-passive-entry` -> `keyfob-relay` only (skips the distance-bounded `keyfob-ranged`);
`unprotected-key-storage` -> `keystore-no-hsm` only (skips the `hsm`-tagged `keystore-hsm`);
`removable-media-ingress` -> `media-host` only (skips the validated `media-host-validated`).

## Caveat (still applies)

Production auto-loading of these YAML rules is **unconfirmed** upstream. They are authored
and harness-validated only. For findings that must ship in the report, emit them as
`individual_risk_categories` in the model rather than relying on auto-load.

## Deferred candidate rules

`unencrypted-ota-channel` is now authored: it keys on the existing `ota` link tag plus the
link's `protocol`/`vpn` (cleartext transport), so "OTA over cleartext" is expressed within
the tag vocabulary with no invented fields — the originally-assumed "OTA-update flag" was
unnecessary.

`iso15118-server-only-tls` is now authored: per-link TLS directionality is modeled within
the tag vocabulary using the `tls-server-only`/`tls-mutual` link tags (plus the existing
`client-certificate` authentication value for mutual TLS), so no field outside the
vocabulary was needed. The `iso15118` link tag identifies the EV↔EVSE Plug & Charge channel.

`internet-exposed-ecu-no-secure-boot` is now authored: the model carries a `secure-boot`
asset tag (assets that implement verified/secure boot carry it), so "lacks secure boot" is
expressed within the tag vocabulary as the absence of that tag, with no invented fields.

`reachable-debug-port` (hardware JTAG/UART debug surface, modeled via the `physical` link
tag) is now authored as a distinct rule from `reachable-unauthenticated-diagnostics`
(logical OBD-II/DoIP/UDS surface); the two cover different attack surfaces and do not
overlap on the fixture.
