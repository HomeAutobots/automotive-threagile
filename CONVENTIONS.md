# Conventions & usage

How to model a vehicle so the custom risk rules and the multi-hop analyzer in this repo
apply to it, and how to run them. The rules and analyzer are **tag-driven** — they match on
the tag vocabulary and link attributes below, never on specific asset names — so they work on
any Threagile model that follows these conventions, not just the bundled one.

## Tag vocabulary

Every tag used on an asset or communication link must be declared in the model's top-level
`tags_available:` block. The controlled vocabulary:

| Group | Tags |
|---|---|
| Domain / role | `safety-critical` `ecu` `gateway` `zone-controller` `connectivity` `infotainment` `telematics` `adas` `powertrain` `chassis` `body` `charging` |
| In-vehicle buses | `can` `can-fd` `lin` `flexray` `ethernet` `some-ip` `doip` |
| External / RF interfaces | `obd-ii` `v2x` `cellular` `bluetooth` `uwb` `gnss` `ota` |
| Exposure / physical | `external` `physical` |
| Capability | `secure-boot` |

## Modeling conventions

- **Default insecure.** Every raw CAN / CAN FD / LIN / FlexRay / SENT link, and any Ethernet
  link without explicit MACsec / IPsec / TLS, is `authentication: none`, `encryption: none`.
  Mark a link secure only where a control is actually designed in.
- **Buses ride on tags, not protocol enums.** Threagile has no native CAN/LIN/Ethernet
  protocol values, so use `protocol: binary` (or `text`/`https` as fitting) and put the real
  bus in the link `tags` (`can`, `can-fd`, `lin`, `flexray`, `ethernet`, `some-ip`, `doip`, …).
- **Exposure.** Mark internet/RF-reachable assets `internet: true` (TCU, IVI, V2X, Wi-Fi/BT,
  GNSS, charge port, …). These are the analyzer's **entry set**.
- **Crown jewels.** Tag safety-critical actuation/authority (brake, steer, BMS, inverter, VCU,
  airbag, ADAS compute) `safety-critical`. These are the analyzer's **targets**.
- **SecOC.** Represent AUTOSAR SecOC (authenticity + freshness, no confidentiality) on a bus
  link as `authentication: credentials` with `encryption: none` (a description noting "SecOC"
  is recommended). Absence of it on a safety bus is what `missing-secoc-on-safety-bus` flags.
- **Secure boot.** Tag assets that implement a verified/secure boot chain with `secure-boot`.
  Internet-exposed compute lacking it is what `internet-exposed-ecu-no-secure-boot` flags.
- **OTA.** Tag any software/firmware update link `ota`. Model the transport honestly via
  `protocol` (`https`/`wss`/`*-encrypted` for TLS/DTLS, or `vpn: true` for a tunnel); a
  cleartext `protocol` on an `ota` link is what `unencrypted-ota-channel` flags.

## How each custom rule keys on the model

Tag your model per the above and these rules apply automatically (in
`model/custom-risk-rules/`):

| Rule | Fires when… |
|---|---|
| `unauthenticated-safety-bus-link` | a `can`/`can-fd`/`lin`/`flexray` link with `authentication: none` reaches a `safety-critical` asset |
| `missing-secoc-on-safety-bus` | a fieldbus link to a `safety-critical` asset whose auth is **not** SecOC (`credentials`) — broader than the above |
| `cross-domain-link-no-filter` | an exposed-domain source (`connectivity`/`telematics`/`infotainment`/`external`/`v2x`) links directly to safety with no `gateway`/`zone-controller` in between, unauthenticated |
| `unauthenticated-gateway-bridge` | a `gateway`/`zone-controller` originates an `authentication: none` bridging link |
| `internet-exposed-ecu-unencrypted` | an `internet: true` asset tagged `ecu`/`telematics`/`infotainment` has `encryption: none` |
| `internet-exposed-ecu-no-secure-boot` | an `internet: true` compute asset (`ecu`/`telematics`/`infotainment`/`connectivity`) lacks the `secure-boot` tag |
| `reachable-unauthenticated-diagnostics` | an `obd-ii`/`doip` link has `authentication: none` |
| `reachable-debug-port` | a `physical`-tagged (JTAG/UART) link has `authentication: none` |
| `unencrypted-ota-channel` | an `ota`-tagged link uses a cleartext transport (not an encrypted `protocol` and not `vpn: true`) |

## Running it

```bash
# Threagile report (built-in rules + merged multi-hop findings) -> output/
./scripts/run-threagile.sh

# Multi-hop attack-path analyzer (paths + chokepoints + per-hop ATM/ATT&CK tags)
python3 scripts/attack_path_analyzer.py model/threagile.yaml --out model/attack-paths.yaml
#   --directed   honor true unidirectional links (readonly:true or a `diode` tag)

# Validate the model parses (strict: rejects duplicate keys, like Threagile's parser)
./scripts/validate-model.sh

# Validate the custom rules with Threagile's cmd/script harness (needs Go + the Threagile source)
git clone https://github.com/Threagile/threagile.git /tmp/threagile-src
./scripts/test-risk-rules.sh /tmp/threagile-src
```

## Caveat: how rule findings reach the report

Threagile's **production auto-loading of YAML risk-rule scripts is unconfirmed upstream**.
So the custom rules here are authored and validated with the `cmd/script` harness, not relied
upon to auto-run during `threagile analyze`. Any finding that must appear in the generated
report is emitted as an `individual_risk_categories` block merged into the model — which is
exactly how the analyzer's attack-path and chokepoint findings get into the unified report.
