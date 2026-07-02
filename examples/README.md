# How to model your vehicle

A step-by-step guide to modeling *your* vehicle with this toolkit. You edit one file
(a Threagile model) using the shared tag vocabulary; the 16 custom risk rules and the
multi-hop attack-path analyzer then apply automatically — they are tag-driven and never
reference specific asset names.

- The reusable engine you're consuming: [`../library/`](../library/README.md)
- The full contract (tag vocabulary, per-rule triggers): [`../library/conventions.md`](../library/conventions.md)
- Your starting point: [`starter-skeleton.yaml`](starter-skeleton.yaml) — a valid 3-node model
  (internet entry → gateway → brake ECU) you grow.

## 0. Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install networkx pyyaml
```

In your fork, make **your** vehicle the instance at `model/threagile.yaml` — either edit it, or
start clean from the skeleton (`cp examples/starter-skeleton.yaml model/threagile.yaml`). Keeping
the default path means all the tooling works unchanged: the vocab-drift guard, the
`attack-paths.yaml` merge in `run-threagile.sh`, and the CI drift check. (A custom filename works
for `validate-model.sh` and the analyzer too, but you'd merge the report yourself.)

## 1. Classify every asset (the decision guide)

For each ECU / compute node / sensor / interface, answer these — the answers become tags
and fields the analyzer keys on:

| Question | If yes → | Effect |
|---|---|---|
| Is it internet/RF-reachable? (modem, IVI, V2X, Wi-Fi/BT, GNSS, charge port) | `internet: true` | **Remote entry point** — the analyzer starts attack paths here. |
| Is it a physical port an attacker can touch? (OBD-II, JTAG/debug, USB/SD) | tag `physical` / `obd-ii` / `removable-media`, keep in scope | **Physical entry point** — paths start here, scored one bucket below remote. |
| Does it perform safety actuation/authority? (brake, steer, BMS, inverter, VCU, airbag, ADAS) | tag `safety-critical` + `integrity: mission-critical` | **Crown jewel** — the analyzer's target; paths are scored against reaching it. |
| Does it bridge domains/zones? (gateway, zone controller) | tag `gateway` / `zone-controller` | **Pivot / chokepoint** — counted in the min-cut analysis. |
| Does it hold long-term keys/certs? | list a data asset tagged `key-material`; add `hsm` only if hardware-backed | Triggers `unprotected-key-storage` if no `hsm`; adds a key-theft hop. |
| Does it receive/install firmware? | list a data asset tagged `firmware-image`; add `firmware-signing` only if verified on-device | Triggers `unverified-firmware-update` if unsigned. |

### Which control tags to add

Add a hardening tag **only when the control is actually designed in** (absence = the risk):
`secure-boot`, `hsm`, `firmware-signing`, `anti-rollback`, `binary-hardening`,
`memory-protection`, `attack-surface-reduction`, `sensor-plausibility`. Two caveats:
- **`ids`** is detect-only — it earns **no** likelihood reduction (AUTOSAR IDS reports, it
  doesn't prevent; stealth bus-off evades it). Tag it for documentation, not credit.
- **`distance-bounding`** is the *secure* marker on UWB/BLE key links — leave it **off** a
  relay-vulnerable link so `relay-vulnerable-passive-entry` fires.

## 2. Model the buses (links)

Threagile has no CAN/Ethernet protocol values, so overload `protocol` and put the real bus in
the link **tags**. Default every in-vehicle link to `authentication: none` unless a control is
designed in:

```yaml
    communication_links:
      To Brake ECU:
        target: brake-ecu
        description: CAN FD to brake-by-wire ECU
        protocol: binary              # binary=CAN/CAN-FD/LIN/FlexRay/SENT; https=Ethernet/SOME-IP
        authentication: none          # or `credentials` for SecOC (AES-CMAC + freshness)
        tags: [can-fd]
        data_assets_sent: [safety-control-messages]
```

Bus tags: `can` `can-fd` `lin` `flexray` `sent` `ethernet` `some-ip` `doip`. See
[`../library/conventions.md`](../library/conventions.md) for SecOC, TLS directionality, OTA, etc.

## 3. Put every in-scope asset in exactly one trust boundary

```yaml
trust_boundaries:
  Safety Domain:
    id: safety-domain
    type: network-virtual-lan
    technical_assets_inside: [brake-ecu, steering-ecu]
```

The validator warns on an in-scope asset with no boundary and errors on one in two.

## 4. Validate, generate, report

```bash
# 1. Structural + referential + vocab-drift checks (fast, local)
./scripts/validate-model.sh                 # defaults to model/threagile.yaml

# 2. Multi-hop attack paths + chokepoints -> individual_risk_categories
python3 library/analyzer/attack_path_analyzer.py model/threagile.yaml --out model/attack-paths.yaml
#    add --entry-tags "" for remote-only, or --directed to honor one-way links

# 3. Full Threagile report (built-in rules + merged paths) -> output/
./scripts/run-threagile.sh                  # merges model/attack-paths.yaml into the report
```

`validate-model.sh` catches the silent-failure traps: an undeclared tag, a dangling link
target, a data-asset typo, an asset in the wrong number of boundaries, or a `tags_available`
that has drifted from `library/tags.yaml`.

## 5. Read the output

Each attack-path finding's title is a hop-by-hop chain:

```
Telematics Control Unit -> Central Gateway -> Brake ECU  [2h, weakest auth none]
| ATT&CK: T0883 -> T0867/T0866 -> ...  | ATM: ATM-T0012 -> ATM-T0051/T0052 -> ...
| realism: corroborated (...)  | entry: demonstrated foothold (...)  | controls: central-gateway:memory-protection (-1)
```

- **severity** = likelihood × impact; impact is the target's integrity, likelihood comes from
  the weakest auth on the path, path length, entry type (remote vs physical), and the hardening
  controls that fired.
- **realism** weights the path by whether real Auto-ISAC ATM campaigns chained its techniques —
  informational, never changes severity.
- **chokepoints** are the min-cut nodes: the best places to insert an authenticated, filtering
  boundary to break the most paths at once.

## 6. Completeness checklist

- [ ] Every external/RF interface is `internet: true`; every physical port is tagged & in-scope.
- [ ] Every safety actuator is tagged `safety-critical` with `mission-critical` integrity.
- [ ] Every bus link is tagged with its bus and has honest `authentication`/`encryption`.
- [ ] Key-holders list a `key-material` data asset; firmware-handlers a `firmware-image` one.
- [ ] Hardening tags reflect controls that are *actually designed in* (absence = risk).
- [ ] Every in-scope asset is in exactly one trust boundary.
- [ ] `tags_available` matches `library/tags.yaml`; `./scripts/validate-model.sh` is clean.
- [ ] `attack-paths.yaml` regenerated after any model edit.

## Extending the toolkit

New attack surface with no matching rule? Scaffold a custom rule (see
[`../library/custom-risk-rules/README.md`](../library/custom-risk-rules/README.md)) and validate
it with `./scripts/test-risk-rules.sh`. New control class? Add a tag to `library/tags.yaml` +
your `tags_available`, and (for likelihood credit) wire it into the analyzer's `CONTROL_CATALOG`
against the technique it defeats.
