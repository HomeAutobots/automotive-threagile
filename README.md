# automotive-threagile

[![CI](https://github.com/HomeAutobots/automotive-threagile/actions/workflows/ci.yml/badge.svg)](https://github.com/HomeAutobots/automotive-threagile/actions/workflows/ci.yml)

A [Threagile](https://threagile.io) threat model of a generic **composite (domain + zonal)
battery-electric vehicle with SAE Level 3+ automation**, plus a multi-hop attack-path
analyzer layered on top.

One model, two analysis passes:

1. **Threagile** runs its built-in risk rules over `model/threagile.yaml` and generates the
   report (`output/`).
2. **`library/analyzer/attack_path_analyzer.py`** reads the same model, builds an
   attacker-reachability graph, and finds the multi-hop attack paths and chokepoints from
   internet/RF-exposed **and physical** entry points to safety-critical actuation — emitted as a
   Threagile `individual_risk_categories` block so the path findings appear in the same report.

## Layout

The repo is a template: **`library/`** is the reusable, vehicle-agnostic engine; **`model/`** is
this vehicle's instance; **`examples/`** helps you start your own. See
[`library/README.md`](library/README.md).

| Path | Contents |
|---|---|
| `library/tags.yaml` | Canonical tag vocabulary (validated against the model). |
| `library/data-asset-taxonomy.yaml` | Reserved data-asset tags (`key-material`, `firmware-image`). |
| `library/conventions.md` | The modeling contract. |
| `library/custom-risk-rules/` | Custom Threagile YAML risk rules + test fixture. |
| `library/analyzer/attack_path_analyzer.py` | Multi-hop attack-path analyzer (Python + networkx). |
| `library/analyzer/examples/` | Bundled demo model + expected analyzer output (used by CI). |
| `model/threagile.yaml` | The canonical BEV model (this vehicle's instance). |
| `model/attack-paths.yaml` | Generated `individual_risk_categories` from the analyzer. |
| `examples/starter-skeleton.yaml` | Minimal valid 3-node model to start a new vehicle from. |
| `scripts/run-threagile.sh` | Wrapper around the Threagile Docker image. |
| `scripts/validate-model.sh` | Model parse + referential-integrity + vocab-drift checks. |
| `output/` | Generated Threagile artifacts (gitignored). |

## Prerequisites

- **Docker** (to run Threagile).
- **Python 3.10+** with `networkx` and `pyyaml`:
  ```bash
  python3 -m venv .venv && source .venv/bin/activate
  pip install networkx pyyaml
  ```

## Usage

Generate the Threagile report (`report.pdf`, diagrams, `risks.json/xlsx`) into `output/`:

```bash
./scripts/run-threagile.sh                 # uses model/threagile.yaml -> output/
```

Run the multi-hop attack-path analyzer:

```bash
python3 library/analyzer/attack_path_analyzer.py model/threagile.yaml --out model/attack-paths.yaml
```

Sanity-check the analyzer against the bundled demo (this is what CI runs):

```bash
python3 library/analyzer/attack_path_analyzer.py library/analyzer/examples/jeep-demo.threagile.yaml --out /tmp/demo.yaml
diff <(grep -v '^#' /tmp/demo.yaml) <(grep -v '^#' library/analyzer/examples/jeep-demo.attack-paths.expected.yaml) && echo "analyzer OK"
```

## Sample findings

Generated from the current model by `./scripts/run-threagile.sh` and
`library/analyzer/attack_path_analyzer.py` (reproducible — your numbers will track the model).

- **Threagile report:** built-in rules plus the merged multi-hop findings below. (The custom
  rules in `library/custom-risk-rules/` are validated separately via the `cmd/script` harness;
  upstream auto-loading is unconfirmed, so they are not part of the built-in count. Run
  `./scripts/run-threagile.sh` for the current totals.)
- **Multi-hop attack paths:** 8 entry points — 6 internet/RF-exposed (TCU, IVI, V2X, Wi-Fi/BT,
  GNSS, charge port) plus 2 physical (OBD-II port, debug port, scored one bucket below remote) —
  reach 8 safety-critical crown jewels (brake, steer, VCU, inverter, BMS, airbag, ADAS compute,
  FlexRay actuator) — **64 attack-path risks + 6 chokepoint risks**.
- **Top chokepoints (min node cut)** — best places to add an authenticated, filtering boundary:

  | Node | Jewel paths it gates |
  |---|---|
  | Central Gateway | 4 |
  | Front Zone Controller | 3 |
  | Chassis Zone Controller | 3 |
  | Battery Management System / Vehicle Control Unit | 2 each |

- **Per-hop technique tagging** — each path hop carries ATM + ATT&CK technique IDs, e.g.:

  ```
  TCU -> Central Gateway -> Chassis Zone Controller -> Brake ECU   [3 hops, weakest auth: none]
  ATT&CK: T0883 -> T0867/T0866 -> ... -> T1692.001/T0849/T0831/T0880
  ATM:    ATM-T0012 -> ATM-T0051/T0052 -> ... -> ATM-T0070/T0068
  realism: corroborated (ATM-P0006 chained the entry + lateral-movement techniques)
  ```

- **Path-realism weighting** — each path is weighted by whether documented real-world
  Auto-ISAC ATM campaigns (`ATM-Pxxxx`, e.g. the BMW and Tesla assessments) exercised its
  techniques: `corroborated` (one real campaign chained ≥2 of the path's techniques),
  `partially-corroborated`, or `theoretical`. The campaign↔technique evidence is embedded in
  the analyzer (no `frameworks/` dependency). It is informational — it does not change severity.

## Modeling conventions

The rules and analyzer are **tag-driven**, so they apply to any model that follows these
conventions — see [library/conventions.md](library/conventions.md) for the full tag vocabulary, per-rule
triggers, and run commands.

- **Default insecure.** Every raw CAN / CAN FD / LIN / FlexRay / SENT link, and any Ethernet
  link without explicit MACsec / IPsec / TLS, is `authentication: none`, `encryption: none`.
  Secure links are marked only where SecOC, MACsec, or TLS is actually designed in.
- **Exposure.** Internet/RF-exposed assets (TCU, IVI, V2X, Wi-Fi/BT, GNSS, charge port) are
  `internet: true` — these are the analyzer's entry set.
- **Crown jewels.** Safety-critical actuation (brake, steer, BMS, inverter, VCU, restraints)
  is tagged `safety-critical` — these are the analyzer's targets.

## Contributing

Changes go through a branch + PR (no direct commits to `main`); CI must pass before merge.
First-time setup in a clone: `git config core.hooksPath .githooks`. See
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE) © HomeAutobots.
