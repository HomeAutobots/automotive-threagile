# automotive-threagile

[![CI](https://github.com/HomeAutobots/automotive-threagile/actions/workflows/ci.yml/badge.svg)](https://github.com/HomeAutobots/automotive-threagile/actions/workflows/ci.yml)

A [Threagile](https://threagile.io) threat model of a generic **composite (domain + zonal)
battery-electric vehicle with SAE Level 3+ automation**, plus a multi-hop attack-path
analyzer layered on top.

One model, two analysis passes:

1. **Threagile** runs its built-in risk rules over `model/threagile.yaml` and generates the
   report (`output/`).
2. **`scripts/attack_path_analyzer.py`** reads the same model, builds an attacker-reachability
   graph, and finds the multi-hop attack paths and chokepoints from internet/RF-exposed assets
   to safety-critical actuation — emitted as a Threagile `individual_risk_categories` block so
   the path findings appear in the same report.

## Layout

| Path | Contents |
|---|---|
| `model/threagile.yaml` | The canonical model (single source of truth). |
| `model/attack-paths.yaml` | Generated `individual_risk_categories` from the analyzer. |
| `model/custom-risk-rules/` | Custom Threagile YAML risk rules. |
| `scripts/attack_path_analyzer.py` | Multi-hop attack-path analyzer (Python + networkx). |
| `scripts/run-threagile.sh` | Wrapper around the Threagile Docker image. |
| `scripts/validate-model.sh` | Quick model-parse sanity check. |
| `scripts/examples/` | Bundled demo model + expected analyzer output (used by CI). |
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
python3 scripts/attack_path_analyzer.py model/threagile.yaml --out model/attack-paths.yaml
```

Sanity-check the analyzer against the bundled demo (this is what CI runs):

```bash
python3 scripts/attack_path_analyzer.py scripts/examples/jeep-demo.threagile.yaml --out /tmp/demo.yaml
diff <(grep -v '^#' /tmp/demo.yaml) <(grep -v '^#' scripts/examples/jeep-demo.attack-paths.expected.yaml) && echo "analyzer OK"
```

## Modeling conventions

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
