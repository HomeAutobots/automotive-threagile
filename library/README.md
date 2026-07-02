# `library/` — the reusable vehicle threat-modeling engine

Everything in this directory is the **reusable toolkit**: the tag vocabulary, the
custom risk rules, the multi-hop attack-path analyzer, and the modeling conventions.
It is vehicle-agnostic. To model *your* vehicle you edit `model/` (the instance) and,
optionally, start from `examples/starter-skeleton.yaml` — you should not need to edit
anything in here.

## Layout

| Path | What it is |
|------|-----------|
| `tags.yaml` | Canonical tag vocabulary (the contract). Copy this into your model's `tags_available`; `scripts/validate-model.sh` fails if they drift. |
| `data-asset-taxonomy.yaml` | Reserved **data-asset** tags (`key-material`, `firmware-image`) that rules/analyzer key off — so your data assets can be named anything. See ADR 0006. |
| `conventions.md` | The modeling contract: default-insecure, protocol-overloading, SecOC = `credentials`, controls-as-tags, TLS directionality, ASIL-in-prose. |
| `custom-risk-rules/` | 16 Threagile YAML risk rules (per-asset/per-link checks) + a parsed-format test fixture. Validated by `scripts/test-risk-rules.sh` via the `cmd/script` harness. |
| `analyzer/attack_path_analyzer.py` | Pass B: builds the attacker-reachability graph, finds multi-hop paths + chokepoints, scores them with the ECU-hardening `CONTROL_CATALOG`, emits `individual_risk_categories`. |
| `analyzer/examples/jeep-demo.*` | A minimal analyzer regression fixture (input model + expected output). |

## How the two passes fit together

1. **Pass A — local rules.** `threagile analyze` runs Threagile's built-in rules plus
   the `custom-risk-rules/`. Structural/datapath findings.
2. **Pass B — multi-hop.** `analyzer/attack_path_analyzer.py` reads the *same*
   `model/threagile.yaml`, computes reachability paths a per-asset rule cannot express,
   and writes `model/attack-paths.yaml` (an `individual_risk_categories` block) that
   merges back into the same report.

Both are **entirely tag-driven** — there are no hardcoded asset ids in the analyzer or
the rules. A different vehicle "just works" as long as its model uses this vocabulary.

## Using the library for your own vehicle

Full walkthrough (decision guide + step-by-step + checklist): [`examples/README.md`](../examples/README.md).
In brief:

1. Start from `examples/starter-skeleton.yaml` (a valid 3-node model) or fork
   `model/threagile.yaml`.
2. Declare `library/tags.yaml`'s tags in your model's `tags_available`.
3. Tag your data assets: the crypto-key one `key-material`, the firmware one
   `firmware-image` (see `data-asset-taxonomy.yaml`).
4. Model your ECUs/links/boundaries following `conventions.md`.
5. Validate: `scripts/validate-model.sh <your-model>.yaml`.
6. Generate paths: `python3 library/analyzer/attack_path_analyzer.py <your-model>.yaml --out <your-paths>.yaml`.
7. Report: `scripts/run-threagile.sh`.

Distribution model and the library/instance split: ADR 0005.
