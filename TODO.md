# TODO / Roadmap

Tracked backlog for the automotive Threagile model + analyzer. Items are grouped by area;
`[ ]` = open, `[x]` = done.

**Suggested next order:** (1) model — mark SecOC links + add the missing buses/debug assets →
(2) the two high-value rules they unblock (`missing-secoc-on-safety-bus`,
`cross-domain-link-no-filter`) → (3) make the repo public with branch protection.

## Custom risk rules (`model/custom-risk-rules/`)
Shipped: `unauthenticated-safety-bus-link`, `internet-exposed-ecu-unencrypted`,
`reachable-unauthenticated-diagnostics` (all CI-enforced via the `cmd/script` harness).

- [ ] `missing-secoc-on-safety-bus` — CAN/CAN-FD link to a `safety-critical` asset that is not
      SecOC-authenticated. *Blocked on:* model marking SecOC links (see Model).
- [ ] `cross-domain-link-no-filter` — connectivity→safety link crossing a trust boundary with
      no authenticated/filtering gateway. High value.
- [ ] `unauthenticated-gateway-bridge` — gateway/zone-controller bridging domains over an
      `auth=none` link.
- [ ] `reachable-debug-port` — exposed JTAG/UART/debug interface. *Blocked on:* modeling debug
      ports as assets. (OBD/DoIP is already covered by `reachable-unauthenticated-diagnostics`.)
- [ ] `unencrypted-ota-channel` — *deferred:* needs an OTA-update flag not in the model.
- [ ] `iso15118-server-only-tls` — *deferred:* needs per-link TLS directionality not modeled.
- [ ] `internet-exposed-ecu-no-secure-boot` — *deferred:* secure-boot is not modeled.

## Model (`model/threagile.yaml`)
- [ ] Mark **SecOC-authenticated** links where the architecture designs them in (today every
      bus link defaults to `authentication: none`). Unblocks `missing-secoc-on-safety-bus` and
      sharpens the analyzer's weakest-auth scoring.
- [ ] Add deferred assets skipped during build-out: FlexRay / SENT / PSI5 leaf buses, TPMS,
      passive-keyless LF/UHF, digital-key device, JTAG/UART/debug ports, USB/SD media. These
      also unblock rules above and fill technique-mapping gaps.
- [ ] Model **secure-boot / firmware-signing** (as tags or data-asset relationships) so the
      related rules become expressible.
- [ ] Drop the `(SEED)` suffix from the title now that it is a full 32-asset model.

## Analyzer (`scripts/attack_path_analyzer.py`)
- [x] Per-hop ATM + ATT&CK technique tagging.
- [ ] Optional **directed / reverse-edge** mode for true unidirectional gateways/diodes (the
      graph is undirected by design today).
- [ ] **Path-realism weighting** — weight/annotate paths by whether a real Auto-ISAC
      `ATM-Pxxxx` campaign exercised that technique against that asset class.
- [ ] Per-path mitigation hints derived from the chokepoint (min-cut) results.
- [ ] `pytest` unit tests beyond the single Jeep-demo regression.

## Technique mapping (maintained locally; not part of the published repo)
- [ ] Fill the ATM / ATT&CK crosswalk orphans now that the assets exist — V2X, GNSS,
      perception sensors, body/BCM, key-fob.

## Repo / process
- [x] CI: model validation, analyzer regression, ruff, Threagile report, custom-rule harness.
- [x] Branch → PR → merge flow with a local `pre-push` guard.
- [ ] **Make the repo public + enable branch protection** on `main` (require a PR and the CI
      status checks before merge). The local `pre-push` hook then becomes a backstop.
- [ ] `LICENSE` — replace the placeholder copyright holder if desired.
- [ ] Revisit the pinned Threagile version (`THREAGILE_REF` in `.github/workflows/ci.yml`);
      re-check whether `includes:` is supported (would simplify the merge in `run-threagile.sh`).

## Testing / docs
- [ ] Broaden the rule test fixture with more negative controls as rules grow.
- [ ] Add a sample findings summary / report screenshot to the README.
