# TODO / Roadmap

Tracked backlog for the automotive Threagile model + analyzer. Items are grouped by area;
`[ ]` = open, `[x]` = done.

**Suggested next order:** (1) model — mark SecOC links + add the missing buses/debug assets →
(2) the two high-value rules they unblock (`missing-secoc-on-safety-bus`,
`cross-domain-link-no-filter`) → (3) make the repo public with branch protection.

## Custom risk rules (`model/custom-risk-rules/`)
Shipped: `unauthenticated-safety-bus-link`, `internet-exposed-ecu-unencrypted`,
`reachable-unauthenticated-diagnostics` (all CI-enforced via the `cmd/script` harness).

- [x] `missing-secoc-on-safety-bus` — fieldbus link to a `safety-critical` asset whose auth is
      not SecOC (`credentials`); strictly broader than `unauthenticated-safety-bus-link`
      (also catches non-SecOC auth). Harness-validated + CI-enforced.
- [x] `cross-domain-link-no-filter` — exposed-domain source linking directly to safety without
      an authenticated gateway/zone in between. Harness-validated + CI-enforced.
- [x] `unauthenticated-gateway-bridge` — gateway/zone-controller originating an `auth=none`
      bridging link. Harness-validated + CI-enforced.
- [x] `reachable-debug-port` — in-scope asset with a `physical`-tagged unauthenticated debug
      (JTAG/UART) link; distinct from `reachable-unauthenticated-diagnostics` (OBD/DoIP).
      Harness-validated + CI-enforced.
- [ ] `unencrypted-ota-channel` — *deferred:* needs an OTA-update flag not in the model.
- [ ] `iso15118-server-only-tls` — *deferred:* needs per-link TLS directionality not modeled.
- [x] `internet-exposed-ecu-no-secure-boot` — internet-exposed ECU/compute lacking the
      `secure-boot` tag. Harness-validated + CI-enforced.

## Model (`model/threagile.yaml`)
- [x] Mark **SecOC-authenticated** links — modeled (as `authentication: credentials` +
      description) on flagship by-wire/propulsion CAN-FD buses (brake, steer, VCU↔inverter,
      VCU→BMS); other safety buses left unauthenticated by design so the gaps stay visible.
- [x] Add deferred assets — added JTAG/UART **debug port**, **digital key / key fob**, **TPMS**,
      a legacy **FlexRay** chassis link/actuator, and **USB/SD media**. *Still deferred:*
      SENT/PSI5 sensor buses and the NFC digital-key surface (need tags not in the vocabulary —
      would require expanding the tag vocabulary first).
- [x] Model **secure-boot** — added a `secure-boot` tag (vocabulary expanded) on the main
      compute, gateways/zones, and flagship safety ECUs; the simpler RF modules + charge
      controller deliberately lack it (the gap the no-secure-boot rule flags).
- [ ] Model **firmware-signing / Uptane** as a distinct property (partially implied today by
      the OTA client-cert link + crypto-material data asset) if a dedicated rule is wanted.
- [x] Drop the `(SEED)` suffix from the title (now `Composite BEV Zonal L3+`).

## Analyzer (`scripts/attack_path_analyzer.py`)
- [x] Per-hop ATM + ATT&CK technique tagging.
- [x] Optional **directed / reverse-edge** mode (`--directed`) — DiGraph with forward+reverse
      edges except true diodes (`readonly: true` or a `diode` tag).
- [ ] **Path-realism weighting** — weight/annotate paths by whether a real Auto-ISAC
      `ATM-Pxxxx` campaign exercised that technique against that asset class. *(Needs the
      local-only campaign data embedded, like the technique tags — deferred.)*
- [x] Per-path mitigation hints (stdout) derived from the chokepoint (min-cut) results.
- [x] `pytest` unit tests (`tests/test_analyzer.py`, 13 cases) + CI `tests` job.

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
- [x] `validate-model.sh` rejects duplicate YAML keys (matches Threagile's strict Go parser;
      PyYAML silently kept the last one).
- [ ] Broaden the rule test fixture with more negative controls as rules grow.
- [x] Add a sample findings summary to the README (report severity breakdown, multi-hop
      paths, chokepoints, a per-hop technique-tagged path).
