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
- [x] `unencrypted-ota-channel` — OTA-tagged (`ota`) link carried over a cleartext transport
      (not https/wss/*-encrypted/ssh/sftp/scp/ftps and not vpn). Keys on the existing `ota`
      link tag, so no new model field was needed. Harness-validated + CI-enforced. (The two
      modeled OTA links already use https + client-cert, so this fires on none of them today —
      it is a guardrail against a future cleartext OTA channel.)
- [x] `iso15118-server-only-tls` — an `iso15118`-tagged charging link that is not mutual TLS
      (no `tls-mutual` tag and authentication not `client-certificate`). Per-link TLS
      directionality is now modeled with the `tls-server-only`/`tls-mutual` link tags, so no
      invented field was needed. Harness-validated + CI-enforced. (Fires on the real model's
      EVCC->EVSE link, which is modeled as ISO 15118-2 server-only TLS.)
- [x] `internet-exposed-ecu-no-secure-boot` — internet-exposed ECU/compute lacking the
      `secure-boot` tag. Harness-validated + CI-enforced.

### ATM-derived candidate rules (gap analysis vs Auto-ISAC ATM, 14 tactics / 77 techniques)
The 10 shipped rules cover the integrity/auth columns (bus spoofing, diagnostics, gateway
bridging, secure boot, OTA, charging). The columns still thin are **Discovery + Lateral
Movement over Automotive Ethernet**, **Affect-Vehicle-Function via DoS/availability**,
**Credential Access**, and **wireless relay / removable media**. Derived candidates:

- [x] `unauthenticated-someip-service-link` — `some-ip`-tagged service link with
      `authentication: none` (SOME/IP has no built-in auth; spoofable SD/RPC). Fills the
      Ethernet Discovery/Lateral-Movement gap. Maps ATM-T0044/T0048/T0049 (discovery),
      ATM-T0051/T0053 (lateral movement), ATM-T0038 (sniffing). Harness-validated + CI-enforced.
- [x] `safety-function-without-redundancy` — asset tagged `safety-critical` not modeled
      `redundant: true` — exposes the function to single-point bus/endpoint DoS. Fills the
      **availability** gap none of the other rules cover. Maps ATM-T0068 (CAN Bus DoS),
      ATM-T0072 (DoS on Vehicle Function), ATM-T0002. Harness-validated + CI-enforced. The
      by-wire actuators (brake-ecu, steering-ecu) are now modeled `redundant: true`
      (ASIL-D fail-operational); the remaining safety functions fire as DoS single-points.
- [x] `relay-vulnerable-passive-entry` — `uwb`/`bluetooth` access link to a `body`-tagged
      controller without the `distance-bounding` tag. Keys on absence of secure ranging, NOT
      authentication (crypto auth does not stop a relay). Added a `distance-bounding`
      capability tag to the vocabulary. Maps ATM-T0007 (Relay Communications), ATM-T0065.
      Harness-validated + CI-enforced. (Fires on the real model's digital-key + Wi-Fi/BT
      passive-entry links to the body controller.)
- [ ] `unprotected-key-storage` — internet-exposed asset that stores crypto/credential data
      (e.g. the `crypto-material` data asset) without `secure-boot` / hardware key storage.
      Maps ATM-T0039 (ECU Credential Dumping), ATM-T0040 (Unsecured Credentials), ATM-T0075.
- [ ] `removable-media-ingress` — unauthenticated `physical` removable-media (USB/SD) link
      into infotainment/telematics (code/data ingress + exfil). Maps ATM-T0013/T0006.
      (Needs a `removable-media` link tag — would expand the vocabulary first.)

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
- [x] Model **per-link TLS directionality** — added `iso15118`, `tls-server-only`, and
      `tls-mutual` link tags (vocabulary expanded); the EVCC->EVSE ISO 15118 link is corrected
      to originate from the in-scope charge controller and modeled as ISO 15118-2 server-only
      TLS (`tls-server-only`, authentication none).
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
- [x] Fill the ATM / ATT&CK crosswalk orphans — all 10 resolved (ATM 3, ATT&CK 7): sensor
      attacks → camera/radar/lidar/ultrasonic/GNSS, adversarial-ML → adas-compute, key-fob
      relay → digital-key/body-controller, V2X → v2x-module, mobile techniques → companion-app.
      Done in the local-only `frameworks/` tree; `validate-frameworks.py` reports 0 orphans.

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
