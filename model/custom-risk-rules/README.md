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

Candidate first rules: unauthenticated-safety-bus-link, internet-exposed-ecu-no-secure-boot,
reachable-debug-port, unencrypted-ota-channel, iso15118-server-only-tls.
