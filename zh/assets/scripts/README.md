# deploy_gate.py — usage

Pure Python standard library, zero third-party dependencies. Python 3.11+.

## Subcommands

### submit
```bash
python deploy_gate.py submit --function <fn> [--content <path>] [--override "<quote>"] [--base-dir X]
```
Runs the four-step gate and prints a JSON result:
```json
{"result":"ALLOW","severity":"INFO","rule_id":"allow","note":"...","remaining":{"daily":5,"function":2},"event_path":"..."}
```
- `--content <path>`: path to the deploy content file for the secret precheck (only the path is passed; zero secret values).
- `--override "<quote>"`: deploy-owner written verbatim release quote (quoted into the log, single-use).
- Exit code 0 = ALLOW, 1 = DENY.

### query
```bash
python deploy_gate.py query [--result ALLOW|DENY] [--function <fn>] [--date-from D] [--date-to D] [--limit N] [--format table|csv|json]
```

### export
```bash
python deploy_gate.py export --format md|json|csv [--out F]
```
Bilingual (Chinese + English) deploy report: allow / deny (grouped by rule_id) / override summary / remaining quota.

### undo
```bash
python deploy_gate.py undo --list | --restore <undo_id>
python deploy_gate.py clean --file <report>
```
Report files go through CleanKeeper undo (backup area + manifest + keep last 3 + sha256 verified restore). Audit logs are not undoable.

### migrate
```bash
python deploy_gate.py migrate
```
Copies legacy `assets/deploy_log` into the default `%LOCALAPPDATA%\Lanzhi\deploy-contract\log` (copy, not delete).

### --selftest
```bash
python deploy_gate.py --selftest
```
19-case gate (8 legacy + 11 new). All must pass before delivery.

## Host integration

- Default storage: `%LOCALAPPDATA%\Lanzhi\deploy-contract\` (log/ state/ reports/ undo/).
- Secret precheck: set `LANZHI_SECRET_GUARD_SCRIPT` to the secret guardian's `secret_guard.py`, or rely on `deploy_rules.json → precheck.script_candidates`. If unavailable → safe default deny.
- Audit export: set `LANZHI_AUDIT_SCRIPT` to the audit base's `audit_core.py` and `LANZHI_AUDIT_BASE` to its storage base; deploy events are ingested as 16-column events (zero secret values).
