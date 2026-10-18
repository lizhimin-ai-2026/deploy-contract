# Deploy Contract Gate (deploy-contract)

A pre-deploy gate (P0 gate layer) for cloud-function deployment requests, enforcing a configurable deploy contract — by default max 6 deploys per day, max 3 per function per day, minimum 30s interval — plus a secret precheck and a verbatim written-override trail. v2.0 adds: secret precheck integration / atomic cross-process counting / verbatim single-use override / dual-channel host interfaces / storage migration with bilingual report / CleanKeeper undo for reports / 19-case self-test gate.

## Core capabilities

- **Four-step gate**: ① secret precheck (secret-guardian) → ② daily ≤ 6 → ③ per-function ≤ 3 → ④ interval ≥ 30s
- **Whitelist**: configurable (example `{syncKnowledge, identify}`); the host system's own deploys go through the same gate
- **Override**: deploy owner's written verbatim release quote into the log, no secondary confirmation, single-use only (scope binding + sha256 single consumption)
- **Atomic counting**: `state/deploy_state.json` + cross-process spinlock, no under-blocking under concurrency; only `ALLOW` events count
- **Dual channel**: `query` / `export` / `submit` subcommands (no UI dependency); voice "check deployment / deploy release / show records / deploy report"
- **Bilingual report**: daily/weekly allow / deny (by rule_id) / override summary + remaining quota (Chinese + English)
- **Undo protection**: report-file deletion goes through CleanKeeper (backup area + manifest + keep 3 + sha256 restore); audit logs are not undoable
- **16-column audit**: deploy.allow/deny/override exported to the audit base (zero secret values on disk)

## Structure

```
deploy-contract/
├── SKILL.md
├── README.md
├── LICENSE.md
├── .gitignore
└── assets/
    ├── deploy_rules.json
    └── scripts/
        ├── deploy_gate.py
        └── README.md
```

## Usage

```bash
# Submit a deploy request (returns allow/deny + rule_id + remaining quota)
python assets/scripts/deploy_gate.py submit --function <fn> [--content <path>] [--override "<quote>"]

# Query / export bilingual report
python assets/scripts/deploy_gate.py query [--result ALLOW|DENY] [--function <fn>] [--format table|csv|json]
python assets/scripts/deploy_gate.py export --format md|json|csv [--out F]

# Undo / migrate / self-test
python assets/scripts/deploy_gate.py undo --list | --restore <undo_id>
python assets/scripts/deploy_gate.py migrate
python assets/scripts/deploy_gate.py --selftest
```

## Verdicts

| Result | Meaning |
|---|---|
| ALLOW | passed the four steps / deploy-owner written release (override, verbatim in log) |
| DENY · CRIT | non-whitelisted function / secret precheck hit / secret guardian unavailable |
| DENY · WARN | daily cap / per-function cap / interval too short |

## Red lines

Computable rules (single source) / default deny / override trail (verbatim) / self same gate / secret red line (zero secret values on disk).

## Version

- v2.0.0 (2026-10-19): full alignment + secret precheck integration + complete override channel + dual-channel ready + open-source ready.
