---
name: Deploy Contract Gate (deploy-contract)
description: A pre-deploy gate for cloud-function deployments enforcing a configurable contract (max N deploys per day, max M per function per day, minimum interval between deploys) plus a secret precheck and a verbatim written-override trail. Four-step gate (secret-precheck → daily cap → per-function cap → interval), atomic cross-process counting, dual-channel query/export/submit host interfaces, CleanKeeper undo for reports, and 16-column audit export. Pure Python standard library, zero third-party dependencies.
version: 2.0.0
---

# Deploy Contract Gate (deploy-contract)

## Overview

A pre-deploy gate (P0 gate layer) for cloud-function deployment requests. It enforces a configurable deploy contract — by default max 6 deploys per day, max 3 per function per day, minimum 30s interval — and blocks anything that violates it. Rules live in `deploy_rules.json` (computable, single source of truth). The host system's own function deploys go through the same gate.

**Core principles**: every deploy must pass the gate; rules are computable; overrides require a verbatim written release quote into the log; the secret red line is never bypassed.

## Four-step gate (trigger → precheck → validate → record)

```
cloud-function deploy request
      │ trigger
      ▼
┌──────────────────────────────────┐
│  Deploy Contract Gate              │
│  ① Secret precheck (secret-guard) │
│  ② Daily deploys ≤ 6              │
│  ③ Per-function deploys ≤ 3       │
│  ④ Interval ≥ 30s                 │
│  → Allow / Deny (→ audit)         │
└──────────────────────────────────┘
```

| Step | Check | Verdict |
|---|---|---|
| ① Secret precheck | Deploy content scanned by the secret guardian | Hit plaintext secret → Deny (CRIT, rule_id=secret-precheck) |
| ② Daily cap | Total deploys today ≤ 6 (Asia/Shanghai +08:00) | Exceeded → Deny (WARN, day-limit) |
| ③ Per-function cap | Same function today ≤ 3 | Exceeded → Deny (WARN, fn-limit) |
| ④ Interval | ≥ 30s since last deploy | Too short → Deny (WARN, interval) |

> Counting semantics (v2.0 fix): only `ALLOW` events count; `DENY` does not consume quota. The day window uses Asia/Shanghai (+08:00, no DST).
> Cross-process atomicity: `state/deploy_state.json` + a spinlock serialize reads/writes so concurrent requests never under-block.

## Whitelist

- Whitelisted functions (configurable example): `{syncKnowledge, identify}`
- The host system's own deploys go through the same gate (only whitelisted functions may deploy).
- Configure the contract in `deploy_rules.json` (single source of truth).

## Override rule

- An override = a written verbatim release quote from the deploy owner (quoted into the log verbatim, no secondary confirmation button).
- The quote is auto-appended to the deploy log `note` column **verbatim**; it only bypasses ② daily / ③ per-function / ④ interval — it can **never** bypass ① whitelist or ① secret precheck.
- Scope binding: the quote must contain the target function name; single-use — consumed once by sha256(first 16 chars) of the verbatim quote; not carried to another function / next day / re-submit.

## Dual-channel host interface (voice + click)

| Voice command | Maps to | Notes |
|---|---|---|
| "Check deployment" | `query` | Query deploy events / daily counts / history |
| "Deploy release `<quote>`" | `submit --override "<quote>"` | Submit + verbatim quote into log |
| "Show deploy records" | `query [--result/--function]` | Filtered query |
| "Deploy report" | `export --format md` | Export bilingual deploy report |

- Click entry: Security Center → Deploy Contract Gate → Submit deploy request / View records.
- Voice ≡ click (single execution path). Failure → safe default (deny).

## Commands

```bash
# Submit a deploy request (gate → allow/deny + rule_id + remaining quota)
python assets/scripts/deploy_gate.py submit --function <fn> [--content <path>] [--override "<quote>"] [--base-dir X]

# Backward compatible: python deploy_gate.py --function <fn> [--override "<quote>"]

# Query: --result ALLOW|DENY / --function / --date-from / --date-to / --limit / --format table|csv|json
python assets/scripts/deploy_gate.py query [options]

# Export bilingual deploy report (md/json/csv)
python assets/scripts/deploy_gate.py export --format md|json|csv [--out F]

# Undo: report files go through CleanKeeper undo (backup area + manifest + keep 3 + sha256 restore)
python assets/scripts/deploy_gate.py undo --list | --restore <undo_id>
python assets/scripts/deploy_gate.py clean --file <report>

# Migrate legacy data to %LOCALAPPDATA%
python assets/scripts/deploy_gate.py migrate

# Self-test gate (19 cases)
python assets/scripts/deploy_gate.py --selftest
```

## Red lines

1. **Computable rules**: `deploy_rules.json` is the single source of truth; do not bypass via code.
2. **Default deny**: failed check → deny; non-whitelisted functions cannot deploy; secret precheck failure → safe default deny.
3. **Override trail**: verbatim written release quote into the log, auditable; single-use only.
4. **Self same gate**: the host system's own deploys are no exception.
5. **Secret red line**: precheck transmits verdict only, zero secret values on disk.
6. **Append-only data**: deploy events are append-only; never modify the upstream database.
7. **No background jobs**: this package is a gate; it never initiates deploys.
8. **Contract required**: every deploy passes this gate with per-deploy confirmation; overrides require a written verbatim release quote.

## Rule files

- `assets/deploy_rules.json`: whitelist / caps / interval / counting / storage / atomic state / secret precheck / override / undo / audit link (computable).
- `assets/scripts/deploy_gate.py`: four-step gate + atomic counting + override + dual-channel + undo + selftest.

## Event export (16-column audit)

| Event type | result | severity | Audit field |
|---|---|---|---|
| Pass | deploy.allow | INFO | target=function |
| Secret hit | deploy.deny | CRIT | rule_id=secret-precheck |
| Daily cap | deploy.deny | WARN | rule_id=day-limit |
| Per-fn cap | deploy.deny | WARN | rule_id=fn-limit |
| Interval | deploy.deny | WARN | rule_id=interval |
| Override | deploy.override | WARN | human_decision=override, note=verbatim quote |

## Version

- v2.0.0 (2026-10-19): secret precheck integration / atomic state / verbatim single-use override / dual-channel / storage migration + bilingual report / CleanKeeper undo / 19-case selftest / open-source split.
