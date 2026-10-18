---
name: 部署契约执行 (deploy-contract)
description: 云函数部署申请前置闸门，强制遵守可配置部署契约（默认单日≤6次、同函数≤3次、间隔≥30秒），并叠加密钥预检与书面放行原话留痕。四步闸门（密钥预检→当日≤6→同函数≤3→间隔≥30s）、跨进程原子计数、双通道 query/export/submit 宿主接口、报告 CleanKeeper 撤销、16 列审计导出。纯 Python 标准库，零第三方依赖。
version: 2.0.0
---

# 部署契约执行 (deploy-contract)

## 概述

云函数部署申请的前置闸门（P0 命门层）。强制遵守可配置部署契约——默认单日部署≤6次、同函数≤3次、间隔≥30秒——不符合即拦截。规则固化于 `deploy_rules.json`（可复算，单一事实源）。本系统自身云函数部署同样走此闸门。

**核心原则**：部署申请先过闸门；规则可复算；破例须书面放行原话逐字入日志；密钥红线不可破。

## 四步校验闸门（触发 → 预检 → 校验 → 记录）

```
云函数部署申请
      │ 触发
      ▼
┌──────────────────────────────┐
│  部署前置闸门（deploy-contract）│
│  ① 密钥预检（密钥守护者）       │
│  ② 当日部署次数 ≤ 6            │
│  ③ 同函数部署次数 ≤ 3          │
│  ④ 间隔 ≥ 30 秒               │
│  → 放行 / 拦截（→ 审计）        │
└──────────────────────────────┘
```

| 步骤 | 校验项 | 判定 |
|---|---|---|
| ① 密钥预检 | 部署内容经密钥守护者扫描 | 命中明文密钥 → 拦截（CRIT，rule_id=secret-precheck） |
| ② 当日次数 | 当日部署总数 ≤ 6（Asia/Shanghai +08:00） | 超限 → 拦截（WARN，day-limit） |
| ③ 同函数次数 | 同一函数当日部署 ≤ 3 | 超限 → 拦截（WARN，fn-limit） |
| ④ 间隔校验 | 距上次部署 ≥ 30 秒 | 过短 → 拦截（WARN，interval） |

> 计数口径（v2.0 修正）：只计 **ALLOW** 事件，拦截(DENY)不占名额。当日窗口以 Asia/Shanghai（+08:00，无 DST）为准。
> 跨进程原子性：状态用 `state/deploy_state.json` + 自旋锁串行化读写，杜绝并发漏拦。

## 白名单（可配置示例）

- 白名单函数（示例）：{syncKnowledge, identify}
- 本系统自身云函数部署：**同走此闸门**（白名单内函数才能部署，不例外）
- 契约与白名单在 `deploy_rules.json` 中配置（单一事实源）。

## 破例规则

- 破例 = 部署负责人在对话中**书面放行原话**（逐字入日志，无二次确认按钮）。
- 原话**自动逐字入日志**（deploy_log note 列），只旁路 ②当日≤6 / ③同函数≤3 / ④间隔≥30s，**不可绕过 ①白名单 与 ①密钥预检**。
- 范围绑定：原话须含目标函数名；单次有效——按原话 sha256 前16位单次消耗，换函数 / 次日 / 再次提交均不延续。

## 双通道宿主接口（语音 + 点击）

| 指令（语音） | 映射 | 说明 |
|---|---|---|
| "检查部署" | `query` | 查询部署事件 / 当日计数 / 历史记录 |
| "部署放行 <原话>" | `submit --override "<原话>"` | 提交部署申请 + 破例原话逐字入日志 |
| "查部署记录" | `query [--result/--function]` | 按条件过滤查询 |
| "出部署报告" | `export --format md` | 导出中英双语部署报告 |

- **点击入口**：安全中心 → 部署契约执行 → 提交部署申请 / 查看部署记录。
- **授权一致**：语音确认 ≡ 点击确认（唯一执行出口）。
- **降级**：双通道异常 → 安全默认（拦截部署）。

## 命令一览

```bash
# 提交部署申请（四步校验 → 返回 allow/deny + rule_id + 剩余配额）
python assets/scripts/deploy_gate.py submit --function <函数名> [--content <待部署内容文件>] [--override "<原话>"] [--base-dir X]

# 向后兼容：python deploy_gate.py --function <函数名> [--override "<原话>"]

# 查询：--result ALLOW|DENY / --function / --date-from / --date-to / --limit / --format table|csv|json
python assets/scripts/deploy_gate.py query [选项]

# 导出中英双语部署报告（md/json/csv）
python assets/scripts/deploy_gate.py export --format md|json|csv [--out F]

# 撤销：报告文件删除走 CleanKeeper 撤销（移备份区 + manifest + 保留3次 + sha256 校验恢复）
python assets/scripts/deploy_gate.py undo --list | --restore <undo_id>
python assets/scripts/deploy_gate.py clean --file <报告文件>

# 旧数据迁移到 %LOCALAPPDATA%
python assets/scripts/deploy_gate.py migrate

# 自检门禁（19 用例）
python assets/scripts/deploy_gate.py --selftest
```

## 红线

1. **规则可复算**：deploy_rules.json 单一来源，禁止改代码绕过；白名单可配置对齐部署契约。
2. **默认拦截**：校验不通过 → 拦截；白名单外函数不可部署；密钥预检异常 → 安全默认拦截。
3. **破例留痕**：书面放行原话逐字入日志，可审计；仅单次有效不延续；无二次确认按钮。
4. **自身同闸门**：本系统自身部署不例外。
5. **密钥红线**：密钥预检只传判定结果，0 密钥值落盘。
6. **不动核心数据**：部署事件只追加，不修改上游数据库。
7. **不后台作业**：本包是部署闸门，不自行发起部署。
8. **部署须契约**：一切部署先过本闸门，经负责人逐次确认；破例必须书面放行原话。

## 规则文件

- `assets/deploy_rules.json`：白名单 / 次数上限 / 间隔阈值 / 计数口径 / 存储 / 原子状态 / 密钥预检 / 破例 / 撤销 / 审计汇入（可复算）。
- `assets/scripts/deploy_gate.py`：四步校验 + 原子计数 + 破例 + 双通道 + undo + selftest。

## 事件汇入（16 列契约）

| 事件类型 | result | severity | 汇入字段 |
|---|---|---|---|
| 四步通过 | deploy.allow | INFO | target=函数名 |
| 密钥预检拦截 | deploy.deny | CRIT | rule_id=secret-precheck |
| 当日超限 | deploy.deny | WARN | rule_id=day-limit |
| 同函数超限 | deploy.deny | WARN | rule_id=fn-limit |
| 间隔过短 | deploy.deny | WARN | rule_id=interval |
| 破例放行 | deploy.override | WARN | human_decision=override, note=原话逐字 |

## 版本

- v2.0.0（2026-10-19）：密钥预检联调 / 原子计数状态 / 破例逐字留痕单次 / 双通道 / 存储迁移+双语报告 / CleanKeeper 撤销 / selftest 19 例 / 开源拆分。
