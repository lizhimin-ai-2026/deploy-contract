# 部署契约执行 (deploy-contract)

云函数部署申请前置闸门（P0 命门层），强制遵守可配置部署契约——默认单日部署≤6次、同函数≤3次、间隔≥30秒——并叠加密钥预检与书面放行原话留痕。v2.0 升级：密钥预检联调 / 跨进程原子计数 / 破例逐字留痕单次 / 双通道宿主接口 / 存储迁移与双语报告 / CleanKeeper 撤销 / 19 例 selftest 门禁。

## 核心能力

- **四步校验**：① 密钥预检（密钥守护者）→ ② 当日≤6 → ③ 同函数≤3 → ④ 间隔≥30s
- **白名单**：可配置（示例 {syncKnowledge, identify}）；本系统自身部署同走闸门
- **破例规则**：负责人书面放行原话逐字入日志，无二次确认按钮，仅单次有效不延续（范围绑定+sha256单次消耗）
- **原子计数**：state/deploy_state.json + 跨进程自旋锁，并发不漏拦；计数只计 ALLOW 事件
- **双通道**：query / export / submit 子命令（无 UI 依赖）；语音"检查部署/部署放行/查部署记录/出部署报告"
- **双语报告**：部署日报/周报 allow/deny(按rule_id)/override 分组 + 剩余配额（中英双语）
- **撤销保护**：报告文件删除走 CleanKeeper（移备份区 + manifest + 保留3次 + sha256 校验）；审计日志不可撤销
- **16 列审计**：deploy.allow/deny/override 汇入审计底座（0 密钥值落盘）

## 结构

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

## 用法

```bash
# 提交一次部署申请（返回 allow/deny + rule_id + 剩余配额）
python assets/scripts/deploy_gate.py submit --function <函数名> [--content <待部署内容文件>] [--override "<原话>"]

# 查询 / 导出双语报告
python assets/scripts/deploy_gate.py query [--result ALLOW|DENY] [--function <fn>] [--format table|csv|json]
python assets/scripts/deploy_gate.py export --format md|json|csv [--out F]

# 撤销 / 迁移 / 自检
python assets/scripts/deploy_gate.py undo --list | --restore <undo_id>
python assets/scripts/deploy_gate.py migrate
python assets/scripts/deploy_gate.py --selftest
```

## 判定

| 结果 | 含义 |
|---|---|
| ALLOW | 四步通过 / 负责人书面放行（override 逐字入日志） |
| DENY · CRIT | 白名单外函数 / 密钥预检命中 / 密钥守护者不可用 |
| DENY · WARN | 当日超限 / 同函数超限 / 间隔过短 |

## 红线

规则可复算（单一来源）/ 默认拦截 / 破例留痕（逐字入日志）/ 自身同闸门 / 密钥红线（0 密钥值落盘）。

## 版本

- v2.0.0（2026-10-19）：全量对齐定稿方案 + 密钥预检联调 + 破例通道完整落地 + 双通道就绪 + 开源就绪。
