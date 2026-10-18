# Deploy Contract (部署契约执行)

开源版部署契约执行技能 —— 通用部署闸门，默认拒绝一切部署，仅放行白名单函数，
按当日≤6 / 同函数≤3 / 间隔≥30s 三道配额闸门 + 密钥预检（需 Secret Guardian）复核。

## 目录结构
- `/`  —— 英文版（English）
- `/zh` —— 中文版（中文）

## 密钥预检（可选集成）
本技能可对接 Secret Guardian（② 密钥红线守护者）做明文密钥预检。
运行环境若未配置，相关自检测试会优雅跳过而非误报失败；
设置 `LANZHI_SECRET_GUARD_SCRIPT=绝对路径/secret_guard.py` 后重跑 `--selftest` 即得全量 20/20。
