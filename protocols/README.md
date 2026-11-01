# LA-HPR 协议索引

最新六候选对照使用 LA-HPR / Mixed33、Seed6 和全函数 beam6，主表见 [EXPERIMENTS.md](../EXPERIMENTS.md)，机器可读汇总见 [data/latest_summary.json](../data/latest_summary.json)。

| 材料 | 范围 |
|---|---|
| [equal_budget/PROTOCOL.json](../data/updates/equal_budget/PROTOCOL.json) | Seed6 / Mixed33 的候选预算、过滤和评审协议 |
| [fulltext6/PROTOCOL.json](../data/updates/fulltext6/PROTOCOL.json) | 全函数 beam6 适配基线 |
| [终止错误补充协议](../data/updates/fulltext6/PROTOCOL_AMENDMENT_TERMINAL_ERRORS.json) | 耗尽重试的格式错误如何保留分母 |
| [experiments](../experiments) | 各轮模型、脚本、输入和检查点哈希的冻结配置 |
| [runtime_observed_20261101.json](runtime_observed_20261101.json) | 远程直接依赖观测 |
| [container_images.json](container_images.json) | 当前 LA-HPR 三类镜像、源码提交和 digest |
| [singleline_model_settings.json](singleline_model_settings.json) | 原三候选六组模型设置，保留其历史身份 |
| [compiler_validation.md](compiler_validation.md) | 早期 18 条共同子集的冻结工程协议 |

原协议与 freeze 保留当时的组名、阶段范围及哈希。当前工程控制覆盖已扩展到 Prime57 57/57 与 Mega141 141/141，并补充修改行激活检查；不能把早期协议的环境覆盖当作当前结果。

`archive/` 保留重命名前的镜像发布记录。当前仓库名为 `LA-HPR`，镜像路径为 `ghcr.io/zzzxc643/la-hpr`；旧摘要仅用于追溯此前发布。
