# 复现范围与脚本

2026-11-01 增补：后续实验见 [EXPERIMENTS.md](EXPERIMENTS.md)，依赖及三类容器见 [CONTAINERS.md](CONTAINERS.md)。`verify_artifact.py` 现在同时复核原始发布与追加结果；下文保留原发布范围说明。已核实当前远程 Tree-sitter 为 0.25.2、C grammar 为 0.24.1、C++ grammar 为 0.23.4；当前观测不等于所有历史运行的完整环境锁定。

## 本次发布已验证

1. `scripts/verify_artifact.py`：校验文件 SHA-256，复算 6 组单行推荐数与语法覆盖、候选漏斗、McNemar 精确双侧检验、多区间完整分母和编译器汇总。Python 标准库，无 GPU/API。
2. `scripts/reconstruct_data.py`：从官方 PrimeVul v0.1 配对文件恢复五个划分。全部 11 个数据文件的字节哈希与本地冻结输入/参考/训练目标一致；不访问任何私有目录或远程接口。

`provenance/*_reconstruction.json` 是精确字节校验依据，含历史 LF/CRLF 换行约定。`*_original_manifest.json` 是原实验清单，里面引用的部分配置/中间文件不在重建输出中，不能把它当成本公开仓库完整性清单。本仓库完整性清单为 `provenance/artifact_sha256.json`。

## 保留的原实验组件

| 脚本 | 功能 |
|---|---|
| `singleline_repair.py` | 单行邻域输入、参考词元动作归类、严格 JSON 与边界渲染 |
| `block_repair.py` | 原坐标多区间输入与确定性渲染 |
| `local_candidate_judge.py` | 三态评审提示、响应合法性校验及缓存函数 |
| `block_review.py` | 多区间评审协议与响应校验 |
| `prepare_singleline_pools.py` | 精确去重、语法筛选、来源轮转；CLI 面向原始 Valid 流程 |
| `normalize_singleline_candidates.py` | 对生成输出做格式规范化并保留原输出身份 |
| `train_singleline.py` | 原 CodeT5+ 的 audit/train/valid 流程，Train 451 / Valid 69 |

这些组件用于展示实施协议；本包不是一键复跑全部实验的训练框架。训练需要另行准备冻结版本的模型缓存和兼容的 GPU 软件栈；原脚本使用 `local_files_only=True`。公开候选索引去除了代码正文，不能直接传入要求 `patched_code` 的组池函数。没有提供 API 密钥，也没有默认调用 API 的入口。

本次发布不重新训练、生成候选或调用评审模型。已记录的核心环境：PyTorch `2.8.0+cu128`、Transformers `4.51.3`；详细参数与模型 revision 以 `protocols/` 为准。Tree-sitter 解析政策由 `train_singleline.py` 实现，包版本未在冻结模型配置中完整记录，不臆造精确依赖锁文件。

## 冻结结果与当前材料的区别

- `protocols/` 的 script/data 哈希指向当时冻结版本；部分脚本或格式规范化在不同阶段发生过变化。它们不是本仓库每份脚本都与所有历史哈希相同的声明。
- 远程评审服务可更新模型实现，服务端模型名不等于可下载的不可变权重版本。重新调用可能得到不同响应；本包逐样本结果是冻结响应的结构化记录。
- 单源与组合的候选数上限不同，评审面对的候选上下文也不同。交集反映系统输出互补，不是对候选内在正确性的金标评估。
- 编译器检查仅发布去路径的退出状态和日志哈希；源树、构建缓存及完整日志未包含。严格重建历史编译环境仍需按原项目依赖恢复，不能仅凭结果哈希重现编译命令。

新增文件或修改文件后，维护者应先审查差异，再运行 `python scripts/verify_artifact.py --write-manifest` 重建完整性清单；一般使用者只运行不带参数的校验。
