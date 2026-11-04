# LA-HPR 审稿人使用指南

更新日期：2026-11-04。本文用于核验公开实验材料；最新已完成实验截至 2026-10-28，增加托管入口和本文不改变实验结果。

## 1. 核验目标与公开范围

LA-HPR 结合 CodeT5+ 局部编辑动作、Seed-Coder 独立候选和 Qwen 三态语义选择，面向**已知漏洞位置的 C/C++ 单行修复**。最新冻结方法名为 `mixed33`：局部模型和 Seed 各生成 3 个原始候选，去重及语法筛选后最多送评 5 项。

| 审查任务 | 公开材料支持的操作 | 所需条件 |
|---|---|---|
| 核验文件和统计 | 检查 SHA-256、样本身份、候选选择及工程结果绑定，复算汇总 | Git、Python 3.10+；无需 GPU、模型或 API 密钥 |
| 追溯单个结果 | 按 `sample_id` 对照逐样本评审、补丁哈希和工程状态 | 文本编辑器或 Python |
| 重建评价输入和参考 | 从指定上游数据重建冻结输入并验证输出字节 | 上游原始数据；MegaVul 另需 `ijson` |
| 准备运行环境 | 拉取核验、编译工具链或 GPU 依赖镜像 | Docker；镜像托管在 GHCR |
| 重跑模型和工程检查 | 审查实现及冻结参数，按条件准备新的运行 | 检查点、模型缓存、评审服务、工程源树及配置 |

微调权重、生成补丁正文、原始 API 缓存和完整工程源树暂未公开。因此公开材料支持数值与协议审查，尚不提供历史全部模型输出的一键复跑。静态 PASS 与工程接受均不等于执行测试证明的漏洞消除。

## 2. 推荐入口：本地无卡核验

从 GitHub 获取最新版本：

```bash
git clone https://github.com/zzzxc643/LA-HPR.git
cd LA-HPR
git rev-parse HEAD
python scripts/verify_artifact.py
```

Gitee 副本提供相同材料：

```bash
git clone https://gitee.com/zzzxcaa/LA-HPR.git
cd LA-HPR
git rev-parse HEAD
python scripts/verify_artifact.py
```

记录 `git rev-parse HEAD` 的完整输出，供审稿意见引用；比较两个托管平台版本时，比较完整提交号。两个地址任选其一克隆即可。

Windows 可使用 PowerShell，Linux/macOS 可使用终端；若系统命令为 `python3`，将上述 `python` 替换为 `python3`。核验脚本只用标准库，不下载模型，不调用在线评审，也不需要先安装训练依赖。

成功时脚本打印 JSON 并以退出码 0 结束。其中 `checksummed_files` 为当前版本纳入校验的文件数，文档增加后该数量会变化；最新数值位于 `updates_20261101.equal_budget` 和 `updates_20261101.fulltext6`。可单独运行：

```bash
python scripts/verify_updates.py
```

`artifact_checksum_mismatch` 表示本地内容与提交的完整性清单不一致。请在干净克隆中重试，并保留错误和提交号；审稿核验请使用**不带** `--write-manifest` 的命令，以免重写核验依据。

## 3. 预期结果与比较口径

| 方法 | Prime57 静态推荐 | Prime57 工程接受 | Mega141 静态推荐 | Mega141 工程接受 |
|---|---:|---:|---:|---:|
| CodeT5+ 全函数 beam6 | 20/57 | 19/57 | 52/141 | 48/141 |
| Seed6 | 28/57 | 24/57 | 98/141 | 90/141 |
| LA-HPR / Mixed33 | 32/57 | 29/57 | 101/141 | 94/141 |

Valid69 静态推荐分别为全函数 beam6 18/69、Seed6 33/69、Mixed33 32/69。完整分母保留输入超限和终止评审格式错误；全函数 beam6 的格式错误在 Valid/Prime/Mega 为 1/1/0，按补充协议计为选择失败。

工程接受检查真实工程参数下的语法与类型，并核对目标函数体和修改行激活。原函数/参考函数控制分别覆盖 Prime57 57/57、Mega141 141/141，工具链为 Clang 20.1.2；这些控制不计入模型成功数。

局部模型使用 Train451，全函数模型使用 Train416。六候选预算相同不表示训练、计算或 Token 成本相同。全函数 beam6 是参考 VulRepair 构建的适配基线。四个针对性行为案例中 Seed6 为 1/4、Mixed33 为 2/4，该小样本结果不能替代全评价池正确率。

## 4. 逐样本证据索引

| 要核对的内容 | 文件入口 |
|---|---|
| 最新汇总和方法名称映射 | [data/latest_summary.json](data/latest_summary.json) |
| Prime57 的 Mixed33 评审 | [mixed33.jsonl](data/updates/equal_budget/prime57/mixed33.jsonl) |
| Prime57 的 Mixed33 工程结果 | [mixed33_engineering.json](data/updates/equal_budget/prime57/mixed33_engineering.json) |
| Seed6、Mixed33 的全部评价池记录 | [data/updates/equal_budget](data/updates/equal_budget) |
| 全函数 beam6 与错误补充协议 | [data/updates/fulltext6](data/updates/fulltext6) |
| Prime57 工程上下文 | [engineering_contexts.json](data/updates/prime57_clang20/engineering_contexts.json) |
| Mega141 工程上下文 | [engineering_contexts.json](data/updates/megavul141/engineering_contexts.json) |
| 成员、来源和划分身份 | [data/splits](data/splits) |
| 冻结配置和运行实现 | [experiments](experiments)、[scripts](scripts) |
| 统计口径、历史对照和局限 | [EXPERIMENTS.md](EXPERIMENTS.md)、[DATA_CARD.md](DATA_CARD.md) |

建议从一条 `mixed33.jsonl` 记录开始：按 `sample_id` 找到对应工程记录，查看 `selected_cand_id`、`reviews`、`success` 和 `selected_patch_sha256`。Prime57 工程记录的 `candidates` 中包含候选编号、`patch_sha256` 和 `status`；核对所选候选与哈希一致后，再查看是否为 `candidate_compile_pass`。完整核验脚本已自动执行这一绑定检查。

哈希用于核对已记录输出身份，不能从哈希恢复补丁正文。评审理由可供审查，但不构成独立的漏洞消除证明。`combined` 是历史组合方法标识，不能与最新 `mixed33` 混用。

## 5. 可选：Docker 核验

镜像平台为 `linux/amd64`。以下固定摘要对应 2026-11-01 已发布实验版本，镜像内实验数据和实现来自提交 `a392316ffd01879b9b55597ae343a71c7268238b`；该镜像不包含之后新增的本文等文档。核对当前仓库完整内容请使用第 2 节。

```bash
docker run --rm ghcr.io/zzzxc643/la-hpr@sha256:f462a753775f351f372fd10e156634d914e2844665f1f23bf55433b76202577e
```

其余镜像为 `ghcr.io/zzzxc643/la-hpr:compiler-20261101` 和 `ghcr.io/zzzxc643/la-hpr:gpu-20261101`，固定摘要见 [镜像清单](protocols/container_images.json)。GPU 镜像已核验依赖导入与版本，未验证实际 CUDA 设备执行。编译镜像提供基础工具链，完整工程与生成配置需要另行恢复。

Gitee 代码副本不改变镜像托管位置；若无法访问 GHCR，先按第 2 节使用本地 Python 核验。构建及挂载说明见 [CONTAINERS.md](CONTAINERS.md)。

## 6. 可选：重建数据

按 [PrimeVul 官方说明](https://github.com/DLVulDet/PrimeVul) 获取 v0.1 的三个 `primevul_{train,valid,test}_paired.jsonl` 文件：

```bash
python scripts/reconstruct_data.py --primevul-dir /path/to/PrimeVul_v0.1 --out rebuilt-primevul
```

按 [MegaVul 来源记录](provenance/megavul_source.json) 获取实验使用的原始 JSON 镜像：

```bash
python -m pip install -r requirements/data.txt
python scripts/reconstruct_megavul.py --megavul-json /path/to/megavul.json --out rebuilt-megavul141
```

输出目录须尚不存在；请放在仓库外，避免新生成文件影响仓库完整性检查。PrimeVul 重建 11 个冻结文件；MegaVul 从约 2.67 GB JSON 重建 141 条输入和参考两个文件，需为源数据预留磁盘空间。来源记录中的 SHA-256 核验用于匹配实验采用的镜像，不能替代与官方发行版本的独立来源验证：该记录仍标记 `upstream_cryptographic_identity_verified: false`。

PrimeVul 单行划分为 Train/Valid/Test 451/69/57。Mega141 是未分配训练/验证/测试划分的扩充评价池，含 84 个暂定关联组，不宣称项目互斥独立泛化。数据细节见 [DATA_CARD.md](DATA_CARD.md)。

## 7. 审稿记录建议

请记录托管地址、完整 Git 提交号、Python 版本、执行命令、退出码，以及有差异的 `sample_id`、方法和文件路径。引用镜像时记录 digest。若重新生成候选或调用评审服务，请单独标明新模型、配置和服务版本，勿将新输出标作历史冻结结果。模型、评审和完整工程重跑的前置条件见 [REPRODUCIBILITY.md](REPRODUCIBILITY.md)。
