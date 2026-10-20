# C/C++ 漏洞单行修复：实验数据与复现材料

配套研究：**《基于局部补丁生成与多源候选选择的C/C++漏洞单行修复方法》**。

本仓库公开冻结实验的划分索引、逐样本结果、候选流转、模型设置、评审协议、编译器检查摘要与数据重建脚本。方法以局部结构化生成控制修改范围，以 CodeT5+ 与 Seed-Coder 的独立候选扩大覆盖，再通过去重、Tree-sitter 语法筛选与三态语义选择形成补丁推荐。

This repository contains frozen evaluation records, split metadata and CPU-only reconstruction/verification tools for C/C++ single-line vulnerability repair. Source functions are reconstructed from the official PrimeVul v0.1 release using commit IDs and SHA-256 hashes.

## 数据与主要结果

| 数据 | Train | Valid | Test | 用途 |
|---|---:|---:|---:|---|
| 单行替换子集 | 451 | 69 | 57 | 核心单行实验 |
| 多区间子集 | 3287 | 439 | — | 开发阶段的表示与渲染扩展验证 |

多区间集合包含相应的单行子集，两者不能作为互相独立的数据集合并计数。未发布 401 条 Overall Test 的实验结果。

在相同的 57 条单行 Test 上：

| 配置 | 微调样本数 | 静态推荐数 | Qwen-SFR | 有语法有效候选的样本数 |
|---|---:|---:|---:|---:|
| CodeT5+ 整函数 | 416 | 15 | 26.3% | 43 |
| CodeT5+ 完整上下文动作 | 416 | 14 | 24.6% | 40 |
| CodeT5+ 匹配局部动作 | 416 | 19 | 33.3% | 41 |
| CodeT5+ 局部独立组 | 451 | 16 | 28.1% | 41 |
| Seed-Coder 独立组 | 零样本 | 22 | 38.6% | 43 |
| 多源组合 | 451（CodeT5+） | 30 | 52.6% | 46 |

**指标含义：** Qwen-SFR = 获得合法 PASS 推荐的样本数 / 全部任务样本数；没有语法有效候选、FAIL、UNCERTAIN 均不计成功。它是静态语义选择指标，不等价于执行测试通过率或漏洞修复正确率。单源最多送评 3 项，组合最多 5 项，不能将系统差异解释为等预算的纯多源效应。评审模型记录的接口模型名为 `qwen3.8-max-0902`，详见 [模型设置](protocols/singleline_model_settings.json)。

其他可复核结果：

- 匹配输入表示的原始 Token 总量由 108740 降至 17823，减少 83.6%；输入预算超限由 9 条降至 0 条。
- 候选流转为 `342 → 297（可渲染）→ 254（去重）→ 181（语法有效）→ 176（送评）`。去掉语法筛选的冻结回放送评 245 项，净送评数量减少 28.2%；这是数量回放，不是 API 费用实测或语义质量消融。
- 多区间 Valid 保留全部 **439** 条作为端到端分母：推荐 96 条，**21.9%**。其中 8 条不符合 PASS-only 选择协议，按无推荐保留；431 条合法响应的条件统计为 22.3%。[口径说明](DATA_CARD.md#多区间历史标签与分母)保留了历史标签的解释。
- Clang 20.1.2 的 `-fsyntax-only` 检查覆盖 10 个项目的共同可验证子集 18/57；组合推荐的 8 项均被接受，即推荐条件接受率 8/8、子集系统覆盖 8/18。该结果不代表全部 57 条的编译率，也不包含链接、回归测试或 PoC 验证。

## 无 GPU 快速复核

需要 Python 3.10+。下面两步仅使用标准库，不调用模型或收费 API。

```bash
git clone https://github.com/zzzxc643/c-cpp-singleline-vulnerability-repair.git
cd c-cpp-singleline-vulnerability-repair
python scripts/verify_artifact.py
```

该脚本检查仓库文件 SHA-256、样本身份、推荐数、候选漏斗、多区间分母与编译器汇总，并重算精确双侧 McNemar 检验。

## 重建原始输入与参考补丁

从 [PrimeVul 官方仓库](https://github.com/DLVulDet/PrimeVul) 的 v0.1 下载说明取得 `primevul_train_paired.jsonl`、`primevul_valid_paired.jsonl` 和 `primevul_test_paired.jsonl`，放入同一目录，然后运行：

```bash
python scripts/reconstruct_data.py --primevul-dir /path/to/PrimeVul_v0.1 --out reconstructed
```

输出目录必须尚不存在。脚本按提交 ID、函数 SHA-256 和上游身份字段解析代码，重建局部/完整输入、编辑坐标和训练目标，验证参考补丁渲染，并检查 11 个文件与冻结版本逐字节一致。历史文件含不同换行格式，脚本会准确恢复。完整重建已在本次发布前通过验证。

编辑位置由参考差异预先提取：这是**给定定位信息的修复任务**，不评测漏洞检测或定位能力。测试参考内容不作为模型生成输入；`references_*.jsonl` 仅用于评估与重建核验。不要使用 Test 参考重新选模型或调参。

本仓库不直接分发各项目的函数代码、模型生成补丁正文、模型权重或工程源树；结果中的哈希用于核验身份，不能反推出补丁正文。原始函数和参考修复可通过上述脚本重建；生成候选正文不在本次发布范围内，因此本包支持**数据重建与数值复核**，不宣称可从冻结哈希重新得到每个模型生成补丁。

## 目录

| 路径 | 内容 |
|---|---|
| `data/splits/` | 5 个划分的样本 ID、项目、CWE、坐标、上游链接与函数哈希 |
| `data/results/` | 6 组单行逐样本评审结果、多区间合法响应和协议错误记录 |
| `data/candidates/` | 候选渲染/语法状态、哈希、来源和送评 ID，无代码正文 |
| `data/tables/` | 图表对应的 CSV；历史数据和规范化完整分母表分别保留 |
| `data/compiler/` | 57 条环境状态、18 条共同子集检查结果及汇总 |
| `protocols/` | 模型版本、超参数、三态评审提示和编译器检查协议 |
| `scripts/` | 数据重建、结果复核、局部/多区间渲染和部分原实验脚本 |
| `figures/` | 架构、输入预算、来源覆盖与候选漏斗图 |
| `provenance/` | 来源哈希、重建预期哈希、上游项目信息与本包完整性清单 |

原实验脚本及其用途见 [复现范围说明](REPRODUCIBILITY.md)。数据字段和适用边界见 [DATA_CARD.md](DATA_CARD.md)。

## 许可与引用

原创方法脚本、说明和本实验产生的数值结果按 [MIT License](LICENSE) 开源。PrimeVul 元数据来源及上游许可见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)；该许可不覆盖重建得到的跨项目源代码或第三方模型权重。

使用本研究材料时，可引用本仓库 URL 和所使用的提交哈希。论文正式发表前不提供虚构作者、DOI 或录用信息。使用 PrimeVul 数据还应引用 [PrimeVul 原论文](https://arxiv.org/abs/2403.18624)，并遵守其数据与原项目许可。
