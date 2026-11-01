# LA-HPR 数据说明

## 来源与任务

当前实验来源为 PrimeVul 与 MegaVul。PrimeVul 使用官方 v0.1 配对集合；公开索引以提交 ID 和 UTF-8 函数字符串的 SHA-256 对齐至官方条目，上游 `target=1` 表示漏洞函数、`target=0` 表示修复后函数。MegaVul 使用已记录版本和完整文件哈希的原始 JSON 镜像，保留源记录行号和上游身份，不声称镜像包装与官方分发逐字节相同。本包保留 CVE/CWE、提交与项目链接，不将这些标签自动解释为已动态验证的漏洞修复金标。

| 范围 | 数量 | 当前身份 |
|---|---:|---|
| PrimeVul 严格单行 Train / Valid / Test | 451 / 69 / 57 | 原冻结划分，共 577 对 |
| MegaVul 扩充评价池 | 141 对 | 原/参考工程控制通过；划分为 `unassigned`，84 个暂定关联组 |
| PrimeVul 多区间 Train / Valid | 3287 / 439 | 开发阶段表示扩展，含相应单行子集 |

两个数据源的划分与重建依据分别位于 [data/splits](data/splits) 和 [provenance](provenance)。最新模型结果见 [EXPERIMENTS.md](EXPERIMENTS.md)。

筛选流程检查前后代码存在且不同、可解析函数名一致，以及双方文件元数据可用时路径一致。缺失文件元数据作为警告保留。单行子集再要求参考差异仅有一个块、删除与新增各一行。曾有栈溢出证据优先级标记，但本研究子集不是栈溢出专用基准。样本成员在生成前冻结，公开成员清单是复现实验选择的依据。

编辑坐标来自参考修复差异。任务不包含定位；生成输入含漏洞函数邻域、标记位置及 CWE，不包含参考替换文本。单行局部窗口在目标行前后各取 8 行，必要时补函数签名；它不是程序依赖切片。单行表示对目标原始行执行替换，生成的替换字符串允许多行。

## 划分字段

`data/splits/{singleline,multiregion}/{split}.jsonl` 每行对应一个样本：

| 字段 | 定义 |
|---|---|
| `sample_id` | 冻结样本标识：提交 ID 与漏洞函数上游哈希的组合 |
| `split`, `project`, `cwe`, `source_file` | 划分、原项目、CWE 列表、项目内文件路径 |
| `commit_id` | 上游修复提交 ID |
| `vulnerable_sha256`, `fixed_sha256` | 原始/参考函数字符串的 UTF-8 SHA-256 |
| `edit_start`, `edit_end` | 单行原坐标，0 起始半开区间 `[start,end)` |
| `edit_regions` | 多区间按原坐标排序的 `slot,start,end` 列表；空区间为插入 |
| `context_start`, `context_end` | 单行窗口的原始行范围 |
| `input_local_sha256`, `input_full_sha256` | 对应模型输入文本哈希（存在时） |
| `action` | 根据参考词元差异构造的动作标签，不是人工语义金标 |
| `kind` | 按参考差异划分为单行、单块或多块，仅用于事后分层统计 |
| `upstream_vulnerable`, `upstream_fixed` | 官方索引、函数哈希、标签、项目/提交/CVE 链接 |

上游 `func_hash` 是大整数。JavaScript 等运行时直接解析为 IEEE-754 Number 会损失精度，应使用支持大整数的 JSON 解析器或读取为字符串；重建脚本使用 Python 整数。

`provenance/split_overlap.json` 记录本包实际成员的跨集合交集。单行 Train/Valid/Test 的样本 ID、漏洞函数 SHA-256、提交 ID 交集均为 0；多区间 Train/Valid 的样本 ID 和漏洞函数哈希交集为 0，提交 ID 有 3 个交集。实验划分没有保证项目互斥或预训练数据不重叠，不能据此宣称跨项目泛化或彻底排除近似代码泄漏。

## 评审结果与候选

最新六候选实验位于 `data/updates/equal_budget/` 与 `data/updates/fulltext6/`。LA-HPR 在冻结记录中的方法标识为 `mixed33`，表示局部 CodeT5 3 项加 Seed 3 项；Seed6 和全函数 beam6 各最多生成 6 项，过滤后最多送评 5 项。公开记录保留原方法标识以绑定历史证据，未将它们改写为项目展示名。`selected_patch_sha256` 与对应工程记录的 `patch_sha256` 用于核对最终推荐身份。

`data/results/singleline/*.jsonl` 保留推荐状态、选中 ID/来源、候选计数与三项布尔/未知判决。三项均为真才能 PASS；任一为假则 FAIL；其余为 UNCERTAIN。合法选择必须只选择 PASS 候选，无 PASS 时不得推荐。`success` 仅指符合这一静态协议，不表示动态修复成功。

`data/candidates/*.jsonl` 保留生成与后处理状态、内容哈希，不含生成文本。Tree-sitter 在完整渲染函数上执行 C 和 C++ 解析，任一根节点无错误则语法通过。宏、类型或构建环境缺失可能影响这种解析；它不等价于编译器检查。组合池按来源固定顺序与秩轮转，最多 5 项。脚本中的 `rules` 是保留接口，冻结正式实验的规则候选数为 0。

## 多区间历史标签与分母

多区间 Valid 是单一 CodeT5+ 多区间表示/渲染方案的开发阶段结果，不是独立 Test 或完整多源系统评测。它含 69 条单行、165 条多行单块和 205 条多块样本。

原冻结归档把 8 条响应标成 `EXCLUDED_PARSE_ERROR` 并从合法响应统计排除。实际错误是：没有 PASS 候选时仍选择 UNCERTAIN 候选，违反 PASS-only 选择协议；不能归因为 JSON 输出截断，也不能按修复失败不利与否删样本。

本包保留 431 条合法响应和另外 8 条协议错误的 ID。完整分母为 439，端到端推荐率为 `96/439 = 21.9%`；`96/431 = 22.3%` 仅为合法响应条件统计。合法响应组成：PASS 96、FAIL 189、UNCERTAIN 29、NO_SYNTAX 117。

历史 `multiregion_sample_outcomes.csv` 原样保留其标签；`multiregion_outcomes_primary.csv` 将那 8 条规范为 `PROTOCOL_ERROR` 并显式写出 `recommended=false`，完整分层分母为 69/165/205。本包不改写原实验归档，历史键名和数字仅用于追溯。

## 编译器结果

当前工程控制覆盖 Prime57 **57/57**、Mega141 **141/141**，使用 Clang **20.1.2**、真实工程头文件与构建配置进行 `-fsyntax-only` 语法和类型检查，并验证目标函数体与修改 token 行激活。最新 LA-HPR / Mixed33 所选补丁工程接受为 **29/57** 和 **94/141**，不将原/参考控制通过计为模型成功。

Prime57 中 54 条为父版上下文、3 条为修复版上下文回填原函数；Mega141 中分别为 115 条和 26 条。后者保留伴随上下文依赖，不代表全部样本的补丁均可独立应用到父提交。工程参数、上下文和原六组结果位于 `data/updates/{prime57_clang20,megavul141}/`，最新六候选工程结果位于 `data/updates/{equal_budget,fulltext6}/`。

最新主表的工程接受率以完整评价池 57 或 141 为分母；推荐条件接受率应另行注明推荐数分母。未推荐、环境阻塞和编译拒绝是不同状态。工程接受不证明链接、回归或漏洞消除。

`data/compiler/` 保留早期阶段：19 条尝试恢复、18 条共同可验证、覆盖 10 个项目，原组合推荐 8/8 接受。这些是历史节点，不能代替当前全覆盖结果。

## MegaVul 索引与关联

`data/splits/megavul/evaluation141.jsonl` 保存公开评价 ID、`source_sample_id`、原始 `source_row`、项目/提交/文件身份、原/参考函数 SHA-256、编辑坐标及输入提示哈希。`input_fields`、`reference_fields` 和 `reference_metadata` 支持恢复精确字段及字节格式，原始代码通过独立下载的原始 JSON 重建。

`association_groups.jsonl` 保留 84 个暂定关联组及其依据，不能直接将它们视为 84 个独立统计单元。Mega141 保持未划分的扩充评价池；不宣称与原 Train/Valid/Test 项目互斥或预训练数据无重叠。CVEfixes、Big-Vul 的历史成员关系不构成额外独立实验来源。

## 发布范围

公开内容不含服务器口令、API 密钥、私人服务地址、原始请求缓存、完整工程源码、生成补丁正文或模型权重。原函数与参考修复从各自记录的数据来源重建；哈希证明内容身份，不证明补丁正确性。训练权重暂不公开，未经重新运行无法从哈希恢复生成候选正文或 Qwen 服务的历史响应。依赖和工程基础镜像见 [CONTAINERS.md](CONTAINERS.md)。
