# LA-HPR 复现说明

当前公开版本涵盖 Prime57、Mega141、六候选对照、全函数 beam6 补充基线及开发阶段多区间结果。最新指标见 [EXPERIMENTS.md](EXPERIMENTS.md)。

## 1. 核验公开结果

```bash
git clone https://github.com/zzzxc643/LA-HPR.git
cd LA-HPR
python scripts/verify_artifact.py
```

Python 3.10+，标准库即可。核验文件 SHA-256、划分与样本身份、三态 PASS 选择、最新逐样本补丁/工程绑定，并复算原六组、六候选对照、全函数基线、候选漏斗、多区间完整分母和早期编译子集。`scripts/verify_updates.py` 可单独复核追加结果。

仓库默认分支由 GitHub Actions 执行核验，三个 Docker 目标构建时也执行相同检查。镜像版本与摘要见 [CONTAINERS.md](CONTAINERS.md) 和 [protocols/container_images.json](protocols/container_images.json)。GPU 镜像完成依赖导入与版本核对，尚未验证实际 CUDA 设备运行。

## 2. 重建数据

从 [PrimeVul 官方说明](https://github.com/DLVulDet/PrimeVul) 获取 v0.1 三个 paired 文件：

```bash
python scripts/reconstruct_data.py --primevul-dir /path/to/PrimeVul_v0.1 --out rebuilt-primevul
```

恢复单行 Train/Valid/Test 451/69/57 和多区间 Train/Valid 3287/439 的全部 11 个输入、参考及训练文件，并验证与冻结版本逐字节一致。

MegaVul 按 [来源记录](provenance/megavul_source.json) 获取指定版本的原始 JSON 镜像：

```bash
python -m pip install -r requirements/data.txt
python scripts/reconstruct_megavul.py --megavul-json /path/to/megavul.json --out rebuilt-megavul141
```

脚本流式处理 2.67 GB JSON，先核对完整文件 SHA-256，再匹配 141 个源记录、提交身份、原/参考函数、提示哈希和参考渲染。输入恢复历史 CRLF；参考代码与标签保留，私有工程证据路径排除。两份公开输出哈希单独核验。两个脚本的输出目录均须尚不存在。

这些重建已经通过实际数据验证。`provenance/*_reconstruction.json` 给出输出字节依据；原实验清单中的配置和中间文件不一定属于重建输出。仓库文件的完整性依据是 `provenance/artifact_sha256.json`。

## 3. 准备模型与运行脚本

训练权重按维护者选择暂不公开。训练或新一轮推理需准备相应模型缓存及自行训练得到的检查点。基础模型为 `Salesforce/codet5p-220m` 和 `ByteDance-Seed/Seed-Coder-8B-Instruct`；固定 revision、检查点文件哈希和解码配置见 [模型设置](protocols/singleline_model_settings.json) 与 [各轮 freeze](experiments)。

| 入口 | 用途 |
|---|---|
| `scripts/train_singleline.py` | 原 CodeT5+ audit/train/valid 流程 |
| `scripts/singleline_repair.py` | 局部输入、动作归类、JSON 校验与确定性渲染 |
| `scripts/full_context_baselines.py` | 原整函数及完整/局部上下文基线 |
| `scripts/generate_singleline_seed.py` | 原 Seed 候选生成入口 |
| `scripts/prepare_singleline_pools.py` | 精确去重、语法筛选和来源轮转 |
| `scripts/local_candidate_judge.py` | 三态响应与 PASS-only 选择校验 |
| `experiments/equal_budget/` | 最新 Seed6 / Mixed33 runtime、依赖脚本与各评价池 freeze |
| `experiments/fulltext6/` | 全函数 beam6 runtime、依赖脚本与各评价池 freeze |
| `experiments/megavul141/` | Mega141 原五组生成、六组评审及工程检查组件 |
| `experiments/prime57_clang20/compiler/` | Prime57 全覆盖工程检查器 |

原脚本使用 `local_files_only=True`，freeze 会核对输入、脚本与检查点哈希。准备新运行时，应按配置恢复目录结构、模型和重建输入，映射本地路径，并形成自己的新 freeze；不能将路径或模型调整后的配置称为历史冻结文件。公开候选索引只含状态和哈希，不能直接传给需要补丁正文的组池函数。

局部模型 Train451；整函数和匹配表示基线 Train416、损失验证子集64。模型选择依据 Valid，不能用 Test 参考重新选模型、调提示或改候选规则。Mega141 保持扩充评价池身份，没有参与本轮新增训练。

## 4. 配置可选评审服务

默认核验和重建不会调用 API。重新评审需自己配置兼容服务地址、可用模型和 `QWEN_API_KEY`。私人服务地址已从公开配置移除。历史接口模型名为 `qwen3.8-max-0902`；服务端名称不代表不可变权重，新调用不保证得到历史响应。

选中候选必须为 PASS；三项判断均真才 PASS，任一为假则 FAIL，其余 UNCERTAIN。重试与终止错误口径按当轮协议执行，全函数 beam6 的终止格式错误补充协议见 [PROTOCOL_AMENDMENT_TERMINAL_ERRORS.json](data/updates/fulltext6/PROTOCOL_AMENDMENT_TERMINAL_ERRORS.json)。

## 5. 工程检查与环境

当前结果的原/参考控制覆盖 Prime57 57/57、Mega141 141/141，使用 Clang20.1.2。工程参数与上下文身份见 `data/updates/{prime57_clang20,megavul141}/engineering_contexts.json`，检查器见 `experiments/*/compiler/`。

工程镜像提供工具链基础环境。严格重跑仍需恢复各上游提交、真实生成配置、头文件、外部依赖和源文件布局；这些完整源树与构建缓存不包含在镜像内。不能仅根据结果哈希恢复原工程或模型补丁。`protocols/compiler_validation.md` 是早期共同子集协议，当前覆盖与改进后的激活口径见 [EXPERIMENTS.md](EXPERIMENTS.md)。

直接依赖版本已从 2026-11-01 远程环境核实，见 [requirements/runtime.txt](requirements/runtime.txt) 与 [观测记录](protocols/runtime_observed_20261101.json)。核心为 PyTorch2.8.0+cu128、Transformers4.51.3、Tree-sitter0.25.2、C grammar0.24.1、C++ grammar0.23.4。该记录不是所有历史传递依赖和系统包的逐字节锁文件。

## 公开范围与维护

公开内容支持数值复核、原数据重建、实现协议审查及环境准备。微调权重、生成补丁正文、原始 API 缓存、完整工程源树暂不公开，因此本版本不提供历史全部模型输出的一键复跑。

`data/results/`、`data/compiler/` 与各轮 freeze 保留历史身份；最新结果从 `data/updates/` 读取。历史脚本哈希可能对应不同阶段的版本，不是本仓库所有公共组件都与每次历史哈希一致的声明。

维护者审查有意修改后运行 `python scripts/verify_artifact.py --write-manifest` 更新完整性清单；普通使用者只运行不带该参数的核验命令。
