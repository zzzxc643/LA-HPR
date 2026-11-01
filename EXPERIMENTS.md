# 追加实验发布记录（2026-11-01）

本次更新公开截至 2026-10-28 已完成实验的逐样本数值结果、协议、脚本和 Docker 构建入口。历史 `data/results/`、`data/compiler/` 与原 451/69/57 划分保持冻结；后续结果放在 `data/updates/`。

## 全覆盖工程检查

原 PrimeVul Test 的 57 对原函数/参考函数控制全部通过 Clang 20.1.2 工程检查。六组所选补丁工程接受数为 `15 / 19 / 15 / 12 / 19 / 28`；顺序为局部 CodeT5、Seed、整函数、完整上下文动作、匹配局部动作、组合。组合 28 项中 27 项符合严格单行输出格式。详见 `data/updates/prime57_clang20/`。

MegaVul 141 对为未重新划分 Train/Valid/Test 的扩充评价池，保留 84 个暂定关联组。原函数/参考函数控制通过 141/141；其模型结果如下。

| 方法 | 静态推荐/141 | 所选补丁工程接受/141 |
|---|---:|---:|
| 局部 CodeT5 | 41 | 40 |
| Seed | 92 | 85 |
| 整函数 | 18 | 17 |
| 完整上下文动作 | 43 | 38 |
| 匹配局部动作 | 55 | 55 |
| 组合 | 100 | 92 |

工程接受要求真实工程参数下的语法编译通过，以及目标函数体和修改 token 行的激活控制通过；不表示链接、回归或漏洞消除。上下文标签、格式限制及编译迁移见各目录报告。两批分母分别保留，不能把 57/57 或 141/141 的参考控制通过写成模型成功。

## 等候选数量与全函数补充基线

等候选数量协议：Seed6 为 Seed 的 6 个原始候选；Mixed33 为 CodeT5 3 个加 Seed 3 个。去重、语法筛选后最多送评 5 个。候选数量相同不表示计算量、Token 成本或训练数据相同。

| 数据 | 方法 | 静态推荐 | 工程接受 |
|---|---|---:|---:|
| Prime57 | Seed6 | 28/57 | 24/57 |
| Prime57 | Mixed33 | 32/57 | 29/57 |
| Prime57 | 全函数 beam6 | 20/57 | 19/57 |
| Mega141 | Seed6 | 98/141 | 90/141 |
| Mega141 | Mixed33 | 101/141 | 94/141 |
| Mega141 | 全函数 beam6 | 52/141 | 48/141 |

全函数 beam6 是受 VulRepair 启发的 CodeT5+ 适配基线，不是官方 VulRepair 复现。它复用 Train416 检查点，Mixed33 局部模型训练量为 451；本次没有新增训练。Valid69 全函数静态推荐 18/69、Prime57 20/57，两者各有 1 条按测试前补充协议保留的终止格式错误；Mega141 无此错误。

四个有目的选择的函数级行为案例中，Seed6 通过 1/4、Mixed33 通过 2/4。该小集合不代表 57 或 141 条的行为修复率，也不是完整 CVE 或工程回归测试。单独记录见 `data/updates/behavior_four_cases.json`。

## 数据与执行入口

```bash
python scripts/verify_artifact.py
python scripts/verify_updates.py
python -m pip install -r requirements/data.txt
python scripts/reconstruct_megavul.py --megavul-json /path/to/megavul.json --out rebuilt-mega141
```

MegaVul 原始文件的下载来源、版本、大小与 SHA-256 见 `provenance/megavul_source.json`；原研究使用第三方 Kaggle 原始 JSON 镜像，不声称其包装字节与官方分发逐字节相同。脚本核对精确文件哈希、源记录行号、提交身份、函数哈希、输入提示哈希和参考渲染，恢复 141 条输入与参考。输入文件恢复历史 CRLF，参考文件排除私有工程证据路径并单独校验。

`experiments/{megavul141,equal_budget,fulltext6}/` 保留当次 runtime、依赖脚本和 freeze 配置；这些入口有检查点与输入哈希保护。使用者需要按配置准备模型、重建输入，并将 `scripts.path` 和模型路径映射到本地目录后形成自己的新 freeze 文件，不能将路径调整后的文件称为历史冻结文件。评审配置中的私人服务地址已移除，重新评审需配置自己的兼容地址及 `QWEN_API_KEY`；不会通过默认校验调用服务。

本发布支持数值复算、原数据重建和环境准备。微调权重、模型候选代码正文、原始 API 响应、完整工程源树及缓存暂不公开，因此不能凭候选哈希重新得到原补丁。镜像的使用与限制见 [CONTAINERS.md](CONTAINERS.md)。
