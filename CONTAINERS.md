# LA-HPR 镜像与环境

GitHub 项目名为 `LA-HPR`，Docker 仓库路径使用小写 `la-hpr`。镜像仓库：`ghcr.io/zzzxc643/la-hpr`。镜像平台为 `linux/amd64`，均可匿名拉取。Dockerfile 和构建日志公开；版本标签如下。

| 标签 | 用途 | 内容 |
|---|---|---|
| `verify-20261101` | 无卡核验与数据重建 | Python 3.12、ijson、公开结果及校验脚本 |
| `compiler-20261101` | C/C++ 工程检查基础环境 | Ubuntu 24.04、Clang 20.1.2、GCC 11、常用构建工具及开发头文件 |
| `gpu-20261101` | 训练与候选生成软件栈 | Python 3.12、PyTorch 2.8.0+cu128、Transformers 4.51.3、冻结的直接依赖 |

```bash
docker run --rm ghcr.io/zzzxc643/la-hpr:verify-20261101
docker run --rm ghcr.io/zzzxc643/la-hpr:compiler-20261101 clang --version
docker run --rm --gpus all ghcr.io/zzzxc643/la-hpr:gpu-20261101 \
  python -c 'import torch; print(torch.__version__, torch.cuda.is_available())'
```

无卡机器可以拉取和检查 GPU 镜像中的依赖；实际 CUDA 推理需要支持 CUDA 12.8 的宿主驱动和 NVIDIA Container Toolkit。镜像构建只检查导入和版本，未在 GitHub 托管 CPU runner 上验证 CUDA 内核运行。

每次发布还提供 `<用途>-sha-<完整Git提交>` 标签。精确引用时使用 [镜像清单](protocols/container_images.json) 中的 registry digest。日期标签随本次发布校正，digest 指向不可变内容。

## 挂载数据与模型

```bash
docker run --rm -v "$PWD/PrimeVul_v0.1:/source:ro" -v "$PWD/rebuilt:/outputs" \
  ghcr.io/zzzxc643/la-hpr:verify-20261101 \
  python scripts/reconstruct_data.py --primevul-dir /source --out /outputs/primevul

docker run --rm -v "$PWD/megavul.json:/source/megavul.json:ro" -v "$PWD/rebuilt:/outputs" \
  ghcr.io/zzzxc643/la-hpr:verify-20261101 \
  python scripts/reconstruct_megavul.py --megavul-json /source/megavul.json --out /outputs/megavul141
```

训练权重按维护者选择暂不公开，也不包含在镜像中。GPU 流程需要自行训练得到的检查点，或研究者已有的冻结权重；模型目录通过 `-v /path/to/models:/models:ro` 挂载。不能用随机初始化或重新下载的基础模型冒充历史微调检查点。

## 工程检查的复现范围

`compiler` 是可重新构建的工具链镜像。历史实验容器曾安装额外项目依赖，并挂载约 41 GB 的工程卷；这些源码、配置、生成头文件和 Bazel 外部依赖不属于镜像层。本次没有把含临时目录的历史容器直接 `docker commit`。

`data/updates/*/engineering_contexts.json` 提供工程身份、历史路径与参数，`experiments/*/compiler/` 提供原检查器。历史绝对路径用于解释证据，运行前需根据上游提交恢复工程及生成配置，再映射路径。镜像内的简单编译检查不代表已重新运行全部 198 对工程检查，也不替代原来的编译与激活证据。

`requirements/runtime.txt` 是从 2026-11-01 远程环境核实的直接依赖版本，`protocols/runtime_observed_20261101.json` 是对应记录。它们不是历史全部传递依赖和操作系统包的逐字节锁定。新增镜像采用不同于历史 AutoDL 的基础系统；PyTorch、Transformers、Tree-sitter 的直接版本与观测环境一致。

本地构建：

```bash
docker build -f docker/Dockerfile --target verify -t repair:verify .
docker build -f docker/Dockerfile --target compiler -t repair:compiler .
docker build -f docker/Dockerfile --target gpu -t repair:gpu .
```
