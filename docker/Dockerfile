FROM python:3.12-slim-bookworm AS verify
LABEL org.opencontainers.image.source="https://github.com/zzzxc643/c-cpp-singleline-vulnerability-repair"
WORKDIR /artifact
COPY . .
RUN python scripts/verify_artifact.py
CMD ["python", "scripts/verify_artifact.py"]

FROM ubuntu:24.04 AS compiler
LABEL org.opencontainers.image.source="https://github.com/zzzxc643/c-cpp-singleline-vulnerability-repair"
ARG DEBIAN_FRONTEND=noninteractive
ARG CLANG_VERSION=1:20.1.2-0ubuntu1~24.04.3
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates git curl python3 python3-venv python3-pip \
    build-essential gcc-11 g++-11 clang-20=${CLANG_VERSION} llvm-20-dev=${CLANG_VERSION} \
    libclang-20-dev=${CLANG_VERSION} lld-20=${CLANG_VERSION} \
    cmake ninja-build pkg-config autoconf automake libtool bison flex \
    libssl-dev libelf-dev libsystemd-dev libglib2.0-dev zlib1g-dev \
    libxml2-dev liblzma-dev libbz2-dev libjpeg-dev libpng-dev \
    && update-alternatives --install /usr/bin/clang clang /usr/bin/clang-20 100 \
    && update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-20 100 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /artifact
COPY . .
RUN python3 scripts/verify_artifact.py && clang --version | head -1 \
    && printf 'int main(void) { return 0; }\n' | clang -x c -fsyntax-only -
CMD ["bash"]

FROM python:3.12-slim-bookworm AS gpu
LABEL org.opencontainers.image.source="https://github.com/zzzxc643/c-cpp-singleline-vulnerability-repair"
RUN apt-get update && apt-get install -y --no-install-recommends git libgomp1 \
    && rm -rf /var/lib/apt/lists/*
COPY requirements/runtime.txt /tmp/runtime.txt
RUN pip install --no-cache-dir torch==2.8.0+cu128 --index-url https://download.pytorch.org/whl/cu128 \
    && pip install --no-cache-dir -r /tmp/runtime.txt \
    && pip check
WORKDIR /artifact
COPY . .
RUN python scripts/verify_artifact.py \
    && python -c "import torch, transformers, tree_sitter_c, tree_sitter_cpp; assert torch.__version__ == '2.8.0+cu128'; assert transformers.__version__ == '4.51.3'"
ENV HF_HOME=/models/huggingface
CMD ["bash"]
