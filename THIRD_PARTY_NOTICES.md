# Third-party notices

## PrimeVul

- Official repository: https://github.com/DLVulDet/PrimeVul
- Dataset version: PrimeVul v0.1 (paired train/valid/test files)
- License documentation revision inspected: `6f54687c84947b1d17486495440b37030d147289`
- License at that revision: MIT, copyright (c) 2024 DLVulDet
- Preserved license: [third_party/PrimeVul-LICENSE](third_party/PrimeVul-LICENSE)
- Paper: *PrimeVul: A Dataset for Improving Large Language Models for Vulnerability Detection*, https://arxiv.org/abs/2403.18624
- Official download instructions and links: https://github.com/DLVulDet/PrimeVul/tree/6f54687c84947b1d17486495440b37030d147289

This package includes selected PrimeVul-derived metadata (identifiers, labels, URLs, hashes) and this study's annotations/results. All selected vulnerable and fixed functions were matched to official paired records by commit and function SHA-256. The inspected repository revision documents upstream provenance; it does not identify an immutable version of externally hosted download files. File hashes of the paired files actually used are recorded in `provenance/upstream_file_hashes.json`.

## MegaVul (2026-11-01 addition)

The additional 141-row evaluation pool derives from [MegaVul](https://github.com/Icyrockton/MegaVul), whose repository declares GPL-3.0. The exact raw JSON used was obtained from the recorded Kaggle mirror; its provenance and SHA-256 are retained in `provenance/megavul_source.json`. The mirror's file packaging is not asserted to be identical to the official distribution. This release provides identity metadata and original study annotations/results; the raw dataset and original function text are obtained separately. Follow MegaVul's license and the original projects' licenses when obtaining and reconstructing the data. This repository's MIT license does not relicense MegaVul or original project code.

## Original project code (reconstruction)

PrimeVul contains functions from many software projects. The PrimeVul repository's MIT license is not a blanket relicensing of those projects. Original function text, reference fixes and model-generated code are not directly bundled here. `scripts/reconstruct_data.py` reads a separately obtained official dataset and reconstructs them locally. That reconstructed code remains subject to applicable original project notices and licenses; this repository's MIT license does not replace them. Project and commit URLs are provided per record and in `provenance/upstream_projects.json`; missing upstream URLs are not asserted to have been independently recovered.

## Models and tools

Model identifiers in configuration files refer to Salesforce/CodeT5+, ByteDance-Seed/Seed-Coder and the recorded Qwen API model. No model weights are redistributed. Each model's own license and provider terms apply to downloading weights or using services. Tree-sitter, PyTorch, Transformers and Clang are referenced as experiment dependencies, not redistributed implementations.
