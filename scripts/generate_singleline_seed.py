"""Generate independent Seed-Coder candidates using only frozen Valid inputs."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import time

from train_singleline import candidate, parsers, read, sha, write


MODEL = "ByteDance-Seed/Seed-Coder-8B-Instruct"
REVISION = "1c5af72afa21c22c9272a0b60a3a404195e88fcd"


def main():
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer, set_seed
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--data", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    torch.set_num_threads(8)
    set_seed(42)
    manifest = json.loads((args.data / "manifest.json").read_text(encoding="utf-8"))
    source = args.data / "inputs_valid.jsonl"
    if sha(source) != manifest["files"][source.name]:
        raise ValueError("manifest_mismatch")
    cases = read(source)
    if len(cases) != 69 or len({r["sample_id"] for r in cases}) != 69:
        raise ValueError("invalid_valid_identity")
    tokenizer = AutoTokenizer.from_pretrained(MODEL, revision=REVISION, local_files_only=True)
    inputs = []
    for case in cases:
        text = case["input_local"]
        if hashlib.sha256(text.encode("utf-8")).hexdigest() != case["input_local_sha256"]:
            raise ValueError("input_hash_mismatch")
        value = tokenizer.apply_chat_template([dict(role="user", content=text)],
                    tokenize=True, add_generation_prompt=True, return_tensors="pt", return_dict=True)
        if value["input_ids"].shape[1] + 256 > 4096:
            raise ValueError("token_budget_exceeded")
        inputs.append(value)
    args.out.mkdir(parents=True, exist_ok=False)
    config = dict(model=MODEL, revision=REVISION, seed=42, data_sha256=sha(source),
                  script_sha256=sha(Path(__file__)), references_opened=False,
                  candidate_module_sha256=sha(Path(__file__).with_name("train_singleline.py")),
                  renderer_module_sha256=sha(Path(__file__).with_name("singleline_repair.py")),
                  generation=dict(num_beams=3, num_return_sequences=3, do_sample=False,
                                  max_new_tokens=256), api_calls=0, truncation=False)
    write(args.out / "config.json", config)
    model = AutoModelForCausalLM.from_pretrained(MODEL, revision=REVISION, local_files_only=True,
                  torch_dtype=torch.bfloat16, attn_implementation="sdpa").cuda().eval()
    engines = parsers()
    counts = Counter(n=len(cases))
    started = time.perf_counter()
    with (args.out / "valid_candidates.jsonl").open("w", encoding="utf-8") as out:
        for case, value in zip(cases, inputs):
            n = value["input_ids"].shape[1]
            tensors = {k: v.to("cuda") for k, v in value.items() if k != "token_type_ids"}
            with torch.inference_mode():
                outputs = model.generate(**tensors, **config["generation"],
                    pad_token_id=tokenizer.pad_token_id if tokenizer.pad_token_id is not None else tokenizer.eos_token_id)
            generated = outputs[:, n:]
            predictions = tokenizer.batch_decode(generated, skip_special_tokens=True,
                                                  clean_up_tokenization_spaces=False)
            rows = [candidate(case, text, engines, i + 1) for i, text in enumerate(predictions)]
            eos = model.generation_config.eos_token_id
            eos = eos if isinstance(eos, list) else [eos]
            seen = set()
            for row, tokens in zip(rows, generated):
                row["source"] = "seed"
                row["output_truncated"] = len(tokens) == 256 and not any(int(t) in eos for t in tokens)
                digest = row.get("patch_sha256")
                row["duplicate"] = digest is not None and digest in seen
                if digest:
                    seen.add(digest)
            counts["samples_with_render_valid"] += any(r["render_valid"] for r in rows)
            counts["samples_with_syntax_valid"] += any(r["syntax_valid"] for r in rows)
            out.write(json.dumps(dict(sample_id=case["sample_id"], input_tokens=n,
                input_sha256=case["input_local_sha256"], candidates=rows), ensure_ascii=False) + "\n")
            out.flush()
            print("SEED_VALID", case["sample_id"], flush=True)
    write(args.out / "valid_summary.json", dict(counts, seconds=time.perf_counter() - started,
          syntax_validity=counts["samples_with_syntax_valid"] / len(cases), llm_sfr=None, api_calls=0))
    print("SEED_VALID_COMPLETE", dict(counts), flush=True)


if __name__ == "__main__":
    main()
