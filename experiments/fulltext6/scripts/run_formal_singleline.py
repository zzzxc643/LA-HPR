"""One frozen Test-SingleLine run using the method selected on Valid."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

from local_candidate_judge import review_batch
from normalize_singleline_candidates import unwrap
from prepare_singleline_pools import select_pool
from review_singleline_pools import prompt_budget
from singleline_repair import model_input
from summarize_singleline_review import audit
from train_singleline import candidate, encode, parsers, read, sha, write


MODULES = ("run_formal_singleline.py", "train_singleline.py", "singleline_repair.py",
           "normalize_singleline_candidates.py", "prepare_singleline_pools.py",
           "review_singleline_pools.py", "local_candidate_judge.py", "summarize_singleline_review.py")


def checked_test(data):
    manifest = json.loads((data / "manifest.json").read_text(encoding="utf-8"))
    path = data / "inputs_test.jsonl"
    if sha(path) != manifest["files"][path.name]:
        raise ValueError("test_manifest_mismatch")
    cases = read(path)
    ids = {r["sample_id"] for r in cases}
    if len(cases) != 57 or len(ids) != 57:
        raise ValueError("expected_57_unique_test_samples")
    for split in ("train", "valid"):
        path = data / f"inputs_{split}.jsonl"
        if sha(path) != manifest["files"][path.name]:
            raise ValueError("split_manifest_mismatch")
        if ids & {r["sample_id"] for r in read(path)}:
            raise ValueError("split_identity_overlap")
    for case in cases:
        if {"target", "action", "fixed_code", "commit_message", "cve_desc"} & case.keys():
            raise ValueError("reference_in_model_input")
        if case["edit_end"] != case["edit_start"] + 1:
            raise ValueError("not_singleline_input")
        for full, field in ((False, "input_local"), (True, "input_full")):
            reconstructed, _, _ = model_input(case["vulnerable_code"], case["edit_start"], case["cwe"], full=full)
            if reconstructed != case[field] or hashlib.sha256(case[field].encode("utf-8")).hexdigest() != case[field + "_sha256"]:
                raise ValueError("test_input_hash_or_prompt_mismatch")
    return cases


def freeze(args):
    cases = checked_test(args.data)
    root = args.valid_root
    configurations = dict(
        codet5=root / "codet5_local_20261017/config.json",
        seed=root / "seed_valid_20261017/config.json",
        judge=root / "qwen38_valid_20261017/config.json")
    settings = {name: json.loads(path.read_text(encoding="utf-8")) for name, path in configurations.items()}
    training = json.loads((root / "codet5_local_20261017/training_summary.json").read_text(encoding="utf-8"))
    model = root / "codet5_local_20261017/model"
    if sha(model / "model.safetensors") != training["model_sha256"]:
        raise ValueError("checkpoint_changed_since_valid")
    config = dict(protocol="formal_singleline_20261017", scope="Test-SingleLine", n=57,
                  frozen_utc=datetime.now(timezone.utc).isoformat(),
                  method="CodeT5 Action Local + Seed + deterministic renderer + Qwen selection",
                  rules_candidates=0, ast_normalization=False, constrained_decoding=False,
                  context_radius=8, seed=42, data_sha256=sha(args.data / "inputs_test.jsonl"),
                  sample_ids=[r["sample_id"] for r in cases],
                  scripts_sha256={name: sha(Path(__file__).with_name(name)) for name in MODULES},
                  valid_configs_sha256={name: sha(path) for name, path in configurations.items()},
                  settings=settings, checkpoint_path=str(model),
                  checkpoint_files_sha256={p.name: sha(p) for p in model.iterdir() if p.is_file()},
                  format_policy="single complete JSON Markdown fence removal only; preserve raw outputs",
                  syntax_policy="strict C or C++ root without errors; all 57 retained",
                  deduplication="exact complete patched function", selection="fixed codet5/seed/rules rotation, maximum 5",
                  formal_test_reference_opened=False, overall_test="deferred by user until multi-line method validated")
    args.out.mkdir(parents=True, exist_ok=False)
    write(args.out / "freeze.json", config)
    print("FROZEN_TEST", len(cases), flush=True)


def frozen_inputs(args):
    config = json.loads((args.out / "freeze.json").read_text(encoding="utf-8"))
    if sha(args.data / "inputs_test.jsonl") != config["data_sha256"]:
        raise ValueError("frozen_test_data_changed")
    for name, expected in config["scripts_sha256"].items():
        if sha(Path(__file__).with_name(name)) != expected:
            raise ValueError("frozen_script_changed:" + name)
    for name, expected in config["checkpoint_files_sha256"].items():
        if sha(Path(config["checkpoint_path"]) / name) != expected:
            raise ValueError("frozen_checkpoint_changed:" + name)
    cases = checked_test(args.data)
    if [r["sample_id"] for r in cases] != config["sample_ids"]:
        raise ValueError("frozen_test_identity_changed")
    return config, cases


def generate(args, config, cases):
    import torch
    from transformers import AutoModelForCausalLM, AutoModelForSeq2SeqLM, AutoTokenizer, set_seed
    source = args.stage
    settings = config["settings"][source]
    torch.set_num_threads(8)
    set_seed(config["seed"])
    if source == "codet5":
        tokenizer = AutoTokenizer.from_pretrained(settings["model"], revision=settings["revision"], local_files_only=True)
        model = AutoModelForSeq2SeqLM.from_pretrained(config["checkpoint_path"], local_files_only=True).cuda().eval()
    else:
        tokenizer = AutoTokenizer.from_pretrained(settings["model"], revision=settings["revision"], local_files_only=True)
        model = AutoModelForCausalLM.from_pretrained(settings["model"], revision=settings["revision"],
                    local_files_only=True, torch_dtype=torch.bfloat16, attn_implementation="sdpa").cuda().eval()
    engines, counts = parsers(), Counter(n=len(cases))
    with (args.out / f"{source}_candidates.jsonl").open("x", encoding="utf-8") as stream:
        for case in cases:
            if source == "codet5":
                try:
                    encoded = encode(tokenizer, case["input_local"], settings["max_input_tokens"])
                except ValueError as exc:
                    stream.write(json.dumps(dict(sample_id=case["sample_id"],
                        input_sha256=case["input_local_sha256"], candidates=[], generation_error=str(exc))) + "\n")
                    stream.flush()
                    counts["input_budget_exceeded"] += 1
                    continue
                tensors = {k: torch.tensor([v], device="cuda") for k, v in encoded.items()}
                n = len(encoded["input_ids"])
            else:
                value = tokenizer.apply_chat_template([dict(role="user", content=case["input_local"])],
                    tokenize=True, add_generation_prompt=True, return_tensors="pt", return_dict=True)
                n = value["input_ids"].shape[1]
                if n + settings["generation"]["max_new_tokens"] > 4096:
                    stream.write(json.dumps(dict(sample_id=case["sample_id"],
                        input_sha256=case["input_local_sha256"], candidates=[], generation_error="token_budget_exceeded")) + "\n")
                    stream.flush()
                    counts["input_budget_exceeded"] += 1
                    continue
                tensors = {k: v.to("cuda") for k, v in value.items() if k != "token_type_ids"}
            options = dict(settings["generation"])
            if source == "seed":
                options["pad_token_id"] = tokenizer.pad_token_id if tokenizer.pad_token_id is not None else tokenizer.eos_token_id
            with torch.inference_mode():
                outputs = model.generate(**tensors, **options)
            generated = outputs[:, n:] if source == "seed" else outputs
            predictions = tokenizer.batch_decode(generated, skip_special_tokens=True, clean_up_tokenization_spaces=False)
            rows = []
            for rank, raw in enumerate(predictions, 1):
                text, policy = unwrap(raw)
                row = candidate(case, text, engines, rank)
                row.update(source=source, raw_prediction=raw, format_normalization=policy)
                rows.append(row)
            counts["samples_with_render_valid"] += any(r["render_valid"] for r in rows)
            counts["samples_with_syntax_valid"] += any(r["syntax_valid"] for r in rows)
            stream.write(json.dumps(dict(sample_id=case["sample_id"], input_tokens=n,
                input_sha256=case["input_local_sha256"], candidates=rows), ensure_ascii=False) + "\n")
            stream.flush()
            print("FORMAL_GENERATE", source, case["sample_id"], flush=True)
    write(args.out / f"{source}_summary.json", dict(counts))


def pools(args, cases):
    groups = {}
    for source in ("codet5", "seed"):
        rows = read(args.out / f"{source}_candidates.jsonl")
        if len(rows) != 57 or {r["sample_id"] for r in rows} != {c["sample_id"] for c in cases}:
            raise ValueError("incomplete_test_candidates")
        groups[source] = {r["sample_id"]: r for r in rows}
    with (args.out / "pools.jsonl").open("x", encoding="utf-8") as stream:
        for case in cases:
            generated = {}
            for source, rows in groups.items():
                row = rows[case["sample_id"]]
                if row["input_sha256"] != case["input_local_sha256"]:
                    raise ValueError("candidate_input_mismatch")
                generated[source] = row["candidates"]
            stream.write(json.dumps(dict(sample_id=case["sample_id"], original_function=case["vulnerable_code"],
                vulnerable_line=case["edit_start"] + 1, **select_pool(generated)), ensure_ascii=False) + "\n")


def review(args, config):
    from openai import OpenAI
    key = os.environ.get("QWEN_API_KEY")
    if not key:
        raise ValueError("missing_qwen_api_key")
    settings = config["settings"]["judge"]
    client = OpenAI(api_key=key, base_url=settings["base_url"], timeout=90, max_retries=0)
    rows = []
    for pool in read(args.out / "pools.jsonl"):
        result = dict(sample_id=pool["sample_id"], selected_cand_id=None, counts=pool["counts"])
        if not pool["candidates"]:
            result.update(status="no_syntax_valid_candidate", success=False)
        else:
            candidates = [dict(cand_id=c["cand_id"], diff=c["diff"]) for c in pool["candidates"]]
            content = json.dumps(dict(original_function=pool["original_function"],
                vulnerable_line=pool["vulnerable_line"], candidates=candidates), ensure_ascii=False)
            bound, method = prompt_budget(content)
            result.update(prompt_budget_tokens=bound, prompt_budget_method=method)
            if bound + settings["max_output_tokens"] > settings["context_limit"]:
                result.update(status="context_limit_pending", success=None)
            else:
                record = review_batch(client, settings["model"], pool["original_function"], candidates,
                    args.out / "requests", vulnerable_line=pool["vulnerable_line"],
                    enable_thinking=settings["enable_thinking"])
                valid = record["status"] == "valid"
                cid = record["selected_cand_id"] if valid else None
                result.update(status=record["status"], request_id=record["request_id"],
                    success=(cid is not None) if valid else None, selected_cand_id=cid,
                    reviews=record["reviews"], selection_reason=record["selection_reason"])
                if cid is not None:
                    winner = next(c for c in pool["candidates"] if c["cand_id"] == cid)
                    result.update(selected_source=winner["source"], final_patch=winner["patched_code"])
                if record["attempts"][-1].get("status_code") in (400, 401, 403, 404, 422):
                    write(args.out / "results.json", rows + [result])
                    raise RuntimeError("qwen_configuration_error")
        rows.append(result)
        write(args.out / "results.json", rows)
        print("FORMAL_REVIEW", pool["sample_id"], result["status"], flush=True)
    records = {p.stem: json.loads(p.read_text(encoding="utf-8")) for p in (args.out / "requests").glob("*.json")}
    report = audit(read(args.out / "pools.jsonl"), rows, records)
    report.update(scope="Test-SingleLine", model=settings["model"],
        freeze_sha256=sha(args.out / "freeze.json"), pools_sha256=sha(args.out / "pools.jsonl"),
        results_sha256=sha(args.out / "results.json"), formal_test_reference_opened=False)
    write(args.out / "audited_summary.json", report)
    print("FORMAL_COMPLETE", json.dumps(report), flush=True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--data", type=Path, required=True)
    p.add_argument("--valid-root", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--stage", choices=("all", "freeze", "codet5", "seed", "pools", "review"), default="all")
    args = p.parse_args()
    if args.stage == "all":
        if args.out.exists():
            raise FileExistsError("formal_run_already_exists")
        status = dict(status="running", scope="Test-SingleLine", n=57, stages=[])
        for stage in ("freeze", "codet5", "seed", "pools", "review"):
            status.update(stage=stage, updated_utc=datetime.now(timezone.utc).isoformat())
            write(args.out.with_suffix(".status.json"), status)
            command = [sys.executable, "-u", str(Path(__file__)), "--data", str(args.data),
                "--valid-root", str(args.valid_root), "--out", str(args.out), "--stage", stage]
            completed = subprocess.run(command)
            status["stages"].append(dict(stage=stage, exit_code=completed.returncode))
            if completed.returncode:
                status.update(status="failed")
                write(args.out.with_suffix(".status.json"), status)
                raise SystemExit(completed.returncode)
        status.update(status="complete", updated_utc=datetime.now(timezone.utc).isoformat())
        write(args.out.with_suffix(".status.json"), status)
        return
    if args.stage == "freeze":
        freeze(args)
        return
    config, cases = frozen_inputs(args)
    if args.stage in ("codet5", "seed"):
        generate(args, config, cases)
    elif args.stage == "pools":
        pools(args, cases)
    else:
        review(args, config)


if __name__ == "__main__":
    main()
