"""Complete-function baselines and a matching local-context control."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import difflib
import hashlib
import json
from pathlib import Path
import re
import time

from audit_full_context_budget import fulltext_input
from normalize_singleline_candidates import unwrap
from prepare_singleline_pools import select_pool
from run_formal_singleline import checked_test, review
from train_singleline import (MODEL, REVISION, candidate, checked_data, encode,
                              parsers, read, sha, syntax, write)


ARMS = ("original_fulltext", "action_full", "action_local_matched")
DEPENDENCIES = ("full_context_baselines.py", "audit_full_context_budget.py", "train_singleline.py",
    "singleline_repair.py", "normalize_singleline_candidates.py", "prepare_singleline_pools.py",
    "run_formal_singleline.py", "review_singleline_pools.py", "local_candidate_judge.py",
    "summarize_singleline_review.py")


def fulltext_candidate(case, raw, engines, rank):
    match = re.fullmatch(r"\s*```(?:c|cpp|c\+\+)?[ \t]*\r?\n([\s\S]*?)\r?\n```\s*", raw, re.IGNORECASE)
    code = match.group(1) if match else raw
    row = dict(rank=rank, source="codet5", raw_prediction=raw, prediction=code,
        format_normalization="single_code_fence_removed" if match else "unchanged",
        render_valid=False, syntax_valid=False)
    if not code.strip() or code.strip() == case["vulnerable_code"].strip():
        row["render_error"] = "empty_or_unchanged_function"
        return row
    def functions(node):
        if node.type == "function_definition":
            return 1
        return sum(functions(child) for child in node.named_children)
    parsed = syntax(code, engines)
    valid = any(parsed[name] and functions(engine.parse(code.encode()).root_node) == 1
                for name, engine in engines.items())
    row.update(render_valid=True, syntax_valid=valid, syntax_parse=parsed, patched_code=code,
        patch_sha256=hashlib.sha256(code.encode()).hexdigest(), diff="".join(difflib.unified_diff(
            case["vulnerable_code"].splitlines(keepends=True), code.splitlines(keepends=True),
            fromfile="original", tofile="candidate")))
    return row


def input_text(case, arm):
    if arm == "original_fulltext":
        return fulltext_input(case)
    return case["input_local" if arm == "action_local_matched" else "input_full"]


def checked_config(args):
    config = json.loads((args.out / "protocol.json").read_text(encoding="utf-8"))
    for name, digest in config["scripts_sha256"].items():
        if sha(Path(__file__).with_name(name)) != digest:
            raise ValueError("baseline_script_drift:" + name)
    for name, digest in config["data_sha256"].items():
        if sha(args.data / name) != digest:
            raise ValueError("baseline_data_drift:" + name)
    return config


def prepare(args):
    checked_data(args.data)
    manifest = json.loads((args.data / "manifest.json").read_text(encoding="utf-8"))
    if sha(args.data / "references_train.jsonl") != manifest["files"]["references_train.jsonl"]:
        raise ValueError("training_reference_drift")
    budget = json.loads(args.budget.read_text(encoding="utf-8"))
    for name, digest in budget["source_hashes"].items():
        filename = "references_train.jsonl" if name == "references_train" else name
        if sha(args.data / filename) != digest:
            raise ValueError("budget_audit_data_drift")
    selected = {split: [r["sample_id"] for r in budget["rows"] if r["split"] == split
        and max(r["action_input"], r["fulltext_input"], r["fulltext_target"]) <= args.limit]
        for split in ("train", "valid")}
    judge = json.loads((args.valid_root / "qwen38_valid_20261017/config.json").read_text(encoding="utf-8"))
    config = dict(protocol="supplemental_full_context_baselines_v1", frozen_utc=datetime.now(timezone.utc).isoformat(),
        model=MODEL, revision=REVISION, arms=ARMS, full_limit=args.limit, local_limit=1024,
        action_output_limit=128, fulltext_output_limit=args.limit, seed=42, epochs=20,
        learning_rate=5e-5, weight_decay=0.01, effective_batch_size=4, device_batch_size=1,
        gradient_accumulation_steps=4, gradient_checkpointing=True, bf16_training=True,
        shared_train_ids=selected["train"], shared_valid_loss_ids=selected["valid"],
        data_sha256={name: manifest["files"][name] for name in ("inputs_train.jsonl", "train.jsonl",
            "references_train.jsonl", "inputs_valid.jsonl", "references_valid.jsonl")},
        test_input_sha256=manifest["files"]["inputs_test.jsonl"],
        scripts_sha256={name: sha(Path(__file__).with_name(name)) for name in DEPENDENCIES},
        settings=dict(judge=judge), generation=dict(num_beams=3, num_return_sequences=3, do_sample=False),
        checkpoint_selection="minimum Valid target loss on common feasible Valid subset",
        budget_policy="complete input or explicit budget failure; never truncate input; all evaluation samples retained",
        fulltext_policy="direct complete-function generation; no action labels, renderer, Seed or rules",
        action_policy="existing JSON actions, single complete JSON fence removal, existing deterministic renderer",
        training_policy="all three arms use identical feasible Train IDs; omitted Train IDs disclosed",
        original_local="451-sample local model remains a separately reported prior run",
        formal_test_opened=False, overall_test="deferred until multi-line validation")
    args.out.mkdir(parents=True, exist_ok=False)
    write(args.out / "protocol.json", config)
    print("BASELINES_PREPARED", len(selected["train"]), len(selected["valid"]), flush=True)


def training_data(args, config, tokenizer):
    _, valid, valid_refs, _ = checked_data(args.data)
    train = read(args.data / "inputs_train.jsonl")
    train_refs = {r["sample_id"]: r for r in read(args.data / "references_train.jsonl")}
    result = []
    for cases, refs, ids in ((train, train_refs, config["shared_train_ids"]),
                             (valid, valid_refs, config["shared_valid_loss_ids"])):
        chosen = {r["sample_id"]: r for r in cases}
        rows = []
        for sid in ids:
            case, reference = chosen[sid], refs[sid]
            limit = config["local_limit"] if args.arm == "action_local_matched" else config["full_limit"]
            target_limit = config["fulltext_output_limit"] if args.arm == "original_fulltext" else config["action_output_limit"]
            target = reference["fixed_code" if args.arm == "original_fulltext" else "target"]
            rows.append(dict(**encode(tokenizer, input_text(case, args.arm), limit),
                labels=encode(tokenizer, target, target_limit)["input_ids"]))
        result.append(rows)
    return result


def train(args, config):
    import torch
    from transformers import (AutoModelForSeq2SeqLM, AutoTokenizer, DataCollatorForSeq2Seq,
                              Seq2SeqTrainer, Seq2SeqTrainingArguments, set_seed)
    torch.set_num_threads(8)
    set_seed(config["seed"])
    folder = args.out / args.arm
    folder.mkdir(exist_ok=False)
    tokenizer = AutoTokenizer.from_pretrained(MODEL, revision=REVISION, local_files_only=True)
    training, validation = training_data(args, config, tokenizer)
    model = AutoModelForSeq2SeqLM.from_pretrained(MODEL, revision=REVISION, local_files_only=True).cuda()
    model.config.use_cache = False
    trainer = Seq2SeqTrainer(model=model, args=Seq2SeqTrainingArguments(
        output_dir=str(folder / "trainer"), num_train_epochs=config["epochs"],
        per_device_train_batch_size=1, per_device_eval_batch_size=1, gradient_accumulation_steps=4,
        learning_rate=config["learning_rate"], weight_decay=config["weight_decay"],
        lr_scheduler_type="linear", warmup_ratio=0.05, bf16=True, optim="adamw_torch",
        gradient_checkpointing=True, gradient_checkpointing_kwargs={"use_reentrant": False},
        eval_strategy="epoch", save_strategy="epoch", save_total_limit=1,
        load_best_model_at_end=True, metric_for_best_model="eval_loss", greater_is_better=False,
        logging_strategy="epoch", report_to="none", seed=42, data_seed=42,
        dataloader_num_workers=0, disable_tqdm=True), train_dataset=training, eval_dataset=validation,
        data_collator=DataCollatorForSeq2Seq(tokenizer=tokenizer, model=model))
    started = time.perf_counter()
    result = trainer.train()
    model.config.use_cache = True
    model.save_pretrained(folder / "model", safe_serialization=True)
    tokenizer.save_pretrained(folder / "model")
    write(folder / "training_summary.json", dict(arm=args.arm, metrics=result.metrics,
        seconds=time.perf_counter()-started, training_samples=len(training), validation_samples=len(validation),
        log_history=trainer.state.log_history, best_checkpoint=trainer.state.best_model_checkpoint,
        best_valid_loss=trainer.state.best_metric, model_sha256=sha(folder / "model/model.safetensors"),
        checkpoint_files_sha256={p.name: sha(p) for p in (folder / "model").iterdir() if p.is_file()},
        peak_allocated_gib=torch.cuda.max_memory_allocated()/1024**3, formal_test_opened=False))
    print("BASELINE_TRAINED", args.arm, flush=True)


def generate(args, config):
    import torch
    from transformers import AutoModelForSeq2SeqLM, AutoTokenizer, set_seed
    torch.set_num_threads(8)
    set_seed(config["seed"])
    split = args.stage
    if split == "test":
        cases = checked_test(args.data)
        if sha(args.data / "inputs_test.jsonl") != config["test_input_sha256"]:
            raise ValueError("test_input_drift")
        for arm in ARMS:
            summary = json.loads((args.out / arm / "valid/audited_summary.json").read_text(encoding="utf-8"))
            if summary["n"] != 69 or not summary["complete"]:
                raise ValueError("all_valid_arms_must_complete_before_test")
    else:
        checked_data(args.data)
        cases = read(args.data / "inputs_valid.jsonl")
    training = json.loads((args.out / args.arm / "training_summary.json").read_text(encoding="utf-8"))
    model_path = args.out / args.arm / "model"
    for name, digest in training["checkpoint_files_sha256"].items():
        if sha(model_path / name) != digest:
            raise ValueError("trained_checkpoint_drift")
    folder = args.out / args.arm / split
    folder.mkdir(exist_ok=False)
    write(folder / "freeze.json", dict(config, scope="Test-SingleLine" if split == "test" else "Valid-SingleLine",
        n=len(cases), arm=args.arm, generation_frozen_utc=datetime.now(timezone.utc).isoformat(),
        formal_test_opened=split == "test", formal_test_reference_opened=False,
        model_sha256=training["model_sha256"], data_sha256_current=sha(args.data / f"inputs_{split}.jsonl")))
    tokenizer = AutoTokenizer.from_pretrained(MODEL, revision=REVISION, local_files_only=True)
    model = AutoModelForSeq2SeqLM.from_pretrained(model_path, local_files_only=True).cuda().eval()
    engines, counts = parsers(), Counter(n=len(cases))
    output_limit = config["fulltext_output_limit"] if args.arm == "original_fulltext" else config["action_output_limit"]
    limit = config["local_limit"] if args.arm == "action_local_matched" else config["full_limit"]
    with (folder / "candidates.jsonl").open("x", encoding="utf-8") as stream, \
            (folder / "pools.jsonl").open("x", encoding="utf-8") as pool_stream:
        for case in cases:
            text = input_text(case, args.arm)
            encoded = tokenizer(text, truncation=False)
            n = len(encoded["input_ids"])
            rows = []
            if n > limit:
                counts["input_budget_exceeded"] += 1
            else:
                tensors = {k: torch.tensor([v], device="cuda") for k, v in encoded.items()}
                with torch.inference_mode():
                    outputs = model.generate(**tensors, **config["generation"], max_new_tokens=output_limit)
                raw_predictions = tokenizer.batch_decode(outputs, skip_special_tokens=True, clean_up_tokenization_spaces=False)
                for rank, (raw, tokens) in enumerate(zip(raw_predictions, outputs), 1):
                    if args.arm == "original_fulltext":
                        row = fulltext_candidate(case, raw, engines, rank)
                    else:
                        normalized, policy = unwrap(raw)
                        row = candidate(case, normalized, engines, rank)
                        row.update(raw_prediction=raw, format_normalization=policy)
                    row["output_truncated"] = len(tokens) - 1 >= output_limit and not any(
                        int(token) == tokenizer.eos_token_id for token in tokens[1:])
                    rows.append(row)
            record = dict(sample_id=case["sample_id"], input_sha256=hashlib.sha256(text.encode()).hexdigest(),
                input_tokens=n, input_budget_exceeded=n > limit, candidates=rows)
            stream.write(json.dumps(record, ensure_ascii=False) + "\n")
            stream.flush()
            pool = dict(sample_id=case["sample_id"], original_function=case["vulnerable_code"],
                vulnerable_line=case["edit_start"]+1, **select_pool({"codet5": rows}))
            pool_stream.write(json.dumps(pool, ensure_ascii=False) + "\n")
            pool_stream.flush()
            counts["syntax_valid_samples"] += bool(pool["candidates"])
            print("BASELINE_GENERATE", args.arm, split, case["sample_id"], flush=True)
    write(folder / "generation_summary.json", dict(counts))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--valid-root", type=Path)
    parser.add_argument("--budget", type=Path)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--arm", choices=ARMS)
    parser.add_argument("--stage", choices=("prepare", "train", "valid", "test", "review-valid", "review-test"), required=True)
    args = parser.parse_args()
    if args.stage == "prepare":
        prepare(args)
        return
    config = checked_config(args)
    if args.stage == "train":
        train(args, config)
    elif args.stage in ("valid", "test"):
        generate(args, config)
    else:
        split = args.stage.split("-")[1]
        review(argparse.Namespace(out=args.out / args.arm / split), config)
        path = args.out / args.arm / split / "audited_summary.json"
        report = json.loads(path.read_text(encoding="utf-8"))
        report.update(scope="Test-SingleLine" if split == "test" else "Valid-SingleLine", arm=args.arm)
        write(path, report)


if __name__ == "__main__":
    main()
