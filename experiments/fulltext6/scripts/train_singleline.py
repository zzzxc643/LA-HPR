"""Ordinary source-only CodeT5+ training and reference-free Valid generation."""
import argparse
from collections import Counter
import difflib
import hashlib
import json
from pathlib import Path
import time

from singleline_repair import render


MODEL = "Salesforce/codet5p-220m"
REVISION = "2b92f36e2782341a50551759fdba0dd15e821f99"


def read(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def encode(tokenizer, text, limit):
    value = tokenizer(text, truncation=False)
    if len(value["input_ids"]) > limit:
        raise ValueError(f"token_budget_exceeded:{len(value['input_ids'])}>{limit}")
    return value


def checked_data(root):
    # Only Train and Valid are opened; Formal Test is not part of model selection.
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    names = ("train.jsonl", "inputs_train.jsonl", "inputs_valid.jsonl", "references_valid.jsonl")
    for name in names:
        if sha(root / name) != manifest["files"][name]:
            raise ValueError(f"manifest_mismatch:{name}")
    train = read(root / "train.jsonl")
    sources = read(root / "inputs_train.jsonl")
    valid = read(root / "inputs_valid.jsonl")
    refs = read(root / "references_valid.jsonl")
    train_ids = {r["sample_id"] for r in train}
    valid_ids = {r["sample_id"] for r in valid}
    if len(train) != 451 or len(train_ids) != 451 or len(valid) != 69 or len(valid_ids) != 69:
        raise ValueError("unexpected_split_size")
    if train_ids & valid_ids or train_ids != {r["sample_id"] for r in sources}:
        raise ValueError("invalid_training_identity")
    if len(refs) != 69 or {r["sample_id"] for r in refs} != valid_ids:
        raise ValueError("invalid_valid_references")
    by_id = {r["sample_id"]: r for r in sources}
    for row in train:
        if row["input_local"] != by_id[row["sample_id"]]["input_local"]:
            raise ValueError("training_input_mismatch")
    for row in sources + valid:
        if {"fixed_code", "target", "action", "commit_message"} & row.keys():
            raise ValueError("reference_in_source")
        for field in ("input_local", "input_full"):
            actual = hashlib.sha256(row[field].encode("utf-8")).hexdigest()
            if actual != row[field + "_sha256"]:
                raise ValueError("input_hash_mismatch")
    return train, valid, {r["sample_id"]: r for r in refs}, {n: sha(root / n) for n in names}


def parsers():
    from tree_sitter import Language, Parser
    import tree_sitter_c
    import tree_sitter_cpp
    return {"c": Parser(Language(tree_sitter_c.language())),
            "cpp": Parser(Language(tree_sitter_cpp.language()))}


def syntax(code, engines):
    return {name: not engine.parse(code.encode("utf-8")).root_node.has_error
            for name, engine in engines.items()}


def candidate(case, prediction, engines, rank):
    row = dict(rank=rank, source="codet5", prediction=prediction, render_valid=False,
               syntax_valid=False)
    try:
        code = render(case, prediction)
    except (ValueError, TypeError) as exc:
        row["render_error"] = str(exc)
        return row
    parsed = syntax(code, engines)
    row.update(render_valid=True, syntax_valid=any(parsed.values()), syntax_parse=parsed,
               patched_code=code, patch_sha256=hashlib.sha256(code.encode("utf-8")).hexdigest(),
               diff="".join(difflib.unified_diff(
                   case["vulnerable_code"].splitlines(keepends=True), code.splitlines(keepends=True),
                   fromfile="original", tofile="candidate")))
    return row


def main():
    import torch
    import transformers
    from transformers import (AutoModelForSeq2SeqLM, AutoTokenizer, DataCollatorForSeq2Seq,
                              Seq2SeqTrainer, Seq2SeqTrainingArguments, set_seed)

    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--data", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--stage", choices=("audit", "train", "valid"), required=True)
    args = p.parse_args()
    torch.set_num_threads(8)
    set_seed(42)
    train, valid, refs, hashes = checked_data(args.data)
    tokenizer = AutoTokenizer.from_pretrained(MODEL, revision=REVISION, local_files_only=True)
    engines = parsers()
    if args.stage == "audit":
        args.out.mkdir(parents=True, exist_ok=False)
        rows = []
        for split, cases in (("train", train), ("valid", valid)):
            for row in cases:
                lengths = {field: len(tokenizer(row[field], truncation=False)["input_ids"])
                           for field in ("input_local", "input_full")}
                encode(tokenizer, row["input_local"], 1024)
                rows.append(dict(split=split, sample_id=row["sample_id"], **lengths))
        targets = [len(encode(tokenizer, r["target"], 128)["input_ids"]) for r in train]
        valid_parses = [dict(sample_id=r["sample_id"],
                             original=syntax(r["vulnerable_code"], engines),
                             reference=syntax(refs[r["sample_id"]]["fixed_code"], engines))
                        for r in valid]
        write(args.out / "token_audit.json", dict(rows=rows, train_target_max=max(targets),
                                                  truncation=False, formal_test_opened=False))
        write(args.out / "valid_syntax_audit.json", valid_parses)
        config = dict(model=MODEL, revision=REVISION, input_field="input_local",
                      max_input_tokens=1024, max_target_tokens=128, seed=42,
                      epochs=20, batch_size=4, learning_rate=5e-5, weight_decay=0.01,
                      selection="minimum Valid target loss; never Formal Test",
                      generation=dict(num_beams=3, num_return_sequences=3, do_sample=False,
                                      max_new_tokens=128),
                      syntax_policy="strict C or C++ parse; keep every sample in denominator",
                      output_policy="free JSON generation followed by deterministic validation; no constrained decoding",
                      data_sha256=hashes, script_sha256=sha(Path(__file__)),
                      torch=torch.__version__, transformers=transformers.__version__, api_calls=0)
        write(args.out / "config.json", config)
        print("AUDIT_COMPLETE", len(train), len(valid), flush=True)
        return

    config = json.loads((args.out / "config.json").read_text(encoding="utf-8"))
    if config["data_sha256"] != hashes or config["script_sha256"] != sha(Path(__file__)):
        raise ValueError("configuration_drift")
    if not torch.cuda.is_available():
        raise RuntimeError("GPU_required")
    model_path = MODEL if args.stage == "train" else str(args.out / "model")
    kwargs = dict(revision=REVISION) if args.stage == "train" else {}
    model = AutoModelForSeq2SeqLM.from_pretrained(model_path, local_files_only=True, **kwargs).cuda()
    if args.stage == "train":
        if (args.out / "trainer").exists() or (args.out / "model").exists():
            raise FileExistsError("use_a_new_run_directory")
        def dataset(rows):
            return [dict(**encode(tokenizer, r["input_local"], 1024),
                         labels=encode(tokenizer, r["target"], 128)["input_ids"]) for r in rows]
        valid_targets = [dict(input_local=r["input_local"], target=refs[r["sample_id"]]["target"])
                         for r in valid]
        trainer = Seq2SeqTrainer(
            model=model, args=Seq2SeqTrainingArguments(
                output_dir=str(args.out / "trainer"), num_train_epochs=20,
                per_device_train_batch_size=4, per_device_eval_batch_size=4,
                learning_rate=5e-5, weight_decay=0.01, lr_scheduler_type="linear",
                warmup_ratio=0.05, bf16=True, optim="adamw_torch",
                eval_strategy="epoch", save_strategy="epoch", save_total_limit=1,
                load_best_model_at_end=True, metric_for_best_model="eval_loss",
                greater_is_better=False, logging_strategy="epoch", report_to="none",
                seed=42, data_seed=42, dataloader_num_workers=0, disable_tqdm=True),
            train_dataset=dataset(train), eval_dataset=dataset(valid_targets),
            data_collator=DataCollatorForSeq2Seq(tokenizer=tokenizer, model=model))
        started = time.perf_counter()
        result = trainer.train()
        model.save_pretrained(args.out / "model", safe_serialization=True)
        tokenizer.save_pretrained(args.out / "model")
        write(args.out / "training_summary.json", dict(
            metrics=result.metrics, seconds=time.perf_counter() - started,
            log_history=trainer.state.log_history, steps=trainer.state.global_step,
            best_checkpoint=trainer.state.best_model_checkpoint, best_valid_loss=trainer.state.best_metric,
            model_sha256=sha(args.out / "model/model.safetensors"),
            training_samples=len(train), validation_samples=len(valid),
            peak_allocated_gib=torch.cuda.max_memory_allocated() / 1024**3,
            formal_test_opened=False, api_calls=0))
        print("TRAIN_COMPLETE", flush=True)
        return

    path = args.out / "valid_candidates.jsonl"
    if path.exists():
        raise FileExistsError("valid_candidates_already_exist")
    model.eval()
    counts = Counter(n=len(valid))
    with path.open("w", encoding="utf-8") as out:
        for case in valid:
            encoded = encode(tokenizer, case["input_local"], 1024)
            tensors = {k: torch.tensor([v], device="cuda") for k, v in encoded.items()}
            with torch.inference_mode():
                outputs = model.generate(**tensors, **config["generation"])
            predictions = tokenizer.batch_decode(outputs, skip_special_tokens=True,
                                                  clean_up_tokenization_spaces=False)
            candidates = [candidate(case, pred, engines, i + 1) for i, pred in enumerate(predictions)]
            seen = set()
            for row in candidates:
                digest = row.get("patch_sha256")
                row["duplicate"] = digest is not None and digest in seen
                if digest:
                    seen.add(digest)
            counts["samples_with_render_valid"] += any(r["render_valid"] for r in candidates)
            counts["samples_with_syntax_valid"] += any(r["syntax_valid"] for r in candidates)
            record = dict(sample_id=case["sample_id"], input_sha256=case["input_local_sha256"],
                          input_tokens=len(encoded["input_ids"]), candidates=candidates)
            out.write(json.dumps(record, ensure_ascii=False) + "\n")
            out.flush()
            print("VALID", counts["samples_with_render_valid"], case["sample_id"], flush=True)
    write(args.out / "valid_summary.json", dict(counts, api_calls=0,
          syntax_validity=counts["samples_with_syntax_valid"] / len(valid),
          llm_sfr=None, note="Syntax diagnostics only; no semantic repair success claimed."))
    print("VALID_COMPLETE", dict(counts), flush=True)


if __name__ == "__main__":
    main()
