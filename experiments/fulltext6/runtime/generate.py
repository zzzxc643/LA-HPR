"""Generate six full-function candidates from a frozen existing checkpoint."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import time


ARMS = ("original_fulltext",)
DEPENDENCIES = ("full_context_baselines.py", "audit_full_context_budget.py", "train_singleline.py",
                "singleline_repair.py", "normalize_singleline_candidates.py", "prepare_singleline_pools.py",
                "run_formal_singleline.py", "review_singleline_pools.py", "local_candidate_judge.py",
                "summarize_singleline_review.py")


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_rows(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def checked_inputs(root, out):
    freeze_path = out / "freeze.json"
    config = json.loads(freeze_path.read_text(encoding="utf-8"))
    if config["runtime_sha256"]["generate.py"] != sha(Path(__file__)):
        raise ValueError("generation_runtime_drift")
    if config["seed"] != 42 or config["n"] not in (69, 57, 141) or set(config["arms"]) != set(ARMS):
        raise ValueError("unexpected_frozen_protocol")
    inputs = out / config["inputs"]["path"]
    if inputs.resolve() != (out / "inputs_pool.jsonl").resolve():
        raise ValueError("unexpected_input_path")
    if sha(inputs) != config["inputs"]["sha256"]:
        raise ValueError("input_file_drift")
    module_dir = root / config["scripts"]["path"]
    if not set(DEPENDENCIES) <= set(config["scripts"]["sha256"]):
        raise ValueError("missing_dependency_hashes")
    for name, digest in config["scripts"]["sha256"].items():
        if sha(module_dir / name) != digest:
            raise ValueError("frozen_module_drift:" + name)
    sys.path.insert(0, str(module_dir))
    from singleline_repair import model_input
    cases = read_rows(inputs)
    if len(cases) != config["n"] or len({case["sample_id"] for case in cases}) != config["n"]:
        raise ValueError("expected_unique_frozen_inputs")
    allowed = {"sample_id", "split", "cwe", "vulnerable_code", "edit_start", "edit_end",
               "context_start", "context_end", "input_local", "input_full",
               "input_local_sha256", "input_full_sha256", "project", "source_file"}
    for case in cases:
        if set(case) - allowed or case["edit_end"] != case["edit_start"] + 1:
            raise ValueError("invalid_or_reference_bearing_input")
        for full, field in ((False, "input_local"), (True, "input_full")):
            value, _, _ = model_input(case["vulnerable_code"], case["edit_start"], case["cwe"], full=full)
            if value != case[field] or hashlib.sha256(value.encode()).hexdigest() != case[field + "_sha256"]:
                raise ValueError("input_prompt_or_hash_mismatch")
    return config, cases, sha(freeze_path)


def validate_arm(config, arm):
    if arm not in ARMS:
        raise ValueError("unexpected_arm")
    settings = config["arms"][arm]
    if (settings["input_mode"] != "fulltext" or settings["max_input_tokens"] != 4096
            or settings["max_new_tokens"] != 4096
            or settings["generation"] != dict(num_beams=6, num_return_sequences=6, do_sample=False)
            or settings["model_kind"] != "seq2seq"):
        raise ValueError("arm_parameter_drift:" + arm)
    if not settings["checkpoint_files_sha256"]:
        raise ValueError("missing_model_hashes")
    if settings.get("tokenizer_path", settings["model_path"]) != settings["model_path"] and not settings.get("tokenizer_files_sha256"):
        raise ValueError("missing_separate_tokenizer_hashes")
    return settings


def input_text(case, settings):
    from audit_full_context_budget import fulltext_input
    return fulltext_input(case)


def resume_rows(folder, cases, settings, arm, freeze_sha):
    path = folder / "candidates.jsonl"
    rows = read_rows(path) if path.exists() else []
    if len(rows) > len(cases):
        raise ValueError("too_many_saved_samples")
    for case, row in zip(cases, rows):
        text_hash = hashlib.sha256(input_text(case, settings).encode()).hexdigest()
        if (row["sample_id"] != case["sample_id"] or row["input_sha256"] != text_hash
                or row["arm"] != arm or row["run_freeze_sha256"] != freeze_sha
                or row["status"] not in ("generated", "input_budget_exceeded")
                or len(row["candidates"]) != (6 if row["status"] == "generated" else 0)):
            raise ValueError("resume_prefix_or_provenance_mismatch")
    return rows


def decoded_length(token_ids, eos_ids, maximum):
    """Count decoder tokens after its start token, excluding batch padding."""
    ids = [int(token) for token in token_ids][1:]
    for index, token in enumerate(ids):
        if token in eos_ids:
            return index + 1, False
    return len(ids), len(ids) >= maximum


def summarize(folder, rows, total, arm, freeze_sha, peak_memory=None):
    counts, candidate_errors = Counter(), Counter()
    for row in rows:
        counts[row["status"]] += 1
        counts["input_tokens"] += row["input_tokens"]
        candidates = row["candidates"]
        counts["generated_candidates"] += len(candidates)
        counts["samples_with_render_valid"] += any(item["render_valid"] for item in candidates)
        counts["samples_with_syntax_valid"] += any(item["syntax_valid"] for item in candidates)
        for item in candidates:
            for name in ("render_valid", "syntax_valid", "output_truncated", "duplicate"):
                counts[name + "_candidates"] += item[name]
            counts["output_tokens"] += item["output_tokens"]
            counts["empty_raw_outputs"] += not item["raw_prediction"].strip()
            if not item["render_valid"]:
                candidate_errors[item.get("render_error", "unknown")] += 1
    report = dict(arm=arm, n=total, registered=len(rows), complete=len(rows) == total,
                  counts=dict(counts), render_errors=dict(candidate_errors),
                  inference_seconds=sum(row["inference_seconds"] for row in rows),
                  run_freeze_sha256=freeze_sha, references_opened=False,
                  updated_utc=datetime.now(timezone.utc).isoformat(),
                  metric_scope="generation/format/parse only; no vulnerability-removal claim",
                  token_accounting="Input once per case; returned decoder sequences through first EOS, including EOS; beam-search internal tokens excluded")
    if peak_memory is not None:
        report["peak_allocated_gib"] = peak_memory
    write(folder / "summary.json", report)


def generate(root, out, arm):
    config, cases, freeze_sha = checked_inputs(root, out)
    settings = validate_arm(config, arm)
    folder = out / arm
    folder.mkdir(parents=True, exist_ok=True)
    lock = folder / "generation.lock"
    with lock.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(dict(started_utc=datetime.now(timezone.utc).isoformat())))
    rows = []
    try:
        rows = resume_rows(folder, cases, settings, arm, freeze_sha)
        if len(rows) == len(cases):
            summarize(folder, rows, len(cases), arm, freeze_sha)
            print("ALREADY_COMPLETE", arm, len(rows), flush=True)
            return
        model_path = root / settings["model_path"]
        tokenizer_path = root / settings.get("tokenizer_path", settings["model_path"])
        for base, hashes in ((model_path, settings["checkpoint_files_sha256"]),
                             (tokenizer_path, settings.get("tokenizer_files_sha256", {}))):
            for name, digest in hashes.items():
                if sha(base / name) != digest:
                    raise ValueError("model_or_tokenizer_file_drift:" + name)
        import torch
        from transformers import AutoModelForSeq2SeqLM, AutoTokenizer, set_seed
        from full_context_baselines import fulltext_candidate
        from train_singleline import parsers
        torch.set_num_threads(4)
        set_seed(config["seed"])
        tokenizer = AutoTokenizer.from_pretrained(tokenizer_path, local_files_only=True)
        model = AutoModelForSeq2SeqLM.from_pretrained(model_path, local_files_only=True,
            torch_dtype=torch.float32).cuda().eval()
        engines = parsers()
        with (folder / "candidates.jsonl").open("a", encoding="utf-8") as stream:
            for case in cases[len(rows):]:
                text = input_text(case, settings)
                encoded = tokenizer(text, truncation=False)
                n = len(encoded["input_ids"])
                over_budget = n > settings["max_input_tokens"]
                record = dict(sample_id=case["sample_id"], arm=arm, run_freeze_sha256=freeze_sha,
                    input_sha256=hashlib.sha256(text.encode()).hexdigest(), input_tokens=n,
                    input_budget_exceeded=over_budget, inference_seconds=0.0, candidates=[],
                    status="input_budget_exceeded" if over_budget else "generated")
                if not over_budget:
                    tensors = {key: torch.tensor([value], device="cuda") for key, value in encoded.items()}
                    options = dict(settings["generation"], max_new_tokens=settings["max_new_tokens"])
                    torch.cuda.synchronize()
                    started = time.perf_counter()
                    with torch.inference_mode():
                        outputs = model.generate(**tensors, **options)
                    torch.cuda.synchronize()
                    record["inference_seconds"] = time.perf_counter() - started
                    predictions = tokenizer.batch_decode(outputs, skip_special_tokens=True,
                                                         clean_up_tokenization_spaces=False)
                    eos = model.generation_config.eos_token_id
                    eos = eos if isinstance(eos, list) else [eos]
                    seen = set()
                    for rank, (raw, tokens) in enumerate(zip(predictions, outputs), 1):
                        item = fulltext_candidate(case, raw, engines, rank)
                        item["generation_arm"] = arm
                        item["output_tokens"], item["output_truncated"] = decoded_length(
                            tokens.tolist(), eos, settings["max_new_tokens"])
                        digest = item.get("patch_sha256")
                        item["duplicate"] = digest is not None and digest in seen
                        if digest:
                            seen.add(digest)
                        record["candidates"].append(item)
                    if len(record["candidates"]) != 6:
                        raise ValueError("incomplete_generation_output")
                stream.write(json.dumps(record, ensure_ascii=False) + "\n")
                stream.flush()
                rows.append(record)
                summarize(folder, rows, len(cases), arm, freeze_sha,
                          torch.cuda.max_memory_allocated() / 1024**3)
                print("GENERATED", arm, len(rows), len(cases), case["sample_id"], record["status"], flush=True)
    except BaseException as exc:
        write(folder / "runtime_error.json", dict(arm=arm, error=type(exc).__name__,
            registered=len(rows), next_sample_id=cases[len(rows)]["sample_id"] if len(rows) < len(cases) else None,
            runtime_failure=True, counted_as_model_failure=False, run_freeze_sha256=freeze_sha,
            updated_utc=datetime.now(timezone.utc).isoformat()))
        raise
    finally:
        lock.unlink()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--arm", choices=ARMS, required=True)
    args = parser.parse_args()
    generate(args.root.resolve(), args.out.resolve(), args.arm)
