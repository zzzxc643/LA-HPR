"""Generate new evaluation candidates with frozen existing models and no references."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import time


ARMS = ("seed",)
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
    if len(cases) != config["n"] or len({c["sample_id"] for c in cases}) != config["n"]:
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
    settings = config["arms"][arm]
    mode = {"codet5_local": "local", "seed": "local", "original_fulltext": "fulltext",
            "action_full": "full", "action_local_matched": "local"}[arm]
    output_limit = 256 if arm == "seed" else 4096 if arm == "original_fulltext" else 128
    input_limit = 4096 if arm in ("original_fulltext", "action_full", "seed") else 1024
    if (settings["input_mode"] != mode or settings["max_input_tokens"] != input_limit
            or settings["max_new_tokens"] != output_limit
            or settings["generation"] != dict(num_beams=6, num_return_sequences=6, do_sample=False)
            or settings["model_kind"] != ("causal" if arm == "seed" else "seq2seq")):
        raise ValueError("arm_parameter_drift:" + arm)
    if not settings["checkpoint_files_sha256"]:
        raise ValueError("missing_model_hashes")
    return settings


def input_text(case, settings):
    if settings["input_mode"] == "fulltext":
        from audit_full_context_budget import fulltext_input
        return fulltext_input(case)
    return case["input_full" if settings["input_mode"] == "full" else "input_local"]


def resume_rows(folder, cases, settings, arm, freeze_sha):
    path = folder / "candidates.jsonl"
    rows = read_rows(path) if path.exists() else []
    if len(rows) > len(cases):
        raise ValueError("too_many_saved_samples")
    for case, row in zip(cases, rows):
        text_hash = hashlib.sha256(input_text(case, settings).encode()).hexdigest()
        if (row["sample_id"] != case["sample_id"] or row["input_sha256"] != text_hash
                or row["arm"] != arm or row["run_freeze_sha256"] != freeze_sha
                or row["status"] not in ("generated", "input_budget_exceeded")):
            raise ValueError("resume_prefix_or_provenance_mismatch")
    return rows


def summarize(folder, rows, total, arm, freeze_sha, peak_memory=None):
    counts = Counter()
    candidate_errors = Counter()
    for row in rows:
        counts[row["status"]] += 1
        candidates = row["candidates"]
        counts["generated_candidates"] += len(candidates)
        counts["samples_with_render_valid"] += any(c["render_valid"] for c in candidates)
        counts["samples_with_syntax_valid"] += any(c["syntax_valid"] for c in candidates)
        for candidate in candidates:
            counts["render_valid_candidates"] += candidate["render_valid"]
            counts["syntax_valid_candidates"] += candidate["syntax_valid"]
            counts["output_truncated_candidates"] += candidate["output_truncated"]
            counts["duplicate_candidates"] += candidate["duplicate"]
            counts["empty_raw_outputs"] += not candidate["raw_prediction"].strip()
            if not candidate["render_valid"]:
                error = candidate.get("render_error", "unknown")
                candidate_errors[error] += 1
                counts["noop_rejections"] += error in ("unchanged_edit", "empty_or_unchanged_function")
                counts["empty_replacement_rejections"] += error == "empty_replacement"
                counts["format_or_render_invalid_candidates"] += 1
    report = dict(arm=arm, n=total, registered=len(rows), complete=len(rows) == total,
                  counts=dict(counts), render_errors=dict(candidate_errors),
                  inference_seconds=sum(r["inference_seconds"] for r in rows),
                  run_freeze_sha256=freeze_sha, references_opened=False,
                  updated_utc=datetime.now(timezone.utc).isoformat(),
                  metric_scope="generation/format/parse only; no vulnerability-removal claim")
    if peak_memory is not None:
        report["peak_allocated_gib"] = peak_memory
    write(folder / "summary.json", report)


def generate(root, out, arm):
    config, cases, freeze_sha = checked_inputs(root, out)
    settings = validate_arm(config, arm)
    folder = out / arm
    folder.mkdir(parents=True, exist_ok=True)
    # Exclusive arm lock prevents concurrent resumptions from generating a sample twice.
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
        for name, digest in settings["checkpoint_files_sha256"].items():
            if sha(model_path / name) != digest:
                raise ValueError("model_file_drift:" + name)
        import torch
        from transformers import AutoModelForCausalLM, AutoModelForSeq2SeqLM, AutoTokenizer, set_seed
        from full_context_baselines import fulltext_candidate
        from normalize_singleline_candidates import unwrap
        from train_singleline import candidate, parsers
        torch.set_num_threads(4)
        set_seed(config["seed"])
        tokenizer_path = root / settings.get("tokenizer_path", settings["model_path"])
        tokenizer = AutoTokenizer.from_pretrained(tokenizer_path, local_files_only=True)
        if arm == "seed":
            model = AutoModelForCausalLM.from_pretrained(model_path, local_files_only=True,
                torch_dtype=torch.bfloat16, attn_implementation="sdpa").cuda().eval()
        else:
            model = AutoModelForSeq2SeqLM.from_pretrained(model_path, local_files_only=True,
                torch_dtype=torch.float32).cuda().eval()
        engines = parsers()
        with (folder / "candidates.jsonl").open("a", encoding="utf-8") as stream:
            for case in cases[len(rows):]:
                text = input_text(case, settings)
                if arm == "seed":
                    encoded = tokenizer.apply_chat_template([dict(role="user", content=text)],
                        tokenize=True, add_generation_prompt=True, return_tensors="pt", return_dict=True)
                    n = encoded["input_ids"].shape[1]
                    over_budget = n + settings["max_new_tokens"] > settings["max_input_tokens"]
                else:
                    encoded = tokenizer(text, truncation=False)
                    n = len(encoded["input_ids"])
                    over_budget = n > settings["max_input_tokens"]
                record = dict(sample_id=case["sample_id"], arm=arm, run_freeze_sha256=freeze_sha,
                    input_sha256=hashlib.sha256(text.encode()).hexdigest(), input_tokens=n,
                    input_budget_exceeded=over_budget, inference_seconds=0.0, candidates=[],
                    status="input_budget_exceeded" if over_budget else "generated")
                if not over_budget:
                    tensors = ({k: v.to("cuda") for k, v in encoded.items() if k != "token_type_ids"}
                               if arm == "seed" else
                               {k: torch.tensor([v], device="cuda") for k, v in encoded.items()})
                    options = dict(settings["generation"], max_new_tokens=settings["max_new_tokens"])
                    if arm == "seed":
                        options["pad_token_id"] = (tokenizer.pad_token_id if tokenizer.pad_token_id is not None
                                                   else tokenizer.eos_token_id)
                    torch.cuda.synchronize()
                    started = time.perf_counter()
                    with torch.inference_mode():
                        outputs = model.generate(**tensors, **options)
                    torch.cuda.synchronize()
                    record["inference_seconds"] = time.perf_counter() - started
                    generated = outputs[:, n:] if arm == "seed" else outputs
                    predictions = tokenizer.batch_decode(generated, skip_special_tokens=True,
                                                         clean_up_tokenization_spaces=False)
                    eos = model.generation_config.eos_token_id
                    eos = eos if isinstance(eos, list) else [eos]
                    seen = set()
                    for rank, (raw, tokens) in enumerate(zip(predictions, generated), 1):
                        if arm == "original_fulltext":
                            item = fulltext_candidate(case, raw, engines, rank)
                        else:
                            normalized, policy = unwrap(raw)
                            item = candidate(case, normalized, engines, rank)
                            item.update(raw_prediction=raw, format_normalization=policy)
                        item["source"] = "seed" if arm == "seed" else "codet5"
                        output_tokens = tokens if arm == "seed" else tokens[1:]
                        item["output_truncated"] = (len(output_tokens) >= settings["max_new_tokens"]
                                                     and not any(int(t) in eos for t in output_tokens))
                        item["output_tokens"] = len(output_tokens)
                        digest = item.get("patch_sha256")
                        item["duplicate"] = digest is not None and digest in seen
                        if digest:
                            seen.add(digest)
                        record["candidates"].append(item)
                    if len(record["candidates"]) != settings["generation"]["num_return_sequences"]:
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
