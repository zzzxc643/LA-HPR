"""Review six full-function candidates with the historical five-item pool policy."""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import sys


ARM = "original_fulltext"
GROUP = "fulltext6"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_rows(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def select_pool(candidates):
    if len(candidates) > 6:
        raise ValueError("raw_candidate_budget")
    if [item["rank"] for item in candidates] != list(range(1, len(candidates) + 1)):
        raise ValueError("candidate_rank_order")
    seen, eligible, audit = set(), [], []
    for item in candidates:
        row = dict(item, source="codet5", generation_arm=ARM, cand_id=len(audit) + 1, exclusion=None)
        if not row["render_valid"]:
            row["exclusion"] = "render_invalid"
        else:
            code = row["patched_code"]
            row["exclusion"] = "duplicate" if code in seen else None
            seen.add(code)
            if row["exclusion"] is None and not row["syntax_valid"]:
                row["exclusion"] = "syntax_invalid"
        if row["exclusion"] is None:
            eligible.append(row)
        audit.append(row)
    selected = eligible[:5]
    counts = dict(raw_by_source={"codet5": len(candidates)}, generated=len(audit),
        unique_render_valid=len(seen), syntax_eligible=len(eligible), submitted=len(selected),
        not_submitted_due_to_budget=[row["cand_id"] for row in eligible[5:]],
        exclusions=dict(Counter(row["exclusion"] for row in audit if row["exclusion"])))
    return dict(candidates=selected, generation_audit=audit, counts=counts)


def build_pools(cases, generated, freeze_sha, fulltext_input, fulltext_candidate, engines):
    ids = [row["sample_id"] for row in generated]
    expected = {case["sample_id"] for case in cases}
    if len(expected) != len(cases) or len(ids) != len(cases) or len(set(ids)) != len(ids) or set(ids) != expected:
        raise ValueError("fulltext6_generation_incomplete_or_duplicate")
    by_id = {row["sample_id"]: row for row in generated}
    pools = []
    for case in cases:
        record = by_id[case["sample_id"]]
        if (record["arm"] != ARM or record["run_freeze_sha256"] != freeze_sha
                or record["input_sha256"] != hashlib.sha256(fulltext_input(case).encode()).hexdigest()):
            raise ValueError("candidate_generation_provenance_mismatch")
        over_budget = record["status"] == "input_budget_exceeded"
        if (record["status"] not in ("generated", "input_budget_exceeded")
                or record["input_budget_exceeded"] != over_budget
                or (record["input_tokens"] > 4096) != over_budget
                or len(record["candidates"]) != (0 if over_budget else 6)):
            raise ValueError("candidate_generation_status_or_count")
        candidates = []
        seen = set()
        for saved in record["candidates"]:
            rebuilt = fulltext_candidate(case, saved["raw_prediction"], engines, saved["rank"])
            for key in ("prediction", "format_normalization", "render_valid", "syntax_valid",
                        "patched_code", "patch_sha256", "diff", "render_error"):
                if rebuilt.get(key) != saved.get(key):
                    raise ValueError("fulltext_candidate_rebuild_mismatch:" + key)
            patch_hash = rebuilt.get("patch_sha256")
            if saved["duplicate"] != (patch_hash is not None and patch_hash in seen):
                raise ValueError("candidate_duplicate_flag_mismatch")
            if patch_hash:
                seen.add(patch_hash)
            rebuilt.update(output_tokens=saved["output_tokens"], output_truncated=saved["output_truncated"],
                duplicate=saved["duplicate"])
            candidates.append(rebuilt)
        pool = select_pool(candidates)
        pools.append(dict(sample_id=case["sample_id"], group=GROUP,
            original_function=case["vulnerable_code"], vulnerable_line=case["edit_start"] + 1,
            cwe=case["cwe"], generation={ARM: {
                key: record[key] for key in ("input_tokens", "input_budget_exceeded", "status")}}, **pool))
    return {GROUP: pools}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--cohort", choices=("valid69", "prime57", "mega141"), required=True)
    parser.add_argument("--stage", choices=("pools", "pooled"), default="pooled")
    args = parser.parse_args()
    run = args.run.resolve()
    folder = run / args.cohort
    protocol = json.loads((run / "PROTOCOL.json").read_text(encoding="utf-8"))
    frozen = json.loads((folder / "freeze.json").read_text(encoding="utf-8"))
    freeze_sha = sha(folder / "freeze.json")
    if freeze_sha != protocol["cohorts"][args.cohort]["freeze_sha256"]:
        raise ValueError("cohort_freeze_changed")
    for name, digest in protocol["runtime_sha256"].items():
        if sha(run / "runtime" / name) != digest:
            raise ValueError("runtime_changed:" + name)
    for name, digest in frozen["runtime_sha256"].items():
        if sha(run / "runtime" / name) != digest:
            raise ValueError("frozen_runtime_changed:" + name)
    for name, digest in frozen["scripts"]["sha256"].items():
        if sha(run / "scripts" / name) != digest:
            raise ValueError("frozen_module_changed:" + name)
    if set(frozen["arms"]) != {ARM}:
        raise ValueError("unexpected_experiment_arms")
    arm = frozen["arms"][ARM]
    if (arm["model_kind"] != "seq2seq" or arm["input_mode"] != "fulltext"
            or arm["max_input_tokens"] != 4096 or arm["max_new_tokens"] != 4096
            or arm["generation"] != dict(num_beams=6, num_return_sequences=6, do_sample=False)):
        raise ValueError("fulltext6_protocol_drift")
    sys.path.insert(0, str(run / "scripts"))
    import legacy_review as review
    from audit_full_context_budget import fulltext_input
    from full_context_baselines import fulltext_candidate
    from train_singleline import parsers
    inputs_path = folder / frozen["inputs"]["path"]
    if inputs_path.resolve() != (folder / "inputs_pool.jsonl").resolve():
        raise ValueError("unexpected_inputs_path")
    cases = read_rows(inputs_path)
    if (sha(inputs_path) != frozen["inputs"]["sha256"]
            or frozen["n"] != {"valid69": 69, "prime57": 57, "mega141": 141}[args.cohort]
            or len(cases) != frozen["n"]):
        raise ValueError("frozen_inputs_changed")
    generated_path = folder / ARM / "candidates.jsonl"
    pools = build_pools(cases, read_rows(generated_path), freeze_sha,
                        fulltext_input, fulltext_candidate, parsers())
    out = folder / "review"
    review.immutable(out / GROUP / "pools.jsonl", "".join(
        json.dumps(row, ensure_ascii=False) + "\n" for row in pools[GROUP]))
    review.write(out / "GENERATION_BINDING.json", dict(
        candidates_sha256=sha(generated_path), freeze_sha256=freeze_sha,
        fulltext_rebuild_verified=True, references_opened=False))
    settings = protocol["judge"]
    cache = run / "pooled_requests"
    cache.mkdir(exist_ok=True)
    requests, records, results = review.plan(pools, settings, cache)
    halted = False
    if args.stage == "pooled":
        key = os.environ.get("QWEN_API_KEY")
        if not key:
            raise ValueError("missing_qwen_api_key")
        from openai import OpenAI
        client = OpenAI(api_key=key, base_url=settings["base_url"], timeout=90, max_retries=0)
        halted = review.execute(requests, records, settings, cache, protocol["max_workers"], client)
    summary = review.summarize(GROUP, pools[GROUP], results[GROUP], records, settings)
    review.write(out / GROUP / "results.json", results[GROUP])
    review.write(out / GROUP / "summary.json", summary)
    review.write(out / "POOLED_STATUS.json", dict(complete=summary["complete"], groups={GROUP: summary},
        halted_configuration_error=halted, old_response_cache_used=False))
    if args.stage == "pooled" and (halted or not summary["complete"]):
        raise RuntimeError("pooled_review_incomplete")
    print("REVIEW_FINISHED", args.cohort, args.stage, flush=True)


if __name__ == "__main__":
    main()
