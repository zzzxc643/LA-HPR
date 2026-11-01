"""Reference-free pooled review with one shared cache and bounded API concurrency."""
import argparse
from collections import Counter
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
import hashlib
import json
import os
from pathlib import Path
import sys
import threading


ARMS = ("codet5_local", "seed", "original_fulltext", "action_full", "action_local_matched")
GROUPS = ARMS + ("combined",)


def digest(value):
    return hashlib.sha256(value).hexdigest()


def read(path):
    return [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def immutable(path, content):
    path = Path(path)
    if path.exists():
        if path.read_text(encoding="utf-8") != content:
            raise ValueError("frozen_review_input_changed:" + str(path))
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def request_for(pool, settings):
    from local_candidate_judge import SYSTEM_PROMPT
    content = json.dumps(dict(original_function=pool["original_function"],
        vulnerable_line=pool["vulnerable_line"], candidates=[
            dict(cand_id=c["cand_id"], diff=c["diff"]) for c in pool["candidates"]]), ensure_ascii=False)
    request = dict(model=settings["model"], temperature=0, max_tokens=3072,
        response_format={"type": "json_object"}, messages=[
            dict(role="system", content=SYSTEM_PROMPT), dict(role="user", content=content)],
        extra_body={"enable_thinking": False})
    return digest(json.dumps(request, sort_keys=True).encode()), request


def checked_record(path, request):
    from local_candidate_judge import parse_reviews
    record = json.loads(path.read_text(encoding="utf-8"))
    rid = digest(json.dumps(request, sort_keys=True).encode())
    if record["request_id"] != rid or record["request"] != request:
        raise ValueError("request_cache_mismatch")
    if record["status"] == "valid":
        ids = [c["cand_id"] for c in json.loads(request["messages"][1]["content"])["candidates"]]
        checked = parse_reviews(record["attempts"][-1]["raw_response"], ids)
        if not record["complete"] or any(record[k] != checked[k] for k in checked):
            raise ValueError("invalid_cached_response")
    return record


def input_text(case, arm):
    if arm == "original_fulltext":
        from audit_full_context_budget import fulltext_input
        return fulltext_input(case)
    return case["input_full" if arm == "action_full" else "input_local"]


def prepare_pools(cases, generated_root, groups, freeze_sha256=None):
    from prepare_singleline_pools import select_pool
    expected = {c["sample_id"] for c in cases}
    generated, hashes, pending = {}, {}, {}
    needed = set(arm for group in groups for arm in (ARMS[:2] if group == "combined" else (group,)))
    for arm in ARMS:
        if arm not in needed:
            continue
        path = generated_root / arm / "candidates.jsonl"
        if not path.exists():
            pending[arm] = "generation_not_started"
            continue
        try:
            content = path.read_bytes()
            rows = [json.loads(line) for line in content.decode("utf-8").splitlines() if line.strip()]
        except json.JSONDecodeError:
            pending[arm] = "generation_file_in_progress"
            continue
        ids = [r["sample_id"] for r in rows]
        if len(set(ids)) != len(ids) or set(ids) - expected:
            raise ValueError("duplicate_or_unexpected_candidate_samples:" + arm)
        if set(ids) != expected:
            pending[arm] = "generation_incomplete"
            continue
        by_id = {r["sample_id"]: r for r in rows}
        for case in cases:
            row = by_id[case["sample_id"]]
            if freeze_sha256 and row.get("run_freeze_sha256") != freeze_sha256:
                raise ValueError("candidate_freeze_mismatch:" + arm)
            if row["input_sha256"] != digest(input_text(case, arm).encode()):
                raise ValueError("candidate_input_hash_mismatch:" + arm)
            if len(row["candidates"]) > 3:
                raise ValueError("candidate_budget_exceeded:" + arm)
        generated[arm], hashes[arm] = by_id, digest(content)
    pools = {}
    pending_groups = {}
    for group in groups:
        arms = ARMS[:2] if group == "combined" else (group,)
        if any(arm not in generated for arm in arms):
            pending_groups[group] = {arm: pending[arm] for arm in arms if arm not in generated}
            continue
        rows = []
        for case in cases:
            candidates, generation = {}, {}
            for arm in arms:
                record = generated[arm][case["sample_id"]]
                generation[arm] = {k: record[k] for k in (
                    "input_tokens", "generation_error", "input_budget_exceeded") if k in record}
                source = "seed" if arm == "seed" else "codet5"
                candidates[source] = [dict(c, generation_arm=arm) for c in record["candidates"]]
            pool = select_pool(candidates)
            for c in pool["generation_audit"]:
                if c.get("render_valid") and (c.get("patched_code") == case["vulnerable_code"]
                                              or not c.get("diff", "").strip()):
                    raise ValueError("unchanged_candidate_marked_render_valid")
            rows.append(dict(sample_id=case["sample_id"], group=group,
                original_function=case["vulnerable_code"], vulnerable_line=case["edit_start"] + 1,
                generation=generation, **pool))
        pools[group] = rows
    return pools, hashes, pending_groups


def plan(pools, settings, cache):
    from review_singleline_pools import prompt_budget
    requests, results = {}, {}
    for group, rows in pools.items():
        results[group] = []
        for pool in rows:
            result = dict(sample_id=pool["sample_id"], group=group, counts=pool["counts"],
                generation=pool["generation"], selected_cand_id=None, selected_patch=None,
                final_patch=None, selected_diff=None, selected_source=None, selected_arm=None)
            if not pool["candidates"]:
                result.update(status="no_syntax_valid_candidate", success=False)
            else:
                rid, request = request_for(pool, settings)
                bound, method = prompt_budget(request["messages"][1]["content"])
                result.update(request_id=rid, prompt_budget_tokens=bound, prompt_budget_method=method)
                if bound + 3072 > settings["context_limit"]:
                    result.update(status="context_limit_pending", success=None)
                else:
                    result.update(status="pending", success=None)
                    requests.setdefault(rid, (pool, request))
            results[group].append(result)
    records = {}
    for rid, (_, request) in requests.items():
        path = cache / (rid + ".json")
        if path.exists():
            records[rid] = checked_record(path, request)
    return requests, records, results


def execute(requests, records, settings, cache, workers, client):
    from local_candidate_judge import review_batch
    halted = threading.Event()
    fatal_codes = (400, 401, 403, 404, 422)

    def call(item):
        rid, (pool, request) = item
        if halted.is_set():
            return rid, None
        record = review_batch(client, settings["model"], pool["original_function"],
            pool["candidates"], cache, vulnerable_line=pool["vulnerable_line"], enable_thinking=False)
        record = checked_record(cache / (rid + ".json"), request)
        if record["attempts"] and record["attempts"][-1].get("status_code") in fatal_codes:
            halted.set()
        print("REVIEW_REQUEST", rid, record["status"], flush=True)
        return rid, record

    for record in records.values():
        if record["attempts"] and record["attempts"][-1].get("status_code") in fatal_codes:
            halted.set()
    pending = iter((rid, value) for rid, value in requests.items()
                   if rid not in records or not records[rid]["complete"])
    with ThreadPoolExecutor(max_workers=workers) as executor:
        active = {}

        def fill():
            while len(active) < workers and not halted.is_set():
                item = next(pending, None)
                if item is None:
                    break
                future = executor.submit(call, item)
                active[future] = item[0]

        fill()
        while active:
            done, _ = wait(active, return_when=FIRST_COMPLETED)
            for future in done:
                del active[future]
                rid, record = future.result()
                if record is not None:
                    records[rid] = record
            fill()
    return halted.is_set()


def summarize(group, pools, results, records, settings):
    statuses, verdicts, sources, arms = Counter(), Counter(), Counter(), Counter()
    for pool, result in zip(pools, results):
        rid = result.get("request_id")
        if result["status"] == "pending" and rid in records:
            record = records[rid]
            valid = record["status"] == "valid" and record["complete"]
            cid = record["selected_cand_id"] if valid else None
            result.update(status=record["status"], success=(cid is not None) if valid else None,
                selected_cand_id=cid, reviews=record["reviews"], selection_reason=record["selection_reason"],
                request_complete=record["complete"])
            if valid:
                verdicts.update(r["result"] for r in record["reviews"])
            if cid is not None:
                winner = next(c for c in pool["candidates"] if c["cand_id"] == cid)
                result.update(selected_patch=winner["patched_code"], final_patch=winner["patched_code"],
                    selected_diff=winner["diff"], selected_source=winner["source"],
                    selected_arm=winner["generation_arm"], selected_rank=winner["rank"])
                sources[winner["source"]] += 1
                arms[winner["generation_arm"]] += 1
        statuses[result["status"]] += 1
    selected = sum(r["success"] is True for r in results)
    unresolved = sum(r["success"] is None for r in results)
    all_fail = sum(r["status"] == "valid" and all(c["result"] == "FAIL" for c in r["reviews"])
                   for r in results)
    uncertain = sum(r["status"] == "valid" and not r["success"] and any(
        c["result"] == "UNCERTAIN" for c in r["reviews"]) for r in results)
    request_ids = {r["request_id"] for r in results if r.get("request_id") in records}
    usage, attempts = Counter(), 0
    for rid in request_ids:
        for attempt in records[rid]["attempts"]:
            attempts += 1
            if attempt.get("usage"):
                usage.update({k: attempt["usage"].get(k, 0) for k in (
                    "prompt_tokens", "completion_tokens", "total_tokens")})
    errors = Counter(c.get("render_error") for p in pools for c in p["generation_audit"]
                     if c.get("render_error"))
    return dict(group=group, n=len(pools), complete=not unresolved, successful_samples=selected,
        reviewed_samples=statuses["valid"], no_syntax_valid_candidate=statuses["no_syntax_valid_candidate"],
        status_counts=dict(statuses), unresolved_errors=unresolved,
        all_fail_samples=all_fail, uncertain_without_pass_samples=uncertain,
        syntax_validity=sum(bool(p["candidates"]) for p in pools) / len(pools),
        llm_sfr=selected / len(pools) if not unresolved else None,
        static_pass_lower_bound=selected / len(pools), candidate_verdicts=dict(verdicts),
        selected_sources=dict(sources), selected_arms=dict(arms), render_errors=dict(errors),
        input_budget_exceeded=sum(any(v.get("input_budget_exceeded") or
            "budget" in v.get("generation_error", "") for v in p["generation"].values()) for p in pools),
        unique_requests=len(request_ids), planned_requests=sum(bool(p["candidates"]) for p in pools),
        api_attempts=attempts, usage=dict(usage),
        model=settings["model"], reference_opened=False,
        metric="Qwen static review pass rate; not execution-proven repair correctness")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scripts", type=Path, required=True)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--generated-root", type=Path, required=True)
    parser.add_argument("--freeze", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--groups", nargs="+", choices=GROUPS, default=list(GROUPS))
    parser.add_argument("--stage", choices=("all", "pools", "review"), default="all")
    parser.add_argument("--workers", type=int, choices=range(1, 7), default=6)
    args = parser.parse_args()
    sys.path.insert(0, str(args.scripts.resolve()))
    freeze = json.loads(args.freeze.read_text(encoding="utf-8"))
    freeze_hash = digest(args.freeze.read_bytes())
    if digest(args.inputs.read_bytes()) != freeze["inputs"]["sha256"] or freeze["n"] != 141:
        raise ValueError("frozen_inputs_changed")
    for name, expected in freeze["scripts"]["sha256"].items():
        if digest((args.scripts / name).read_bytes()) != expected:
            raise ValueError("frozen_script_changed:" + name)
    if "review.py" in freeze.get("runtime_sha256", {}) and (
            digest(Path(__file__).read_bytes()) != freeze["runtime_sha256"]["review.py"]):
        raise ValueError("frozen_review_runtime_changed")
    settings = freeze["settings"]["judge"]
    if (settings["model"] != "qwen3.8-max-0902" or settings["enable_thinking"] is not False
            or settings["max_output_tokens"] != 3072):
        raise ValueError("judge_must_match_frozen_protocol")
    cases = read(args.inputs)
    if len(cases) != 141 or len({c["sample_id"] for c in cases}) != 141:
        raise ValueError("expected_141_unique_inputs")
    forbidden = {"target", "action", "fixed_code", "commit_message", "cve_desc"}
    if any(forbidden & c.keys() for c in cases):
        raise ValueError("reference_fields_in_inputs")
    pools, hashes, pending = prepare_pools(cases, args.generated_root, args.groups, freeze_hash)
    args.out.mkdir(parents=True, exist_ok=True)
    for group, rows in pools.items():
        folder = args.out / group
        immutable(folder / "pools.jsonl", "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows))
        config = dict(group=group, n=141, inputs_sha256=digest(args.inputs.read_bytes()),
            freeze_sha256=digest(args.freeze.read_bytes()), settings=settings,
            candidates_sha256={arm: hashes[arm] for arm in (ARMS[:2] if group == "combined" else (group,))},
            reference_opened=False)
        immutable(folder / "config.json", json.dumps(config, ensure_ascii=False, indent=2) + "\n")
    cache = args.out / "requests"
    cache.mkdir(exist_ok=True)
    requests, records, results = plan(pools, settings, cache)
    stopped = False
    if args.stage != "pools" and any(rid not in records or not records[rid]["complete"] for rid in requests):
        from openai import OpenAI
        key = os.environ.get("QWEN_API_KEY")
        if not key:
            raise ValueError("missing_qwen_api_key")
        client = OpenAI(api_key=key, base_url=settings["base_url"], timeout=90, max_retries=0)
        stopped = execute(requests, records, settings, cache, args.workers, client)
    summaries = {}
    for group, rows in pools.items():
        summary = summarize(group, rows, results[group], records, settings)
        folder = args.out / group
        write(folder / "results.json", results[group])
        summary.update(pools_sha256=digest((folder / "pools.jsonl").read_bytes()),
            results_sha256=digest((folder / "results.json").read_bytes()))
        write(folder / "audited_summary.json", summary)
        summaries[group] = summary
    status = dict(requested_groups=args.groups, ready_groups=list(pools), pending_groups=pending,
        planned_unique_requests=len(requests), valid_cached_requests=sum(
            r["status"] == "valid" for r in records.values()), halted_configuration_error=stopped,
        all_requested_complete=not pending and all(s["complete"] for s in summaries.values()),
        groups=summaries, reference_opened=False)
    write(args.out / "status.json", status)
    print("REVIEW_STATUS", json.dumps({k: v for k, v in status.items() if k != "groups"}), flush=True)
    if stopped:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
