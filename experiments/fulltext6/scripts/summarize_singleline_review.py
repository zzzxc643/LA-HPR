"""Audit complete Valid review records and report the fixed sample denominator."""
import argparse
from collections import Counter
import json
from pathlib import Path

from local_candidate_judge import parse_reviews
from train_singleline import read, sha, write


def audit(pools, results, requests):
    ids = {p["sample_id"] for p in pools}
    by_id = {r["sample_id"]: r for r in results}
    if len(pools) != len(ids) or len(results) != len(by_id) or by_id.keys() != ids:
        raise ValueError("incomplete_or_duplicate_sample_results")
    counts, usage, sources, candidate_verdicts = Counter(), Counter(), Counter(), Counter()
    request_ids = set()
    maximum_actual_prompt = 0
    for pool in pools:
        result = by_id[pool["sample_id"]]
        if not pool["candidates"]:
            if result["status"] != "no_syntax_valid_candidate" or result["success"] is not False:
                raise ValueError("invalid_empty_pool_result")
            counts["no_syntax_valid_candidate"] += 1
            continue
        if result["status"] != "valid" or type(result["success"]) is not bool:
            raise ValueError("review_is_not_complete")
        rid = result["request_id"]
        if rid in request_ids:
            raise ValueError("duplicate_review_request")
        request_ids.add(rid)
        record = requests[rid]
        if record["status"] != "valid" or not record["complete"]:
            raise ValueError("unfinished_cached_review")
        request_data = json.loads(record["request"]["messages"][1]["content"])
        expected = [dict(cand_id=c["cand_id"], diff=c["diff"]) for c in pool["candidates"]]
        if request_data != dict(original_function=pool["original_function"],
                                vulnerable_line=pool["vulnerable_line"], candidates=expected):
            raise ValueError("request_pool_mismatch")
        envelope = {key: record[key] for key in ("reviews", "selected_cand_id", "selection_reason")}
        checked = parse_reviews(json.dumps(envelope), [r["cand_id"] for r in expected])
        if any(result[k] != checked[k] for k in envelope):
            raise ValueError("result_cache_mismatch")
        for row in checked["reviews"]:
            candidate_verdicts[row["result"]] += 1
        passing = result["selected_cand_id"] is not None
        if passing != result["success"]:
            raise ValueError("success_selection_mismatch")
        counts["reviewed_samples"] += 1
        counts["successful_samples"] += passing
        counts["all_fail_samples"] += all(r["result"] == "FAIL" for r in checked["reviews"])
        counts["uncertain_without_pass_samples"] += not passing and any(
            r["result"] == "UNCERTAIN" for r in checked["reviews"])
        if passing:
            winner = next(r for r in pool["candidates"] if r["cand_id"] == result["selected_cand_id"])
            if winner["patched_code"] != result["final_patch"] or winner["source"] != result["selected_source"]:
                raise ValueError("final_patch_mismatch")
            sources[winner["source"]] += 1
        for attempt in record["attempts"]:
            counts["api_attempts"] += 1
            counts["retries"] += attempt["attempt"] > 1
            if attempt.get("usage"):
                for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
                    usage[key] += attempt["usage"][key]
                maximum_actual_prompt = max(maximum_actual_prompt, attempt["usage"]["prompt_tokens"])
    return dict(n=len(pools), complete=True, **counts, candidate_verdicts=dict(candidate_verdicts),
                selected_sources=dict(sources), usage=dict(usage), maximum_actual_prompt_tokens=maximum_actual_prompt,
                syntax_validity=counts["reviewed_samples"] / len(pools),
                llm_sfr=counts["successful_samples"] / len(pools),
                unresolved_errors=0, metric="Qwen static review pass rate; not execution-proven correctness")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--pools", type=Path, required=True)
    p.add_argument("--review", type=Path, required=True)
    args = p.parse_args()
    config = json.loads((args.review / "config.json").read_text(encoding="utf-8"))
    if config["pools_sha256"] != sha(args.pools):
        raise ValueError("review_input_drift")
    results = json.loads((args.review / "results.json").read_text(encoding="utf-8"))
    requests = {p.stem: json.loads(p.read_text(encoding="utf-8")) for p in (args.review / "requests").glob("*.json")}
    report = audit(read(args.pools), results, requests)
    report.update(model=config["model"], enable_thinking=config["enable_thinking"],
                  pools_sha256=sha(args.pools), results_sha256=sha(args.review / "results.json"))
    write(args.review / "audited_summary.json", report)
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
