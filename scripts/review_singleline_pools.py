"""Review preselected Valid pools once per sample; persist all API outcomes."""
import argparse
from collections import Counter
import json
import os
from pathlib import Path

from local_candidate_judge import review_batch, SYSTEM_PROMPT
from train_singleline import read, sha, write


def prompt_budget(content, tokenizer=None):
    messages = [dict(role="system", content=SYSTEM_PROMPT), dict(role="user", content=content)]
    if tokenizer is not None:
        tokens = tokenizer.apply_chat_template(messages, tokenize=True, add_generation_prompt=True)
        return len(tokens), "model_tokenizer"
    # Byte-level BPE cannot emit more tokens than UTF-8 bytes, before chat framing.
    # Reserve another 4096 tokens for the two-message template and special tokens.
    return sum(len(m["content"].encode("utf-8")) for m in messages) + 4096, "utf8_byte_upper_bound_plus_4096"


def main():
    from openai import OpenAI
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--pools", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--model", required=True)
    p.add_argument("--base-url", required=True)
    p.add_argument("--api-key-env", default="QWEN_API_KEY")
    budget = p.add_mutually_exclusive_group(required=True)
    budget.add_argument("--tokenizer", help="Tokenizer matching the chosen Qwen API model")
    budget.add_argument("--utf8-byte-bound", action="store_true",
                        help="Conservative byte-level BPE bound when the API tokenizer is unpublished")
    p.add_argument("--context-limit", type=int, required=True, help="Verified API model context limit")
    p.add_argument("--disable-thinking", action="store_true", help="Explicit Qwen non-thinking mode")
    args = p.parse_args()
    key = os.environ.get(args.api_key_env)
    if not key:
        raise ValueError("missing_api_key")
    pools = read(args.pools)
    if len(pools) != 69 or len({r["sample_id"] for r in pools}) != 69:
        raise ValueError("incomplete_valid_pools")
    if args.tokenizer:
        from transformers import AutoTokenizer
        tokenizer = AutoTokenizer.from_pretrained(args.tokenizer, local_files_only=True)
    else:
        tokenizer = None
    config = dict(model=args.model, base_url=args.base_url, pools_sha256=sha(args.pools),
                  tokenizer=args.tokenizer, context_limit=args.context_limit,
                  budget_method="utf8_byte_upper_bound_plus_4096" if args.utf8_byte_bound else "model_tokenizer",
                  enable_thinking=False if args.disable_thinking else None,
                  max_output_tokens=3072, script_sha256=sha(Path(__file__)),
                  judge_module_sha256=sha(Path(__file__).with_name("local_candidate_judge.py")))
    args.out.mkdir(parents=True, exist_ok=True)
    config_path = args.out / "config.json"
    if config_path.exists():
        if json.loads(config_path.read_text(encoding="utf-8")) != config:
            raise ValueError("review_configuration_drift")
    else:
        write(config_path, config)
    client = OpenAI(api_key=key, base_url=args.base_url, timeout=90, max_retries=0)
    rows, counts = [], Counter(n=len(pools))
    for pool in pools:
        selected = pool["candidates"]
        result = dict(sample_id=pool["sample_id"], selected_cand_id=None, counts=pool["counts"])
        if not selected:
            result.update(status="no_syntax_valid_candidate", success=False)
        else:
            candidates = [{"cand_id": r["cand_id"], "diff": r["diff"]} for r in selected]
            content = json.dumps(dict(original_function=pool["original_function"],
                vulnerable_line=pool["vulnerable_line"], candidates=candidates), ensure_ascii=False)
            budget_tokens, method = prompt_budget(content, tokenizer)
            result["prompt_budget_tokens"] = budget_tokens
            result["prompt_budget_method"] = method
            if budget_tokens + 3072 > args.context_limit:
                result.update(status="context_limit_pending", success=None)
            else:
                options = dict(enable_thinking=False) if args.disable_thinking else {}
                reviewed = review_batch(client, args.model, pool["original_function"], candidates,
                                        args.out / "requests", vulnerable_line=pool["vulnerable_line"], **options)
                valid = reviewed["status"] == "valid"
                cid = reviewed["selected_cand_id"] if valid else None
                result.update(status=reviewed["status"], success=(cid is not None) if valid else None,
                              selected_cand_id=cid, request_id=reviewed["request_id"],
                              reviews=reviewed["reviews"], selection_reason=reviewed["selection_reason"])
                result["actual_prompt_tokens"] = next((a.get("usage", {}).get("prompt_tokens")
                    for a in reversed(reviewed["attempts"]) if a.get("usage")), None)
                if valid:
                    for review in reviewed["reviews"]:
                        counts["candidate_" + review["result"].lower()] += 1
                if cid is not None:
                    winner = next(r for r in selected if r["cand_id"] == cid)
                    result.update(selected_source=winner["source"], final_patch=winner["patched_code"])
                if reviewed["attempts"] and reviewed["attempts"][-1].get("status_code") in (400, 401, 403, 404, 422):
                    rows.append(result)
                    write(args.out / "results.json", rows)
                    raise RuntimeError("review_configuration_error; inspect cached status_code")
        rows.append(result)
        write(args.out / "results.json", rows)
        counts[result["status"]] += 1
        print("REVIEW", result["sample_id"], result["status"], flush=True)
    complete = all(r["success"] is not None for r in rows)
    counts["successful_samples"] = sum(r["success"] is True for r in rows)
    write(args.out / "summary.json", dict(counts, complete=complete,
          llm_sfr=counts["successful_samples"] / len(pools) if complete else None,
          syntax_validity=sum(bool(p["candidates"]) for p in pools) / len(pools),
          scope="Valid-SingleLine only; static Qwen review, not tested repair correctness"))


if __name__ == "__main__":
    main()
