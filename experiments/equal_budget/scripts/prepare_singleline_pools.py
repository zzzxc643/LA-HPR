"""Exact deduplication, strict syntax filtering and fixed source rotation."""
import argparse
from collections import Counter
import json
from pathlib import Path

from train_singleline import read, sha, write


SOURCES = ("codet5", "seed", "rules")


def select_pool(generated):
    if set(generated) - set(SOURCES):
        raise ValueError("unknown_source")
    seen, eligible, rows = set(), {s: [] for s in SOURCES}, []
    for source in SOURCES:
        candidates = generated.get(source, [])
        if len(candidates) > 3:
            raise ValueError("source_budget_exceeded")
        for candidate in candidates:
            row = dict(candidate, source=source, cand_id=len(rows) + 1)
            row["exclusion"] = None
            if not row["render_valid"]:
                row["exclusion"] = "render_invalid"
            else:
                code = row["patched_code"]
                row["exclusion"] = "duplicate" if code in seen else None
                seen.add(code)
                if row["exclusion"] is None and not row["syntax_valid"]:
                    row["exclusion"] = "syntax_invalid"
            if row["exclusion"] is None:
                eligible[source].append(row)
            rows.append(row)
    selected = []
    for rank in range(3):
        for source in SOURCES:
            if rank < len(eligible[source]) and len(selected) < 5:
                selected.append(eligible[source][rank])
    selected_ids = {r["cand_id"] for r in selected}
    omitted = [r["cand_id"] for r in rows if r["exclusion"] is None and r["cand_id"] not in selected_ids]
    counts = dict(raw_by_source={s: len(generated.get(s, [])) for s in SOURCES},
                  generated=len(rows), unique_render_valid=len(seen),
                  syntax_eligible=sum(len(v) for v in eligible.values()),
                  submitted=len(selected), not_submitted_due_to_budget=omitted,
                  exclusions=dict(Counter(r["exclusion"] for r in rows if r["exclusion"])))
    return dict(candidates=selected, generation_audit=rows, counts=counts)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--data", type=Path, required=True)
    p.add_argument("--codet5", type=Path, required=True)
    p.add_argument("--seed", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    path = args.data / "inputs_valid.jsonl"
    manifest = json.loads((args.data / "manifest.json").read_text(encoding="utf-8"))
    if sha(path) != manifest["files"][path.name]:
        raise ValueError("manifest_mismatch")
    cases = read(path)
    ids = {c["sample_id"] for c in cases}
    groups = {}
    for source, file in (("codet5", args.codet5), ("seed", args.seed)):
        records = read(file)
        if len(records) != len(cases) or {r["sample_id"] for r in records} != ids:
            raise ValueError("incomplete_candidate_set")
        groups[source] = {r["sample_id"]: r for r in records}
    args.out.mkdir(parents=True, exist_ok=False)
    counts = Counter(n=len(cases))
    with (args.out / "pools.jsonl").open("w", encoding="utf-8") as stream:
        for case in cases:
            generated = {}
            for source, records in groups.items():
                row = records[case["sample_id"]]
                if row["input_sha256"] != case["input_local_sha256"]:
                    raise ValueError("candidate_input_mismatch")
                generated[source] = row["candidates"]
            pool = select_pool(generated)
            counts["samples_with_syntax_valid"] += bool(pool["candidates"])
            stream.write(json.dumps(dict(sample_id=case["sample_id"],
                original_function=case["vulnerable_code"], vulnerable_line=case["edit_start"] + 1,
                **pool), ensure_ascii=False) + "\n")
    write(args.out / "summary.json", dict(counts, syntax_validity=counts["samples_with_syntax_valid"] / len(cases),
          llm_sfr=None, api_calls=0, rules_generator_implemented=False,
          source_sha256=dict(inputs=sha(path), codet5=sha(args.codet5), seed=sha(args.seed)),
          pools_sha256=sha(args.out / "pools.jsonl"), deduplication="exact full patch only",
          syntax="C or C++ root has no parse error", selection="fixed source rotation, at most 5"))


if __name__ == "__main__":
    main()
