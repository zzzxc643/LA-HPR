"""Remove only a complete JSON Markdown fence, preserving raw model outputs."""
import argparse
from collections import Counter
import json
from pathlib import Path
import re

from train_singleline import candidate, parsers, read, sha, write


def unwrap(prediction):
    match = re.fullmatch(r"\s*```(?:json)?[ \t]*\r?\n([\s\S]*?)\r?\n```\s*",
                         prediction, flags=re.IGNORECASE)
    return (match.group(1), "single_json_fence_removed") if match else (prediction, "unchanged")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--data", type=Path, required=True)
    p.add_argument("--candidates", type=Path, required=True)
    p.add_argument("--source", choices=("codet5", "seed"), required=True)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    path = args.data / "inputs_valid.jsonl"
    manifest = json.loads((args.data / "manifest.json").read_text(encoding="utf-8"))
    if sha(path) != manifest["files"][path.name]:
        raise ValueError("manifest_mismatch")
    cases = {r["sample_id"]: r for r in read(path)}
    rows = read(args.candidates)
    if len(rows) != 69 or len(cases) != 69 or {r["sample_id"] for r in rows} != cases.keys():
        raise ValueError("incomplete_valid_candidates")
    args.out.mkdir(parents=True, exist_ok=False)
    engines = parsers()
    counts = Counter(n=len(cases))
    with (args.out / "valid_candidates.jsonl").open("w", encoding="utf-8") as stream:
        for record in rows:
            case = cases[record["sample_id"]]
            if record["input_sha256"] != case["input_local_sha256"] or len(record["candidates"]) > 3:
                raise ValueError("candidate_provenance_mismatch")
            processed, seen = [], set()
            for raw in record["candidates"]:
                prediction, action = unwrap(raw["prediction"])
                row = candidate(case, prediction, engines, raw["rank"])
                row.update(source=args.source, raw_prediction=raw["prediction"], format_normalization=action)
                if "output_truncated" in raw:
                    row["output_truncated"] = raw["output_truncated"]
                digest = row.get("patch_sha256")
                row["duplicate"] = digest is not None and digest in seen
                if digest:
                    seen.add(digest)
                counts[action] += 1
                processed.append(row)
            counts["samples_with_render_valid"] += any(r["render_valid"] for r in processed)
            counts["samples_with_syntax_valid"] += any(r["syntax_valid"] for r in processed)
            stream.write(json.dumps(dict(record, candidates=processed), ensure_ascii=False) + "\n")
    write(args.out / "config.json", dict(policy="remove single complete json or unlabelled Markdown fence only",
          raw_candidates_sha256=sha(args.candidates), source_inputs_sha256=sha(path),
          script_sha256=sha(Path(__file__)), candidate_module_sha256=sha(Path(__file__).with_name("train_singleline.py")),
          renderer_module_sha256=sha(Path(__file__).with_name("singleline_repair.py")),
          model_calls=0, api_calls=0, references_opened=False))
    write(args.out / "valid_summary.json", dict(counts, llm_sfr=None, api_calls=0,
          syntax_validity=counts["samples_with_syntax_valid"] / len(cases)))
    print(args.source, dict(counts), flush=True)


if __name__ == "__main__":
    main()
