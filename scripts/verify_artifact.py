"""Verify public data checksums and recompute reported aggregate results (CPU only)."""
import argparse
from collections import Counter
import csv
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load(path):
    if path.suffix == ".jsonl":
        return [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line]
    return json.loads(path.read_text(encoding="utf-8-sig"))


def keyed(rows):
    result = {r["sample_id"]: r for r in rows}
    assert len(result) == len(rows), "duplicate_sample_id"
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write-manifest", action="store_true",
                        help="Maintainer: regenerate checksums after reviewing intentional edits")
    args = parser.parse_args()
    manifest_path = ROOT / "provenance/artifact_sha256.json"
    paths = [p for p in sorted(ROOT.rglob("*")) if p.is_file() and p != manifest_path
             and not any(part in (".git", "__pycache__", ".venv", "reconstructed")
                         for part in p.relative_to(ROOT).parts)]
    hashes = {p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    if args.write_manifest:
        manifest_path.write_text(json.dumps(hashes, indent=2) + "\n", encoding="utf-8")
    assert hashes == load(manifest_path), "artifact_checksum_mismatch"
    summary = load(ROOT / "data/summary.json")
    report = {"checksummed_files": len(hashes), "singleline": {}, "multiregion": {}, "compiler": {}}
    expected_counts = {"singleline": {"train": 451, "valid": 69, "test": 57},
                       "multiregion": {"train": 3287, "valid": 439}}
    split_maps = {}
    for task, splits in expected_counts.items():
        split_maps[task] = {}
        for split, count in splits.items():
            records = keyed(load(ROOT / f"data/splits/{task}/{split}.jsonl"))
            assert len(records) == count, "split_size_mismatch"
            split_maps[task][split] = records
    test_ids = set(split_maps["singleline"]["test"])
    passed_sets = {}
    for method, expected in summary["singleline_model_comparison"].items():
        records = keyed(load(ROOT / f"data/results/singleline/{method}.jsonl"))
        assert set(records) == test_ids
        passed = {sid for sid, row in records.items() if row["success"]}
        passed_sets[method] = passed
        covered = sum(bool(r["counts"]["submitted"]) for r in records.values())
        for row in records.values():
            selected = [r for r in row["reviews"] if r["cand_id"] == row.get("selected_cand_id")]
            assert bool(row["success"]) == bool(selected and selected[0]["result"] == "PASS")
        assert len(passed) == expected["qwen_pass_samples"]
        assert covered == expected["syntax_covered_samples"]
        report["singleline"][method] = {"n": len(records), "recommended": len(passed),
                                        "qwen_sfr": len(passed) / len(records), "syntax_covered": covered}
    combined, seed = passed_sets["combined"], passed_sets["seed_independent"]
    # Exact two-sided McNemar test from discordant paired outcomes; no scipy dependency.
    from math import comb
    b, c = len(combined - seed), len(seed - combined)
    exact_p = min(1.0, 2 * sum(comb(b + c, i) for i in range(min(b, c) + 1)) / 2 ** (b + c))
    report["paired_combined_vs_seed"] = {"combined_only": b, "seed_only": c, "exact_p": exact_p}
    flow_path = ROOT / "data/tables/singleline_candidate_flow_by_sample.csv"
    with flow_path.open(encoding="utf-8-sig", newline="") as stream:
        flow = list(csv.DictReader(stream))
    assert {r["sample_id"] for r in flow} == test_ids
    totals = {k: sum(int(r[k]) for r in flow) for k in flow[0] if k != "sample_id"}
    assert list(totals.values()) == [342, 297, 254, 181, 176, 245]
    report["candidate_funnel"] = totals
    report["offline_submission_reduction"] = (245 - 176) / 245
    legal = keyed(load(ROOT / "data/results/multiregion/legal_responses.jsonl"))
    errors = keyed(load(ROOT / "data/results/multiregion/protocol_errors.json"))
    assert not legal.keys() & errors.keys()
    assert legal.keys() | errors.keys() == split_maps["multiregion"]["valid"].keys()
    assert len(legal) == 431 and len(errors) == 8
    n_pass = sum(bool(r["success"]) for r in legal.values())
    assert n_pass == 96
    report["multiregion"] = {"n": 439, "legal_responses": 431, "protocol_errors": 8,
                             "recommended": n_pass, "primary_qwen_sfr": n_pass / 439,
                             "conditional_qwen_sfr": n_pass / len(legal)}
    compiler = load(ROOT / "data/compiler/case_results.json")
    assert set(keyed(compiler)) == test_ids
    common = [r for r in compiler if r["status"] == "verifiable"]
    expected = load(ROOT / "data/compiler/summary.json")
    assert len(common) == expected["verifiable"] == 18
    assert len({r["project"] for r in common}) == 10
    for row in common:
        assert row["original"]["passed"] and row["reference"]["passed"]
        assert row["target_function_active"]
    for method, aggregate in expected["methods"].items():
        cases = [r["methods"][method] for r in common]
        accepted = sum(r.get("status") == "checked" and r.get("passed") is True for r in cases)
        rejected = sum(r.get("status") == "checked" and r.get("passed") is False for r in cases)
        assert accepted == aggregate["passed"]
        assert rejected == aggregate["compiler_rejected"]
        assert accepted + rejected == aggregate["recommended"]
        report["compiler"][method] = {"n": 18, "recommended": accepted + rejected, "accepted": accepted}
    from verify_updates import verify
    report["updates_20261101"] = verify()
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
