"""Audit complete-function Train/Valid lengths without opening Formal Test."""
import argparse
import json
from pathlib import Path

from train_singleline import MODEL, REVISION, checked_data, read, sha, write


def fulltext_input(case):
    return ("Repair this C/C++ function. The known vulnerable line is "
        + str(case["edit_start"] + 1) + " (1-based). Return only the complete repaired function.\nCWE: "
        + ", ".join(case["cwe"]) + "\n" + case["vulnerable_code"])


def main():
    from transformers import AutoTokenizer
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    training, valid, valid_refs, hashes = checked_data(args.data)
    del training
    manifest = json.loads((args.data / "manifest.json").read_text(encoding="utf-8"))
    ref_path = args.data / "references_train.jsonl"
    if sha(ref_path) != manifest["files"][ref_path.name]:
        raise ValueError("training_reference_hash_mismatch")
    train_refs = {r["sample_id"]: r for r in read(ref_path)}
    train = read(args.data / "inputs_train.jsonl")
    tokenizer = AutoTokenizer.from_pretrained(MODEL, revision=REVISION, local_files_only=True)
    rows = []
    for split, cases, refs in (("train", train, train_refs), ("valid", valid, valid_refs)):
        if {r["sample_id"] for r in cases} != refs.keys():
            raise ValueError("reference_identity_mismatch")
        for case in cases:
            ref = refs[case["sample_id"]]
            values = dict(action_input=case["input_full"], action_target=ref["target"],
                fulltext_input=fulltext_input(case), fulltext_target=ref["fixed_code"])
            rows.append(dict(split=split, sample_id=case["sample_id"], **{
                key: len(tokenizer(value, truncation=False)["input_ids"]) for key, value in values.items()}))
    distributions = {}
    for split in ("train", "valid"):
        selected = [r for r in rows if r["split"] == split]
        distributions[split] = dict(n=len(selected), maxima={k: max(r[k] for r in selected)
            for k in ("action_input", "action_target", "fulltext_input", "fulltext_target")},
            coverage={str(limit): dict(action=sum(r["action_input"] <= limit for r in selected),
                fulltext=sum(max(r["fulltext_input"], r["fulltext_target"]) <= limit for r in selected))
                for limit in (1024, 2048, 4096, 8192, 16384, 32768)})
    args.out.mkdir(parents=True, exist_ok=False)
    report = dict(model=MODEL, revision=REVISION, formal_test_opened=False,
        reference_test_opened=False, truncation=False, source_hashes=dict(hashes,
            references_train=sha(ref_path)), rows=rows, distributions=distributions)
    write(args.out / "budget_audit.json", report)
    print(json.dumps(distributions, indent=2), flush=True)


if __name__ == "__main__":
    main()
