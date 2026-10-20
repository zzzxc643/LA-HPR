"""Rebuild frozen inputs/references from an existing official PrimeVul v0.1 download.

Python 3.10+; standard library only. No network, model inference or API calls.
"""
import argparse
from difflib import SequenceMatcher
import hashlib
import json
from pathlib import Path
import shutil

import block_repair
import singleline_repair


ROOT = Path(__file__).resolve().parents[1]


def digest(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def read_jsonl(path):
    with path.open(encoding="utf-8-sig") as stream:
        return [json.loads(line) for line in stream if line.strip()]


def resolve_functions(primevul_dir, split, records):
    needed = {(r["commit_id"], r[side + "_sha256"])
              for r in records for side in ("vulnerable", "fixed")}
    found = {}
    source = primevul_dir / f"primevul_{split}_paired.jsonl"
    with source.open(encoding="utf-8-sig") as stream:
        for line in stream:
            row = json.loads(line)
            key = (row["commit_id"], digest(row["func"]))
            if key in needed:
                if key in found and found[key]["func"] != row["func"]:
                    raise ValueError("conflicting_upstream_function")
                found[key] = row
    if needed - found.keys():
        raise ValueError(f"{split}: {len(needed - found.keys())} upstream functions missing")
    for record in records:
        for side in ("vulnerable", "fixed"):
            row = found[(record["commit_id"], record[side + "_sha256"])]
            expected = record["upstream_" + side]
            if row["target"] != expected["target"] or str(row["func_hash"]) != str(expected["func_hash"]):
                raise ValueError("upstream_identity_mismatch")
    return found


def rebuild_singleline(meta, before, after):
    old, new = before.splitlines(), after.splitlines()
    changes = [op for op in SequenceMatcher(None, old, new, autojunk=False).get_opcodes()
               if op[0] != "equal"]
    if len(changes) != 1:
        raise ValueError("not_one_edit_block")
    tag, start, end, new_start, new_end = changes[0]
    if tag != "replace" or end - start != 1 or new_end - new_start != 1:
        raise ValueError("not_singleline_replacement")
    if (start, end) != (meta["edit_start"], meta["edit_end"]):
        raise ValueError("coordinate_mismatch")
    local, left, right = singleline_repair.model_input(before, start, meta["cwe"])
    full, _, _ = singleline_repair.model_input(before, start, meta["cwe"], full=True)
    case = dict(sample_id=meta["sample_id"], split=meta["split"], project=meta["project"],
                cwe=meta["cwe"], source_file=meta["source_file"], vulnerable_code=before,
                edit_start=start, edit_end=end, context_start=left, context_end=right,
                input_local=local, input_full=full,
                input_local_sha256=digest(local), input_full_sha256=digest(full))
    action = singleline_repair.infer_action(old[start], new[new_start])
    target = json.dumps(dict(action=action, replacement=new[new_start]), ensure_ascii=False)
    if singleline_repair.render(case, target) != after or action != meta["action"]:
        raise ValueError("reference_roundtrip_mismatch")
    reference = dict(sample_id=meta["sample_id"], commit_id=meta["commit_id"],
                     fixed_code=after, target=target, action=action,
                     vulnerable_sha256=digest(before), fixed_sha256=digest(after))
    train = dict(sample_id=meta["sample_id"], input_local=local, input_full=full, target=target)
    return case, reference, train


def rebuild_multiregion(meta, before, after):
    old, new = before.splitlines(keepends=True), after.splitlines(keepends=True)
    changes = [op for op in SequenceMatcher(None, old, new, autojunk=False).get_opcodes()
               if op[0] != "equal"]
    regions, edits = [], []
    for slot, (_, start, end, new_start, new_end) in enumerate(changes, 1):
        regions.append(dict(slot=slot, start=start, end=end))
        edits.append(dict(slot=slot, replacement="".join(new[new_start:new_end])))
    if regions != meta["edit_regions"]:
        raise ValueError("coordinate_mismatch")
    kind = ("singleline" if len(changes) == 1 and changes[0][2] - changes[0][1] == 1
            and changes[0][4] - changes[0][3] == 1
            else "single_block" if len(changes) == 1 else "multiple_blocks")
    case = dict(sample_id=meta["sample_id"], split=meta["split"], project=meta["project"],
                cwe=meta["cwe"], source_file=meta["source_file"], vulnerable_code=before,
                edit_regions=regions)
    text = block_repair.model_input(case)
    case.update(input_local=text, input_local_sha256=digest(text), vulnerable_sha256=digest(before))
    target = json.dumps(dict(edits=edits), ensure_ascii=False)
    if block_repair.render(case, target) != after or kind != meta["kind"]:
        raise ValueError("reference_roundtrip_mismatch")
    reference = dict(sample_id=meta["sample_id"], commit_id=meta["commit_id"], fixed_code=after,
                     target=target, kind=kind, vulnerable_sha256=digest(before), fixed_sha256=digest(after))
    return case, reference


def write_checked(path, rows, expected):
    text = "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows)
    if expected["newline"] == "CRLF":
        text = text.replace("\n", "\r\n")
    raw = text.encode("utf-8")
    if hashlib.sha256(raw).hexdigest() != expected["sha256"]:
        raise ValueError(f"frozen_file_hash_mismatch:{path.name}")
    path.write_bytes(raw)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--primevul-dir", type=Path, required=True,
                        help="Directory containing primevul_{train,valid,test}_paired.jsonl")
    parser.add_argument("--out", type=Path, required=True, help="A new, non-existing output directory")
    args = parser.parse_args()
    # Complete all source resolution before creating output; never overwrite prior data.
    metadata = {}
    for task in ("singleline", "multiregion"):
        for path in sorted((ROOT / "data/splits" / task).glob("*.jsonl")):
            metadata[(task, path.stem)] = read_jsonl(path)
    functions = {}
    for split in ("train", "valid", "test"):
        records = [r for (_, s), rows in metadata.items() if s == split for r in rows]
        functions[split] = resolve_functions(args.primevul_dir, split, records)
    args.out.mkdir(parents=True, exist_ok=False)
    report = {}
    for (task, split), records in metadata.items():
        destination = args.out / task
        destination.mkdir(exist_ok=True)
        manifest = json.loads((ROOT / "provenance" / f"{task}_{split}_reconstruction.json").read_text())
        inputs, references, training = [], [], []
        for meta in records:
            before = functions[split][(meta["commit_id"], meta["vulnerable_sha256"])]["func"]
            after = functions[split][(meta["commit_id"], meta["fixed_sha256"])]["func"]
            result = (rebuild_singleline(meta, before, after) if task == "singleline"
                      else rebuild_multiregion(meta, before, after))
            case, reference = result[:2]
            for field in ("input_local_sha256", "input_full_sha256"):
                if field in meta and case[field] != meta[field]:
                    raise ValueError("model_input_hash_mismatch")
            inputs.append(case)
            references.append(reference)
            if task == "singleline" and split == "train":
                training.append(result[2])
        files = {f"inputs_{split}.jsonl": inputs, f"references_{split}.jsonl": references}
        if training:
            files["train.jsonl"] = training
        for name, rows in files.items():
            write_checked(destination / name, rows, manifest["files"][name])
        report[f"{task}/{split}"] = dict(rows=len(inputs), verified_files=len(files))
    # Historical hashes include original line endings; keep them exactly for the training audit.
    for task in ("singleline", "multiregion"):
        shutil.copyfile(ROOT / "provenance" / f"{task}_original_manifest.json",
                        args.out / task / "manifest.json")
    (args.out / "reconstruction_report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
