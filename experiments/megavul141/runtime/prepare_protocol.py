"""Prepare source relationships and a protocol template without running models."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

from generate import ARMS, DEPENDENCIES, read_rows, sha, write


EXPECTED_MODELS = {
    "codet5_local": "ac89310834ff441ffd3ea6d4d5d0acfde1ecc7660ad48d2b2e85689cdc07915c",
    "original_fulltext": "61e174041aa84c9deffbfb1d01e5684f3bc49436b35cb5ecf261b2d6301a5d68",
    "action_full": "8aa35875c496358c45635d30bce958c0d4366f5a54a4f6040d45cf46ca2764c0",
    "action_local_matched": "f2afd923263b1f194886531b6f7ea906c581c14a585b6bf536af14208e6ac91a",
}


def prepare(root, out, pool):
    source_dir = root / "repair_validation_prep"
    if not source_dir.exists():
        source_dir = root / "scripts"
    sys.path.insert(0, str(source_dir))
    from singleline_repair import TOKEN
    historical = root / "reports/local_singleline_v1"
    formal = json.loads((historical / "formal_test_singleline_20261017/freeze.json").read_text(encoding="utf-8"))
    baselines = historical / "full_baselines_20261017"
    baseline = json.loads((baselines / "protocol.json").read_text(encoding="utf-8"))
    expected_scripts = dict(formal["scripts_sha256"])
    for name, digest in baseline["scripts_sha256"].items():
        if name in expected_scripts and expected_scripts[name] != digest:
            raise ValueError("historical_script_hash_disagreement:" + name)
        expected_scripts[name] = digest
    for name in DEPENDENCIES:
        if sha(source_dir / name) != expected_scripts[name]:
            raise ValueError("local_script_differs_from_frozen_original:" + name)
    accepted = read_rows(pool / "accepted_pairs.jsonl")
    inputs = read_rows(pool / "evaluation/inputs_pool.jsonl")
    groups = read_rows(pool / "association_groups.jsonl")
    if len(accepted) != 141 or len(inputs) != 141:
        raise ValueError("expected_141_accepted_inputs")
    if len({row["sample_id"] for row in accepted}) != 141 or len({row["sample_id"] for row in inputs}) != 141:
        raise ValueError("duplicate_pool_identity")
    if any(row["vulnerable_code"] != case["vulnerable_code"] for row, case in zip(accepted, inputs)):
        raise ValueError("input_original_function_mismatch")
    accepted_by_id = {case["sample_id"]: row for row, case in zip(accepted, inputs)}
    def tokens(code):
        return tuple(token for token in TOKEN.findall(code) if not token.startswith(("//", "/*")))
    original_root = root / "repair_validation_prep/local_singleline_v1"
    if not original_root.exists():
        raise ValueError("frozen_original_data_missing_for_relationship_audit")
    indexes = {}
    original_hashes = {}
    for split in ("train", "valid", "test"):
        path = original_root / ("inputs_" + split + ".jsonl")
        ref_path = original_root / ("references_" + split + ".jsonl")
        original_hashes[str(path.relative_to(root)).replace("\\", "/")] = sha(path)
        original_hashes[str(ref_path.relative_to(root)).replace("\\", "/")] = sha(ref_path)
        cases = read_rows(path)
        refs = {row["sample_id"]: row for row in read_rows(ref_path)}
        indexes[split] = (cases, refs)
    relationships = []
    counts = {split: Counter() for split in indexes}
    for case in inputs:
        row = accepted_by_id[case["sample_id"]]
        original_token = tokens(row["vulnerable_code"])
        fixed_token = tokens(row["fixed_code"])
        matches = {}
        for split, (cases, refs) in indexes.items():
            relations = {key: [] for key in ("exact_vulnerable", "token_vulnerable", "token_pair", "commit", "project")}
            for previous in cases:
                sid = previous["sample_id"]
                previous_token = tokens(previous["vulnerable_code"])
                if row["vulnerable_code"] == previous["vulnerable_code"]:
                    relations["exact_vulnerable"].append(sid)
                if original_token == previous_token:
                    relations["token_vulnerable"].append(sid)
                    if fixed_token == tokens(refs[sid]["fixed_code"]):
                        relations["token_pair"].append(sid)
                if row["commit_id"] == refs[sid]["commit_id"]:
                    relations["commit"].append(sid)
                if row.get("project", "").lower() == previous.get("project", "").lower():
                    relations["project"].append(sid)
            matches[split] = relations
            counts[split].update(key for key, values in relations.items() if values)
        relationships.append(dict(sample_id=case["sample_id"], original_sample_id=row["sample_id"],
            split="unassigned", audit_group_id=row["audit_group_id"],
            grouping_status="provisional_documented_scope", project=row.get("project"),
            original_split_relationships=matches,
            companion_context_required=row["verified_compile_evidence"]["snapshot"] != "verified_first_parent",
            snapshot=row["verified_compile_evidence"]["snapshot"]))
    out.mkdir(parents=True, exist_ok=True)
    relationships_path = out / "relationships.jsonl"
    with relationships_path.open("x", encoding="utf-8") as stream:
        for row in relationships:
            stream.write(json.dumps(row, ensure_ascii=False) + "\n")
    report = dict(n=len(inputs), group_records=len(groups),
        audit_group_count=len({r["audit_group_id"] for r in relationships}),
        relationship_counts={split: dict(counter) for split, counter in counts.items()},
        project_disjoint=not any(counter["project"] for counter in counts.values()),
        source_or_project_disjoint_external_test_asserted=False,
        original_splits_unchanged=True, original_data_sha256=original_hashes,
        accepted_pool_sha256=sha(pool / "accepted_pairs.jsonl"),
        inputs_sha256=sha(pool / "evaluation/inputs_pool.jsonl"),
        association_groups_sha256=sha(pool / "association_groups.jsonl"),
        relationships_sha256=sha(relationships_path),
        method="exact original text; comment-insensitive lexical token original/pair; exact commit ID; case-insensitive exact project name",
        limitations="No new exhaustive near-clone, CVE-alias or project-alias analysis; same project alone is not proof of training contamination.",
        evaluation_scope="frozen augmented evaluation pool, known-location task; no claim of independent cross-project generalization")
    write(out / "relationship_audit.json", report)
    arms = {}
    for arm in ARMS:
        if arm == "seed":
            arms[arm] = dict(model_path="__SET_VERIFIED_SEED_SNAPSHOT_PATH__", model_kind="causal", input_mode="local",
                max_input_tokens=4096, max_new_tokens=256,
                generation={key: value for key, value in formal["settings"]["seed"]["generation"].items() if key != "max_new_tokens"},
                checkpoint_files_sha256={}, pretrained_model=formal["settings"]["seed"]["model"],
                revision=formal["settings"]["seed"]["revision"])
            continue
        if arm == "codet5_local":
            model_path = "reports/local_singleline_v1/codet5_local_20261017/model"
            files = formal["checkpoint_files_sha256"]
        else:
            model_path = "reports/local_singleline_v1/full_baselines_20261017/" + arm + "/model"
            training = json.loads((baselines / arm / "training_summary.json").read_text(encoding="utf-8"))
            files = training["checkpoint_files_sha256"]
            if training["training_samples"] != len(baseline["shared_train_ids"]):
                raise ValueError("baseline_training_identity_disagreement")
        if files["model.safetensors"] != EXPECTED_MODELS[arm]:
            raise ValueError("unexpected_frozen_model:" + arm)
        arms[arm] = dict(model_path=model_path, model_kind="seq2seq",
            input_mode="fulltext" if arm == "original_fulltext" else "full" if arm == "action_full" else "local",
            max_input_tokens=4096 if arm in ("original_fulltext", "action_full") else 1024,
            max_new_tokens=4096 if arm == "original_fulltext" else 128,
            generation=dict(num_beams=3, num_return_sequences=3, do_sample=False),
            checkpoint_files_sha256=files, pretrained_model=baseline["model"], revision=baseline["revision"])
    template = dict(protocol="megavul_frozen_model_repair_20261022_v1", n=141, seed=42,
        frozen_utc=datetime.now(timezone.utc).isoformat(),
        inputs=dict(path="inputs_pool.jsonl", sha256=report["inputs_sha256"]),
        scripts=dict(path="scripts", sha256={name: expected_scripts[name] for name in DEPENDENCIES}),
        runtime_sha256={path.name: sha(path) for path in Path(__file__).parent.glob("*.py")},
        arms=arms, settings=dict(judge=formal["settings"]["judge"]),
        relationship_audit_sha256=sha(out / "relationship_audit.json"),
        historical_protocol_sha256=dict(formal=sha(historical / "formal_test_singleline_20261017/freeze.json"),
                                       baselines=sha(baselines / "protocol.json")),
        model_training_started=False, reference_files_available_to_generation=False,
        requires_remote_seed_snapshot_hashes=True,
        all_case_denominator=141,
        evaluation_policy="Freeze all generated outputs before reference exact-match evaluation; no model-output-based exclusions; compile acceptance and static review are distinct.")
    write(out / "protocol_template.json", template)
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--pool", type=Path, required=True)
    args = parser.parse_args()
    prepare(args.root.resolve(), args.out.resolve(), args.pool.resolve())
