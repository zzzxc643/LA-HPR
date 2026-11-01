"""Recompute the additional frozen experiment counts without models or API calls."""
from collections import Counter
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    path = ROOT / name
    text = path.read_text(encoding='utf-8-sig')
    return [json.loads(s) for s in text.splitlines() if s] if path.suffix == '.jsonl' else json.loads(text)


def keyed(rows, expected_ids):
    result = {r['sample_id']: r for r in rows}
    assert len(result) == len(rows) and set(result) == expected_ids, 'sample_identity_mismatch'
    return result


def review(rows):
    for row in rows:
        selected = row.get('selected_cand_id')
        selected_reviews = [r for r in (row.get('reviews') or []) if r['cand_id'] == selected]
        assert bool(row['success']) == bool(selected_reviews and selected_reviews[0]['result'] == 'PASS')
        if row['success']:
            assert len(selected_reviews) == 1
            assert all(selected_reviews[0][k] is True for k in ('vul_eliminated', 'func_preserved', 'no_new_bug'))
            assert len(row['selected_patch_sha256']) == 64
        assert not {'final_patch', 'selected_patch', 'selected_diff'}.intersection(row)
    return sum(r['success'] for r in rows)


def checked_engineering(reviews, engineering, expected_ids):
    records = keyed(engineering, expected_ids)
    accepted = 0
    for row in reviews:
        item = records[row['sample_id']]
        if 'candidates' in item:
            # Prime57 equal-budget output records the selected candidate inside a list.
            candidates = item['candidates']
            if row['success']:
                assert len(candidates) == 1
                item = candidates[0]
                assert item['candidate_id'] == row['selected_cand_id']
            else:
                assert not candidates
                continue
        if item['status'] == 'candidate_compile_pass':
            assert row['success']
            accepted += 1
        if row['success']:
            assert item['patch_sha256'] == row['selected_patch_sha256'], 'selected_patch_binding_mismatch'
    return accepted


def verify():
    prime_ids = {r['sample_id'] for r in load('data/splits/singleline/test.jsonl')}
    valid_ids = {r['sample_id'] for r in load('data/splits/singleline/valid.jsonl')}
    metadata = load('data/splits/megavul/evaluation141.jsonl')
    mega_ids = {r['sample_id'] for r in metadata}
    assert len(mega_ids) == len(metadata) == 141
    assert len({r['source_sample_id'] for r in metadata}) == 141
    assert all(r['split'] == 'unassigned' for r in metadata)
    assert len(load('data/splits/megavul/association_groups.jsonl')) == 84
    report = {'megavul141': {}, 'prime57_clang20': {}, 'equal_budget': {}, 'fulltext6': {}}
    summary = load('data/updates/megavul141/SUMMARY.json')
    for method, expected in summary['groups'].items():
        rows = load(f'data/updates/megavul141/{method}.jsonl')
        keyed(rows, mega_ids)
        static = review(rows)
        engineering = checked_engineering(rows, load(f'data/updates/megavul141/{method}_engineering.json'), mega_ids)
        assert static == expected['static_pass'] and engineering == expected['engineering_accepted']
        report['megavul141'][method] = {'n': 141, 'static': static, 'engineering': engineering}
    prime = load('data/updates/prime57_clang20/model_results.json')
    expected_prime = {'codet5_local': (16, 15), 'seed': (22, 19), 'original_fulltext': (15, 15),
                      'action_full': (14, 12), 'action_local_matched': (19, 19), 'combined': (30, 28)}
    for method, expected in expected_prime.items():
        rows = [r for r in prime if r['group'] == method]
        keyed(rows, prime_ids)
        assert all(r['controls_status'] == 'controls_pass' for r in rows)
        counts = (sum(r['static_pass'] for r in rows), sum(r['engineering_status'] == 'candidate_compile_pass' for r in rows))
        assert counts == expected
        report['prime57_clang20'][method] = {'n': 57, 'static': counts[0], 'engineering': counts[1]}
    equal_expected = {'prime57': {'seed6': (28, 24), 'mixed33': (32, 29)},
                      'mega141': {'seed6': (98, 90), 'mixed33': (101, 94)}}
    for cohort, ids in [('valid69', valid_ids), ('prime57', prime_ids), ('mega141', mega_ids)]:
        report['equal_budget'][cohort] = {}
        for method in ('seed6', 'mixed33'):
            rows = load(f'data/updates/equal_budget/{cohort}/{method}.jsonl')
            keyed(rows, ids)
            static = review(rows)
            expected = load(f'data/updates/equal_budget/{cohort}/{method}_summary.json')
            assert static == expected['successful_samples']
            result = {'n': len(ids), 'static': static}
            if cohort != 'valid69':
                engineering = checked_engineering(rows, load(f'data/updates/equal_budget/{cohort}/{method}_engineering.json'), ids)
                assert (static, engineering) == equal_expected[cohort][method]
                result['engineering'] = engineering
            report['equal_budget'][cohort][method] = result
        rows = load(f'data/updates/fulltext6/{cohort}/results.jsonl')
        keyed(rows, ids)
        static = review(rows)
        aggregate = next(r for r in load('data/updates/fulltext6/RESULTS_SUMMARY.json')['cohorts'] if r['cohort'] == cohort)
        assert static == aggregate['static_selected']
        result = {'n': len(ids), 'static': static}
        if cohort != 'valid69':
            engineering = checked_engineering(rows, load(f'data/updates/fulltext6/{cohort}/engineering.json'), ids)
            assert engineering == aggregate['engineering_accepted']
            result['engineering'] = engineering
        report['fulltext6'][cohort] = result
    behavior = load('data/updates/behavior_four_cases.json')
    assert behavior['samples'] == behavior['valid_control_samples'] == len(behavior['cases']) == 4
    for group in ('seed6', 'mixed33'):
        counts = Counter(r[group] for r in behavior['cases'])
        assert counts == behavior['groups'][group]
    report['behavior_four_cases'] = behavior['groups']
    return report


if __name__ == '__main__':
    print(json.dumps(verify(), indent=2))
