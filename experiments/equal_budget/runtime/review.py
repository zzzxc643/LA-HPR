"""Fresh pooled selection and separate, hash-consistent one-candidate judgments."""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import sys


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_rows(path):
    return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line.strip()]


def select_pool(generated):
    """Same historical ordering/filtering with a six-item single-source allowance."""
    sources = ('codet5', 'seed')
    if set(generated) - set(sources) or sum(map(len, generated.values())) > 6:
        raise ValueError('raw_candidate_budget')
    seen, eligible, audit = set(), {source: [] for source in sources}, []
    for source in sources:
        for item in generated.get(source, []):
            row = dict(item, source=source, cand_id=len(audit) + 1, exclusion=None)
            if not row['render_valid']:
                row['exclusion'] = 'render_invalid'
            else:
                code = row['patched_code']
                row['exclusion'] = 'duplicate' if code in seen else None
                seen.add(code)
                if row['exclusion'] is None and not row['syntax_valid']:
                    row['exclusion'] = 'syntax_invalid'
            if row['exclusion'] is None:
                eligible[source].append(row)
            audit.append(row)
    selected = []
    for rank in range(6):
        for source in sources:
            if rank < len(eligible[source]) and len(selected) < 5:
                selected.append(eligible[source][rank])
    ids = {row['cand_id'] for row in selected}
    counts = dict(raw_by_source={source: len(generated.get(source, [])) for source in sources},
        generated=len(audit), unique_render_valid=len(seen), syntax_eligible=sum(map(len, eligible.values())),
        submitted=len(selected), not_submitted_due_to_budget=[row['cand_id'] for row in audit if row['exclusion'] is None and row['cand_id'] not in ids],
        exclusions=dict(Counter(row['exclusion'] for row in audit if row['exclusion'])))
    return dict(candidates=selected, generation_audit=audit, counts=counts)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path, required=True)
    parser.add_argument('--cohort', choices=('valid69', 'prime57', 'mega141'), required=True)
    parser.add_argument('--stage', choices=('pools', 'pooled', 'independent', 'all'), default='all')
    args = parser.parse_args()
    run = args.run.resolve()
    folder = run / args.cohort
    protocol = json.loads((run / 'PROTOCOL.json').read_text(encoding='utf-8'))
    frozen = json.loads((folder / 'freeze.json').read_text(encoding='utf-8'))
    if sha(folder / 'freeze.json') != protocol['cohorts'][args.cohort]['freeze_sha256']:
        raise ValueError('cohort_freeze_changed')
    for name, digest in protocol['runtime_sha256'].items():
        if sha(run / 'runtime' / name) != digest:
            raise ValueError('runtime_changed:' + name)
    for name, digest in frozen['scripts']['sha256'].items():
        if sha(run / 'scripts' / name) != digest:
            raise ValueError('frozen_module_changed:' + name)
    sys.path.insert(0, str(run / 'scripts'))
    import legacy_review as review
    from train_singleline import candidate, parsers
    cases = read_rows(folder / 'inputs_pool.jsonl')
    if sha(folder / 'inputs_pool.jsonl') != frozen['inputs']['sha256'] or len(cases) != frozen['n']:
        raise ValueError('frozen_inputs_changed')
    inputs = {case['sample_id']: case for case in cases}
    generated = {}
    for source, details in frozen['reused'].items():
        path = run / details['path']
        if sha(path) != details['sha256']:
            raise ValueError('reused_candidates_changed')
        generated[source] = {row['sample_id']: row for row in read_rows(path)}
    six = read_rows(folder / 'seed/candidates.jsonl')
    if len(six) != len(cases) or {row['sample_id'] for row in six} != set(inputs):
        raise ValueError('seed6_not_complete')
    if any(row['run_freeze_sha256'] != sha(folder / 'freeze.json') or len(row['candidates']) not in (0, 6) for row in six):
        raise ValueError('seed6_generation_binding_or_count')
    generated['seed6'] = {row['sample_id']: row for row in six}
    engines = parsers()
    syntax_changes = []

    def rebuilt(case, source, arm):
        record = generated[source][case['sample_id']]
        if record['input_sha256'] != case['input_local_sha256']:
            raise ValueError('candidate_input_mismatch')
        candidates = []
        for saved in record['candidates']:
            item = candidate(case, saved['prediction'], engines, saved['rank'])
            for key in ('render_valid', 'patched_code', 'patch_sha256', 'diff'):
                if item.get(key) != saved.get(key):
                    raise ValueError('historical_render_changed:' + key)
            if item['syntax_valid'] != saved['syntax_valid']:
                syntax_changes.append(dict(sample_id=case['sample_id'], source=source, rank=saved['rank'], before=saved['syntax_valid'], after=item['syntax_valid']))
            item.update(generation_arm=arm, historical_syntax_valid=saved['syntax_valid'])
            candidates.append(item)
        return candidates

    pools = {'seed6': [], 'mixed33': []}
    for case in cases:
        prepared = {
            'seed6': {'seed': rebuilt(case, 'seed6', 'seed6')},
            'mixed33': {'codet5': rebuilt(case, 'codet5', 'codet5_local'), 'seed': rebuilt(case, 'seed', 'seed3')},
        }
        for arm, candidates in prepared.items():
            pool = select_pool(candidates)
            pools[arm].append(dict(sample_id=case['sample_id'], group=arm,
                original_function=case['vulnerable_code'], vulnerable_line=case['edit_start'] + 1,
                generation={}, **pool))
    out = folder / 'review'
    out.mkdir(parents=True, exist_ok=True)
    for arm, rows in pools.items():
        review.immutable(out / arm / 'pools.jsonl', ''.join(json.dumps(row, ensure_ascii=False) + '\n' for row in rows))
    review.write(out / 'SYNTAX_RECHECK.json', dict(changed=syntax_changes, uniform_current_parser=True))
    settings = protocol['judge']
    key = os.environ.get('QWEN_API_KEY')
    if args.stage != 'pools' and not key:
        raise ValueError('missing_qwen_api_key')
    client = None
    if key:
        from openai import OpenAI
        client = OpenAI(api_key=key, base_url=settings['base_url'], timeout=90, max_retries=0)
    summaries = {}
    if args.stage in ('pools', 'pooled', 'all'):
        cache = run / 'pooled_requests'
        cache.mkdir(exist_ok=True)
        requests, records, results = review.plan(pools, settings, cache)
        halted = False
        if args.stage != 'pools':
            halted = review.execute(requests, records, settings, cache, protocol['max_workers'], client)
        for arm, rows in pools.items():
            summary = review.summarize(arm, rows, results[arm], records, settings)
            review.write(out / arm / 'results.json', results[arm])
            review.write(out / arm / 'summary.json', summary)
            summaries[arm] = summary
        review.write(out / 'POOLED_STATUS.json', dict(complete=all(row['complete'] for row in summaries.values()),
            groups=summaries, halted_configuration_error=halted, old_response_cache_used=False))
        if halted or args.stage != 'pools' and not all(row['complete'] for row in summaries.values()):
            raise RuntimeError('pooled_review_incomplete')

    if args.stage in ('independent', 'all'):
        unique, occurrences = {}, []
        for arm, rows in pools.items():
            for pool in rows:
                for item in pool['candidates']:
                    identity = dict(sample_id=pool['sample_id'], original_sha256=hashlib.sha256(pool['original_function'].encode()).hexdigest(),
                                    vulnerable_line=pool['vulnerable_line'], patch_sha256=item['patch_sha256'])
                    uid = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
                    unique.setdefault(uid, dict(sample_id=uid, group='independent', original_function=pool['original_function'],
                        vulnerable_line=pool['vulnerable_line'], generation={}, counts={}, candidates=[dict(item, cand_id=1)]))
                    occurrences.append(dict(**identity, candidate_identity=uid, group=arm, cand_id=item['cand_id']))
        cache = run / 'candidate_requests'
        cache.mkdir(exist_ok=True)
        candidate_pools = {'independent': list(unique.values())}
        requests, records, results = review.plan(candidate_pools, settings, cache)
        halted = review.execute(requests, records, settings, cache, protocol['max_workers'], client)
        review.summarize('independent', candidate_pools['independent'], results['independent'], records, settings)
        labels = {row['sample_id']: row for row in results['independent']}
        independent = [dict(row, status=labels[row['candidate_identity']]['status'],
                            verdict=(labels[row['candidate_identity']].get('reviews') or [{}])[0].get('result'),
                            request_id=labels[row['candidate_identity']].get('request_id')) for row in occurrences]
        review.write(out / 'independent_results.json', results['independent'])
        review.write(out / 'independent_occurrences.json', independent)
        complete = all(row['status'] == 'valid' for row in independent)
        coverage = {arm: sum(any(row['sample_id'] == case['sample_id'] and row['group'] == arm and row['verdict'] == 'PASS'
                    for row in independent) for case in cases) for arm in pools}
        review.write(out / 'INDEPENDENT_STATUS.json', dict(complete=complete, unique_candidates=len(unique), occurrences=len(occurrences),
            pass_covered_samples=coverage, denominator=len(cases), fixed_single_candidate_labels=True,
            use='Candidate-quality diagnostic; does not alter pooled final selections or establish dynamic correctness'))
        if halted or not complete:
            raise RuntimeError('independent_review_incomplete')
    print('REVIEW_FINISHED', args.cohort, args.stage, flush=True)


if __name__ == '__main__':
    main()
