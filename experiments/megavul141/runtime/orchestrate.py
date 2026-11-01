"""Run two inference lanes and review completed groups with one shared cache."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    a.out.mkdir(exist_ok=True, parents=True)
    logs = a.out / 'logs'
    logs.mkdir(exist_ok=True)
    state = dict(protocol='megavul_model_repair_20261022_v1', n=141,
                 status='running', generation={}, review={},
                 scheduling='seed plus one CodeT5 arm; review uses CPU/API concurrently')
    guard = threading.Lock()

    def save():
        state['updated_utc'] = datetime.now(timezone.utc).isoformat()
        path = a.out / 'STATUS.json'
        temp = path.with_suffix('.tmp')
        temp.write_text(json.dumps(state, indent=2) + '\n')
        temp.replace(path)

    def run_arm(arm):
        with guard:
            state['generation'][arm] = dict(status='running')
            save()
        env = dict(os.environ)
        env.pop('QWEN_API_KEY', None)
        cmd = [sys.executable, '-u', str(a.out / 'runtime/generate.py'),
               '--root', str(a.root), '--out', str(a.out), '--arm', arm]
        with (logs / (arm + '.log')).open('a') as stream:
            result = subprocess.run(cmd, env=env, stdout=stream, stderr=subprocess.STDOUT)
        with guard:
            state['generation'][arm] = dict(status='complete' if result.returncode == 0 else 'runtime_failed',
                                           exit_code=result.returncode)
            save()
        return result.returncode == 0

    def small_lane():
        for arm in ('codet5_local', 'action_local_matched', 'action_full', 'original_fulltext'):
            if not run_arm(arm):
                return False
        return True

    def review_ready(generation_finished):
        groups = ('codet5_local', 'seed', 'action_local_matched', 'action_full', 'original_fulltext', 'combined')
        for group in groups:
            if group in state['review']:
                continue
            needed = ('codet5_local', 'seed') if group == 'combined' else (group,)
            if not all(state['generation'].get(arm, {}).get('status') == 'complete' for arm in needed):
                continue
            if not os.environ.get('QWEN_API_KEY'):
                with guard:
                    state['review'][group] = dict(status='missing_api_key')
                    save()
                continue
            if not (a.out / 'runtime/review.py').exists():
                if generation_finished:
                    raise FileNotFoundError('review runtime missing')
                continue
            cmd = [sys.executable, '-u', str(a.out / 'runtime/review.py'),
                   '--inputs', str(a.out / 'inputs_pool.jsonl'), '--generated-root', str(a.out),
                   '--freeze', str(a.out / 'freeze.json'), '--out', str(a.out / 'review'),
                   '--scripts', str(a.root / 'scripts'), '--groups', group, '--workers', '6']
            with guard:
                state['review'][group] = dict(status='running')
                save()
            with (logs / ('review_' + group + '.log')).open('a') as stream:
                result = subprocess.run(cmd, stdout=stream, stderr=subprocess.STDOUT)
            summary_path = a.out / 'review' / group / 'audited_summary.json'
            valid_complete = (summary_path.exists() and
                              json.loads(summary_path.read_text()).get('complete') is True)
            with guard:
                state['review'][group] = dict(status='complete' if result.returncode == 0 and valid_complete else 'review_failed',
                                             exit_code=result.returncode)
                save()
            if result.returncode or not valid_complete:
                return False
        return True

    with guard:
        save()
    review_ok = True
    with ThreadPoolExecutor(max_workers=2) as workers:
        jobs = [workers.submit(run_arm, 'seed'), workers.submit(small_lane)]
        while not all(job.done() for job in jobs):
            if review_ok:
                review_ok = review_ready(False)
            time.sleep(5)
        generation_ok = all(job.result() for job in jobs)
    if review_ok:
        review_ok = review_ready(True)
    with guard:
        state['status'] = ('generation_and_review_complete' if generation_ok and review_ok
                           and len(state['review']) == 6 and all(x['status'] == 'complete' for x in state['review'].values())
                           else 'needs_attention')
        state['compiler_status'] = 'separate_local_pipeline'
        save()
    if state['status'] != 'generation_and_review_complete':
        raise SystemExit(1)


if __name__ == '__main__':
    main()
