"""Resume the frozen budget experiment with one GPU lane and six API workers."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import subprocess
import sys
import threading


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--run', type=Path, required=True)
    args = parser.parse_args()
    run = args.run.resolve()
    protocol = json.loads((run / 'PROTOCOL.json').read_text())
    for name, digest in protocol['runtime_sha256'].items():
        if hashlib.sha256((run / 'runtime' / name).read_bytes()).hexdigest() != digest:
            raise ValueError('frozen_runtime_changed:' + name)
    logs = run / 'logs'
    logs.mkdir(exist_ok=True)
    lock = run / 'run.lock'
    if lock.exists():
        previous = json.loads(lock.read_text())
        try:
            os.kill(previous['pid'], 0)
        except ProcessLookupError:
            lock.unlink()
        else:
            raise ValueError('experiment_already_running')
    lock.write_text(json.dumps(dict(pid=os.getpid())))
    guard = threading.Lock()
    state = dict(status='running', started_utc=datetime.now(timezone.utc).isoformat(), generation={}, review={},
                 old_results_changed=False, additional_training=False, credentials_persisted=False)

    def save():
        state['updated_utc'] = datetime.now(timezone.utc).isoformat()
        path = run / 'STATUS.json'
        temporary = path.with_suffix('.tmp')
        temporary.write_text(json.dumps(state, indent=2) + '\n')
        temporary.replace(path)

    def call(kind, cohort, stage=None):
        name = kind + '_' + cohort + (('_' + stage) if stage else '')
        cmd = [sys.executable, '-u', str(run / 'runtime' / ('generate.py' if kind == 'generation' else 'review.py'))]
        if kind == 'generation':
            cmd += ['--root', str(args.root), '--out', str(run / cohort), '--arm', 'seed']
        else:
            cmd += ['--run', str(run), '--cohort', cohort, '--stage', stage]
        env = dict(os.environ)
        if kind == 'generation':
            env.pop('QWEN_API_KEY', None)
        with guard:
            state[kind if kind == 'generation' else 'review'][name] = dict(status='running', command=cmd)
            save()
        with (logs / (name + '.log')).open('a') as stream:
            result = subprocess.run(cmd, env=env, stdout=stream, stderr=subprocess.STDOUT)
        with guard:
            state[kind if kind == 'generation' else 'review'][name].update(status='complete' if result.returncode == 0 else 'runtime_failed', exit_code=result.returncode)
            save()
        if result.returncode:
            raise RuntimeError(name + '_failed')

    try:
        versions = {name: importlib.metadata.version(name) for name in (
            'torch', 'transformers', 'openai', 'tree-sitter', 'tree-sitter-c', 'tree-sitter-cpp')}
        environment = dict(recorded_utc=datetime.now(timezone.utc).isoformat(), python=sys.version,
            executable=sys.executable, packages=versions, kernel=list(os.uname()),
            gpu=subprocess.run(['nvidia-smi', '--query-gpu=name,memory.total,driver_version', '--format=csv,noheader'], capture_output=True, text=True).stdout.strip(),
            model_hashes_verification='Every required Seed checkpoint file is SHA256 checked by each generation invocation before loading')
        path = run / 'ENVIRONMENT.json'
        if not path.exists():
            path.write_text(json.dumps(environment, indent=2) + '\n')
        save()
        call('generation', 'valid69')
        call('review', 'valid69', 'pools')
        if not os.environ.get('QWEN_API_KEY'):
            state['status'] = 'valid_generation_complete_missing_api_key'
            save()
            return
        call('review', 'valid69', 'pooled')
        state['valid_execution_check'] = 'passed_without_parameter_selection'
        save()
        with ThreadPoolExecutor(max_workers=1) as workers:
            jobs = [workers.submit(call, 'review', 'valid69', 'independent')]
            for cohort in ('prime57', 'mega141'):
                call('generation', cohort)
                jobs.append(workers.submit(call, 'review', cohort, 'all'))
            for job in jobs:
                job.result()
        state['status'] = 'generation_and_fresh_review_complete'
        save()
    except BaseException as exc:
        state['status'] = 'needs_attention'
        state['error'] = type(exc).__name__
        save()
        raise
    finally:
        lock.unlink()


if __name__ == '__main__':
    main()
