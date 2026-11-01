"""Run the frozen fulltext baseline, with Valid review gating both test cohorts."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import subprocess
import sys


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
    lock = run / 'run.lock'
    if lock.exists():
        previous = json.loads(lock.read_text())
        try:
            os.kill(previous['pid'], 0)
        except ProcessLookupError:
            lock.unlink()
        else:
            raise ValueError('experiment_already_running')
    with lock.open('x') as stream:
        json.dump(dict(pid=os.getpid()), stream)
    logs = run / 'logs'
    logs.mkdir(exist_ok=True)
    state = dict(status='running', started_utc=datetime.now(timezone.utc).isoformat(),
        stages={}, old_results_changed=False, additional_training=False, credentials_persisted=False)

    def save():
        state['updated_utc'] = datetime.now(timezone.utc).isoformat()
        temporary = run / 'STATUS.tmp'
        temporary.write_text(json.dumps(state, indent=2) + '\n')
        temporary.replace(run / 'STATUS.json')

    def call(kind, cohort):
        name = kind + '_' + cohort
        command = [sys.executable, '-u', str(run / 'runtime' / (kind + '.py'))]
        if kind == 'generate':
            command += ['--root', str(args.root), '--out', str(run / cohort), '--arm', 'original_fulltext']
        else:
            command += ['--run', str(run), '--cohort', cohort, '--stage', 'pooled']
        env = dict(os.environ, HF_HUB_OFFLINE='1', TRANSFORMERS_OFFLINE='1', TOKENIZERS_PARALLELISM='false')
        if kind == 'generate':
            env.pop('QWEN_API_KEY', None)
        state['stages'][name] = dict(status='running', command=command)
        save()
        with (logs / (name + '.log')).open('a') as stream:
            result = subprocess.run(command, env=env, stdout=stream, stderr=subprocess.STDOUT)
        state['stages'][name].update(status='complete' if result.returncode == 0 else 'runtime_failed', exit_code=result.returncode)
        save()
        if result.returncode:
            raise RuntimeError(name + '_failed')

    try:
        environment = dict(recorded_utc=datetime.now(timezone.utc).isoformat(), python=sys.version,
            executable=sys.executable, packages={name:importlib.metadata.version(name) for name in
                ['torch','transformers','tokenizers','openai','tree-sitter','tree-sitter-c','tree-sitter-cpp']},
            gpu=subprocess.run(['nvidia-smi','--query-gpu=name,memory.total,driver_version','--format=csv,noheader'], capture_output=True, text=True).stdout.strip(),
            checkpoint_verification='Every file hashed before each cohort generation; local files only')
        if not (run / 'ENVIRONMENT.json').exists():
            (run / 'ENVIRONMENT.json').write_text(json.dumps(environment, indent=2) + '\n')
        save()
        for cohort in ['valid69', 'prime57', 'mega141']:
            call('generate', cohort)
            if not os.environ.get('QWEN_API_KEY'):
                state['status'] = 'generation_complete_missing_api_key'
                save()
                return
            call('review', cohort)
            checked = json.loads((run / cohort / 'review/POOLED_STATUS.json').read_text())
            if not checked['complete']:
                raise RuntimeError('review_gate_incomplete')
            if cohort == 'valid69':
                state['valid_execution_check'] = 'passed_without_parameter_selection'
                save()
        state['status'] = 'generation_and_review_complete'
        save()
    except BaseException as exc:
        state.update(status='needs_attention', error=type(exc).__name__)
        save()
        raise
    finally:
        lock.unlink()


if __name__ == '__main__':
    main()
