"""Record the actual local engineering-check environment used for this run."""
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
from pathlib import Path
import subprocess

ROOT = Path('/tmp/megavul_model_repair_20261022_v1/compiler')
folder = ROOT / 'environment'
folder.mkdir(exist_ok=True)
commands = [
    ('clang', ['clang', '--version']),
    ('clang_cpp', ['clang++', '--version']),
    ('kernel', ['uname', '-a']),
    ('distribution', ['cat', '/etc/os-release']),
    ('python', ['python3', '--version']),
    ('cmake', ['cmake', '--version']),
    ('ninja', ['ninja', '--version']),
]
records = {}
for name, argv in commands:
    process = subprocess.run(argv, capture_output=True)
    data = process.stdout + process.stderr
    path = folder / (name + '.log')
    path.write_bytes(data)
    records[name] = dict(argv=argv, exit_code=process.returncode, log=str(path),
                         log_sha256=hashlib.sha256(data).hexdigest(), output=data.decode(errors='replace'))
versions = {name: importlib.metadata.version(name) for name in ('tree-sitter', 'tree-sitter-c', 'tree-sitter-cpp')}
result = dict(recorded_utc=datetime.now(timezone.utc).isoformat(), commands=records, python_packages=versions,
              scope='Local Docker engineering checks for the new 141-pair experiment; independent of inference host and original 57-case checker.')
(ROOT / 'ENVIRONMENT.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result), flush=True)
