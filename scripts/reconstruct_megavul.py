"""Reconstruct the frozen 141 inputs from the separately downloaded raw MegaVul mirror."""
import argparse
from difflib import SequenceMatcher
import hashlib
import json
from pathlib import Path

import ijson
import singleline_repair

ROOT = Path(__file__).resolve().parents[1]


def file_sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(8 * 1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--megavul-json', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if args.out.exists():
        raise ValueError('Output directory must not exist')
    source = json.loads((ROOT / 'provenance/megavul_source.json').read_text())
    if args.megavul_json.stat().st_size != source['bytes'] or file_sha(args.megavul_json) != source['sha256']:
        raise ValueError('MegaVul source does not match the recorded raw mirror')
    metadata = [json.loads(s) for s in (ROOT / 'data/splits/megavul/evaluation141.jsonl').read_text().splitlines()]
    needed = {r['source_row']: r for r in metadata}
    found = {}
    with args.megavul_json.open('rb') as stream:
        for index, row in enumerate(ijson.items(stream, 'item', use_float=True)):
            if index in needed:
                meta = needed[index]
                before, after = row['func_before'], row['func']
                if row['commit_hash'] != meta['commit_id'] or digest(before) != meta['vulnerable_sha256'] or digest(after) != meta['fixed_sha256']:
                    raise ValueError(f'Endpoint identity mismatch at source row {index}')
                found[index] = (before, after)
            if len(found) == len(needed):
                break
    if len(found) != 141:
        raise ValueError('Not all 141 source rows were found')
    inputs, references = [], []
    for meta in metadata:
        before, after = found[meta['source_row']]
        local, left, right = singleline_repair.model_input(before, meta['edit_start'], meta['cwe'])
        full, _, _ = singleline_repair.model_input(before, meta['edit_start'], meta['cwe'], full=True)
        if digest(local) != meta['input_local_sha256'] or digest(full) != meta['input_full_sha256']:
            raise ValueError('Frozen prompt hash mismatch')
        values = dict(sample_id=meta['sample_id'], split='unassigned', cwe=meta['cwe'],
                      vulnerable_code=before, edit_start=meta['edit_start'], edit_end=meta['edit_end'],
                      context_start=left, context_end=right, input_local=local, input_full=full,
                      input_local_sha256=digest(local), input_full_sha256=digest(full),
                      project=meta['project'], source_file=meta['source_file'])
        case = {k: values[k] for k in meta['input_fields']}
        changes = [op for op in SequenceMatcher(None, before.splitlines(), after.splitlines(), autojunk=False).get_opcodes()
                   if op[0] != 'equal']
        if len(changes) != 1:
            raise ValueError('Expected one reference edit')
        tag, start, end, new_start, new_end = changes[0]
        if (tag, start, end, new_end - new_start) != ('replace', meta['edit_start'], meta['edit_end'], 1):
            raise ValueError('Reference edit coordinates differ')
        action = meta['reference_metadata']['action']
        target = json.dumps({'action': action, 'replacement': after.splitlines()[new_start]}, ensure_ascii=False)
        if singleline_repair.render(case, target) != after:
            raise ValueError('Reference rendering differs')
        reference = dict(meta['reference_metadata'], fixed_code=after, target=target)
        inputs.append(case)
        references.append({k: reference[k] for k in meta['reference_fields']})
    expected = json.loads((ROOT / 'provenance/megavul_reconstruction.json').read_text())
    outputs = {}
    for name, records in [('inputs_pool.jsonl', inputs), ('references_pool.jsonl', references)]:
        raw = ''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in records).encode()
        if name == 'inputs_pool.jsonl' and expected['inputs_newline'] == 'CRLF':
            raw = raw.replace(b'\n', b'\r\n')
        if hashlib.sha256(raw).hexdigest() != expected[name]:
            raise ValueError(f'Reconstruction checksum mismatch: {name}')
        outputs[name] = raw
    args.out.mkdir(parents=True)
    for name, raw in outputs.items():
        (args.out / name).write_bytes(raw)
    print(json.dumps({'samples': len(inputs), 'files': list(outputs), 'checksums_verified': True}))


if __name__ == '__main__':
    main()
