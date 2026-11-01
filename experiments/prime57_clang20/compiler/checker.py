"""Reuse genuine project commands for controls and generated function patches."""
import argparse
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
import difflib
import fcntl
import hashlib
import json
from pathlib import Path
import re
import shutil
import sys

sys.path.insert(0, '/inputs')
import run_compiler_batch as batch
import tree_sitter
import tree_sitter_c
import tree_sitter_cpp

CHECKER_VERSION = 'generated_function_v2_all_changed_token_lines'


def locate_context(data, code, language):
    """Some frozen57 snippets omit the genuine declaration prefix; retain it verbatim."""
    registry = Path(__file__).resolve().parent / 'clang_ast_locators.json'
    if registry.exists():
        key = sha(data) + ':' + sha(code.encode())
        captured = read(registry).get(key)
        if captured:
            return captured['snippet_start'], captured['function_end'], captured['body_start'] + 1, captured
    try:
        start, end, brace = batch.locate(data, code, language)
        return start, end, brace, dict(mode='complete_ast_function', retained_declaration_prefix='',
                                     snippet_start=start, function_end=end, body_start=brace - 1,
                                     full_declaration_tokens=batch.tokens(data[start:brace - 1].decode('utf-8', errors='surrogateescape')))
    except ValueError:
        text = data.decode('utf-8', errors='surrogateescape')
        matches = [m for m in batch.TOKEN.finditer(text)
                   if not m.group().isspace() and not m.group().startswith(('//', '/*'))]
        wanted = batch.tokens(code)
        values = [m.group() for m in matches]
        starts = [i for i, value in enumerate(values) if value == wanted[0]
                  and values[i:i + len(wanted)] == wanted]
        if len(starts) != 1:
            raise ValueError('unique_frozen_token_region_matches=' + str(len(starts)))
        first = starts[0]
        start = len(text[:matches[first].start()].encode('utf-8', errors='surrogateescape'))
        end = len(text[:matches[first + len(wanted) - 1].end()].encode('utf-8', errors='surrogateescape'))
        brace_index = first + wanted.index('{')
        brace = len(text[:matches[brace_index].end()].encode('utf-8', errors='surrogateescape'))
        module = tree_sitter_cpp if language.lower() in ('cpp', 'c++') else tree_sitter_c
        parser = tree_sitter.Parser(tree_sitter.Language(module.language()))
        stack = [parser.parse(data).root_node]
        enclosing = []
        while stack:
            node = stack.pop()
            if node.type == 'function_definition':
                body = node.child_by_field_name('body')
                declaration = node.child_by_field_name('declarator')
                if (body is not None and declaration is not None and node.start_byte <= start < body.start_byte
                        and node.end_byte == end and body.start_byte + 1 == brace):
                    enclosing.append(node)
            stack.extend(node.named_children)
        if len(enclosing) != 1:
            raise ValueError('complete_enclosing_ast_function_matches=' + str(len(enclosing)))
        node = enclosing[0]
        declaration = node.child_by_field_name('declarator')
        actual_declarator = batch.tokens(data[declaration.start_byte:declaration.end_byte].decode('utf-8', errors='surrogateescape'))
        def declared_name(function, payload):
            stack = [function.child_by_field_name('declarator')]
            while stack:
                child = stack.pop()
                if child.type == 'function_declarator':
                    name = child.child_by_field_name('declarator')
                    return batch.tokens(payload[name.start_byte:name.end_byte].decode())
                stack.extend(child.named_children)
            raise ValueError('target_function_declarator_missing')
        prefix = data[node.start_byte:start].decode('utf-8', errors='surrogateescape')
        snippet_data = (prefix + code).encode()
        snippet_tree = parser.parse(snippet_data)
        stack = [snippet_tree.root_node]
        snippet_definitions = []
        while stack:
            child = stack.pop()
            if child.type == 'function_definition':
                snippet_definitions.append(child)
            stack.extend(child.named_children)
        assert len(snippet_definitions) == 1, 'frozen_snippet_function_count'
        actual_name = declared_name(node, data)
        assert declared_name(snippet_definitions[0], snippet_data) == actual_name, 'frozen_snippet_function_name_mismatch'
        metadata = dict(mode='unique_token_region_with_complete_enclosing_ast_function',
                        retained_declaration_prefix=prefix, ast_function_start=node.start_byte,
                        snippet_start=start, function_end=end, body_start=brace - 1,
                        actual_declarator_tokens=actual_declarator,
                        actual_function_name_tokens=actual_name,
                        full_declaration_tokens=batch.tokens(data[node.start_byte:brace - 1].decode('utf-8', errors='surrogateescape')))
        return start, end, brace, metadata


def locate(data, code, language):
    return locate_context(data, code, language)[:3]


def read(path):
    return json.loads(path.read_text())


def sha(data):
    return hashlib.sha256(data).hexdigest()


def checked_run(case, target, data, path, marker=None):
    target.write_bytes(data)
    result = batch.run(case['argv'], case['cwd'], path, timeout=90)
    result['source_sha256'] = sha(data)
    if marker:
        result['marker'] = marker
        result['marker_seen'] = marker.encode() in path.read_bytes()
    return result


def active(result):
    return result['exit_code'] != 0 and not result['timed_out'] and result['marker_seen']


def edit_marker(data, code, language, line, marker):
    start, end, _ = locate(data, code, language)
    fragment = data[start:end].decode('utf-8', errors='surrogateescape')
    matches = [m for m in batch.TOKEN.finditer(fragment)
               if not m.group().isspace() and not m.group().startswith(('//', '/*'))]
    assert [m.group() for m in matches] == batch.tokens(code)
    token_index = len(batch.tokens('\n'.join(code.splitlines()[:line])))
    offset = matches[token_index].start() if token_index < len(matches) else len(fragment)
    at = start + len(fragment[:offset].encode('utf-8', errors='surrogateescape'))
    return data[:at] + ('\n#error ' + marker + '\n').encode() + data[at:]


def control_logs_intact(record):
    return all(Path(r['log']).is_file() and sha(Path(r['log']).read_bytes()) == r['log_sha256']
               for r in record.get('checks', {}).values())


def controls(case, root, retry=False):
    folder = root / 'controls' / case['source_sample_id']
    result_path = folder / 'result.json'
    if result_path.exists():
        record = read(result_path)
        assert control_logs_intact(record), 'Changed control evidence'
        if (record.get('locator_validation') == 'complete_ast_function_v1'
                and record.get('context_generation') == case.get('context_generation')
                and (not retry or record['status'] == 'controls_pass')):
            return record
    folder.mkdir(parents=True, exist_ok=True)
    if result_path.exists():
        number = len(list(folder.glob('previous_result.*.json'))) + 1
        shutil.copyfile(result_path, folder / ('previous_result.%04d.json' % number))
    number = len(list(folder.glob('attempt_*'))) + 1
    folder = folder / ('attempt_%04d' % number)
    folder.mkdir(exist_ok=True)
    target = Path(case['target'])
    record = dict(sample_id=case['sample_id'], source_sample_id=case['source_sample_id'],
                  snapshot=case['snapshot'], argv=case['argv'], cwd=case['cwd'],
                  target=str(target), status='environment_unavailable', checks={},
                  locator_validation='complete_ast_function_v1', function_locator=case.get('function_locator'))
    record['context_generation'] = case.get('context_generation')
    if case.get('preflight_reason'):
        record.update(reason=case['preflight_reason'], source_not_modified=True)
        batch.save(result_path, record)
        print('control', case['sample_id'], record['status'], record['reason'], flush=True)
        return record
    original_bytes = None
    try:
        assert Path(case['cwd']).is_dir(), 'recorded_working_directory_missing'
        original_bytes = target.read_bytes()
        expected_role = 'original' if case['snapshot'] == 'verified_first_parent' else 'reference'
        assert sha(original_bytes) == case['files'][expected_role]['sha256'], 'snapshot_source_hash_mismatch'
        record['restored_sha256'] = sha(original_bytes)
        changes = [op for op in difflib.SequenceMatcher(None, case['vulnerable_code'].splitlines(),
                   case['fixed_code'].splitlines(), autojunk=False).get_opcodes() if op[0] != 'equal']
        assert len(changes) == 1
        for role, code, line in [('original', case['vulnerable_code'], changes[0][1]),
                                 ('reference', case['fixed_code'], changes[0][3])]:
            data = (root / case['files'][role]['path']).read_bytes()
            assert sha(data) == case['files'][role]['sha256']
            _, _, brace = locate(data, code, case['language'])
            record['checks'][role] = checked_run(case, target, data, folder / (role + '.log'))
            marker = 'MODEL_REPAIR_BODY_ACTIVE_' + case['source_sample_id'] + '_' + role
            marked = data[:brace] + ('\n#error ' + marker + '\n').encode() + data[brace:]
            record['checks'][role + '_body'] = checked_run(case, target, marked, folder / (role + '.body.log'), marker)
            marker = 'MODEL_REPAIR_EDIT_ACTIVE_' + case['source_sample_id'] + '_' + role
            marked = edit_marker(data, code, case['language'], line, marker)
            record['checks'][role + '_edit'] = checked_run(case, target, marked, folder / (role + '.edit.log'), marker)
        positive = all(record['checks'][role]['exit_code'] == 0 and not record['checks'][role]['timed_out']
                       for role in ('original', 'reference'))
        negative = all(active(record['checks'][role + '_' + kind])
                       for role in ('original', 'reference') for kind in ('body', 'edit'))
        record['status'] = 'controls_pass' if positive and negative else 'environment_control_failed'
    except Exception as exc:
        record['reason'] = type(exc).__name__ + ': ' + str(exc)
    finally:
        if original_bytes is not None:
            target.write_bytes(original_bytes)
            assert sha(target.read_bytes()) == sha(original_bytes), 'Source restoration failed'
            record['source_restored'] = True
    batch.save(result_path, record)
    print('control', case['sample_id'], record['status'], record.get('reason', ''), flush=True)
    return record


def function_shape(code, language):
    module = tree_sitter_cpp if language.lower() in ('cpp', 'c++') else tree_sitter_c
    data = code.encode()
    parser = tree_sitter.Parser(tree_sitter.Language(module.language()))
    tree = parser.parse(data)
    definitions = []
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type == 'function_definition':
            definitions.append(node)
        stack.extend(node.named_children)
    if len(definitions) != 1:
        raise ValueError('generated_function_definition_count=' + str(len(definitions)))
    node = definitions[0]
    if batch.tokens((data[:node.start_byte] + data[node.end_byte:]).decode()):
        raise ValueError('generated_tokens_outside_target_function')
    body = node.child_by_field_name('body')
    declarator = node.child_by_field_name('declarator')
    if body is None or declarator is None:
        raise ValueError('generated_function_has_no_body_or_declarator')
    return batch.tokens(data[node.start_byte:body.start_byte].decode()), body.start_byte + 1


def changed_token_positions(before, after):
    def matches(text):
        return [m for m in batch.TOKEN.finditer(text)
                if not m.group().isspace() and not m.group().startswith(('//', '/*'))]
    old, new = matches(before), matches(after)
    edits = [op for op in difflib.SequenceMatcher(None, [m.group() for m in old],
             [m.group() for m in new], autojunk=False).get_opcodes() if op[0] != 'equal']
    lines = {}
    for _, _, _, start, end in edits:
        indices = range(start, end) if start < end else [min(start, len(new) - 1)]
        for index in indices:
            position = new[index].start()
            line = after.count('\n', 0, position)
            lines.setdefault(line, len(after[:position].encode()))
    return sorted(lines.items())


def candidate(case, item, root, control):
    patch = item.get('patched_code')
    diagnostic = dict(rank=item.get('rank'), candidate_id=item.get('cand_id', item.get('candidate_id')),
                      render_valid=bool(item.get('render_valid')), status='invalid_render')
    if not item.get('render_valid') or not isinstance(patch, str) or not patch:
        return diagnostic
    digest = sha(patch.encode())
    diagnostic['patch_sha256'] = digest
    if batch.tokens(patch) == batch.tokens(case['vulnerable_code']):
        diagnostic['status'] = 'no_op'
        return diagnostic
    try:
        prefix = case.get('function_locator', {}).get('retained_declaration_prefix', '')
        declaration, brace = function_shape(prefix + patch, case['language'])
        brace -= len(prefix.encode())
        expected, _ = function_shape(prefix + case['vulnerable_code'], case['language'])
        if declaration != expected:
            raise ValueError('generated_function_declarator_changed')
    except ValueError as exc:
        diagnostic.update(status='invalid_function_shape', reason=str(exc))
        return diagnostic
    if control['status'] != 'controls_pass':
        diagnostic['status'] = 'environment_unavailable'
        diagnostic['control_status'] = control['status']
        return diagnostic
    folder = root / 'cache' / case['source_sample_id'] / digest
    cached = folder / 'result.json'
    if cached.exists():
        value = read(cached)
        assert control_logs_intact(value), 'Changed candidate evidence'
        if value.get('checker_version') == CHECKER_VERSION and value.get('context_generation') == case.get('context_generation'):
            return dict(diagnostic, **value)
    folder.mkdir(parents=True, exist_ok=True)
    log_folder = folder
    if cached.exists():
        prior = cached.read_bytes()
        (folder / ('previous_result.' + sha(prior)[:16] + '.json')).write_bytes(prior)
        log_folder = folder / ('attempt_%04d' % (len(list(folder.glob('attempt_*'))) + 1))
        log_folder.mkdir(exist_ok=True)
    target = Path(case['target'])
    restored = target.read_bytes()
    assert sha(restored) == control['restored_sha256'], 'Source changed since controls'
    record = dict(source_sample_id=case['source_sample_id'], sample_id=case['sample_id'],
                  patch_sha256=digest, snapshot=case['snapshot'], checker_version=CHECKER_VERSION,
                  activation_scope='Function body and all lines with added substantive tokens; pure deletion hunks check a surviving boundary, not direct activation of removed tokens.',
                  status='environment_unavailable', checks={})
    record['context_generation'] = case.get('context_generation')
    try:
        original = (root / case['files']['original']['path']).read_bytes()
        start, end, _, locator = locate_context(original, case['vulnerable_code'], case['language'])
        record['function_locator'] = locator
        if locator.get('full_declaration_tokens'):
            assert declaration == locator['full_declaration_tokens'], 'actual_complete_function_declaration_changed'
            record['complete_actual_declaration_unchanged'] = True
        generated = original[:start] + patch.encode() + original[end:]
        (folder / 'patched_function.txt').write_text(patch)
        (folder / 'patched.source').write_bytes(generated)
        compiled = checked_run(case, target, generated, log_folder / 'compile.log')
        record['checks']['compile'] = compiled
        if compiled['timed_out']:
            record['status'] = 'compiler_timeout'
        elif compiled['exit_code'] != 0:
            record['status'] = 'compiler_rejected'
        else:
            marker = 'MODEL_PATCH_BODY_ACTIVE_' + case['source_sample_id']
            pos = start + brace
            marked = generated[:pos] + ('\n#error ' + marker + '\n').encode() + generated[pos:]
            record['checks']['body'] = checked_run(case, target, marked, log_folder / 'body.log', marker)
            positions = changed_token_positions(case['vulnerable_code'], patch)
            assert positions, 'No substantive changed tokens'
            record['changed_token_line_count'] = len(positions)
            for number, (line, offset) in enumerate(positions):
                marker = 'MODEL_PATCH_EDIT_ACTIVE_' + case['source_sample_id'] + '_' + str(number)
                at = start + offset
                marked = generated[:at] + ('\n#error ' + marker + '\n').encode() + generated[at:]
                name = 'edit_' + str(number)
                record['checks'][name] = checked_run(case, target, marked, log_folder / (name + '.log'), marker)
                record['checks'][name]['patch_line'] = line
            record['status'] = ('candidate_compile_pass' if all(active(check) for name, check in record['checks'].items() if name != 'compile')
                                else 'candidate_activation_failed')
    except Exception as exc:
        record['reason'] = type(exc).__name__ + ': ' + str(exc)
    finally:
        target.write_bytes(restored)
        assert sha(target.read_bytes()) == sha(restored), 'Source restoration failed'
        record['source_restored'] = True
    batch.save(cached, record)
    return dict(diagnostic, **record)


def run_group(cases, root, candidates, method, retry):
    lock = root / 'locks' / (sha(cases[0]['source_root'].encode()) + '.lock')
    lock.parent.mkdir(exist_ok=True)
    with lock.open('w') as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        for case in cases:
            control = controls(case, root, retry)
            if candidates is None:
                continue
            row = candidates.get(case['sample_id'])
            if row is None:
                continue
            diagnostics = [candidate(case, item, root, control) for item in row['candidates']]
            record = dict(sample_id=case['sample_id'], source_sample_id=case['source_sample_id'], method=method,
                          control_status=control['status'], candidates=diagnostics,
                          input_sha256=sha(json.dumps(row, sort_keys=True, ensure_ascii=False).encode()))
            result_path = root / 'candidate_results' / method / (case['sample_id'] + '.json')
            if result_path.exists():
                previous = result_path.read_bytes()
                archived = result_path.parent / 'previous' / (case['sample_id'] + '.' + sha(previous)[:16] + '.json')
                archived.parent.mkdir(exist_ok=True)
                if not archived.exists():
                    archived.write_bytes(previous)
            batch.save(result_path, record)
            print('candidates', method, case['sample_id'], dict(Counter(v['status'] for v in diagnostics)), flush=True)


def summary(root, total):
    records = [read(path) for path in (root / 'controls').glob('*/result.json')]
    result = dict(total_cases=total, controls_finished=len(records),
                  controls_status_counts=dict(Counter(r['status'] for r in records)), methods={},
                  note='All candidate passes are diagnostics, not system recommendation success.')
    for folder in sorted((root / 'candidate_results').glob('*')):
        rows = [read(path) for path in folder.glob('*.json')]
        result['methods'][folder.name] = dict(samples=len(rows),
            candidate_status_counts=dict(Counter(c['status'] for row in rows for c in row['candidates'])))
    batch.save(root / 'SUMMARY.json', result)
    return result


def audit(root, cases):
    errors, evidence = [], {}
    untouched_unavailable = []
    by_id = {case['source_sample_id']: case for case in cases}
    for case in cases:
        path = root / 'controls' / case['source_sample_id'] / 'result.json'
        if not path.exists():
            continue
        record = read(path)
        if not record.get('source_restored'):
            untouched_unavailable.append(dict(sample_id=case['sample_id'], reason=record.get('reason'),
                                             source_not_modified=bool(record.get('source_not_modified'))))
            continue
        expected_role = 'original' if case['snapshot'] == 'verified_first_parent' else 'reference'
        lock = root / 'locks' / (sha(case['source_root'].encode()) + '.lock')
        with lock.open('w') as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            if sha(Path(case['target']).read_bytes()) != case['files'][expected_role]['sha256']:
                errors.append(dict(sample_id=case['sample_id'], error='source_not_restored'))
    paths = list((root / 'controls').glob('*/result.json')) + list((root / 'cache').glob('*/*/result.json'))
    for path in paths:
        record = read(path)
        case = by_id[record['source_sample_id']]
        evidence[str(path)] = sha(path.read_bytes())
        if record['status'] == 'controls_pass':
            for role in ('original', 'reference'):
                check = record['checks'][role]
                if check['exit_code'] != 0 or check['timed_out'] or check['source_sha256'] != case['files'][role]['sha256']:
                    errors.append(dict(path=str(path), check=role, error='passing_control_positive_invalid'))
        elif record['status'] == 'candidate_compile_pass':
            check = record['checks']['compile']
            if check['exit_code'] != 0 or check['timed_out']:
                errors.append(dict(path=str(path), error='passing_candidate_positive_invalid'))
            if sha((path.parent / 'patched_function.txt').read_bytes()) != record['patch_sha256']:
                errors.append(dict(path=str(path), error='candidate_patch_hash'))
            if sha((path.parent / 'patched.source').read_bytes()) != check['source_sha256']:
                errors.append(dict(path=str(path), error='candidate_translation_unit_hash'))
        for name, check in record.get('checks', {}).items():
            if check['argv'] != case['argv'] or check['cwd'] != case['cwd']:
                errors.append(dict(path=str(path), check=name, error='recorded_project_command_changed'))
            log = Path(check['log'])
            command = log.with_suffix(log.suffix + '.command.json')
            if sha(log.read_bytes()) != check['log_sha256']:
                errors.append(dict(path=str(path), check=name, error='log_hash'))
            metadata = read(command)
            if not all(check[k] == value for k, value in metadata.items()):
                errors.append(dict(path=str(path), check=name, error='command_metadata'))
            if check.get('marker'):
                seen = check['marker'].encode() in log.read_bytes()
                if seen != check['marker_seen']:
                    errors.append(dict(path=str(path), check=name, error='activation_marker_flag_mismatch'))
                if record['status'] in ('controls_pass', 'candidate_compile_pass') and not active(check):
                    errors.append(dict(path=str(path), check=name, error='passing_record_has_inactive_control'))
            evidence[str(log)] = sha(log.read_bytes())
            evidence[str(command)] = sha(command.read_bytes())
    for path in [root / 'clang_ast_locators.json'] + list((root / 'locator_evidence').rglob('*')):
        if path.is_file():
            evidence[str(path)] = sha(path.read_bytes())
    result = dict(errors=errors, audited_cases=len(cases), checked_records=len(paths),
                  untouched_unavailable_sources=untouched_unavailable,
                  restoration_scope='All modified source files; unavailable untouched contexts are listed separately.',
                  source_restoration_verified=not any(e['error'] == 'source_not_restored' for e in errors),
                  evidence_sha256=evidence)
    batch.save(root / 'AUDIT.json', result)
    assert not errors, errors
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--workers', type=int, default=4)
    parser.add_argument('--candidates', type=Path)
    parser.add_argument('--method')
    parser.add_argument('--retry-controls', action='store_true')
    parser.add_argument('--audit-only', action='store_true')
    args = parser.parse_args()
    assert 1 <= args.workers <= 4
    root = args.root
    cases = read(root / 'cases.json')
    if args.audit_only:
        result = audit(root, cases)
        print(json.dumps(dict(audited_cases=result['audited_cases'], checked_records=result['checked_records'], errors=result['errors'])), flush=True)
        return
    candidates = None
    if args.candidates:
        assert args.method and re.fullmatch(r'[A-Za-z0-9_-]+', args.method)
        rows = [json.loads(line) for line in args.candidates.read_text().splitlines() if line.strip()]
        candidates = {r['sample_id']: r for r in rows}
        assert len(candidates) == len(rows), 'Duplicate candidate sample ids'
        assert set(candidates) <= {c['sample_id'] for c in cases}, 'Unknown candidate ids'
        cases = [c for c in cases if c['sample_id'] in candidates]
    groups = defaultdict(list)
    for case in cases:
        groups[case['source_root']].append(case)
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        list(pool.map(lambda items: run_group(items, root, candidates, args.method, args.retry_controls), groups.values()))
    print(json.dumps(summary(root, len(read(root / 'cases.json')))), flush=True)
    audit(root, read(root / 'cases.json'))


if __name__ == '__main__':
    main()
