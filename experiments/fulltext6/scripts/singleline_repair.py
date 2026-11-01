"""CPU-only input formatting and deterministic edits for local_singleline_v1."""
import json
import re


ACTIONS = {"REPLACE_LINE", "REPLACE_OPERATOR", "REPLACE_CONSTANT", "REPLACE_API"}
TOKEN = re.compile(
    r'//[^\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|'
    r'0[xX][0-9a-fA-F]+\w*|\d+(?:\.\d+)?\w*|[A-Za-z_]\w*|'
    r'>>=|<<=|->|\+\+|--|&&|\|\||==|!=|<=|>=|<<|>>|\S'
)
OPERATORS = {"<", ">", "<=", ">=", "==", "!=", "+", "-", "*", "/", "%",
             "&", "|", "^", "&&", "||", "<<", ">>", "!", "~"}


def infer_action(old, new):
    """Conservative token-diff labels; generic edits remain REPLACE_LINE."""
    a, b = TOKEN.findall(old), TOKEN.findall(new)
    if len(a) == len(b):
        changed = [i for i, (x, y) in enumerate(zip(a, b)) if x != y]
        if len(changed) == 1:
            i = changed[0]
            if a[i] in OPERATORS and b[i] in OPERATORS:
                return "REPLACE_OPERATOR"
            if a[i][:1].isdigit() and b[i][:1].isdigit():
                return "REPLACE_CONSTANT"
            if (i + 1 < len(a) and a[i + 1] == b[i + 1] == "("
                    and a[i].isidentifier() and b[i].isidentifier()
                    and a[i] not in {"if", "for", "while", "switch", "sizeof"}
                    and b[i] not in {"if", "for", "while", "switch", "sizeof"}):
                return "REPLACE_API"
    return "REPLACE_LINE"


def model_input(code, line_index, cwe, radius=8, full=False):
    lines = code.splitlines()
    if not 0 <= line_index < len(lines):
        raise ValueError("invalid_location")
    left, right = (0, len(lines)) if full else (
        max(0, line_index - radius), min(len(lines), line_index + radius + 1))
    selected = lines[left:line_index] + ["<vul_start>", lines[line_index], "<vul_end>"] + lines[line_index + 1:right]
    # Retain the source function signature, without consulting the reference.
    signature_end = next((i + 1 for i, line in enumerate(lines) if "{" in line), 1)
    prefix = ""
    if left:
        prefix = "\n".join(lines[:min(left, signature_end)]) + "\n/* omitted source lines */\n"
    context = prefix + "\n".join(selected)
    instruction = (
        "Repair the marked line of this C/C++ function. The location is supplied. "
        "Return only JSON with action and replacement. action must be one of "
        + ", ".join(sorted(ACTIONS)) + ". replacement is the code replacing the marked line; "
        "it may contain multiple lines. Preserve indentation and valid-input behavior. "
        "Do not repeat the surrounding code or the markers."
    )
    return instruction + "\nCWE: " + ", ".join(cwe) + "\n" + context, left, right


def render(case, prediction):
    """Apply only at the supplied line; reject malformed, empty and no-op edits."""
    edit = json.loads(prediction) if isinstance(prediction, str) else prediction
    if not isinstance(edit, dict) or set(edit) != {"action", "replacement"}:
        raise ValueError("invalid_edit_schema")
    if not isinstance(edit["action"], str) or edit["action"] not in ACTIONS:
        raise ValueError("unknown_action")
    replacement = edit["replacement"]
    if not isinstance(replacement, str) or not replacement.strip():
        raise ValueError("empty_replacement")
    if "<vul_start>" in replacement or "<vul_end>" in replacement:
        raise ValueError("markers_in_replacement")
    lines = case["vulnerable_code"].splitlines(keepends=True)
    start, end = case["edit_start"], case["edit_end"]
    if type(start) is not int or type(end) is not int or not 0 <= start < end <= len(lines):
        raise ValueError("invalid_location")
    if end != start + 1:
        raise ValueError("not_single_line")
    original = lines[start]
    newline = "\r\n" if original.endswith("\r\n") else "\n" if original.endswith("\n") else ""
    replacement = replacement.rstrip("\r\n") + newline
    if replacement == original:
        raise ValueError("unchanged_edit")
    return "".join(lines[:start]) + replacement + "".join(lines[end:])
