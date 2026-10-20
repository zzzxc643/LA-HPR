"""Known-region C/C++ editing with original line coordinates and exact rendering."""
import json

from local_candidate_judge import unique_object


def checked_regions(case):
    lines = case["vulnerable_code"].splitlines(keepends=True)
    regions = case["edit_regions"]
    if not isinstance(regions, list) or not regions:
        raise ValueError("missing_edit_regions")
    previous_start, previous_end = -1, 0
    for index, region in enumerate(regions, 1):
        if not isinstance(region, dict) or set(region) != {"slot", "start", "end"}:
            raise ValueError("invalid_region_schema")
        slot, start, end = (region[k] for k in ("slot", "start", "end"))
        if any(type(x) is not int for x in (slot, start, end)):
            raise ValueError("invalid_region_coordinates")
        if slot != index or not 0 <= start <= end <= len(lines):
            raise ValueError("invalid_region_coordinates")
        if start < previous_end or start <= previous_start:
            raise ValueError("overlapping_or_unordered_regions")
        previous_start, previous_end = start, end
    return lines, regions


def render(case, prediction):
    lines, regions = checked_regions(case)
    value = json.loads(prediction, object_pairs_hook=unique_object) if isinstance(prediction, str) else prediction
    if not isinstance(value, dict) or set(value) != {"edits"} or not isinstance(value["edits"], list):
        raise ValueError("invalid_block_edit_schema")
    edits = {}
    for edit in value["edits"]:
        if not isinstance(edit, dict) or set(edit) != {"slot", "replacement"}:
            raise ValueError("invalid_block_edit_schema")
        slot, replacement = edit["slot"], edit["replacement"]
        if type(slot) is not int or slot in edits or not 1 <= slot <= len(regions):
            raise ValueError("invalid_or_duplicate_slot")
        if not isinstance(replacement, str):
            raise ValueError("replacement_must_be_string")
        if "<edit_" in replacement or "</edit_" in replacement:
            raise ValueError("markers_in_replacement")
        edits[slot] = replacement
    if set(edits) != {r["slot"] for r in regions}:
        raise ValueError("missing_edit_slot")
    parts, cursor = [], 0
    for region in regions:
        parts.extend(("".join(lines[cursor:region["start"]]), edits[region["slot"]]))
        cursor = region["end"]
    parts.append("".join(lines[cursor:]))
    code = "".join(parts)
    if not code.strip() or code == case["vulnerable_code"]:
        raise ValueError("empty_or_unchanged_patch")
    return code


def model_input(case, radius=8):
    lines, regions = checked_regions(case)
    windows = []
    for region in regions:
        left = max(0, region["start"] - radius)
        right = min(len(lines), max(region["end"], region["start"] + 1) + radius)
        if windows and left <= windows[-1][1]:
            windows[-1][1] = max(windows[-1][1], right)
        else:
            windows.append([left, right])
    signature_end = next((i + 1 for i, line in enumerate(lines) if "{" in line), 1)
    context = []
    if windows[0][0]:
        context.extend(line.rstrip("\r\n") for line in lines[:min(signature_end, windows[0][0])])
    starts = {r["start"]: r for r in regions}
    ends = {r["end"]: r for r in regions if r["start"] != r["end"]}
    for left, right in windows:
        if left:
            context.append("/* omitted original lines */")
        for index in range(left, right + 1):
            if index in ends:
                context.append(f"</edit_{ends[index]['slot']}>")
            if index in starts:
                region = starts[index]
                context.append(f"<edit_{region['slot']}>")
                if region["start"] == region["end"]:
                    context.append(f"</edit_{region['slot']}>")
            if index < right:
                context.append(lines[index].rstrip("\r\n"))
    instruction = (
        "Repair the marked regions of this C/C++ function. All locations are supplied. "
        "Return only JSON: {\"edits\":[{\"slot\":1,\"replacement\":\"code\"}]}. "
        "Include every supplied slot exactly once. Each replacement replaces only that marked region, "
        "in original coordinates. An empty marked region is an insertion point; an empty replacement "
        "deletes a region. Preserve indentation, required line endings and valid-input behavior. "
        "Do not repeat surrounding code or markers.\nCWE: " + ", ".join(case["cwe"])
    )
    return instruction + "\n" + "\n".join(context)
