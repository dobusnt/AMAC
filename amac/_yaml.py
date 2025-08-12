import json
import re
from typing import Any, Tuple, List

def safe_load(stream: Any) -> Any:
    """A tiny YAML subset parser used for tests.

    Supports mappings, lists, and simple scalar types (str, int, float,
    booleans, null) with ``#`` comments. This is not a full YAML
    implementation but is sufficient for the config files used in tests.
    """
    if hasattr(stream, 'read'):
        text = stream.read()
    else:
        text = str(stream)
    lines = _strip_comments(text).splitlines()
    data, _ = _parse_block(lines, 0, 0)
    return data

def _strip_comments(text: str) -> str:
    out_lines = []
    for line in text.splitlines():
        in_single = False
        in_double = False
        new_line = []
        for ch in line:
            if ch == "'" and not in_double:
                in_single = not in_single
            elif ch == '"' and not in_single:
                in_double = not in_double
            elif ch == '#' and not in_single and not in_double:
                break
            new_line.append(ch)
        out_lines.append(''.join(new_line))
    return '\n'.join(out_lines)

def _parse_block(lines: List[str], idx: int, indent: int) -> Tuple[Any, int]:
    mapping = {}
    sequence = None
    n = len(lines)
    while idx < n:
        raw = lines[idx]
        if not raw.strip():
            idx += 1
            continue
        cur_indent = len(raw) - len(raw.lstrip(' '))
        if cur_indent < indent:
            break
        line = raw.strip()
        if line.startswith('- '):
            if mapping:
                raise ValueError('mixing list and dict at same level is unsupported')
            if sequence is None:
                sequence = []
            item = line[2:].strip()
            if not item:
                idx += 1
                val, idx = _parse_block(lines, idx, cur_indent + 2)
                sequence.append(val)
                continue
            if item.endswith(':') or ': ' in item:
                # allow "- key: value" style
                if item.endswith(':'):
                    key = item[:-1].strip()
                    idx += 1
                    val, idx = _parse_block(lines, idx, cur_indent + 4)
                    sequence.append({key: val})
                    continue
                else:
                    key, rest = item.split(':', 1)
                    key = key.strip()
                    rest = rest.strip()
                    val = _parse_scalar(rest)
                    idx += 1
                    sequence.append({key: val})
                    continue
            sequence.append(_parse_scalar(item))
            idx += 1
        else:
            if sequence is not None:
                raise ValueError('mixing list and dict at same level is unsupported')
            if ':' not in line:
                raise ValueError(f'Invalid line: {line!r}')
            key, rest = line.split(':', 1)
            key = key.strip()
            rest = rest.strip()
            if rest:
                mapping[key] = _parse_scalar(rest)
                idx += 1
            else:
                idx += 1
                val, idx = _parse_block(lines, idx, cur_indent + 2)
                mapping[key] = val
    return (sequence if sequence is not None else mapping), idx

def _parse_scalar(token: str) -> Any:
    token = token.strip()
    if token == '' or token.lower() in {'null', 'none'}:
        return None
    if token.lower() == 'true':
        return True
    if token.lower() == 'false':
        return False
    if token.startswith('[') or token.startswith('{'):
        try:
            return json.loads(token)
        except json.JSONDecodeError:
            pass
    if re.fullmatch(r'-?\d+', token):
        try:
            return int(token)
        except ValueError:
            pass
    if re.fullmatch(r'-?\d+\.\d*', token):
        try:
            return float(token)
        except ValueError:
            pass
    if (token.startswith('"') and token.endswith('"')) or (token.startswith("'") and token.endswith("'")):
        return token[1:-1]
    return token
