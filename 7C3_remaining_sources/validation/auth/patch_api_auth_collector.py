from __future__ import annotations

import re
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
MAIN_PATH = PROJECT_ROOT / "api" / "main.py"


def function_slice(text: str, function_name: str):
    pattern = re.compile(rf"(?m)^def\s+{re.escape(function_name)}\s*\(")
    match = pattern.search(text)

    if not match:
        raise RuntimeError(
            f"Function {function_name} was not found in api/main.py"
        )

    start = match.start()

    next_route = re.search(
        r"(?m)^@app\.",
        text[match.end():],
    )

    if next_route:
        end = match.end() + next_route.start()
    else:
        end = len(text)

    return start, end, text[start:end]


def ensure_dict_entry(
    block: str,
    variable_name: str,
    key: str,
    value_literal: str,
) -> str:

    dict_pattern = re.compile(
        rf"(?ms)(^\s*{re.escape(variable_name)}\s*=\s*\{{)(.*?)(^\s*\}})"
    )

    match = dict_pattern.search(block)

    if not match:
        raise RuntimeError(
            f"Unable to locate dictionary {variable_name}"
        )

    body = match.group(2)

    key_pattern = re.compile(
        rf"(?m)^\s*[\"']{re.escape(key)}[\"']\s*:"
    )

    if key_pattern.search(body):
        return block

    entry_match = re.search(
        r"(?m)^(\s*)[\"'][^\"']+[\"']\s*:",
        body,
    )

    indent = entry_match.group(1) if entry_match else "            "

    addition = f'{indent}"{key}": {value_literal},\n'
    new_body = body + addition

    return (
        block[:match.start(2)]
        + new_body
        + block[match.end(2):]
    )


def patch_live_telemetry(text: str) -> str:
    start, end, block = function_slice(
        text,
        "get_live_telemetry",
    )

    block = ensure_dict_entry(
        block,
        "collectors",
        "auth",
        "False",
    )

    block = re.sub(
        r"healthy_count\s*==\s*4\b",
        "healthy_count == len(collectors)",
        block,
    )

    block = re.sub(
        r"([\"']expected_collector_count[\"']\s*:\s*)4\b",
        r"\1len(collectors)",
        block,
    )

    if not re.search(
        r"[\"']auth[\"']\s*:\s*False",
        block,
    ):
        raise RuntimeError(
            "Failed to add auth collector to /telemetry/live"
        )

    if "healthy_count == len(collectors)" not in block:
        raise RuntimeError(
            "Failed to make live collector health count dynamic"
        )

    if not re.search(
        r"[\"']expected_collector_count[\"']\s*:\s*len\(collectors\)",
        block,
    ):
        raise RuntimeError(
            "Failed to make expected_collector_count dynamic"
        )

    print("[OK] /telemetry/live collector map includes auth")
    print("[OK] /telemetry/live health count is dynamic")

    return text[:start] + block + text[end:]


def patch_endpoint_overview(text: str) -> str:
    start, end, block = function_slice(
        text,
        "endpoint_overview",
    )

    block = ensure_dict_entry(
        block,
        "collector_states",
        "auth",
        '"OFFLINE"',
    )

    if not re.search(
        r"[\"']auth[\"']\s*:\s*[\"']OFFLINE[\"']",
        block,
    ):
        raise RuntimeError(
            "Failed to add auth collector to /endpoint/overview"
        )

    print("[OK] /endpoint/overview collector map includes auth")

    return text[:start] + block + text[end:]


def main():
    if not MAIN_PATH.exists():
        raise RuntimeError(
            f"api/main.py not found at {MAIN_PATH}"
        )

    original = MAIN_PATH.read_text(
        encoding="utf-8",
    )

    updated = patch_live_telemetry(
        original
    )

    updated = patch_endpoint_overview(
        updated
    )

    backup_path = MAIN_PATH.with_suffix(
        ".py.auth_hook_backup"
    )

    if not backup_path.exists():
        backup_path.write_text(
            original,
            encoding="utf-8",
        )
        print(f"[BACKUP] {backup_path}")

    MAIN_PATH.write_text(
        updated,
        encoding="utf-8",
    )

    print(f"[DONE] Updated {MAIN_PATH}")


if __name__ == "__main__":
    main()
