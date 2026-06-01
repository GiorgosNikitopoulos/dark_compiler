from __future__ import annotations

import hashlib
import re

from .models import ChangedFunction

DIFF_FILE_RE = re.compile(r"^\+\+\+\s+b/(.+)$")
HUNK_RE = re.compile(r"^@@.*@@\s*(.*)$")


def changed_functions_from_diff(item_id: str, patch_diff: str) -> list[ChangedFunction]:
    if not patch_diff.strip():
        return []

    current_file = ""
    out: list[ChangedFunction] = []
    seen: set[str] = set()
    for raw_line in patch_diff.splitlines():
        file_match = DIFF_FILE_RE.match(raw_line)
        if file_match:
            current_file = file_match.group(1).strip()
            continue

        hunk_match = HUNK_RE.match(raw_line)
        if not hunk_match:
            continue

        header = hunk_match.group(1).strip() or "unknown_scope"
        function_name = header.split("(")[0].strip() or "unknown_function"
        dedup_key = f"{current_file}:{header}"
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        digest = hashlib.sha256(f"{item_id}:{dedup_key}".encode("utf-8")).hexdigest()[:20]
        out.append(
            ChangedFunction(
                function_id=digest,
                file_path=current_file or "unknown_file",
                function_name=function_name,
                hunk_header=header,
            )
        )
    return out
