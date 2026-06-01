from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .models import CommitPair


def append_jsonl(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload, sort_keys=True) + "\n")


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


def _read_json(path: Path) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    return []


def _item_id(repo_url: str, parent_sha: str, patch_sha: str) -> str:
    base = f"{repo_url}:{parent_sha}:{patch_sha}"
    return hashlib.sha256(base.encode("utf-8")).hexdigest()[:16]


def _normalize_repo_url(value: Any) -> str | None:
    if not value:
        return None
    repo = str(value).strip()
    if not repo:
        return None
    if repo.startswith(("http://", "https://", "git@")):
        return repo
    if "/" in repo:
        return f"https://github.com/{repo}"
    return repo


def _extract_parent_sha(row: dict[str, Any]) -> str | None:
    direct = row.get("parent_sha") or row.get("vuln_sha") or row.get("base_sha")
    if direct:
        return str(direct)

    parents = row.get("parents")
    if isinstance(parents, list) and parents:
        first = parents[0]
        if isinstance(first, str) and first:
            return first
        if isinstance(first, dict):
            sha = first.get("sha")
            if sha:
                return str(sha)
    return None


def _extract_commit_pair(row: dict[str, Any]) -> CommitPair | None:
    repo_url = _normalize_repo_url(row.get("repo_url") or row.get("repo") or row.get("repository"))
    patch_sha = row.get("patch_sha") or row.get("fix_sha") or row.get("sha")
    parent_sha = _extract_parent_sha(row)
    if not (repo_url and patch_sha and parent_sha):
        return None

    patch_ref = str(row.get("patch_ref") or patch_sha)
    patch_diff = str(row.get("patch_diff") or row.get("patch") or row.get("diff") or "")
    return CommitPair(
        item_id=_item_id(str(repo_url), str(parent_sha), str(patch_sha)),
        repo_url=str(repo_url),
        parent_sha=str(parent_sha),
        patch_sha=str(patch_sha),
        patch_ref=patch_ref,
        patch_diff=patch_diff,
        metadata=row,
    )


def load_commit_pairs(input_results_dir: Path) -> list[CommitPair]:
    candidate_files = [
        input_results_dir / "accepted_patches.jsonl",
        input_results_dir / "paired_objects.jsonl",
    ]
    rows: list[dict[str, Any]] = []
    for path in candidate_files:
        if path.exists():
            if path.suffix == ".jsonl":
                rows.extend(_read_jsonl(path))
            elif path.suffix == ".json":
                rows.extend(_read_json(path))

    pairs: list[CommitPair] = []
    seen: set[str] = set()
    for row in rows:
        pair = _extract_commit_pair(row)
        if not pair:
            continue
        if pair.item_id in seen:
            continue
        seen.add(pair.item_id)
        pairs.append(pair)
    return pairs
