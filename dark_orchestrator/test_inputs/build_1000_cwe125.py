#!/usr/bin/env python3
"""Build test_inputs/1000_cwe125 from accepted_patches.jsonl (CWE-125 only, mixed repos)."""

from __future__ import annotations

import json
import random
import re
from collections import defaultdict
from pathlib import Path

CPP_EXT = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh", ".hxx"}
EXCLUDE_REPO_RE = re.compile(
    r"("
    r"linux-mailinglist-archives|"
    r"/vulns$|"
    r"^yifengyou/|"
    r"open-vela/|"
    r"AOSP|android_|platform_|external_|"
    r"kernel/common|linux-ag35|winlibs|twrp|lineageos|cyanogenmod|"
    r"kernel_|linux-android|droidian|Evolution-X|Devices/|"
    r"linux-[0-9]|linux_[0-9]|"
    r"terribleOpenSSL|chromiumos-platform|"
    r"suyu$|yuzu|"
    r"IF[0-9]{4}|firmware$|"
    r"centos-stream|kernel_asus|sdm660|"
    r"TWLMenu|prueba|Purple-Shell|/sd_seq"
    r")",
    re.I,
)
PREFERRED_ORGS = re.compile(
    r"^(apache|google|microsoft|facebook|meta|llvm|mozilla|gnome|kde|redis|nginx|"
    r"openssl|curl|libarchive|libpng|harfbuzz|radareorg|xiph|haproxy|samba|"
    r"wireshark|qemu|systemd|ImageMagick|libgit2|libsdl-org|fmtlib|nlohmann|"
    r"open-telemetry|protocolbuffers|grpc|ceph|torvalds|git|php|nodejs|"
    r"python|rust-lang|sqlite|zlib|lz4|madler|json-c|akheron|DaveGamble|kr/|"
    r"libssh2|libass|vstakhov|pupnp|tio|memcached|varnishcache|c-ares|libuv|"
    r"libevent|libxml2|gnutls|openssh|tcpdump|libpcap|libical|libgd|libvpx|"
    r"libjpeg-turbo|freetype|libexpat|catchorg|google)/",
    re.I,
)
TARGET_SIZE = 1000
SEED = 42
DEFAULT_SOURCE = Path(
    "/home/gnikitopoulos/sima_binpool/uve_extractor/125_commits/accepted_patches.jsonl"
)

# Strict first; tiered fill if corpus cannot reach TARGET_SIZE.
_TIERS: tuple[tuple[float, int, int], ...] = (
    (0.85, 100, 6000),
    (0.80, 100, 6000),
    (0.85, 50, 8000),
    (0.80, 50, 8000),
)


def _is_cwe125(row: dict) -> bool:
    for key in ("cwe_id", "target_cwe"):
        if (row.get(key) or "").upper() == "CWE-125":
            return True
    triage = row.get("triage") or {}
    return (triage.get("mapped_cwe") or "").upper() == "CWE-125"


def _qualifies(row: dict, *, min_conf: float, patch_lo: int, patch_hi: int) -> bool:
    if not _is_cwe125(row):
        return False
    repo = row.get("repo") or ""
    if EXCLUDE_REPO_RE.search(repo):
        return False
    if repo.count("/") != 1:
        return False

    triage = row.get("triage") or {}
    if triage.get("accepted") is False:
        return False
    if triage.get("localized_enough") is False:
        return False
    if float(triage.get("confidence") or 0) < min_conf:
        return False

    parents = row.get("parents")
    if not (isinstance(parents, list) and parents and parents[0]):
        return False

    patch = row.get("patch") or ""
    if not (patch_lo <= len(patch) <= patch_hi):
        return False

    files = row.get("files") or []
    if len(files) != 1:
        return False
    filename = files[0].get("filename") or ""
    if Path(filename).suffix.lower() not in CPP_EXT:
        return False

    return bool(row.get("sha"))


def _score(row: dict) -> tuple[float, ...]:
    triage = row.get("triage") or {}
    conf = float(triage.get("confidence") or 0.5)
    patch_len = len(row.get("patch") or "")
    size_penalty = abs(patch_len - 800) / 800.0
    preferred = 1.0 if PREFERRED_ORGS.search(row.get("repo") or "") else 0.0
    return (preferred, conf, -size_penalty, -patch_len)


def _load_pool(source: Path) -> list[dict]:
    seen: set[str] = set()
    pool: list[dict] = []
    for line in source.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        sha = str(row.get("sha") or "").strip().lower()
        if not sha or sha in seen:
            continue
        for min_conf, patch_lo, patch_hi in _TIERS:
            if _qualifies(row, min_conf=min_conf, patch_lo=patch_lo, patch_hi=patch_hi):
                seen.add(sha)
                pool.append(row)
                break
    return pool


def _interleave_by_repo(rows: list[dict], *, target: int, seed: int) -> list[dict]:
    """Round-robin across repos so consecutive rows rarely share a repo."""
    by_repo: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        by_repo[str(row["repo"])].append(row)

    for repo_rows in by_repo.values():
        repo_rows.sort(key=_score, reverse=True)

    repos = list(by_repo)
    random.seed(seed)
    random.shuffle(repos)
    repos.sort(key=lambda r: (-len(by_repo[r]), r.lower()))

    selected: list[dict] = []
    seen_sha: set[str] = set()
    while len(selected) < target:
        progressed = False
        for repo in list(repos):
            bucket = by_repo.get(repo) or []
            while bucket and bucket[0]["sha"].lower() in seen_sha:
                bucket.pop(0)
            if not bucket:
                continue
            row = bucket.pop(0)
            selected.append(row)
            seen_sha.add(row["sha"].lower())
            progressed = True
            if len(selected) >= target:
                break
        if not progressed:
            break
    return selected


def build(
    source: Path,
    out_dir: Path,
    *,
    target_size: int = TARGET_SIZE,
    seed: int = SEED,
) -> list[dict]:
    pool = _load_pool(source)
    selected = _interleave_by_repo(pool, target=min(target_size, len(pool)), seed=seed)

    out_dir.mkdir(parents=True, exist_ok=True)
    jsonl_path = out_dir / "accepted_patches.jsonl"
    with jsonl_path.open("w", encoding="utf-8") as fh:
        for row in selected:
            fh.write(json.dumps(row, sort_keys=True) + "\n")

    manifest_path = out_dir / "manifest.tsv"
    with manifest_path.open("w", encoding="utf-8") as fh:
        fh.write("#\trepo\tsha\tparent\tcwe\tfile\tpatch_len\tconfidence\tmessage\n")
        for index, row in enumerate(selected, 1):
            filename = row["files"][0]["filename"]
            message = (row.get("message") or "").split("\n", 1)[0].replace("\t", " ")[:120]
            confidence = (row.get("triage") or {}).get("confidence", "")
            fh.write(
                f"{index}\t{row['repo']}\t{row['sha'][:12]}\t{row['parents'][0][:12]}\t"
                f"{row.get('cwe_id', '')}\t{filename}\t{len(row.get('patch', ''))}\t"
                f"{confidence}\t{message}\n"
            )

    stats_path = out_dir / "sampling_stats.json"
    repos = [str(r["repo"]) for r in selected]
    max_run = cur = 1
    for i in range(1, len(repos)):
        if repos[i] == repos[i - 1]:
            cur += 1
        else:
            max_run = max(max_run, cur)
            cur = 1
    stats_path.write_text(
        json.dumps(
            {
                "target_size": target_size,
                "pool_size": len(pool),
                "selected_size": len(selected),
                "distinct_repos": len(set(repos)),
                "max_consecutive_same_repo": max_run,
                "seed": seed,
                "source": str(source),
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return selected


def main() -> None:
    here = Path(__file__).resolve().parent
    out_dir = here / "1000_cwe125"
    selected = build(DEFAULT_SOURCE, out_dir)
    print(f"wrote {len(selected)} rows to {out_dir / 'accepted_patches.jsonl'}")


if __name__ == "__main__":
    main()
