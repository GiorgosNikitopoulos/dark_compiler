#!/usr/bin/env python3
"""Build test_inputs/100_realistic from uve_extractor/125_commits/accepted_patches.jsonl."""

from __future__ import annotations

import json
import random
import re
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
SKIP_REPOS = {
    "libssh2/libssh2",
    "vstakhov/libucl",
    "pupnp/pupnp",
    "libass/libass",
    "tio/tio",
}
SAMPLE_SIZE = 100
SEED = 42


def _is_realistic(row: dict) -> bool:
    repo = row.get("repo") or ""
    if repo in SKIP_REPOS:
        return False
    if EXCLUDE_REPO_RE.search(repo):
        return False
    if repo.count("/") != 1:
        return False

    triage = row.get("triage") or {}
    if triage.get("accepted") is False:
        return False
    if triage.get("localized_enough") is False:
        return False
    if float(triage.get("confidence") or 0) < 0.85:
        return False

    parents = row.get("parents")
    if not (isinstance(parents, list) and parents and parents[0]):
        return False

    patch = row.get("patch") or ""
    if not (100 <= len(patch) <= 6000):
        return False

    files = row.get("files") or []
    if len(files) != 1:
        return False
    filename = files[0].get("filename") or ""
    if Path(filename).suffix.lower() not in CPP_EXT:
        return False

    if not row.get("sha"):
        return False
    if not (row.get("cwe_id") or row.get("target_cwe")):
        return False
    return True


def _score(row: dict) -> tuple[float, ...]:
    triage = row.get("triage") or {}
    conf = float(triage.get("confidence") or 0.5)
    patch_len = len(row.get("patch") or "")
    size_penalty = abs(patch_len - 800) / 800.0
    preferred = 1.0 if PREFERRED_ORGS.search(row.get("repo") or "") else 0.0
    return (preferred, conf, -size_penalty, -patch_len)


def build(
    source: Path,
    out_dir: Path,
    *,
    sample_size: int = SAMPLE_SIZE,
    seed: int = SEED,
) -> list[dict]:
    best_by_repo: dict[str, dict] = {}
    for line in source.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if not _is_realistic(row):
            continue
        repo = str(row["repo"])
        prev = best_by_repo.get(repo)
        if prev is None or _score(row) > _score(prev):
            best_by_repo[repo] = row

    candidates = list(best_by_repo.values())
    preferred = [row for row in candidates if PREFERRED_ORGS.search(row.get("repo") or "")]
    other = [row for row in candidates if row not in preferred]

    random.seed(seed)
    random.shuffle(other)
    selected = (preferred + other)[:sample_size]
    selected.sort(key=lambda row: (str(row["repo"]).lower(), str(row["sha"])))

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

    return selected


def main() -> None:
    here = Path(__file__).resolve().parent
    source = Path("/home/gnikitopoulos/sima_binpool/uve_extractor/125_commits/accepted_patches.jsonl")
    out_dir = here / "100_realistic"
    selected = build(source, out_dir)
    print(f"wrote {len(selected)} rows to {out_dir / 'accepted_patches.jsonl'}")


if __name__ == "__main__":
    main()
