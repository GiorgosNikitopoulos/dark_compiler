"""Adapter from a (CommitPair, side) to a CXXCrafter build + ELF trace.

Mirrors ``uve_extractor_pp.pc_adapter.run_partial_compile`` but instead of
shelling out to ``setup_pcompile_git2.py`` we drive CXXCrafter in-process
with a versioned ``dark_cxx`` image tag, then run the per-layer ELF tracer
against the resulting image, then ``rmi`` every attempt.
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from . import cleanup, naming
from .models import CXXCompileOutcome
from .tracer import trace_elfs

logger = logging.getLogger(__name__)


def _ensure_cxxcrafter_importable() -> None:
    """Add CXXCrafter's ``src/`` to sys.path on demand.

    The package is laid out as a sibling of dark_orchestrator so we don't
    require an explicit ``pip install`` of CXXCrafter for development use.
    """
    try:
        import cxxcrafter  # noqa: F401
        return
    except ImportError:
        pass
    here = Path(__file__).resolve()
    candidate = here.parents[2] / "CXXCrafter-Community-Edition" / "src"
    if candidate.is_dir():
        sys.path.insert(0, str(candidate))


def _clone_repo_at(repo_url: str, sha: str, dest: Path, clone_timeout: int = 600) -> Path:
    """Clone ``repo_url`` and check out ``sha`` into ``dest``.

    Mirrors the host-side analog of ``setup_pcompile_git2.setup_pcompile_git``
    L45-L66 but runs locally so we can hand the resulting source tree to
    CXXCrafter.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)

    subprocess.run(
        ["git", "clone", "--no-checkout", repo_url, str(dest)],
        check=True,
        timeout=clone_timeout,
    )
    subprocess.run(
        ["git", "-C", str(dest), "checkout", sha],
        check=True,
        timeout=clone_timeout,
    )
    try:
        subprocess.run(
            ["git", "-C", str(dest), "submodule", "update", "--init", "--recursive"],
            check=False,
            timeout=clone_timeout,
        )
    except Exception as exc:
        logger.warning("submodule update failed for %s@%s: %s", repo_url, sha, exc)
    return dest


def run_cxx_compile(
    pair,
    side: str,
    output_dir: Path,
    run_id: str,
    keep_images: bool = False,
) -> CXXCompileOutcome:
    """Build ``pair``'s ``side`` checkout with CXXCrafter and trace ELFs."""
    _ensure_cxxcrafter_importable()
    from cxxcrafter import CXXCrafter  # type: ignore[import-not-found]

    target_sha = pair.parent_sha if side == "parent" else pair.patch_sha
    label = "vulnerable" if side == "parent" else "non_vulnerable"

    side_dir = output_dir / "cxx_compile" / pair.item_id / side
    side_dir.mkdir(parents=True, exist_ok=True)
    src_dir = side_dir / "src"
    elfs_out_dir = side_dir / "trace"

    error: str | None = None
    crafter = None
    success = False
    elf_count = 0
    elfs_by_layer: list[dict[str, Any]] = []
    elf_dir: str | None = None
    final_image_tag: str | None = None
    attempts = 1

    try:
        try:
            _clone_repo_at(pair.repo_url, target_sha, src_dir)
        except Exception as exc:
            error = f"clone_failed: {exc}"
            logger.warning("clone failed for %s@%s: %s", pair.repo_url, target_sha, exc)
            return CXXCompileOutcome(
                side=side,
                vulnerability_label=label,
                image_tag=None,
                success=False,
                elf_count=0,
                elfs_by_layer=[],
                elf_dir=None,
                attempts=0,
                error=error,
            )

        def tag_factory(attempt: int) -> str:
            tag = naming.image_tag(run_id, pair.item_id, side, attempt=attempt)
            cleanup.register_image(tag)
            return tag

        seed_tag = naming.image_tag(run_id, pair.item_id, side, attempt=1)
        cleanup.register_image(seed_tag)
        final_image_tag = seed_tag

        crafter = CXXCrafter(str(src_dir), image_tag_factory=tag_factory)
        try:
            _, success_flag = crafter.run()
            success = bool(success_flag)
        except Exception as exc:
            error = f"cxxcrafter_exception: {exc}"
            logger.exception("CXXCrafter raised for %s/%s", pair.item_id, side)
            success = False

        for itag in getattr(crafter, "intermediate_image_tags", []) or []:
            cleanup.register_image(itag)
        intermediate_tags = list(getattr(crafter, "intermediate_image_tags", []) or [])
        attempts = max(1, len(intermediate_tags))
        if intermediate_tags:
            final_image_tag = intermediate_tags[-1]

        if success and final_image_tag:
            try:
                trace_result = trace_elfs(final_image_tag, elfs_out_dir)
                elf_count = trace_result.total_elfs
                elfs_by_layer = trace_result.layers
                elf_dir = trace_result.elf_dir
            except Exception as exc:
                logger.exception("ELF tracer failed for %s", final_image_tag)
                error = error or f"tracer_failed: {exc}"
        elif not success and not error:
            error = "cxxcrafter_failed"

    finally:
        if not keep_images:
            try:
                cleanup.purge_all_for(run_id, pair.item_id, side)
            except Exception:
                logger.exception("image purge failed for %s/%s", pair.item_id, side)

    return CXXCompileOutcome(
        side=side,
        vulnerability_label=label,
        image_tag=final_image_tag,
        success=success,
        elf_count=elf_count,
        elfs_by_layer=elfs_by_layer,
        elf_dir=elf_dir,
        attempts=attempts,
        error=error,
    )
