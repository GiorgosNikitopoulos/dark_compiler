"""Adapter from a (CommitPair, side) to a CXXCrafter build + ELF trace.

Mirrors ``uve_extractor_pp.pc_adapter.run_partial_compile`` but instead of
shelling out to ``setup_pcompile_git2.py`` we drive CXXCrafter in-process
with a versioned ``dark_cxx`` image tag, then run the per-layer ELF tracer
against the resulting image, then ``rmi`` every attempt.

Key behaviours added in the parent-reuse refresh:

* Each (item_id, side) pair clones into a uniquely-named directory so
  CXXCrafter's playground (``~/.cxxcrafter/dockerfile_playground/<base>``)
  does not collide across pairs/sides.
* ``run_pair_compile`` first builds parent through the LLM loop. If that
  succeeds, the working Dockerfile is snapshotted to
  ``<parent_side_dir>/Dockerfile.success`` and re-used to build patch
  directly via ``executor()`` - skipping the LLM regeneration entirely. If
  the fast path fails the patch falls back to a full CXXCrafter run.
* CXXCrafter import errors (e.g. ``LLM_MODEL not configured``) are caught
  and surfaced as actionable ``RuntimeError`` instead of letting them
  propagate as a bare ValueError.
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
from .tracer import MODE_LAST_ELF_LAYER, trace_elfs

logger = logging.getLogger(__name__)


def _ensure_cxxcrafter_importable() -> None:
    """Import the cxxcrafter package, falling back to a local sys.path injection.

    Raises ``RuntimeError`` with an actionable hint if the package itself is
    importable but raises at module-load time (the most common failure is
    ``ValueError("LLM_MODEL is not configured ...")`` from
    ``cxxcrafter/config.py``).
    """
    try:
        import cxxcrafter  # noqa: F401
        return
    except ImportError:
        pass
    except Exception as exc:
        raise RuntimeError(
            "CXXCrafter is installed but failed to import "
            f"({type(exc).__name__}: {exc}). Configure CONFIG_LLM_MODEL in "
            "CXXCrafter-Community-Edition/src/cxxcrafter/config.py and the "
            "matching API key env var."
        ) from exc

    here = Path(__file__).resolve()
    candidate = here.parents[2] / "CXXCrafter-Community-Edition" / "src"
    if candidate.is_dir():
        sys.path.insert(0, str(candidate))
    try:
        import cxxcrafter  # noqa: F401
    except ImportError as exc:
        raise RuntimeError(
            "cxxcrafter package not found. `pip install -e "
            f"{candidate.parent}` or add it to PYTHONPATH."
        ) from exc
    except Exception as exc:
        raise RuntimeError(
            "CXXCrafter loaded from sys.path but raised at import "
            f"({type(exc).__name__}: {exc}). Configure CONFIG_LLM_MODEL in "
            "CXXCrafter-Community-Edition/src/cxxcrafter/config.py and the "
            "matching API key env var."
        ) from exc


def _clone_repo_at(repo_url: str, sha: str, dest: Path, clone_timeout: int = 600) -> Path:
    """Clone ``repo_url`` and check out ``sha`` into ``dest``."""
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


def _src_dir_for(side_dir: Path, item_id: str, side: str) -> Path:
    """Per-(item, side) checkout dir whose basename is unique.

    CXXCrafter derives its playground path from ``os.path.basename(project_path)``
    so we need a unique name per pair-side; otherwise every pair/side stomps
    on the same ``~/.cxxcrafter/dockerfile_playground/<base>/Dockerfile``.
    """
    return side_dir / f"{item_id}_{side}"


def _mutate_dockerfile_for_patch(text: str, parent_sha: str, patch_sha: str) -> str:
    """Rewrite any baked-in parent SHA references to point at the patch SHA.

    CXXCrafter's generated Dockerfiles typically rely on ``COPY . /workdir``
    against the build context, in which case no rewrite is needed - swapping
    the build context tree is sufficient. But some generated Dockerfiles
    bake in ``RUN git clone ... && git checkout <parent_sha>``; this hook
    handles that case by replacing the SHA wherever it appears (full and
    12-char abbreviation).
    """
    if not text or not parent_sha or not patch_sha or parent_sha == patch_sha:
        return text
    out = text.replace(parent_sha, patch_sha)
    if len(parent_sha) >= 12:
        out = out.replace(parent_sha[:12], patch_sha[:12])
    return out


def _run_full_cxxcrafter(
    pair,
    side: str,
    side_dir: Path,
    src_dir: Path,
    run_id: str,
    keep_images: bool,
    elf_mode: str,
) -> CXXCompileOutcome:
    """LLM-driven path: clone, run CXXCrafter from scratch, trace ELFs."""
    _ensure_cxxcrafter_importable()
    from cxxcrafter import CXXCrafter  # type: ignore[import-not-found]

    label = "vulnerable" if side == "parent" else "non_vulnerable"
    target_sha = pair.parent_sha if side == "parent" else pair.patch_sha
    elfs_out_dir = side_dir / "trace"

    error: str | None = None
    crafter = None
    success = False
    elf_count = 0
    elfs_by_layer: list[dict[str, Any]] = []
    elf_dir: str | None = None
    final_image_tag: str | None = None
    chosen_layer_index: int | None = None
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
                chosen_layer_index=None,
                built_via="skipped",
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
                trace_result = trace_elfs(final_image_tag, elfs_out_dir, mode=elf_mode)
                elf_count = trace_result.total_elfs
                elfs_by_layer = trace_result.layers
                elf_dir = trace_result.elf_dir
                chosen_layer_index = trace_result.chosen_layer_index
            except Exception as exc:
                logger.exception("ELF tracer failed for %s", final_image_tag)
                error = error or f"tracer_failed: {exc}"

            # Snapshot the working Dockerfile so the patch fast-path can re-use it.
            try:
                dockerfile_src = getattr(crafter, "dockerfile_path", None)
                if dockerfile_src and Path(dockerfile_src).is_file():
                    snapshot = side_dir / "Dockerfile.success"
                    shutil.copyfile(dockerfile_src, snapshot)
            except Exception as exc:
                logger.warning(
                    "could not snapshot working Dockerfile for %s/%s: %s",
                    pair.item_id, side, exc,
                )
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
        chosen_layer_index=chosen_layer_index,
        built_via="llm",
    )


def _fast_path_patch(
    pair,
    parent_dockerfile_text: str,
    side_dir: Path,
    src_dir: Path,
    run_id: str,
    keep_images: bool,
    elf_mode: str,
) -> CXXCompileOutcome:
    """Re-use parent's working Dockerfile to build the patch checkout.

    Returns an outcome with ``built_via == 'parent_reuse'`` on success or
    ``built_via == 'llm_pending_fallback'`` on failure (signalling the caller
    to fall back to ``_run_full_cxxcrafter``).
    """
    _ensure_cxxcrafter_importable()
    from cxxcrafter.execution_module.docker_manager import (  # type: ignore[import-not-found]
        build_docker_image_by_api,
    )

    label = "non_vulnerable"
    elfs_out_dir = side_dir / "trace"

    elf_count = 0
    elfs_by_layer: list[dict[str, Any]] = []
    elf_dir: str | None = None
    chosen_layer_index: int | None = None
    error: str | None = None
    image_tag: str | None = None

    try:
        try:
            _clone_repo_at(pair.repo_url, pair.patch_sha, src_dir)
        except Exception as exc:
            return CXXCompileOutcome(
                side="patch",
                vulnerability_label=label,
                image_tag=None,
                success=False,
                elf_count=0,
                elfs_by_layer=[],
                elf_dir=None,
                attempts=0,
                error=f"clone_failed: {exc}",
                chosen_layer_index=None,
                built_via="skipped",
            )

        mutated = _mutate_dockerfile_for_patch(
            parent_dockerfile_text, pair.parent_sha, pair.patch_sha,
        )
        dockerfile_dest = src_dir / "Dockerfile"
        dockerfile_dest.write_text(mutated, encoding="utf-8")
        # Keep a copy alongside the records too for forensics.
        try:
            (side_dir / "Dockerfile.reused").write_text(mutated, encoding="utf-8")
        except Exception:
            pass

        image_tag = naming.image_tag(run_id, pair.item_id, "patch", attempt=0)
        # vfast attempt -> tag with attempt 0 so it is distinct from the LLM v1+
        cleanup.register_image(image_tag)

        # The Dockerfile already worked for parent, so trust the docker engine
        # success flag directly and skip the LLM-based discriminator call.
        flag, message, image_id = build_docker_image_by_api(str(src_dir), tag=image_tag)
        success = bool(flag)

        if success:
            try:
                trace_result = trace_elfs(image_tag, elfs_out_dir, mode=elf_mode)
                elf_count = trace_result.total_elfs
                elfs_by_layer = trace_result.layers
                elf_dir = trace_result.elf_dir
                chosen_layer_index = trace_result.chosen_layer_index
            except Exception as exc:
                logger.exception("ELF tracer (fast path) failed for %s", image_tag)
                error = f"tracer_failed: {exc}"
                success = False
        else:
            preview = ""
            if isinstance(message, str):
                preview = message.strip().splitlines()[-1][:300] if message.strip() else ""
            error = f"fast_path_build_failed: {preview or 'no message'}"

    finally:
        if not keep_images:
            try:
                cleanup.purge_image(image_tag) if image_tag else None
            except Exception:
                logger.exception("fast-path image purge failed for %s", image_tag)

    return CXXCompileOutcome(
        side="patch",
        vulnerability_label=label,
        image_tag=image_tag,
        success=success if not error else False,
        elf_count=elf_count,
        elfs_by_layer=elfs_by_layer,
        elf_dir=elf_dir,
        attempts=1,
        error=error,
        chosen_layer_index=chosen_layer_index,
        built_via="parent_reuse" if (success and not error) else "llm_pending_fallback",
    )


def run_cxx_compile(
    pair,
    side: str,
    output_dir: Path,
    run_id: str,
    keep_images: bool = False,
    elf_mode: str = MODE_LAST_ELF_LAYER,
) -> CXXCompileOutcome:
    """Single-side LLM-driven build (kept for backwards compatibility / fallback)."""
    side_dir = output_dir / "cxx_compile" / pair.item_id / side
    side_dir.mkdir(parents=True, exist_ok=True)
    src_dir = _src_dir_for(side_dir, pair.item_id, side)
    return _run_full_cxxcrafter(pair, side, side_dir, src_dir, run_id, keep_images, elf_mode)


def run_pair_compile(
    pair,
    output_dir: Path,
    run_id: str,
    keep_images: bool = False,
    elf_mode: str = MODE_LAST_ELF_LAYER,
) -> tuple[CXXCompileOutcome, CXXCompileOutcome]:
    """Build parent then patch, re-using parent's Dockerfile when possible."""
    parent_side_dir = output_dir / "cxx_compile" / pair.item_id / "parent"
    patch_side_dir = output_dir / "cxx_compile" / pair.item_id / "patch"
    parent_side_dir.mkdir(parents=True, exist_ok=True)
    patch_side_dir.mkdir(parents=True, exist_ok=True)

    parent_src = _src_dir_for(parent_side_dir, pair.item_id, "parent")
    patch_src = _src_dir_for(patch_side_dir, pair.item_id, "patch")

    parent_outcome = _run_full_cxxcrafter(
        pair, "parent", parent_side_dir, parent_src, run_id, keep_images, elf_mode,
    )

    parent_dockerfile_text: str | None = None
    if parent_outcome.success:
        snapshot = parent_side_dir / "Dockerfile.success"
        try:
            if snapshot.is_file():
                parent_dockerfile_text = snapshot.read_text(encoding="utf-8")
        except Exception as exc:
            logger.warning(
                "could not read snapshot Dockerfile for %s: %s", pair.item_id, exc,
            )

    if parent_dockerfile_text:
        patch_outcome = _fast_path_patch(
            pair, parent_dockerfile_text, patch_side_dir, patch_src,
            run_id, keep_images, elf_mode,
        )
        if patch_outcome.built_via == "llm_pending_fallback":
            logger.info(
                "fast path failed for %s/patch (%s); falling back to LLM",
                pair.item_id, patch_outcome.error,
            )
            # Wipe the cloned tree so the LLM run starts clean.
            if patch_src.exists():
                shutil.rmtree(patch_src, ignore_errors=True)
            patch_outcome = _run_full_cxxcrafter(
                pair, "patch", patch_side_dir, patch_src, run_id, keep_images, elf_mode,
            )
    else:
        patch_outcome = _run_full_cxxcrafter(
            pair, "patch", patch_side_dir, patch_src, run_id, keep_images, elf_mode,
        )

    return parent_outcome, patch_outcome
