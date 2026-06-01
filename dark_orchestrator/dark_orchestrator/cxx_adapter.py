"""Adapter from a (CommitPair, side) to a CXXCrafter build + ELF trace.

Two-stage strategy per pair:

1. **Parent (vulnerable)** is built by the full CXXCrafter LLM loop. We
   capture its successful image tag and its working Dockerfile.
2. **Patch (non_vulnerable)** is built **on top of the parent's image**.
   We synthesize a tiny Dockerfile of the form

   ::

       FROM <parent_image_tag>
       RUN rm -rf /tmp/src
       COPY ./<patch_basename> /tmp/src
       <every step from the parent's Dockerfile that came after its source COPY>

   This skips the whole apt-update / dependency install / system bootstrap
   for patch (typically ~95% of the wall-clock for small projects, even
   more for big ones), and guarantees both sides ran identical environment
   + identical build commands - the only difference is the source tree.

There is **no fallback** to a separate LLM run for patch. If the synthesized
``FROM parent`` build fails, patch is recorded as failed for that pair.

Each (item_id, side) clones into a uniquely-named directory
(``side_dir/<item_id>_<side>``) so CXXCrafter's playground
(``~/.cxxcrafter/dockerfile_playground/<basename>``) does not collide
across pairs or sides.

Parent's image is kept alive until the patch build finishes; only then
do we ``rmi`` everything for that pair.
"""
from __future__ import annotations

import logging
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


def _parent_playground_dockerfile(parent_basename: str) -> Path:
    """Path where CXXCrafter wrote the working Dockerfile for parent."""
    return Path("~/.cxxcrafter/dockerfile_playground").expanduser() / parent_basename / "Dockerfile"


def _post_source_steps(dockerfile_text: str, source_basename: str) -> list[str]:
    """Return the lines of ``dockerfile_text`` after the source ``COPY``.

    Locates the ``COPY ./<source_basename>`` (or bare ``COPY <source_basename>``)
    instruction, then returns every subsequent line verbatim. Multi-line
    ``COPY`` continuations (lines ending with backslash) are skipped.

    Returns ``[]`` when the source COPY can't be found - the caller should
    treat that as a hard failure rather than guessing.
    """
    lines = dockerfile_text.splitlines()
    copy_idx: int | None = None
    for i, ln in enumerate(lines):
        stripped = ln.strip()
        if not stripped.upper().startswith("COPY "):
            continue
        # First non-flag positional argument after COPY is the source.
        tokens = stripped.split()[1:]
        for tok in tokens:
            if tok.startswith("--"):
                continue
            head = tok.lstrip("./").split("/")[0]
            if head == source_basename:
                copy_idx = i
            break  # only inspect the first positional arg
        if copy_idx is not None:
            break

    if copy_idx is None:
        return []

    end_idx = copy_idx
    while lines[end_idx].rstrip().endswith("\\") and end_idx + 1 < len(lines):
        end_idx += 1
    return lines[end_idx + 1:]


def _skipped_outcome(side: str, error: str) -> CXXCompileOutcome:
    label = "vulnerable" if side == "parent" else "non_vulnerable"
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


def _run_cxxcrafter_side(
    pair,
    side: str,
    side_dir: Path,
    src_dir: Path,
    run_id: str,
    keep_images: bool,
    elf_mode: str,
    defer_image_purge: bool = False,
) -> CXXCompileOutcome:
    """Run a full CXXCrafter LLM-driven build for one side and trace ELFs.

    When ``defer_image_purge`` is set, the per-side image cleanup is *not*
    performed in this function's ``finally``; the caller is responsible
    for invoking ``cleanup.purge_all_for(...)`` once the image is no
    longer needed (e.g. after the patch side has consumed it as a base).
    """
    _ensure_cxxcrafter_importable()
    from cxxcrafter import CXXCrafter  # type: ignore[import-not-found]

    label = "vulnerable" if side == "parent" else "non_vulnerable"
    target_sha = pair.parent_sha if side == "parent" else pair.patch_sha
    elfs_out_dir = side_dir / "trace"

    error: str | None = None
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
            return _skipped_outcome(side, error)

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
        elif not success and not error:
            error = "cxxcrafter_failed"

    finally:
        if not keep_images and not defer_image_purge:
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


def _build_patch_from_parent(
    pair,
    side_dir: Path,
    src_dir: Path,
    parent_image_tag: str,
    parent_dockerfile_text: str,
    run_id: str,
    keep_images: bool,
    elf_mode: str,
) -> CXXCompileOutcome:
    """Build patch on top of parent's image by replaying parent's tail.

    The synthesized Dockerfile is ::

        FROM <parent_image_tag>
        RUN rm -rf /tmp/src
        COPY ./<patch_basename> /tmp/src
        <every step from parent Dockerfile after its source COPY>

    Build context is a freshly created dir holding the patch source under
    ``<patch_basename>/``. No mutation of parent's commands - whatever
    worked for parent is replayed verbatim against the patch source.
    """
    _ensure_cxxcrafter_importable()
    from cxxcrafter.execution_module.docker_manager import (  # type: ignore[import-not-found]
        build_docker_image_by_api,
    )

    parent_basename = f"{pair.item_id}_parent"
    patch_basename = f"{pair.item_id}_patch"

    tail = _post_source_steps(parent_dockerfile_text, parent_basename)
    if not tail:
        return _skipped_outcome(
            "patch",
            "patch_from_parent_failed: could not locate parent source COPY in Dockerfile",
        )

    elfs_out_dir = side_dir / "trace"

    try:
        _clone_repo_at(pair.repo_url, pair.patch_sha, src_dir)
    except Exception as exc:
        return _skipped_outcome("patch", f"clone_failed: {exc}")

    ctx_dir = side_dir / "from_parent_ctx"
    if ctx_dir.exists():
        shutil.rmtree(ctx_dir, ignore_errors=True)
    ctx_dir.mkdir(parents=True, exist_ok=True)
    shutil.copytree(src_dir, ctx_dir / patch_basename)

    dockerfile_text = (
        f"FROM {parent_image_tag}\n"
        "RUN rm -rf /tmp/src\n"
        f"COPY ./{patch_basename} /tmp/src\n"
        + "\n".join(tail).rstrip()
        + "\n"
    )
    dockerfile_path = ctx_dir / "Dockerfile"
    dockerfile_path.write_text(dockerfile_text, encoding="utf-8")
    # Forensic copy alongside the side records.
    try:
        (side_dir / "Dockerfile.from_parent").write_text(dockerfile_text, encoding="utf-8")
    except Exception:
        pass

    image_tag = naming.image_tag(run_id, pair.item_id, "patch", attempt=1)
    cleanup.register_image(image_tag)

    error: str | None = None
    success = False
    elf_count = 0
    elfs_by_layer: list[dict[str, Any]] = []
    elf_dir: str | None = None
    chosen_layer_index: int | None = None

    try:
        flag, message, _image_id = build_docker_image_by_api(str(ctx_dir), tag=image_tag)
        success = bool(flag)

        if success:
            try:
                tr = trace_elfs(image_tag, elfs_out_dir, mode=elf_mode)
                elf_count = tr.total_elfs
                elfs_by_layer = tr.layers
                elf_dir = tr.elf_dir
                chosen_layer_index = tr.chosen_layer_index
            except Exception as exc:
                logger.exception("ELF tracer (parent_base) failed for %s", image_tag)
                error = f"tracer_failed: {exc}"
                success = False
        else:
            preview = ""
            if isinstance(message, str) and message.strip():
                preview = message.strip().splitlines()[-1][:300]
            error = f"patch_from_parent_failed: {preview or 'no message'}"
    finally:
        if not keep_images:
            try:
                cleanup.purge_image(image_tag)
            except Exception:
                logger.exception("patch image purge failed for %s", image_tag)
        # Reclaim the build-context tree (it's a full copy of the source).
        try:
            shutil.rmtree(ctx_dir, ignore_errors=True)
        except Exception:
            pass

    return CXXCompileOutcome(
        side="patch",
        vulnerability_label="non_vulnerable",
        image_tag=image_tag,
        success=success,
        elf_count=elf_count,
        elfs_by_layer=elfs_by_layer,
        elf_dir=elf_dir,
        attempts=1,
        error=error,
        chosen_layer_index=chosen_layer_index,
        built_via="parent_base",
    )


def run_cxx_compile(
    pair,
    side: str,
    output_dir: Path,
    run_id: str,
    keep_images: bool = False,
    elf_mode: str = MODE_LAST_ELF_LAYER,
) -> CXXCompileOutcome:
    """Compile a single side via CXXCrafter and trace its ELFs.

    Standalone helper kept for backwards compatibility. Pair-level callers
    should use ``run_pair_compile`` to get parent_base optimisation.
    """
    side_dir = output_dir / "cxx_compile" / pair.item_id / side
    side_dir.mkdir(parents=True, exist_ok=True)
    src_dir = _src_dir_for(side_dir, pair.item_id, side)
    return _run_cxxcrafter_side(
        pair, side, side_dir, src_dir, run_id, keep_images, elf_mode,
    )


def run_pair_compile(
    pair,
    output_dir: Path,
    run_id: str,
    keep_images: bool = False,
    elf_mode: str = MODE_LAST_ELF_LAYER,
) -> tuple[CXXCompileOutcome, CXXCompileOutcome]:
    """Build parent (LLM), then patch (FROM parent_image, replay tail).

    No fallback: if the parent_base build fails for patch, patch is
    recorded as failed for this pair. We do *not* fall back to a fresh
    LLM run because that would produce a Dockerfile possibly very
    different from parent's - the binaries would no longer be apples-to-
    apples comparable, defeating the whole point of pair extraction.
    """
    parent_side_dir = output_dir / "cxx_compile" / pair.item_id / "parent"
    patch_side_dir = output_dir / "cxx_compile" / pair.item_id / "patch"
    parent_side_dir.mkdir(parents=True, exist_ok=True)
    patch_side_dir.mkdir(parents=True, exist_ok=True)

    parent_src = _src_dir_for(parent_side_dir, pair.item_id, "parent")
    patch_src = _src_dir_for(patch_side_dir, pair.item_id, "patch")

    parent_outcome = _run_cxxcrafter_side(
        pair, "parent", parent_side_dir, parent_src,
        run_id, keep_images, elf_mode,
        defer_image_purge=True,
    )

    try:
        if not parent_outcome.success or not parent_outcome.image_tag:
            patch_outcome = _skipped_outcome(
                "patch",
                "parent_failed_no_base_image",
            )
        else:
            parent_dockerfile_path = _parent_playground_dockerfile(
                f"{pair.item_id}_parent"
            )
            try:
                parent_dockerfile_text = parent_dockerfile_path.read_text(
                    encoding="utf-8",
                )
            except Exception as exc:
                logger.warning(
                    "could not read parent's working Dockerfile at %s: %s",
                    parent_dockerfile_path, exc,
                )
                patch_outcome = _skipped_outcome(
                    "patch",
                    f"parent_dockerfile_unreadable: {exc}",
                )
            else:
                # Snapshot the parent's working Dockerfile next to the records
                # so the synthesized patch Dockerfile can be diffed against it.
                try:
                    (parent_side_dir / "Dockerfile.success").write_text(
                        parent_dockerfile_text, encoding="utf-8",
                    )
                except Exception:
                    pass
                patch_outcome = _build_patch_from_parent(
                    pair=pair,
                    side_dir=patch_side_dir,
                    src_dir=patch_src,
                    parent_image_tag=parent_outcome.image_tag,
                    parent_dockerfile_text=parent_dockerfile_text,
                    run_id=run_id,
                    keep_images=keep_images,
                    elf_mode=elf_mode,
                )
    finally:
        # Parent's image was kept alive so the patch build could `FROM` it;
        # now that patch is done (or skipped), reclaim every parent image.
        if not keep_images:
            try:
                cleanup.purge_all_for(run_id, pair.item_id, "parent")
            except Exception:
                logger.exception(
                    "deferred parent image purge failed for %s", pair.item_id,
                )

    return parent_outcome, patch_outcome
