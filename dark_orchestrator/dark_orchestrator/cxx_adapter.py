"""Adapter from a (CommitPair, side) to a CXXCrafter build + ELF trace.

Two-stage strategy per pair:

1. **Parent (vulnerable)** is built by the full CXXCrafter LLM loop. We
   capture its successful image tag and its working Dockerfile.
2. **Patch (non_vulnerable)** is built **on top of the parent's image**.
   We synthesize a tiny Dockerfile of the form

   ::

       FROM <parent_image_tag>
       RUN rm -rf <parent_dest>
       COPY ./<patch_basename> <parent_dest>
       <every step from the parent's Dockerfile that came after its source COPY,
        with parent_sha rewritten to patch_sha>

   ``<parent_dest>`` is whatever destination the LLM chose for parent's
   ``COPY ./<basename>_parent <dst>`` - we *must* reuse it verbatim,
   otherwise the patch source lands in a directory the build never
   touches and the inherited parent source (still pristine on the
   ``FROM`` image) gets compiled instead, producing parent-identical
   binaries. Any ``git checkout <parent_sha>`` style command in the
   tail is rewritten so it pins to ``patch_sha`` instead of silently
   reverting our COPY.

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
do we ``rmi`` everything for that pair. After each item, the CXXCrafter
playground copy under ``~/.cxxcrafter/dockerfile_playground/`` is removed
(logs under ``~/.cxxcrafter/logs/`` are kept).
"""
from __future__ import annotations

import logging
import re
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


def _cleanup_clone_src(src_dir: Path, *, item_id: str, side: str) -> None:
    """Remove a per-side git checkout after the Docker build no longer needs it."""
    if not src_dir.is_dir():
        return
    try:
        shutil.rmtree(src_dir)
        logger.info("removed clone source %s (%s/%s)", src_dir.name, item_id, side)
    except Exception as exc:
        logger.warning("failed to remove clone source %s: %s", src_dir, exc)


def _playground_project_dir(project_basename: str) -> Path:
    return Path("~/.cxxcrafter/dockerfile_playground").expanduser() / project_basename


def _cleanup_playground(project_basename: str, *, item_id: str, side: str) -> None:
    """Remove CXXCrafter's per-project playground (repo copy + Dockerfile history).

    ``~/.cxxcrafter/logs/`` is left intact. Call only after the parent
    Dockerfile has been read for patch synthesis (or the build failed).
    """
    playground_dir = _playground_project_dir(project_basename)
    if not playground_dir.is_dir():
        return
    try:
        shutil.rmtree(playground_dir)
        logger.info(
            "removed CXXCrafter playground %s (%s/%s)",
            playground_dir.name,
            item_id,
            side,
        )
    except Exception as exc:
        logger.warning(
            "failed to remove CXXCrafter playground %s: %s",
            playground_dir,
            exc,
        )


def _parent_playground_dockerfile(parent_basename: str) -> Path:
    """Path where CXXCrafter wrote the working Dockerfile for parent."""
    return _playground_project_dir(parent_basename) / "Dockerfile"


def _post_source_steps(
    dockerfile_text: str,
    source_basename: str,
) -> tuple[str | None, list[str], str | None]:
    """Locate the source ``COPY`` and return ``(destination, tail_lines, workdir)``.

    ``destination`` is the path the source was copied to (the second
    positional argument of the ``COPY`` instruction). ``tail_lines``
    contains every Dockerfile line after the ``COPY`` (and after any
    backslash-continuations of it). ``workdir`` is the ``WORKDIR`` in
    effect at that ``COPY`` (not the final ``WORKDIR`` in the file).

    Multi-line ``COPY`` instructions are joined into one logical line
    before tokenisation so source/dest detection still works when the
    LLM splits them across newlines.

    Returns ``(None, [], None)`` when the source ``COPY`` can't be found -
    the caller must treat that as a hard failure (we have no idea where
    to drop the patch source).
    """
    lines = dockerfile_text.splitlines()

    # Build (start_index, end_index_inclusive, joined_text) per logical
    # instruction so we can match a COPY whose source/dest spans
    # backslash-continuation lines.
    logical: list[tuple[int, int, str]] = []
    i = 0
    while i < len(lines):
        start = i
        buf = lines[i].rstrip()
        while buf.endswith("\\") and i + 1 < len(lines):
            buf = buf[:-1] + " " + lines[i + 1].strip()
            i += 1
        logical.append((start, i, buf))
        i += 1

    current_workdir: str | None = None
    for _start, end, joined in logical:
        stripped = joined.strip()
        if stripped.upper().startswith("WORKDIR "):
            current_workdir = stripped.split(None, 1)[1].strip()
            continue
        if not stripped.upper().startswith("COPY "):
            continue
        tokens = stripped.split()[1:]
        positional = [t for t in tokens if not t.startswith("--")]
        if len(positional) < 2:
            continue
        src_tok = positional[0]
        head = src_tok.lstrip("./").rstrip("/").split("/")[0]
        if head != source_basename:
            continue
        destination = positional[-1]
        return destination, lines[end + 1:], current_workdir

    return None, [], None


def _patch_preamble_lines(
    parent_image_tag: str,
    parent_dest: str,
    patch_basename: str,
    copy_workdir: str | None,
) -> list[str]:
    """Build ``FROM`` / optional ``WORKDIR`` / clear / ``COPY`` for patch replay.

    When the parent's source ``COPY`` target is ``.`` or ``./``, ``rm -rf .``
    is rejected by coreutils inside Docker. Clear directory *contents* instead
    and pin ``WORKDIR`` to where the parent ``COPY`` ran.
    """
    dest = parent_dest.strip()
    lines = [f"FROM {parent_image_tag}"]

    if dest in (".", "./"):
        if copy_workdir:
            lines.append(f"WORKDIR {copy_workdir}")
        lines.append("RUN find . -mindepth 1 -maxdepth 1 -exec rm -rf {} +")
    else:
        lines.append(f"RUN rm -rf {parent_dest}")

    lines.append(f"COPY ./{patch_basename} {parent_dest}")
    return lines


_REFETCH_PATTERNS = (
    "git clone",
    "git fetch",
    "git pull",
    "wget ",
    "curl ",
    "apt-get source",
)

# Third-party APT mirrors we never want the LLM-generated Dockerfile to
# rewrite ``/etc/apt/sources.list`` to. CXXCrafter's seed template used to
# include a ``sed -i ... mirrors.aliyun.com`` line that the LLM faithfully
# copied; we now strip any such RUN block defensively so stale playground
# Dockerfiles and any future regression don't route apt through these hosts.
_CN_MIRROR_HOSTS = (
    "mirrors.aliyun.com",
    "mirrors.tuna.tsinghua.edu.cn",
    "mirrors.huaweicloud.com",
    "mirrors.cloud.tencent.com",
    "mirrors.ustc.edu.cn",
    "mirrors.bfsu.edu.cn",
    "mirrors.163.com",
    "mirror.sjtu.edu.cn",
)


def _strip_cn_apt_mirrors(text: str) -> tuple[str, list[str]]:
    """Drop any Dockerfile ``RUN`` block that rewrites ``sources.list`` to a CN mirror.

    Walks the Dockerfile line-by-line, joining backslash continuations into
    one logical instruction (same logic as :func:`_post_source_steps`). If a
    logical RUN block mentions both ``sources.list`` and one of
    ``_CN_MIRROR_HOSTS``, the whole block (every source line that
    contributed to it) is removed; everything else is preserved verbatim so
    the rest of the build is byte-identical.

    Returns ``(scrubbed_text, dropped_logical_lines)``. ``dropped_logical_lines``
    is what the caller should log at WARNING so we can see in CI when the
    LLM tried to backslide.
    """
    if not text:
        return text, []

    src_lines = text.splitlines(keepends=False)
    out_lines: list[str] = []
    dropped: list[str] = []

    i = 0
    while i < len(src_lines):
        start = i
        buf = src_lines[i].rstrip()
        # Join backslash-continuation block into one logical instruction
        # without losing the original source-line slice for emission.
        while buf.endswith("\\") and i + 1 < len(src_lines):
            buf = buf[:-1] + " " + src_lines[i + 1].strip()
            i += 1
        end = i  # inclusive

        joined_low = buf.lower()
        instr = buf.lstrip().upper()
        is_run = instr.startswith("RUN ") or instr.startswith("RUN\t")
        hits_cn = (
            is_run
            and "sources.list" in joined_low
            and any(host in joined_low for host in _CN_MIRROR_HOSTS)
        )
        if hits_cn:
            dropped.append(buf.strip())
        else:
            out_lines.extend(src_lines[start : end + 1])
        i = end + 1

    scrubbed = "\n".join(out_lines)
    # Preserve trailing newline behaviour: re-add a single trailing \n iff
    # the original text had one, so callers that compare bytes don't see
    # spurious newline drift.
    if text.endswith("\n") and not scrubbed.endswith("\n"):
        scrubbed += "\n"
    return scrubbed, dropped


def _log_cn_mirror_drops(context: str, item_id: str, dropped: list[str]) -> None:
    for ln in dropped:
        logger.warning(
            "%s[%s]: dropped CN-mirror APT rewrite from Dockerfile: %r",
            context, item_id, ln,
        )


def reset_cxxcrafter_playground(playground_root: Path | None = None) -> int:
    """Remove every cached Dockerfile under ``~/.cxxcrafter/dockerfile_playground/``.

    CXXCrafter caches working Dockerfiles per project basename; a stale
    cache from a previous run can still carry the old aliyun ``sed`` line
    even after the template fix. Wiping the cache forces a fresh LLM-
    generated Dockerfile on the next build. Returns the number of project
    cache dirs removed so the caller can log it.
    """
    root = playground_root or (Path("~/.cxxcrafter/dockerfile_playground").expanduser())
    if not root.is_dir():
        return 0
    n = 0
    for child in root.iterdir():
        if child.is_dir():
            shutil.rmtree(child, ignore_errors=True)
            n += 1
    return n


def _rewrite_parent_sha(
    tail: list[str],
    parent_sha: str,
    patch_sha: str,
) -> tuple[list[str], list[str]]:
    """Rewrite ``parent_sha`` -> ``patch_sha`` (full and 7-char short form)
    everywhere in ``tail`` and surface any commands that look like an
    upstream re-fetch.

    Without this rewrite, a parent tail of the form

    ::

        RUN git checkout <parent_sha>

    would silently revert our COPY back to parent's source after the
    patch was already in place, so parent and patch would compile from
    the same tree and produce byte-identical binaries.

    Returns ``(rewritten_tail, refetch_warnings)``. ``refetch_warnings``
    is a list of stripped tail lines that hit one of the refetch
    patterns; the caller should log them but we still attempt the build
    because most refetches are harmless (e.g. ``apt-get`` for tooling).
    """
    rewritten: list[str] = []
    warnings: list[str] = []

    short_parent = parent_sha[:7] if parent_sha and len(parent_sha) >= 7 else None
    short_patch = patch_sha[:7] if patch_sha and len(patch_sha) >= 7 else patch_sha

    short_pattern = (
        re.compile(rf"(?<![0-9a-fA-F]){re.escape(short_parent)}(?![0-9a-fA-F])")
        if short_parent
        else None
    )

    for ln in tail:
        new = ln
        if parent_sha and parent_sha in new:
            new = new.replace(parent_sha, patch_sha)
        if short_pattern is not None:
            new = short_pattern.sub(short_patch, new)
        rewritten.append(new)
        low = ln.lower()
        if any(p in low for p in _REFETCH_PATTERNS):
            warnings.append(ln.strip())

    return rewritten, warnings


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
        RUN rm -rf <parent_dest>
        COPY ./<patch_basename> <parent_dest>
        <parent's post-source steps with parent_sha rewritten to patch_sha>

    Build context is a freshly created dir holding the patch source under
    ``<patch_basename>/``. ``<parent_dest>`` is read off the parent's
    working Dockerfile so the patch source overwrites the same path the
    rest of the build expects to read from. SHA references in the tail
    are rewritten so any ``git checkout`` / ``git fetch`` step pins to
    the patch SHA instead of silently reverting our COPY.
    """
    _ensure_cxxcrafter_importable()
    from cxxcrafter.execution_module.docker_manager import (  # type: ignore[import-not-found]
        build_docker_image_by_api,
    )

    parent_basename = f"{pair.item_id}_parent"
    patch_basename = f"{pair.item_id}_patch"

    parent_dest, tail, copy_workdir = _post_source_steps(
        parent_dockerfile_text, parent_basename,
    )
    if parent_dest is None or not tail:
        return _skipped_outcome(
            "patch",
            "patch_from_parent_failed: could not locate parent source COPY in Dockerfile",
        )

    tail, refetch_warnings = _rewrite_parent_sha(
        tail, pair.parent_sha or "", pair.patch_sha or "",
    )
    for warn in refetch_warnings:
        logger.warning(
            "patch_from_parent[%s]: parent's tail contains a likely upstream "
            "fetch step which may revert your patch source: %r",
            pair.item_id, warn,
        )

    # Even after the template fix, the LLM may regenerate a
    # ``RUN sed -i ... mirrors.aliyun.com`` block. Strip any such block
    # from the tail so the patch build never re-points apt at a CN mirror,
    # then split back into the line-oriented form the assembler expects.
    scrubbed_tail_text, dropped_tail = _strip_cn_apt_mirrors("\n".join(tail))
    if dropped_tail:
        _log_cn_mirror_drops("patch_from_parent.tail", pair.item_id, dropped_tail)
    tail = scrubbed_tail_text.splitlines()

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
        "\n".join(
            _patch_preamble_lines(
                parent_image_tag,
                parent_dest,
                patch_basename,
                copy_workdir,
            )
        )
        + "\n"
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
    outcome = _run_cxxcrafter_side(
        pair, side, side_dir, src_dir, run_id, keep_images, elf_mode,
    )
    _cleanup_clone_src(src_dir, item_id=pair.item_id, side=side)
    _cleanup_playground(
        f"{pair.item_id}_{side}",
        item_id=pair.item_id,
        side=side,
    )
    return outcome


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
    _cleanup_clone_src(parent_src, item_id=pair.item_id, side="parent")

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
                # Defensively strip any CN-mirror APT rewrite the LLM may
                # have baked in. The patch build will FROM the parent image
                # (those mirror sed steps already ran in the parent layers
                # and we can't un-pull them), but we don't want them
                # *replayed* via the tail, and we don't want the forensic
                # ``Dockerfile.success`` snapshot to mislead anyone
                # inspecting the build.
                parent_dockerfile_text, dropped_parent = _strip_cn_apt_mirrors(
                    parent_dockerfile_text,
                )
                if dropped_parent:
                    _log_cn_mirror_drops(
                        "parent_dockerfile", pair.item_id, dropped_parent,
                    )
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
        _cleanup_playground(
            f"{pair.item_id}_parent",
            item_id=pair.item_id,
            side="parent",
        )
        _cleanup_clone_src(patch_src, item_id=pair.item_id, side="patch")

    return parent_outcome, patch_outcome
