from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
from pathlib import Path
from typing import Any

from . import cleanup, naming
from .cxx_adapter import run_pair_compile
from .diff_parser import changed_functions_from_diff
from .io import append_jsonl, load_commit_pairs
from .metrics import MetricsTracker
from .models import CommitSummaryRecord, CXXCompileOutcome, FunctionStatusRecord
from .state import StateStore
from .tracer import MODE_LAST_ELF_LAYER, VALID_MODES

logger = logging.getLogger(__name__)


def _failure_outcome(side: str, error: str) -> CXXCompileOutcome:
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


def _build_pair_result(
    idx: int,
    pair,
    parent_outcome: CXXCompileOutcome,
    patch_outcome: CXXCompileOutcome,
) -> dict[str, Any]:
    changed = changed_functions_from_diff(pair.item_id, pair.patch_diff)
    failed_this_item = not (parent_outcome.success and patch_outcome.success)
    side_success = {
        "parent": parent_outcome.success,
        "patch": patch_outcome.success,
    }
    side_elf_counts = {
        "parent": parent_outcome.elf_count,
        "patch": patch_outcome.elf_count,
    }
    side_image_tags = {
        "parent": parent_outcome.image_tag,
        "patch": patch_outcome.image_tag,
    }
    side_attempts = {
        "parent": parent_outcome.attempts,
        "patch": patch_outcome.attempts,
    }
    side_built_via = {
        "parent": parent_outcome.built_via,
        "patch": patch_outcome.built_via,
    }
    side_chosen_layer = {
        "parent": parent_outcome.chosen_layer_index,
        "patch": patch_outcome.chosen_layer_index,
    }

    function_records: list[dict] = []
    for fn in changed:
        for outcome in (parent_outcome, patch_outcome):
            layer_summary = [
                {
                    "layer_index": entry.get("layer_index"),
                    "elf_count": len(entry.get("elf_paths") or []),
                    "kept": bool(entry.get("kept", False)),
                }
                for entry in (outcome.elfs_by_layer or [])
            ]
            record = FunctionStatusRecord(
                item_id=pair.item_id,
                function_id=fn.function_id,
                file_path=fn.file_path,
                function_name=fn.function_name,
                source_side=outcome.side,
                vulnerability_label=outcome.vulnerability_label,
                change_origin="from_patch_diff",
                image_tag=outcome.image_tag,
                success=outcome.success,
                elf_count=outcome.elf_count,
                elf_dir=outcome.elf_dir,
                layer_summary=layer_summary,
                patch_ref=pair.patch_ref,
                repo_url=pair.repo_url,
                parent_sha=pair.parent_sha,
                patch_sha=pair.patch_sha,
                chosen_layer_index=outcome.chosen_layer_index,
                built_via=outcome.built_via,
            )
            function_records.append(record.to_dict())

    summary = CommitSummaryRecord(
        item_id=pair.item_id,
        patch_ref=pair.patch_ref,
        repo_url=pair.repo_url,
        parent_sha=pair.parent_sha,
        patch_sha=pair.patch_sha,
        changed_functions_count=len(changed),
        side_success=side_success,
        side_elf_counts=side_elf_counts,
        side_image_tags=side_image_tags,
        side_attempts=side_attempts,
        side_built_via=side_built_via,
        side_chosen_layer=side_chosen_layer,
        compilation_status="failed" if failed_this_item else "success",
    )
    return {
        "idx": idx,
        "pair": pair,
        "changed_count": len(changed),
        "function_records": function_records,
        "summary": summary.to_dict(),
        "failed": failed_this_item,
        "elf_total": parent_outcome.elf_count + patch_outcome.elf_count,
    }


def run_pipeline(
    input_results_dir: Path,
    output_dir: Path,
    item_jobs: int,
    resume: bool,
    run_id: str | None = None,
    keep_images: bool = False,
    elf_mode: str = MODE_LAST_ELF_LAYER,
) -> None:
    if elf_mode not in VALID_MODES:
        raise ValueError(f"unknown elf_mode {elf_mode!r}; expected one of {VALID_MODES}")

    output_dir.mkdir(parents=True, exist_ok=True)
    records_dir = output_dir / "records"
    records_dir.mkdir(parents=True, exist_ok=True)
    function_status_path = records_dir / "function_status.jsonl"
    commit_summary_path = records_dir / "commit_summary.jsonl"

    state = StateStore(output_dir)
    metrics = MetricsTracker(output_dir)

    registry = cleanup.get_registry()
    registry.keep_images = keep_images
    registry.set_metric_callback(lambda key, amount: metrics.inc(key, amount))

    completed_ids = state.load_completed_item_ids() if resume else set()
    if not resume:
        completed_ids = set()

    pairs = load_commit_pairs(input_results_dir)
    if not pairs:
        raise ValueError(
            "No commit pairs were loaded from input-results-dir. "
            "Expected rows with repo/repo_url, patch sha (sha/patch_sha), and parent commit (parent_sha or parents[0])."
        )
    metrics.set_total_items(len(pairs))

    checkpoint = state.load_checkpoint() if resume else {}
    if resume:
        previous_metrics = checkpoint.get("metrics", {})
        for key, value in previous_metrics.items():
            if hasattr(metrics.snapshot, key) and isinstance(value, int):
                setattr(metrics.snapshot, key, value)
        metrics.set_total_items(len(pairs))
        if not run_id:
            run_id = checkpoint.get("run_id")
    if not run_id:
        run_id = naming.make_run_id()

    pending_pairs: list[tuple[int, object]] = []
    for idx, pair in enumerate(pairs):
        if pair.item_id in completed_ids:
            metrics.inc("skipped_items", 1)
            metrics.flush({"item_id": pair.item_id, "event": "skip"})
            continue
        pending_pairs.append((idx, pair))

    def _process_pair(idx: int, pair) -> dict[str, Any]:
        try:
            parent_outcome, patch_outcome = run_pair_compile(
                pair=pair,
                output_dir=output_dir,
                run_id=run_id,
                keep_images=keep_images,
                elf_mode=elf_mode,
            )
            return _build_pair_result(idx, pair, parent_outcome, patch_outcome)
        except BaseException as exc:
            logger.exception("pair %s crashed", pair.item_id)
            err = f"pair_crashed: {type(exc).__name__}: {exc}"
            return _build_pair_result(
                idx,
                pair,
                _failure_outcome("parent", err),
                _failure_outcome("patch", err),
            )

    cleanup.install_signal_handlers()
    try:
        max_workers = item_jobs if item_jobs > 0 else 1
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_map = {
                executor.submit(_process_pair, idx, pair): (idx, pair.item_id)
                for idx, pair in pending_pairs
            }
            for future in as_completed(future_map):
                idx_item = future_map[future]
                try:
                    result = future.result()
                except BaseException as exc:
                    logger.exception("future for %s raised: %s", idx_item, exc)
                    continue
                idx = result["idx"]
                pair = result["pair"]

                metrics.inc("total_changed_functions", result["changed_count"])
                metrics.inc("extracted_elfs", result["elf_total"])
                for record in result["function_records"]:
                    append_jsonl(function_status_path, record)
                    if record["success"]:
                        metrics.inc("compiled_functions", 1)
                    else:
                        metrics.inc("failed_functions", 1)

                append_jsonl(commit_summary_path, result["summary"])

                if result["failed"]:
                    metrics.inc("failed_items", 1)
                else:
                    metrics.inc("completed_items", 1)

                state.append_completed_item(
                    {
                        "item_id": pair.item_id,
                        "index": idx,
                        "status": result["summary"]["compilation_status"],
                    }
                )
                state.save_checkpoint(
                    {
                        "last_processed_index": idx,
                        "last_item_id": pair.item_id,
                        "run_id": run_id,
                        "metrics": asdict(metrics.snapshot),
                    }
                )
                metrics.flush({"item_id": pair.item_id, "event": "processed"})
    finally:
        try:
            cleanup.cleanup_all()
        finally:
            cleanup.uninstall_signal_handlers()
            registry.set_metric_callback(None)
            metrics.flush({"event": "shutdown"})
