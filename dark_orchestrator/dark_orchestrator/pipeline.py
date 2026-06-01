from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
from pathlib import Path

from . import cleanup, naming
from .cxx_adapter import run_cxx_compile
from .diff_parser import changed_functions_from_diff
from .io import append_jsonl, load_commit_pairs
from .metrics import MetricsTracker
from .models import CommitSummaryRecord, FunctionStatusRecord
from .state import StateStore


def run_pipeline(
    input_results_dir: Path,
    output_dir: Path,
    item_jobs: int,
    resume: bool,
    run_id: str | None = None,
    keep_images: bool = False,
) -> None:
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

    def _process_pair(idx: int, pair) -> dict:
        changed = changed_functions_from_diff(pair.item_id, pair.patch_diff)
        parent_outcome = run_cxx_compile(
            pair=pair,
            side="parent",
            output_dir=output_dir,
            run_id=run_id,
            keep_images=keep_images,
        )
        patch_outcome = run_cxx_compile(
            pair=pair,
            side="patch",
            output_dir=output_dir,
            run_id=run_id,
            keep_images=keep_images,
        )

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

        function_records: list[dict] = []
        for fn in changed:
            for outcome in (parent_outcome, patch_outcome):
                layer_summary = [
                    {
                        "layer_index": entry.get("layer_index"),
                        "elf_count": len(entry.get("elf_paths") or []),
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

    cleanup.install_signal_handlers()
    try:
        max_workers = item_jobs if item_jobs > 0 else 1
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_map = {
                executor.submit(_process_pair, idx, pair): (idx, pair.item_id)
                for idx, pair in pending_pairs
            }
            for future in as_completed(future_map):
                result = future.result()
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
