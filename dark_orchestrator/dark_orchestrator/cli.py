from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from .metrics import MetricsTracker
from .pipeline import run_pipeline
from .tracer import MODE_LAST_ELF_LAYER, VALID_MODES

logger = logging.getLogger(__name__)


def _add_common_run_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--input-results-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument(
        "--jobs",
        type=int,
        default=1,
        help="Number of parallel commit-pair workers",
    )
    parser.add_argument(
        "--run-id",
        default=None,
        help=(
            "Optional fixed run id; auto-generated when omitted (and "
            "auto-restored from the checkpoint when resuming). Used as the "
            "prefix for every Docker image and container created by this run."
        ),
    )
    parser.add_argument(
        "--keep-images",
        action="store_true",
        help="Skip rmi/prune cleanup (debugging only). The Ctrl+C teardown still runs but no-ops on image removal.",
    )
    parser.add_argument(
        "--elf-mode",
        choices=list(VALID_MODES),
        default=MODE_LAST_ELF_LAYER,
        help=(
            "ELF tracer mode. last_elf_layer (default) keeps only the last "
            "image layer that produced ELFs (skips trailing CMD/ENV layers); "
            "all extracts ELFs from every layer."
        ),
    )

    # Resume controls. Auto-resume is the default - if the output dir already
    # has state/checkpoint.json + state/completed_items.jsonl we pick up where
    # we left off without any flag. Use --fresh to force a clean run.
    resume_group = parser.add_mutually_exclusive_group()
    resume_group.add_argument(
        "--fresh",
        action="store_true",
        help=(
            "Force a clean run by wiping state/ (checkpoint and completed_items). "
            "Records and previously extracted ELF traces are kept."
        ),
    )
    resume_group.add_argument(
        "--retry-failed",
        action="store_true",
        help=(
            "On resume, also re-enqueue pairs whose previous status was "
            "'failed'. By default only pairs with status 'success' are skipped."
        ),
    )
    # Backwards compatibility: --resume used to be required to opt into resume
    # behaviour. Now it is implicit, so accept the flag but treat it as a no-op.
    parser.add_argument(
        "--resume",
        action="store_true",
        help=argparse.SUPPRESS,
    )


def _configure_logging() -> None:
    if logging.getLogger().handlers:
        return
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def main() -> None:
    _configure_logging()

    parser = argparse.ArgumentParser(
        description="dark_orchestrator: drive CXXCrafter over commit pairs with per-build ELF tracing"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    run_cmd = sub.add_parser(
        "run",
        help="Run the CXXCrafter compile-and-trace pipeline (auto-resumes if state exists)",
    )
    _add_common_run_args(run_cmd)

    # `resume` subcommand kept as a deprecated alias of `run` for backwards
    # compatibility - auto-resume is now implicit on `run`.
    resume_cmd = sub.add_parser(
        "resume",
        help="(deprecated) Alias for `run`; resume is now automatic",
    )
    _add_common_run_args(resume_cmd)

    metrics_cmd = sub.add_parser("metrics", help="Rebuild yield_summary.json from yield_timeseries.jsonl")
    metrics_cmd.add_argument("--output-dir", required=True)

    args = parser.parse_args()
    if args.cmd in {"run", "resume"}:
        if args.cmd == "resume":
            print(
                "[dark-orchestrator] note: `resume` is deprecated; auto-resume "
                "is now the default for `run`. Use --fresh to force a clean run.",
                file=sys.stderr,
            )
        if getattr(args, "resume", False):
            print(
                "[dark-orchestrator] note: --resume is deprecated and a no-op; "
                "auto-resume is now the default. Use --fresh to opt out.",
                file=sys.stderr,
            )
        run_pipeline(
            input_results_dir=Path(args.input_results_dir),
            output_dir=Path(args.output_dir),
            item_jobs=args.jobs,
            fresh=bool(args.fresh),
            retry_failed=bool(args.retry_failed),
            run_id=args.run_id,
            keep_images=bool(args.keep_images),
            elf_mode=args.elf_mode,
        )
        return

    tracker = MetricsTracker(Path(args.output_dir))
    tracker.rebuild_summary_from_timeseries()


if __name__ == "__main__":
    main()
