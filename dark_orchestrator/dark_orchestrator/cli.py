from __future__ import annotations

import argparse
from pathlib import Path

from .metrics import MetricsTracker
from .pipeline import run_pipeline
from .tracer import MODE_LAST_ELF_LAYER, VALID_MODES


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
        help="Optional fixed run id; auto-generated when omitted. Used as the prefix for every Docker image and container created by this run.",
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
        help="ELF tracer mode. last_elf_layer (default) keeps only the last image layer that produced ELFs (skips trailing CMD/ENV layers); all extracts ELFs from every layer.",
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="dark_orchestrator: drive CXXCrafter over commit pairs with per-build ELF tracing"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    run_cmd = sub.add_parser("run", help="Run the CXXCrafter compile-and-trace pipeline")
    _add_common_run_args(run_cmd)
    run_cmd.add_argument("--resume", action="store_true")

    resume_cmd = sub.add_parser("resume", help="Resume a previous run from its checkpoint")
    _add_common_run_args(resume_cmd)

    metrics_cmd = sub.add_parser("metrics", help="Rebuild yield_summary.json from yield_timeseries.jsonl")
    metrics_cmd.add_argument("--output-dir", required=True)

    args = parser.parse_args()
    if args.cmd in {"run", "resume"}:
        run_pipeline(
            input_results_dir=Path(args.input_results_dir),
            output_dir=Path(args.output_dir),
            item_jobs=args.jobs,
            resume=(args.cmd == "resume") or bool(getattr(args, "resume", False)),
            run_id=args.run_id,
            keep_images=bool(args.keep_images),
            elf_mode=args.elf_mode,
        )
        return

    tracker = MetricsTracker(Path(args.output_dir))
    tracker.rebuild_summary_from_timeseries()


if __name__ == "__main__":
    main()
