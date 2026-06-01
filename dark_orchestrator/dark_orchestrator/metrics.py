from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


@dataclass
class YieldSnapshot:
    total_items: int = 0
    completed_items: int = 0
    skipped_items: int = 0
    failed_items: int = 0
    total_changed_functions: int = 0
    compiled_functions: int = 0
    failed_functions: int = 0
    extracted_elfs: int = 0
    images_cleaned: int = 0
    images_failed_cleanup: int = 0
    timestamp: str = field(default_factory=utc_now)


class MetricsTracker:
    def __init__(self, output_dir: Path) -> None:
        self.metrics_dir = output_dir / "metrics"
        self.metrics_dir.mkdir(parents=True, exist_ok=True)
        self.timeseries_path = self.metrics_dir / "yield_timeseries.jsonl"
        self.summary_path = self.metrics_dir / "yield_summary.json"
        self.snapshot = YieldSnapshot()

    def set_total_items(self, total: int) -> None:
        self.snapshot.total_items = total

    def inc(self, key: str, amount: int = 1) -> None:
        if not hasattr(self.snapshot, key):
            raise AttributeError(f"Unknown metric: {key}")
        setattr(self.snapshot, key, getattr(self.snapshot, key) + amount)

    def flush(self, extra: dict[str, Any] | None = None) -> None:
        self.snapshot.timestamp = utc_now()
        payload = asdict(self.snapshot)
        if extra:
            payload.update(extra)
        with self.timeseries_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, sort_keys=True) + "\n")
        self.summary_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    def rebuild_summary_from_timeseries(self) -> dict[str, Any]:
        last_payload: dict[str, Any] = {}
        if self.timeseries_path.exists():
            for line in self.timeseries_path.read_text(encoding="utf-8").splitlines():
                row = line.strip()
                if row:
                    last_payload = json.loads(row)
        if not last_payload:
            last_payload = asdict(self.snapshot)
        self.summary_path.write_text(json.dumps(last_payload, indent=2, sort_keys=True), encoding="utf-8")
        return last_payload
