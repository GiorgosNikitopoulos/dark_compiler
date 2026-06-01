from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class StateStore:
    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir
        self.state_dir = output_dir / "state"
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.checkpoint_path = self.state_dir / "checkpoint.json"
        self.completed_items_path = self.state_dir / "completed_items.jsonl"

    def load_checkpoint(self) -> dict[str, Any]:
        if not self.checkpoint_path.exists():
            return {}
        return json.loads(self.checkpoint_path.read_text(encoding="utf-8"))

    def save_checkpoint(self, payload: dict[str, Any]) -> None:
        self.checkpoint_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True),
            encoding="utf-8",
        )

    def append_completed_item(self, payload: dict[str, Any]) -> None:
        with self.completed_items_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, sort_keys=True) + "\n")

    def load_completed_item_ids(self) -> set[str]:
        if not self.completed_items_path.exists():
            return set()
        out: set[str] = set()
        for line in self.completed_items_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            item_id = row.get("item_id")
            if item_id:
                out.add(str(item_id))
        return out
