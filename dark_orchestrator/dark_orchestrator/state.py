from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


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
        try:
            return json.loads(self.checkpoint_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            logger.warning(
                "checkpoint at %s is corrupt (%s); ignoring",
                self.checkpoint_path,
                exc,
            )
            return {}

    def save_checkpoint(self, payload: dict[str, Any]) -> None:
        self.checkpoint_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True),
            encoding="utf-8",
        )

    def append_completed_item(self, payload: dict[str, Any]) -> None:
        # If a previous SIGKILL/OOM truncated the last line, the file may not
        # end with '\n'. Prepend one so we don't fuse the broken tail with the
        # new row into a single unparseable line.
        needs_leading_nl = False
        try:
            if (
                self.completed_items_path.exists()
                and self.completed_items_path.stat().st_size > 0
            ):
                with self.completed_items_path.open("rb") as probe:
                    probe.seek(-1, 2)
                    if probe.read(1) != b"\n":
                        needs_leading_nl = True
        except OSError:
            needs_leading_nl = False

        with self.completed_items_path.open("a", encoding="utf-8") as fh:
            if needs_leading_nl:
                fh.write("\n")
            fh.write(json.dumps(payload, sort_keys=True) + "\n")

    def _iter_completed_rows(self) -> list[dict[str, Any]]:
        """Yield parsed rows, tolerating a truncated/corrupt final line.

        SIGKILL mid-write can leave a partial trailing line. We log and
        skip such lines rather than crashing the resume.
        """
        if not self.completed_items_path.exists():
            return []
        rows: list[dict[str, Any]] = []
        text = self.completed_items_path.read_text(encoding="utf-8")
        lines = text.splitlines()
        for lineno, raw in enumerate(lines, start=1):
            line = raw.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                if lineno == len(lines):
                    logger.warning(
                        "completed_items final line at %s is truncated (%s); skipping",
                        self.completed_items_path,
                        exc,
                    )
                else:
                    logger.warning(
                        "completed_items line %d at %s is corrupt (%s); skipping",
                        lineno,
                        self.completed_items_path,
                        exc,
                    )
        return rows

    def load_completed_item_ids(self) -> set[str]:
        out: set[str] = set()
        for row in self._iter_completed_rows():
            item_id = row.get("item_id")
            if item_id:
                out.add(str(item_id))
        return out

    def load_completed_item_statuses(self) -> dict[str, str]:
        """Return ``{item_id: status}`` from the persisted completion log.

        When a pair appears multiple times (e.g. retried after a previous
        failure), the *last* recorded status wins.
        """
        out: dict[str, str] = {}
        for row in self._iter_completed_rows():
            item_id = row.get("item_id")
            status = row.get("status")
            if item_id and status:
                out[str(item_id)] = str(status)
        return out

    def wipe(self) -> None:
        """Delete checkpoint + completed-items log, leave records/ alone.

        Used by the ``--fresh`` flag to force a clean run without
        clobbering already-extracted ELF directories or commit summaries.
        """
        for path in (self.checkpoint_path, self.completed_items_path):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            except OSError as exc:
                logger.warning("could not wipe %s: %s", path, exc)
