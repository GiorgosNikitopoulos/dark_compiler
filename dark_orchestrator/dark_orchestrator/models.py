from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


def utc_now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


@dataclass
class CommitPair:
    item_id: str
    repo_url: str
    parent_sha: str
    patch_sha: str
    patch_ref: str
    patch_diff: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ChangedFunction:
    function_id: str
    file_path: str
    function_name: str
    hunk_header: str


@dataclass
class LayerELFEntry:
    """Per-Dockerfile-step ELF discovery summary.

    Each Docker image layer is a diff over the previous step, so the ELFs
    listed here are the binaries that *that specific* RUN/COPY produced.
    """

    layer_index: int
    layer_digest: str
    elf_paths: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CXXCompileOutcome:
    side: str
    vulnerability_label: str
    image_tag: str | None
    success: bool
    elf_count: int
    elfs_by_layer: list[dict[str, Any]]
    elf_dir: str | None
    attempts: int = 1
    error: str | None = None
    # Index of the layer whose ELFs we kept (None when none kept / mode=all).
    chosen_layer_index: int | None = None
    # "llm" when CXXCrafter generated the Dockerfile from scratch (the only
    # successful path), "skipped" when we never attempted (e.g. clone failed).
    built_via: str = "llm"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FunctionStatusRecord:
    item_id: str
    function_id: str
    file_path: str
    function_name: str
    source_side: str
    vulnerability_label: str
    change_origin: str
    image_tag: str | None
    success: bool
    elf_count: int
    elf_dir: str | None
    layer_summary: list[dict[str, Any]]
    patch_ref: str
    repo_url: str
    parent_sha: str
    patch_sha: str
    chosen_layer_index: int | None = None
    built_via: str = "llm"
    timestamp: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CommitSummaryRecord:
    item_id: str
    patch_ref: str
    repo_url: str
    parent_sha: str
    patch_sha: str
    changed_functions_count: int
    side_success: dict[str, bool]
    side_elf_counts: dict[str, int]
    side_image_tags: dict[str, str | None]
    side_attempts: dict[str, int]
    compilation_status: str
    side_built_via: dict[str, str] = field(default_factory=dict)
    side_chosen_layer: dict[str, int | None] = field(default_factory=dict)
    timestamp: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
