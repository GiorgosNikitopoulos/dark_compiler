"""Per-layer ELF tracer.

Docker (and OCI) image tarballs ship one tarball per layer, where each layer
is the *diff* of the file system after the corresponding Dockerfile step
(``RUN``/``COPY``/``ADD``). That makes them an exact ledger of "what this
build step produced". By saving the image, walking each layer in order, and
recognising files that begin with the ELF magic header (``\\x7fELF``), we get
a faithful trace of every binary the build emitted, attributed to the step
that emitted it.

Two operating modes:

* ``last_elf_layer`` (default): scan every layer in pass 1 to discover where
  ELFs were added; pick the **last layer that actually added at least one
  ELF** (this skips trailing metadata-only layers like ``CMD``/``ENV`` which
  show up as empty diffs); then in pass 2 only physically extract the
  binaries from that one layer to ``out_dir/elfs/`` as a *flat* listing
  (basenames only). Collisions are disambiguated with ``__N`` suffixes.
* ``all``: extract every ELF from every layer to ``out_dir/elfs/layer_NNN/``
  (also flat per layer).

Either way the manifest at ``out_dir/elf_manifest.json`` records the
per-layer summary, including a ``binaries`` list mapping the flat output
filename back to the ELF's original in-image path so the source is never
lost.
"""
from __future__ import annotations

import json
import logging
import shutil
import tarfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

try:
    import docker
    from docker.errors import APIError, NotFound
except Exception:  # pragma: no cover
    docker = None  # type: ignore[assignment]
    APIError = Exception  # type: ignore[assignment,misc]
    NotFound = Exception  # type: ignore[assignment,misc]

logger = logging.getLogger(__name__)

ELF_MAGIC = b"\x7fELF"
ELF_MAGIC_LEN = len(ELF_MAGIC)
_MAX_PATH_COMPONENT = 200

MODE_LAST_ELF_LAYER = "last_elf_layer"
MODE_ALL = "all"
VALID_MODES = (MODE_LAST_ELF_LAYER, MODE_ALL)


@dataclass
class TraceResult:
    image_tag: str
    mode: str
    total_elfs: int
    unique_elfs: int
    chosen_layer_index: int | None
    chosen_layer_digest: str | None
    layers: list[dict[str, Any]]
    manifest_path: str
    elf_dir: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "image_tag": self.image_tag,
            "mode": self.mode,
            "total_elfs": self.total_elfs,
            "unique_elfs": self.unique_elfs,
            "chosen_layer_index": self.chosen_layer_index,
            "chosen_layer_digest": self.chosen_layer_digest,
            "layers": self.layers,
            "manifest_path": self.manifest_path,
            "elf_dir": self.elf_dir,
        }


def _safe_basename(name: str) -> str:
    """Reduce a tar entry name to a single safe basename for flat output.

    Strips any directory components (so we never write under ``tmp/src/...``
    inside ``elfs/``), drops empty/``.``/``..`` segments, and caps the
    resulting name length to ``_MAX_PATH_COMPONENT``.
    """
    base = Path(name).name
    if base in ("", ".", ".."):
        return "_unnamed"
    if len(base) > _MAX_PATH_COMPONENT:
        base = base[:_MAX_PATH_COMPONENT]
    return base


def _disambiguate(basename: str, used: dict[str, int]) -> str:
    """Pick a unique flat filename in a destination dir.

    First occurrence keeps the original basename. Subsequent occurrences
    get a ``__N`` suffix inserted before the first dot so the extension
    chain (``.so.1.7.18``, ``.c.o``) survives intact.
    """
    if basename not in used:
        used[basename] = 0
        return basename
    used[basename] += 1
    n = used[basename]
    if "." in basename:
        head, _, tail = basename.partition(".")
        return f"{head}__{n}.{tail}"
    return f"{basename}__{n}"


def _save_image(image_tag: str, dest: Path) -> None:
    if docker is None:
        raise RuntimeError("docker SDK not available")
    client = docker.from_env()
    try:
        image = client.images.get(image_tag)
    except NotFound as exc:
        raise FileNotFoundError(f"image not found: {image_tag}") from exc
    with dest.open("wb") as fh:
        for chunk in image.save(named=True):
            fh.write(chunk)


def _read_manifest(outer: tarfile.TarFile) -> list[dict[str, Any]]:
    try:
        member = outer.getmember("manifest.json")
    except KeyError as exc:
        raise RuntimeError("manifest.json missing from image tar") from exc
    fh = outer.extractfile(member)
    if fh is None:
        raise RuntimeError("could not read manifest.json from image tar")
    payload = json.loads(fh.read().decode("utf-8"))
    if not isinstance(payload, list) or not payload:
        raise RuntimeError("unexpected manifest.json shape")
    return payload


def _iter_layer_paths(manifest: list[dict[str, Any]]) -> Iterable[str]:
    layers = manifest[0].get("Layers") or []
    for entry in layers:
        if isinstance(entry, str):
            yield entry


def _scan_layer_for_elf_names(outer: tarfile.TarFile, layer_path: str) -> tuple[list[str], bool]:
    """Return (elf_entry_names, skipped) for a single layer without writing."""
    try:
        layer_member = outer.getmember(layer_path)
    except KeyError:
        logger.warning("layer %s missing from image tar", layer_path)
        return [], True
    inner_fh = outer.extractfile(layer_member)
    if inner_fh is None:
        logger.warning("could not open layer %s", layer_path)
        return [], True

    elf_names: list[str] = []
    try:
        with tarfile.open(fileobj=inner_fh, mode="r|*") as inner:
            for entry in inner:
                if not entry.isfile():
                    continue
                data_fh = inner.extractfile(entry)
                if data_fh is None:
                    continue
                head = data_fh.read(ELF_MAGIC_LEN)
                if head == ELF_MAGIC:
                    elf_names.append(entry.name)
    finally:
        try:
            inner_fh.close()
        except Exception:
            pass
    return elf_names, False


def _extract_layer_elfs(
    outer: tarfile.TarFile,
    layer_path: str,
    expected_names: set[str],
    dest_dir: Path,
    used_names: dict[str, int],
) -> list[dict[str, str]]:
    """Pull only the ELFs whose names are in ``expected_names`` to ``dest_dir``.

    Files are written *flat* into ``dest_dir`` (no nested directories from
    the in-image path). ``used_names`` is mutated to track basename
    collisions across calls sharing a destination.

    Returns a list of ``{"name": flat_filename, "src_path": in_image_path}``
    so the caller can record the original location in the manifest.
    """
    written: list[dict[str, str]] = []
    if not expected_names:
        return written
    layer_member = outer.getmember(layer_path)
    inner_fh = outer.extractfile(layer_member)
    if inner_fh is None:
        return written
    try:
        with tarfile.open(fileobj=inner_fh, mode="r|*") as inner:
            remaining = set(expected_names)
            for entry in inner:
                if not entry.isfile() or entry.name not in remaining:
                    continue
                data_fh = inner.extractfile(entry)
                if data_fh is None:
                    continue
                head = data_fh.read(ELF_MAGIC_LEN)
                if head != ELF_MAGIC:
                    continue
                src_path = entry.name.lstrip("./")
                flat = _disambiguate(_safe_basename(entry.name), used_names)
                dest_path = dest_dir / flat
                with dest_path.open("wb") as out_fh:
                    out_fh.write(head)
                    shutil.copyfileobj(data_fh, out_fh)
                written.append({"name": flat, "src_path": src_path})
                remaining.discard(entry.name)
                if not remaining:
                    break
    finally:
        try:
            inner_fh.close()
        except Exception:
            pass
    return written


def trace_elfs(
    image_tag: str,
    out_dir: Path,
    mode: str = MODE_LAST_ELF_LAYER,
) -> TraceResult:
    """Discover every ELF the build produced and extract the relevant subset."""
    if mode not in VALID_MODES:
        raise ValueError(f"unknown trace mode {mode!r}; expected one of {VALID_MODES}")

    out_dir.mkdir(parents=True, exist_ok=True)
    elf_root = out_dir / "elfs"
    elf_root.mkdir(parents=True, exist_ok=True)

    image_tar_path = out_dir / "_image.tar"
    if image_tar_path.exists():
        image_tar_path.unlink()

    discovered: list[dict[str, Any]] = []  # one entry per layer, populated in pass 1
    chosen_index: int | None = None

    try:
        _save_image(image_tag, image_tar_path)

        # Pass 1 - discovery only. No bytes hit the output dir yet.
        with tarfile.open(image_tar_path, mode="r") as outer_scan:
            manifest = _read_manifest(outer_scan)
            for layer_index, layer_path in enumerate(_iter_layer_paths(manifest)):
                elf_names, skipped = _scan_layer_for_elf_names(outer_scan, layer_path)
                discovered.append(
                    {
                        "layer_index": layer_index,
                        "layer_digest": layer_path,
                        "elf_names": elf_names,
                        "skipped": skipped,
                    }
                )

        # Decide which layers we actually want to extract.
        if mode == MODE_LAST_ELF_LAYER:
            for entry in reversed(discovered):
                if entry["elf_names"]:
                    chosen_index = entry["layer_index"]
                    break
            keep_indices: set[int] = {chosen_index} if chosen_index is not None else set()
        else:
            keep_indices = {entry["layer_index"] for entry in discovered if entry["elf_names"]}

        # Pass 2 - extraction (only the layers we marked to keep).
        # In ``last_elf_layer`` mode every kept layer shares the single
        # ``elfs/`` destination, so a single ``used_names`` dict carries
        # collision counters across layers. In ``all`` mode each layer has
        # its own ``layer_NNN/`` dir, so each layer gets a fresh counter.
        layers_summary: list[dict[str, Any]] = []
        unique_paths: set[str] = set()
        total_elfs = 0
        shared_used: dict[str, int] = {}
        if keep_indices:
            with tarfile.open(image_tar_path, mode="r") as outer_extract:
                for entry in discovered:
                    layer_index = entry["layer_index"]
                    elf_names: list[str] = entry["elf_names"]
                    keep = layer_index in keep_indices
                    binaries: list[dict[str, str]] = []
                    if keep and elf_names:
                        if mode == MODE_LAST_ELF_LAYER:
                            dest_dir = elf_root
                            used = shared_used
                        else:
                            dest_dir = elf_root / f"layer_{layer_index:03d}"
                            used = {}
                        dest_dir.mkdir(parents=True, exist_ok=True)
                        binaries = _extract_layer_elfs(
                            outer_extract,
                            entry["layer_digest"],
                            set(elf_names),
                            dest_dir,
                            used,
                        )
                        for bin_entry in binaries:
                            unique_paths.add(bin_entry["src_path"])
                            total_elfs += 1
                    layers_summary.append(
                        {
                            "layer_index": layer_index,
                            "layer_digest": entry["layer_digest"],
                            "elf_paths": [b["name"] for b in binaries] if keep else [],
                            "binaries": binaries if keep else [],
                            "elf_candidates": len(elf_names),
                            "kept": keep,
                            "skipped": entry.get("skipped", False),
                        }
                    )
        else:
            for entry in discovered:
                layers_summary.append(
                    {
                        "layer_index": entry["layer_index"],
                        "layer_digest": entry["layer_digest"],
                        "elf_paths": [],
                        "binaries": [],
                        "elf_candidates": len(entry["elf_names"]),
                        "kept": False,
                        "skipped": entry.get("skipped", False),
                    }
                )
    finally:
        try:
            if image_tar_path.exists():
                image_tar_path.unlink()
        except Exception:
            pass

    elf_dir_str = str(elf_root)

    chosen_digest = None
    if chosen_index is not None:
        for entry in discovered:
            if entry["layer_index"] == chosen_index:
                chosen_digest = entry["layer_digest"]
                break

    manifest_path = out_dir / "elf_manifest.json"
    manifest_payload: dict[str, Any] = {
        "image_tag": image_tag,
        "mode": mode,
        "total_elfs": total_elfs,
        "unique_elfs": len(unique_paths),
        "chosen_layer_index": chosen_index,
        "chosen_layer_digest": chosen_digest,
        "layers": layers_summary,
        "elf_dir": elf_dir_str,
    }
    manifest_path.write_text(
        json.dumps(manifest_payload, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    return TraceResult(
        image_tag=image_tag,
        mode=mode,
        total_elfs=total_elfs,
        unique_elfs=len(unique_paths),
        chosen_layer_index=chosen_index,
        chosen_layer_digest=chosen_digest,
        layers=layers_summary,
        manifest_path=str(manifest_path),
        elf_dir=elf_dir_str,
    )
