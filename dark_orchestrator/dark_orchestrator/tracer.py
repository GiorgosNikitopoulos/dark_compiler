"""Per-layer ELF tracer.

Docker (and OCI) image tarballs ship one tarball per layer, where each layer
is the *diff* of the file system after the corresponding Dockerfile step
(``RUN``/``COPY``/``ADD``). That makes them an exact ledger of "what this
build step produced". By saving the image, walking each layer in order, and
recognising files that begin with the ELF magic header (``\\x7fELF``), we get
a faithful trace of every binary the build emitted, attributed to the step
that emitted it.

The tracer:

1. Streams ``docker save <image>`` to a temp tarball.
2. Reads ``manifest.json`` to find the ordered list of layer tarballs.
3. For each layer, walks every regular file inside, peeks at the first 4
   bytes, and if they match the ELF magic the file is written to
   ``<out_dir>/elfs/layer_NNN/<path>`` and recorded in the manifest.
4. Writes ``<out_dir>/elf_manifest.json`` with the per-layer list and the
   image-wide dedup'd binary list.
5. Cleans up the temp image tarball.

The image itself is **not** removed here; the orchestrator owns image
lifecycle via ``cleanup.purge_image`` so failure modes stay separate.
"""
from __future__ import annotations

import json
import logging
import shutil
import tarfile
from dataclasses import dataclass
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


@dataclass
class TraceResult:
    image_tag: str
    total_elfs: int
    unique_elfs: int
    layers: list[dict[str, Any]]
    manifest_path: str
    elf_dir: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "image_tag": self.image_tag,
            "total_elfs": self.total_elfs,
            "unique_elfs": self.unique_elfs,
            "layers": self.layers,
            "manifest_path": self.manifest_path,
            "elf_dir": self.elf_dir,
        }


def _safe_relpath(name: str) -> Path:
    """Sanitize a tar entry name into a path that cannot escape out_dir."""
    parts = []
    for part in Path(name).parts:
        if part in ("", ".", ".."):
            continue
        if part.startswith("/"):
            part = part.lstrip("/")
        if not part:
            continue
        if len(part) > _MAX_PATH_COMPONENT:
            part = part[:_MAX_PATH_COMPONENT]
        parts.append(part)
    if not parts:
        return Path("_unnamed")
    return Path(*parts)


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


def _peek_is_elf(stream) -> tuple[bool, bytes]:
    head = stream.read(ELF_MAGIC_LEN)
    return (head == ELF_MAGIC, head)


def trace_elfs(image_tag: str, out_dir: Path) -> TraceResult:
    """Extract every ELF produced by a Docker image, grouped by layer."""
    out_dir.mkdir(parents=True, exist_ok=True)
    elf_root = out_dir / "elfs"
    elf_root.mkdir(parents=True, exist_ok=True)

    image_tar_path = out_dir / "_image.tar"
    if image_tar_path.exists():
        image_tar_path.unlink()

    layers_summary: list[dict[str, Any]] = []
    unique_paths: set[str] = set()
    total_elfs = 0

    try:
        _save_image(image_tag, image_tar_path)
        with tarfile.open(image_tar_path, mode="r") as outer:
            manifest = _read_manifest(outer)
            for layer_index, layer_path in enumerate(_iter_layer_paths(manifest)):
                layer_dir = elf_root / f"layer_{layer_index:03d}"
                elf_paths_for_layer: list[str] = []
                try:
                    layer_member = outer.getmember(layer_path)
                except KeyError:
                    logger.warning("layer %s missing from image tar", layer_path)
                    layers_summary.append(
                        {
                            "layer_index": layer_index,
                            "layer_digest": layer_path,
                            "elf_paths": [],
                            "skipped": True,
                        }
                    )
                    continue
                inner_fh = outer.extractfile(layer_member)
                if inner_fh is None:
                    logger.warning("could not open layer %s", layer_path)
                    layers_summary.append(
                        {
                            "layer_index": layer_index,
                            "layer_digest": layer_path,
                            "elf_paths": [],
                            "skipped": True,
                        }
                    )
                    continue
                try:
                    with tarfile.open(fileobj=inner_fh, mode="r|*") as inner:
                        for entry in inner:
                            if not entry.isfile():
                                continue
                            data_fh = inner.extractfile(entry)
                            if data_fh is None:
                                continue
                            is_elf, head = _peek_is_elf(data_fh)
                            if not is_elf:
                                continue
                            rel = _safe_relpath(entry.name)
                            dest_path = layer_dir / rel
                            dest_path.parent.mkdir(parents=True, exist_ok=True)
                            with dest_path.open("wb") as out_fh:
                                out_fh.write(head)
                                shutil.copyfileobj(data_fh, out_fh)
                            recorded = entry.name.lstrip("./")
                            elf_paths_for_layer.append(recorded)
                            unique_paths.add(recorded)
                            total_elfs += 1
                finally:
                    try:
                        inner_fh.close()
                    except Exception:
                        pass
                layers_summary.append(
                    {
                        "layer_index": layer_index,
                        "layer_digest": layer_path,
                        "elf_paths": elf_paths_for_layer,
                    }
                )
    finally:
        try:
            if image_tar_path.exists():
                image_tar_path.unlink()
        except Exception:
            pass

    manifest_path = out_dir / "elf_manifest.json"
    manifest_payload: dict[str, Any] = {
        "image_tag": image_tag,
        "total_elfs": total_elfs,
        "unique_elfs": len(unique_paths),
        "layers": layers_summary,
        "elf_dir": str(elf_root),
    }
    manifest_path.write_text(json.dumps(manifest_payload, indent=2, sort_keys=True), encoding="utf-8")

    return TraceResult(
        image_tag=image_tag,
        total_elfs=total_elfs,
        unique_elfs=len(unique_paths),
        layers=layers_summary,
        manifest_path=str(manifest_path),
        elf_dir=str(elf_root),
    )
