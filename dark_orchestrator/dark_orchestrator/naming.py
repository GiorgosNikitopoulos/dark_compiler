"""Centralized naming for dark_orchestrator-managed Docker images and containers.

Every image we tag and every container we spawn is given a deterministic
``dark_cxx`` prefix so they are trivially listable / reapable from the host:

    docker images  --filter "reference=dark_cxx/*"
    docker ps -a   --filter "name=dark_cxx_"

The ``run_id`` is generated once per pipeline invocation and recorded in the
checkpoint so resumed runs keep grouping their resources under the same id.
"""
from __future__ import annotations

import os
import re
from datetime import datetime

IMAGE_NAMESPACE = "dark_cxx"
CONTAINER_PREFIX = "dark_cxx_"

_INVALID_TAG_CHARS = re.compile(r"[^a-z0-9._-]")


def _sanitize(component: str) -> str:
    """Force a name component into a Docker-legal lowercase token."""
    cleaned = _INVALID_TAG_CHARS.sub("-", component.lower())
    cleaned = cleaned.strip("-._")
    return cleaned or "x"


def make_run_id() -> str:
    """Generate a fresh run id, e.g. ``20260531_223000_a1b2``."""
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    suffix = os.urandom(2).hex()
    return f"{stamp}_{suffix}"


def image_tag(run_id: str, item_id: str, side: str, attempt: int = 1) -> str:
    """Return the per-attempt image tag.

    Example: ``dark_cxx/20260531_223000_a1b2/abcdef0123456789/parent:v1``
    """
    return (
        f"{IMAGE_NAMESPACE}/"
        f"{_sanitize(run_id)}/"
        f"{_sanitize(item_id)}/"
        f"{_sanitize(side)}:v{int(attempt)}"
    )


def image_tag_glob(run_id: str | None = None, item_id: str | None = None, side: str | None = None) -> str:
    """Return a Docker reference glob matching attempt tags for a scope."""
    parts = [IMAGE_NAMESPACE]
    parts.append(_sanitize(run_id) if run_id else "*")
    parts.append(_sanitize(item_id) if item_id else "*")
    parts.append(f"{_sanitize(side)}" if side else "*")
    return "/".join(parts) + ":*"


def container_name(run_id: str, item_id: str, side: str, suffix: str | None = None) -> str:
    """Return a unique container name within the dark_cxx prefix."""
    rand = suffix or os.urandom(2).hex()
    return (
        CONTAINER_PREFIX
        + f"{_sanitize(run_id)}_{_sanitize(item_id)}_{_sanitize(side)}_{_sanitize(rand)}"
    )


def is_dark_cxx_image_ref(reference: str) -> bool:
    return reference.startswith(IMAGE_NAMESPACE + "/")


def is_dark_cxx_container_name(name: str) -> bool:
    return name.lstrip("/").startswith(CONTAINER_PREFIX)
