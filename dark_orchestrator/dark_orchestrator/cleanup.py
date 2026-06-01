"""Image / container lifecycle and Ctrl+C teardown for dark_orchestrator.

Responsibilities:

* Track every image tag and container name we create so we can stop and
  remove them on demand.
* Provide ``purge_image`` / ``purge_all_for`` so the adapter can free disk
  the moment a build's ELFs have been extracted.
* Install SIGINT/SIGTERM handlers that perform a best-effort teardown
  (stop+rm dark_cxx_* containers, rmi dark_cxx/* images, prune dangling
  layers) before re-raising KeyboardInterrupt.

All Docker calls are guarded with try/except so cleanup never crashes the
pipeline even if the daemon is unhealthy.
"""
from __future__ import annotations

import logging
import signal
import threading
from typing import Any, Callable

try:
    import docker
    from docker.errors import APIError, NotFound
except Exception:  # pragma: no cover - docker optional at import time
    docker = None  # type: ignore[assignment]
    APIError = Exception  # type: ignore[assignment,misc]
    NotFound = Exception  # type: ignore[assignment,misc]

from . import naming

logger = logging.getLogger(__name__)


class CleanupRegistry:
    """Thread-safe registry of dark_cxx images and containers."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._images: set[str] = set()
        self._containers: set[str] = set()
        self._signal_handlers_installed = False
        self._previous_handlers: dict[int, Any] = {}
        self._on_cleanup_metric: Callable[[str, int], None] | None = None
        self.keep_images = False

    def set_metric_callback(self, cb: Callable[[str, int], None] | None) -> None:
        self._on_cleanup_metric = cb

    def _bump(self, key: str, amount: int = 1) -> None:
        if self._on_cleanup_metric is not None:
            try:
                self._on_cleanup_metric(key, amount)
            except Exception:  # pragma: no cover
                logger.exception("metric callback failed")

    def register_image(self, image_tag: str) -> None:
        with self._lock:
            self._images.add(image_tag)

    def register_container(self, container_name: str) -> None:
        with self._lock:
            self._containers.add(container_name)

    def forget_image(self, image_tag: str) -> None:
        with self._lock:
            self._images.discard(image_tag)

    def forget_container(self, container_name: str) -> None:
        with self._lock:
            self._containers.discard(container_name)

    def _client(self):
        if docker is None:
            return None
        try:
            return docker.from_env()
        except Exception as exc:  # pragma: no cover
            logger.warning("docker client unavailable for cleanup: %s", exc)
            return None

    def stop_and_remove_container(self, name: str) -> None:
        client = self._client()
        if client is None:
            return
        try:
            container = client.containers.get(name)
        except NotFound:
            self.forget_container(name)
            return
        except APIError as exc:
            logger.warning("could not look up container %s: %s", name, exc)
            return
        try:
            container.stop(timeout=5)
        except Exception:
            pass
        try:
            container.remove(force=True)
        except Exception as exc:
            logger.warning("could not remove container %s: %s", name, exc)
        finally:
            self.forget_container(name)

    def remove_image(self, tag: str) -> bool:
        if self.keep_images:
            return False
        client = self._client()
        if client is None:
            return False
        try:
            client.images.remove(tag, force=True, noprune=False)
            self._bump("images_cleaned", 1)
            return True
        except NotFound:
            return True
        except APIError as exc:
            logger.warning("could not remove image %s: %s", tag, exc)
            self._bump("images_failed_cleanup", 1)
            return False
        finally:
            self.forget_image(tag)

    def purge_image(self, tag: str) -> bool:
        return self.remove_image(tag)

    def purge_all_for(self, run_id: str, item_id: str, side: str) -> None:
        with self._lock:
            scoped = [
                t
                for t in self._images
                if t.startswith(f"{naming.IMAGE_NAMESPACE}/{naming._sanitize(run_id)}/{naming._sanitize(item_id)}/{naming._sanitize(side)}:")
            ]
        for tag in scoped:
            self.remove_image(tag)

    def prune_dangling(self) -> None:
        if self.keep_images:
            return
        client = self._client()
        if client is None:
            return
        try:
            client.images.prune(filters={"dangling": True})
        except Exception as exc:  # pragma: no cover
            logger.warning("dangling prune failed: %s", exc)

    def cleanup_all(self) -> None:
        with self._lock:
            containers = list(self._containers)
            images = list(self._images)
        for name in containers:
            self.stop_and_remove_container(name)
        for tag in images:
            self.remove_image(tag)
        self._sweep_by_prefix()
        self.prune_dangling()

    def _sweep_by_prefix(self) -> None:
        """Catch any stragglers we lost track of (e.g. on race conditions)."""
        client = self._client()
        if client is None:
            return
        try:
            for container in client.containers.list(all=True):
                for nm in [container.name] + (container.attrs.get("Names") or []):
                    if isinstance(nm, str) and naming.is_dark_cxx_container_name(nm):
                        try:
                            container.stop(timeout=5)
                        except Exception:
                            pass
                        try:
                            container.remove(force=True)
                        except Exception:
                            pass
                        break
        except Exception as exc:  # pragma: no cover
            logger.warning("container sweep failed: %s", exc)
        if self.keep_images:
            return
        try:
            for image in client.images.list():
                tags = image.tags or []
                for tag in tags:
                    if naming.is_dark_cxx_image_ref(tag):
                        try:
                            client.images.remove(tag, force=True, noprune=False)
                            self._bump("images_cleaned", 1)
                        except Exception:
                            self._bump("images_failed_cleanup", 1)
        except Exception as exc:  # pragma: no cover
            logger.warning("image sweep failed: %s", exc)

    def install_signal_handlers(self) -> None:
        if self._signal_handlers_installed:
            return

        def _handler(signum, frame):  # noqa: ARG001
            logger.warning("received signal %s; tearing down dark_cxx resources", signum)
            try:
                self.cleanup_all()
            finally:
                self.uninstall_signal_handlers()
                if signum == signal.SIGINT:
                    raise KeyboardInterrupt
                raise SystemExit(128 + int(signum))

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                self._previous_handlers[sig] = signal.getsignal(sig)
                signal.signal(sig, _handler)
            except (ValueError, OSError):
                # signal handlers can only be set in the main thread
                pass
        self._signal_handlers_installed = True

    def uninstall_signal_handlers(self) -> None:
        if not self._signal_handlers_installed:
            return
        for sig, prev in self._previous_handlers.items():
            try:
                signal.signal(sig, prev)
            except (ValueError, OSError):
                pass
        self._previous_handlers.clear()
        self._signal_handlers_installed = False


_REGISTRY = CleanupRegistry()


def get_registry() -> CleanupRegistry:
    return _REGISTRY


def register_image(image_tag: str) -> None:
    _REGISTRY.register_image(image_tag)


def register_container(container_name: str) -> None:
    _REGISTRY.register_container(container_name)


def purge_image(tag: str) -> bool:
    return _REGISTRY.purge_image(tag)


def purge_all_for(run_id: str, item_id: str, side: str) -> None:
    _REGISTRY.purge_all_for(run_id, item_id, side)


def cleanup_all() -> None:
    _REGISTRY.cleanup_all()


def install_signal_handlers() -> None:
    _REGISTRY.install_signal_handlers()


def uninstall_signal_handlers() -> None:
    _REGISTRY.uninstall_signal_handlers()
