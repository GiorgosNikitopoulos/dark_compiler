import logging
import os
import threading

_root_init_lock = threading.Lock()
_handler_lock = threading.Lock()
_root_initialized = False


class _ThreadFilter(logging.Filter):
    """Route log records to the file handler owned by the creating thread."""

    def __init__(self, thread_id: int) -> None:
        super().__init__()
        self._thread_id = thread_id

    def filter(self, record: logging.LogRecord) -> bool:
        return record.thread == self._thread_id


def _formatter(project_name: str) -> logging.Formatter:
    return logging.Formatter(
        f"%(asctime)s - %(name)s -{project_name} - %(levelname)s - %(message)s",
    )


def _ensure_root_logging() -> None:
    """Configure root once with a shared console handler (stdout may interleave)."""
    global _root_initialized
    with _root_init_lock:
        if _root_initialized:
            return
        root = logging.getLogger()
        root.setLevel(logging.DEBUG)
        has_console = any(
            isinstance(handler, logging.StreamHandler)
            and not isinstance(handler, logging.FileHandler)
            for handler in root.handlers
        )
        if not has_console:
            console = logging.StreamHandler()
            console.setLevel(logging.DEBUG)
            console.setFormatter(
                logging.Formatter(
                    "%(asctime)s - %(name)s - %(threadName)s - "
                    "%(levelname)s - %(message)s",
                ),
            )
            root.addHandler(console)
        _root_initialized = True


def attach_thread_log_file(log_file: str, project_name: str) -> logging.FileHandler:
    """Attach a per-thread file handler to the root logger."""
    _ensure_root_logging()
    log_dir = os.path.dirname(log_file)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    handler = logging.FileHandler(log_file, encoding="utf-8")
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(_formatter(project_name))
    handler.addFilter(_ThreadFilter(threading.get_ident()))
    with _handler_lock:
        logging.getLogger().addHandler(handler)
    return handler


def detach_thread_log_handler(handler: logging.Handler | None) -> None:
    """Remove and close a handler previously returned by ``attach_thread_log_file``."""
    if handler is None:
        return
    with _handler_lock:
        root = logging.getLogger()
        if handler in root.handlers:
            root.removeHandler(handler)
    handler.close()


def setup_logging(log_file: str, project_name: str) -> logging.FileHandler:
    """Backward-compatible alias for ``attach_thread_log_file``."""
    return attach_thread_log_file(log_file, project_name)


def log_the_dockerfile(dockerfile_path, version, history_dir):

    dockerfile_version_name = os.path.basename(dockerfile_path)+ '-v' + str(version)
    dockerfile_version_path = os.path.join(history_dir, dockerfile_version_name)
    with open(dockerfile_path, 'r') as f:
        content = f.read()
    with open(dockerfile_version_path, 'w') as f:
        f.write(content)
        
def log_the_error_message(error_message, version, history_dir):
    error_message_version_name = "error_message"+ '-v' + str(version)
    error_message_version_path = os.path.join(history_dir, error_message_version_name)
    with open(error_message_version_path, 'w') as f:
        f.write(error_message)
