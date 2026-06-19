import os
import docker
import subprocess
import logging
import platform


def _get_docker_client() -> docker.APIClient:
    """
    Return a ready-to-use docker.APIClient based on the current OS.
    Raises DockerUnavailableError if the Docker service is not available.
    """
    system = platform.system()
    if system == 'Windows':
        # On Windows, Docker uses a named pipe
        pipe_path = r'\\.\\pipe\\docker_engine'
        if not os.path.exists(pipe_path):
            raise RuntimeError(
                'Docker named pipe \\\\.\\pipe\\docker_engine not found. '
                'Ensure Docker Desktop or Docker Engine is installed and running.'
            )
        base_url = 'npipe:////./pipe/docker_engine'
    else:
        # On Linux and macOS, Docker uses a Unix socket
        sock_path = '/var/run/docker.sock'
        if not os.path.exists(sock_path):
            raise RuntimeError(
                '/var/run/docker.sock not found. '
                'Ensure Docker is installed and the daemon is running.'
            )
        base_url = 'unix://var/run/docker.sock'

    # Create the client and verify connectivity
    try:
        client = docker.APIClient(base_url=base_url)
        client.ping()
        return client
    except Exception as e:
        raise RuntimeError(f'Docker daemon not available: {e}') from e


def build_docker_image(project_dir, tag=None):
    cmd = ["docker", "build"]
    if tag:
        cmd.extend(["-t", tag])
    cmd.append(project_dir)
    result = subprocess.run(cmd, capture_output=False, text=True)
    if result.returncode != 0:
        return False
    return True


def _extract_image_id(chunk_history):
    """Best-effort: pull the final image id out of the build chunk stream.

    The docker engine emits an ``aux`` chunk like
    ``{"aux": {"ID": "sha256:..."}}`` on success, and a textual
    ``Successfully built <short_id>`` line as a fallback.
    """
    for chunk in reversed(chunk_history):
        aux = chunk.get('aux') if isinstance(chunk, dict) else None
        if isinstance(aux, dict) and aux.get('ID'):
            return aux['ID']
    for chunk in reversed(chunk_history):
        stream = chunk.get('stream') if isinstance(chunk, dict) else None
        if isinstance(stream, str) and 'Successfully built' in stream:
            try:
                return stream.strip().split()[-1]
            except Exception:
                pass
    return None


def build_docker_image_by_api(project_dir, tag=None):
    """Build an image via the Docker engine API.

    Args:
        project_dir: directory containing the Dockerfile.
        tag: optional repository:tag string to apply to the resulting image.
            When set, ``rm``/``forcerm`` are also passed so the legacy
            builder cleans up its intermediate containers automatically.

    Returns:
        ``(flag_success, message_or_chunks, image_id)`` where ``image_id``
        is the sha256 of the final image when known and ``None`` otherwise.
    """

    logger = logging.getLogger(__name__)
    logger.disabled = False
    client = _get_docker_client()
    flag_success = True
    image_id = None
    try:
        build_kwargs = {"path": project_dir, "decode": True, "rm": True, "forcerm": True}
        if tag:
            build_kwargs["tag"] = tag
        response = client.build(**build_kwargs)
        chunk_history = []
        unexpected_chunk = []
        for chunk in response:
            if 'stream' in chunk:
                if chunk['stream'] == '\n': continue
                logger.info(chunk['stream'])
            else:
                unexpected_chunk.append(chunk)
            chunk_history.append(chunk)
        
        if 'errorDetail' in chunk_history[-1]:
            flag_success = False
            error = chunk['errorDetail']['message']
            if len(chunk_history) >=5:
                return flag_success, "".join([chunk_item['stream'] for chunk_item in chunk_history[-5:-1] if 'stream' in chunk_item])+error, None
            else:
                return flag_success, "".join([chunk_item['stream'] for chunk_item in chunk_history[:-1] if 'stream' in chunk_item])+error, None
        if 'message' in chunk:
            if 'dockerfile parse error' in chunk['message']:
                flag_success = False
                return flag_success, chunk['message'], None

        image_id = _extract_image_id(chunk_history)
        return flag_success, chunk_history, image_id
    except Exception as e:
        flag_success = False
        message = str(e)
        return flag_success, message, None