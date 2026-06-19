from .docker_manager import build_docker_image_by_api
from .discriminator import build_success_check_2, build_success_check_reflection

prev_message = ""


def check_message(message):
    global prev_message
    if message is None:
        message = prev_message
    else:
        prev_message = message
    return message

def executor(dockerfile_path, build_system_name, tag=None):
    """Build the project's Dockerfile and run the success discriminators.

    Returns ``(flag_success, message, image_id)``. ``image_id`` is the sha256
    of the produced image when the build succeeded and the engine reported
    one, otherwise ``None``. The optional ``tag`` is forwarded so the
    orchestrator can label every dark_orchestrator-managed build.
    """
    flag_success, execution_message, image_id = build_docker_image_by_api(dockerfile_path, tag=tag)

    execution_message = check_message(execution_message)
    if flag_success == True:
        flag_success, success_check_message = build_success_check_2(dockerfile_path, execution_message, build_system_name)
        if flag_success == True:
            flag_success, reflection_message = build_success_check_reflection(dockerfile_path, execution_message, build_system_name)
            return flag_success, reflection_message, image_id
        else:
            return flag_success, success_check_message, image_id
    else:
        return flag_success, execution_message, image_id




