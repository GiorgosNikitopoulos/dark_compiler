import re

def remove_ansi_escape_sequences(text):
    # DiffDiff:add other matches
    try:
        ansi_escape_1 = re.compile(r'\^\[\[([0-9]+)(;[0-9]+)*[mG]')
        ansi_escape_2 = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
        message = re.sub(r'\x1b\[[0-9;]*[mK]|\x1b\(B', '', ansi_escape_1.sub('', text))
        cleaned_message = ansi_escape_2.sub('', message)
    except Exception as e:
        cleaned_message = text
    return cleaned_message

def extract_json_content(text):
    pattern = r"```json(.*?)```"
    match = re.search(pattern, text, re.DOTALL)

    if match:
        return match.group(1).strip().replace('\n', '')

    stripped = text.strip()
    if stripped.startswith('(') and stripped.endswith(')'):
        return stripped.replace('\n', '')

    # Common bare success form when the model skips the ```json fence.
    simple = re.search(r'\((True|False)\s*,\s*None\)', stripped)
    if simple:
        return simple.group(0)

    return "No json content found"