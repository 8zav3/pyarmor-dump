import re

NAME = "v7"
MAJOR = 7

HEADER_RE = re.compile(
    r"^#\s*Pyarmor\s+7\.(\d+)\.(\d+)([^\n]*)", re.IGNORECASE | re.MULTILINE
)


IMPORT_RE = re.compile(
    r"^\s*from\s+\.?pytransform[\w]*\s+import\s+(pyarmor_runtime|pyarmor)\b",
    re.MULTILINE,
)
SUPER_IMPORT_RE = re.compile(
    r"^\s*from\s+\.?pytransform[\w]*\s+import\s+pyarmor\b", re.MULTILINE
)
RUNTIME_CALL_RE = re.compile(r"^\s*pyarmor_runtime\s*\(", re.MULTILINE)
SUPER_CALL_RE = re.compile(r"^\s*pyarmor\s*\(", re.MULTILINE)


PAYLOAD_RE = re.compile(
    r"__pyarmor\w*__\(\s*__name__\s*,\s*[^,]+,\s*(b'(?:[^'\\]|\\.)*')",
    re.DOTALL,
)

PAYLOAD_MAGIC = b"PYARMOR\x00"


def score(text):
    points = 0.0
    markers = []

    if HEADER_RE.search(text):
        points += 0.55
        markers.append("header:v7")

    match = IMPORT_RE.search(text)
    if match:
        points += 0.25
        if match.group(1) == "pyarmor":
            markers.append("bootstrap:pyarmor(super)")
        else:
            markers.append("bootstrap:pytransform")

    if PAYLOAD_RE.search(text):
        points += 0.18
        markers.append("call:__pyarmor__")

    return min(points, 0.98), tuple(markers)


def details(text):
    info = {"suffix": None, "relative": False, "super": False}

    match = IMPORT_RE.search(text)
    if match:
        info["super"] = match.group(1) == "pyarmor"
        line = text[match.start() : match.end()]
        info["relative"] = "from ." in line

    suffix = re.search(r"suffix\s*=\s*['\"]([^'\"]*)['\"]", text)
    if suffix:
        info["suffix"] = suffix.group(1)

    return info
