import re

NAME = "v8_rft"
MAJOR = 8

HEADER_RE = re.compile(
    r"^#\s*Pyarmor\s+8\.(\d+)\.(\d+)([^\n]*)", re.IGNORECASE | re.MULTILINE
)


IMPORT_RE = re.compile(
    r"^\s*from\s+(pyarmor_runtime_\d{6})\s+import\s+__pyarmor__", re.MULTILINE
)

PAYLOAD_RE = re.compile(
    r"__pyarmor__\(\s*__name__\s*,\s*[^,]+,\s*(b'(?:[^'\\]|\\.)*')", re.DOTALL
)

PAYLOAD_MAGIC = b"PY"


def score(text):
    points = 0.0
    markers = []

    if HEADER_RE.search(text):
        points += 0.55
        markers.append("header:v8")

    match = IMPORT_RE.search(text)
    if match:
        points += 0.25
        markers.append("bootstrap:" + match.group(1))

    if PAYLOAD_RE.search(text):
        points += 0.18
        markers.append("call:__pyarmor__")

    return min(points, 0.98), tuple(markers)


def details(text):
    info = {"runtime_package": None}
    match = IMPORT_RE.search(text)
    if match:
        info["runtime_package"] = match.group(1)
    return info
