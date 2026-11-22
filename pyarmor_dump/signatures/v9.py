import re

from . import v8_rft as _rft

NAME = "v9"
MAJOR = 9

HEADER_RE = re.compile(
    r"^#\s*Pyarmor\s+9\.(\d+)\.(\d+)([^\n]*)", re.IGNORECASE | re.MULTILINE
)

IMPORT_RE = _rft.IMPORT_RE
PAYLOAD_RE = _rft.PAYLOAD_RE
PAYLOAD_MAGIC = _rft.PAYLOAD_MAGIC


def score(text):
    points = 0.0
    markers = []

    if HEADER_RE.search(text):
        points += 0.55
        markers.append("header:v9")

    match = IMPORT_RE.search(text)
    if match:
        points += 0.25
        markers.append("bootstrap:" + match.group(1))

    if PAYLOAD_RE.search(text):
        points += 0.18
        markers.append("call:__pyarmor__")

    return min(points, 0.98), tuple(markers)


def details(text):
    return _rft.details(text)
