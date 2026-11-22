from __future__ import annotations

import ast
import enum
import functools
import os
import re
from dataclasses import dataclass
from typing import Optional, Tuple

from . import signatures


_MAX_READ = 8 * 1024 * 1024

_HEADER_RE = re.compile(
    r"^#\s*Pyarmor\s+(\d+)\.(\d+)\.(\d+)([^\n]*)", re.IGNORECASE | re.MULTILINE
)


class PyArmorVersion(enum.Enum):
    V7 = "v7"
    V8_RFT = "v8_rft"
    V9 = "v9"
    UNKNOWN = "unknown"

    @property
    def label(self):
        return {
            "v7": "PyArmor 7.x",
            "v8_rft": "PyArmor 8.x (RFT)",
            "v9": "PyArmor 9.x",
            "unknown": "not PyArmor-protected",
        }[self.value]


@dataclass(frozen=True)
class PayloadInfo:
    magic: str
    py_version: Optional[Tuple[int, int]] = None
    marshal_magic: Optional[int] = None

    def to_dict(self):
        return {
            "magic": self.magic,
            "py_version": list(self.py_version) if self.py_version else None,
            "marshal_magic": self.marshal_magic,
        }


@dataclass(frozen=True)
class VersionInfo:
    version: PyArmorVersion
    confidence: float
    header: Optional[str] = None
    markers: Tuple[str, ...] = ()
    payload: Optional[PayloadInfo] = None
    path: Optional[str] = None

    @property
    def is_protected(self):
        return self.version is not PyArmorVersion.UNKNOWN

    def to_dict(self):
        return {
            "version": self.version.value,
            "label": self.version.label,
            "confidence": self.confidence,
            "header": self.header,
            "markers": list(self.markers),
            "payload": self.payload.to_dict() if self.payload else None,
            "path": self.path,
        }


def _read_text(path):
    with open(path, "rb") as handle:
        raw = handle.read(_MAX_READ)

    return raw.decode("utf-8", errors="replace")


def parse_payload(blob):
    if len(blob) >= 11 and blob[:2] == b"PY" and blob[2:8].isdigit():
        py_version = (blob[9], blob[10]) if blob[8] == 0 else None
        marshal_magic = (
            int.from_bytes(blob[12:14], "little") if len(blob) >= 14 else None
        )
        return PayloadInfo(blob[:8].decode("ascii"), py_version, marshal_magic)

    if blob.startswith(b"PYARMOR\x00"):
        return PayloadInfo("PYARMOR")

    return None


def _payload_from(module, text):
    match = module.PAYLOAD_RE.search(text)
    if not match:
        return None
    try:
        blob = ast.literal_eval(match.group(1))
    except (SyntaxError, ValueError):
        return None
    if not isinstance(blob, bytes):
        return None
    return parse_payload(blob)


def _finish(module, points, markers, payload, header, path):
    version = {
        "v7": PyArmorVersion.V7,
        "v8_rft": PyArmorVersion.V8_RFT,
        "v9": PyArmorVersion.V9,
    }[module.NAME]
    return VersionInfo(
        version=version,
        confidence=round(min(points, 0.98), 2),
        header=header,
        markers=tuple(markers),
        payload=payload,
        path=path,
    )


def detect_text(text, path=None):
    header_match = _HEADER_RE.search(text)
    header_line = header_match.group(0).strip() if header_match else None
    header_major = int(header_match.group(1)) if header_match else None

    if header_major is not None:
        module = signatures.BY_MAJOR.get(header_major)
        if module is None:
            return VersionInfo(
                version=PyArmorVersion.UNKNOWN,
                confidence=0.0,
                header=header_line,
                markers=("header:unknown-major",),
                path=path,
            )
        points, markers = module.score(text)
        return _finish(
            module,
            points,
            markers,
            _payload_from(module, text),
            header_line,
            path,
        )

    scores = []
    for module in signatures.ALL:
        points, markers = module.score(text)
        scores.append((points, module, markers))

    top = max(score[0] for score in scores)
    if top < 0.2:
        return VersionInfo(
            version=PyArmorVersion.UNKNOWN,
            confidence=0.0,
            header=None,
            markers=(),
            path=path,
        )

    winners = [score for score in scores if score[0] == top]
    points, module, markers = winners[0]
    if len(winners) > 1 and any(score[1] is signatures.v9 for score in winners):
        module = signatures.v8_rft
        markers = tuple(markers) + ("ambiguous-v8-v9",)

    return _finish(
        module,
        points,
        markers,
        _payload_from(module, text),
        None,
        path,
    )


@functools.lru_cache(maxsize=256)
def _detect_cached(path, mtime_ns, size):
    del mtime_ns, size
    return detect_text(_read_text(path), path=path)


def detect_file(path):
    path = os.path.abspath(path)
    stat = os.stat(path)
    return _detect_cached(path, stat.st_mtime_ns, stat.st_size)


def clear_cache():
    _detect_cached.cache_clear()
