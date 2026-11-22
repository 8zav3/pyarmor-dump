from __future__ import annotations

import re
from dataclasses import dataclass

from .version_detect import PyArmorVersion


_SUPER_IMPORT = re.compile(
    r"^\s*from\s+\.?pytransform[\w]*\s+import\s+pyarmor\b", re.MULTILINE
)

_SUPER_CALL = re.compile(
    r"^\s*pyarmor\s*\(\s*__name__\s*,", re.MULTILINE
)

_SUPER_NAMES = re.compile(
    r"CO_NAMES\s*=\s*set\(\[[^\]]*['\"]pyarmor['\"]", re.DOTALL
)


@dataclass(frozen=True)
class SuperModeInfo:
    enabled: bool
    generation: str
    markers: tuple
    note: str

    def to_dict(self):
        return {
            "enabled": self.enabled,
            "generation": self.generation,
            "markers": list(self.markers),
            "note": self.note,
        }


def detect(text, version=None):
    if isinstance(version, PyArmorVersion):
        version = version.value

    markers = []
    if _SUPER_IMPORT.search(text):
        markers.append("bootstrap:pyarmor-import")
    if _SUPER_CALL.search(text):
        markers.append("call:pyarmor")
    if _SUPER_NAMES.search(text):
        markers.append("protect-template:super")

    if markers:
        return SuperModeInfo(
            enabled=True,
            generation="v7",
            markers=tuple(markers),
            note=(
                "PyArmor 7 super mode: the wrapper imports the pyarmor object "
                "directly instead of calling pyarmor_runtime()."
            ),
        )

    if version in ("v8_rft", "v9"):
        return SuperModeInfo(
            enabled=False,
            generation=version,
            markers=(),
            note="Super mode is a PyArmor 7 feature and is not present in 8/9.",
        )

    return SuperModeInfo(
        enabled=False,
        generation=version or "unknown",
        markers=(),
        note="Normal bootstrap.",
    )


def describe(info):
    if info.enabled:
        return "super mode (v7 bootstrap)"
    return "not enabled"
