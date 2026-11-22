from __future__ import annotations

import importlib.util
import sys


MAGIC = {
    (3, 7): 3394,
    (3, 8): 3413,
    (3, 9): 3425,
    (3, 10): 3439,
    (3, 11): 3495,
    (3, 12): 3531,
    (3, 13): 3571,
}

REVERSE = {value: version for version, value in MAGIC.items()}


def magic_bytes(version=None):
    if version is None:
        return importlib.util.MAGIC_NUMBER
    if isinstance(version, str):
        major, minor = version.split(".", 1)
        version = (int(major), int(minor))
    value = MAGIC.get(tuple(version))
    if value is None:
        raise ValueError("no known magic number for Python %s" % (version,))
    return value.to_bytes(2, "little") + b"\r\n"


def magic_value(data):
    if len(data) < 2:
        raise ValueError("header is too short")
    return int.from_bytes(data[:2], "little")


def version_for(value):
    return REVERSE.get(value)


def runtime_version():
    return sys.version_info[:2]


def runtime_magic():
    return magic_value(importlib.util.MAGIC_NUMBER)
