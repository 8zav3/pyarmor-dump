from __future__ import annotations

import importlib.util
import marshal
import os
import struct
from dataclasses import dataclass


ARMOR_FUNCTIONS = frozenset(
    {
        "C_ENTER_CO_OBJECT_INDEX",
        "C_ASSERT_ARMORED_INDEX",
        "C_LEAVE_CO_OBJECT_INDEX",
        "VMC_INIT_FRAME_INDEX",
        "VMC_EVAL_VMCODE_INDEX",
    }
)
ARMOR_NAMES = frozenset({"__assert_armored__"})

MAX_SCAN = 5000


@dataclass
class WriteResult:
    module: str
    path: str
    size: int = 0
    armored: bool = False
    error: str = ""

    def to_dict(self):
        return {
            "module": self.module,
            "path": self.path,
            "size": self.size,
            "armored": self.armored,
            "error": self.error,
        }


def armor_markers(code):
    found = set()
    stack = [code]
    seen = set()
    scanned = 0

    while stack and scanned < MAX_SCAN:
        current = stack.pop()
        scanned += 1
        if id(current) in seen:
            continue
        seen.add(id(current))

        for name in current.co_names:
            if name in ARMOR_NAMES:
                found.add("co_names:" + name)

        for const in current.co_consts:
            if isinstance(const, type(code)):
                stack.append(const)
                continue
            name = getattr(const, "__name__", None)
            if name in ARMOR_FUNCTIONS:
                found.add("const:" + name)

    return sorted(found)


def is_armored(code):
    return bool(armor_markers(code))


def build_header(code=None, magic=None, source=None):
    if magic is None:
        magic = importlib.util.MAGIC_NUMBER
    elif isinstance(magic, int):
        magic = magic.to_bytes(2, "little") + b"\r\n"

    flags = 0
    if source and os.path.isfile(source):
        stat = os.stat(source)
        mtime = int(stat.st_mtime) & 0xFFFFFFFF
        size = stat.st_size & 0xFFFFFFFF
    else:
        mtime = 0
        size = 0

    return magic + struct.pack("<III", flags, mtime, size)


def module_path(module, is_package=False):
    parts = module.split(".")
    if is_package:
        return os.path.join(*parts, "__init__.pyc")
    return os.path.join(*parts[:-1], parts[-1] + ".pyc") if len(parts) > 1 else parts[0] + ".pyc"


def write_pyc(path, code, magic=None, source=None):
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)

    header = build_header(code, magic=magic, source=source)
    payload = marshal.dumps(code)
    data = header + payload

    temp = path + ".tmp"
    try:
        with open(temp, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    except BaseException:
        try:
            os.unlink(temp)
        except OSError:
            pass
        raise

    return len(data)


class PycWriter:
    def __init__(self, output_dir, magic=None):
        self.output_dir = os.path.abspath(output_dir)
        self.magic = magic

    def write(self, module, code, is_package=False, source=None):
        relative = module_path(module, is_package=is_package)
        path = os.path.join(self.output_dir, relative)
        result = WriteResult(module=module, path=path)

        markers = armor_markers(code)
        if markers:
            result.armored = True
            result.error = "armored code object (" + ", ".join(markers) + ")"
            return result

        try:
            result.size = write_pyc(
                path, code, magic=self.magic, source=source
            )
        except (ValueError, TypeError, OSError) as exc:
            result.error = "%s: %s" % (type(exc).__name__, exc)

        return result
