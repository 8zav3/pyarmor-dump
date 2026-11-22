from __future__ import annotations

import builtins
import ctypes
import os
import struct
import sys

ASSERT_NAMES = (
    "__assert_armored__",
    "__assert_called__",
    "__assert_imported__",
)


def _build_debugger_stub():
    if os.name != "nt":
        return None

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.VirtualAlloc.restype = ctypes.c_void_p
    kernel32.VirtualAlloc.argtypes = [
        ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_uint32,
    ]
    kernel32.VirtualProtect.restype = ctypes.c_int
    kernel32.VirtualProtect.argtypes = [
        ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32),
    ]

    address = kernel32.VirtualAlloc(None, 16, 0x3000, 0x04)
    if not address:
        return None

    ctypes.memmove(address, b"\x31\xc0\xc3", 3)

    old = ctypes.c_uint32()
    kernel32.VirtualProtect(address, 16, 0x20, ctypes.byref(old))
    return address


_DEBUGGER_STUB = _build_debugger_stub()


def _nothing():
    return None


def _ignore(*args, **kwargs):
    return None


def _assert_ok(*args, **kwargs):
    return None


class AntiDebugPatch:
    def __init__(self, stealth=True, freeze=True, assert_stubs=False):
        self.stealth = stealth
        self.freeze = freeze
        self.assert_stubs = assert_stubs

        self._saved = {}
        self._stubbed = []
        self._installed = False

    @property
    def real_settrace(self):
        return self._saved.get("settrace", sys.settrace)

    @property
    def real_gettrace(self):
        return self._saved.get("gettrace", sys.gettrace)

    def install(self):
        if self._installed:
            return

        for name in ("gettrace", "getprofile", "settrace", "setprofile"):
            self._saved[name] = getattr(sys, name)

        if self.stealth:
            sys.gettrace = _nothing
            sys.getprofile = _nothing

        if self.freeze:
            sys.settrace = _ignore
            sys.setprofile = _ignore

        if self.assert_stubs:
            for name in ASSERT_NAMES:
                if not hasattr(builtins, name):
                    self._stubbed.append(name)
                    setattr(builtins, name, _assert_ok)

        self._installed = True

    def uninstall(self):
        if not self._installed:
            return

        for name, value in self._saved.items():
            setattr(sys, name, value)

        for name in self._stubbed:
            if getattr(builtins, name, None) is _assert_ok:
                delattr(builtins, name)
        self._stubbed = []
        self._installed = False

    def __enter__(self):
        self.install()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.uninstall()
        return False


def _cstring(data, offset):
    end = data.find(b"\x00", offset)
    if end < 0:
        raise ValueError("unterminated string in PE image")
    return data[offset:end].decode("ascii", errors="replace")


def _image_size(data):
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\x00\x00":
        raise ValueError("not a PE image")
    opt = pe + 4 + 20
    return struct.unpack_from("<I", data, opt + 56)[0]


def _pe_imports(data, memory=False):
    if data[:2] != b"MZ":
        raise ValueError("missing MZ header")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\x00\x00":
        raise ValueError("missing PE signature")

    coff = pe + 4
    nsections = struct.unpack_from("<H", data, coff + 2)[0]
    opt_size = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]

    if magic == 0x20B:
        directories = opt + 112
        thunk_size = 8
        thunk_fmt = "<Q"
        flag = 1 << 63
    elif magic == 0x10B:
        directories = opt + 96
        thunk_size = 4
        thunk_fmt = "<I"
        flag = 1 << 31
    else:
        raise ValueError("unknown optional header magic 0x%x" % magic)

    import_rva = struct.unpack_from("<I", data, directories + 8)[0]

    sections = []
    section = opt + opt_size
    for index in range(nsections):
        base = section + index * 40
        virtual_size, virtual_addr, raw_size, raw_ptr = struct.unpack_from(
            "<IIII", data, base + 8
        )
        sections.append((virtual_addr, max(virtual_size, raw_size), raw_ptr))

    def rva_to_offset(rva):
        if memory:
            return rva
        for virtual_addr, size, raw_ptr in sections:
            if virtual_addr <= rva < virtual_addr + size:
                return raw_ptr + (rva - virtual_addr)
        raise ValueError("RVA 0x%x is outside every section" % rva)

    imports = []
    descriptor = rva_to_offset(import_rva)
    while True:
        fields = struct.unpack_from("<IIIII", data, descriptor)
        if not any(fields):
            break
        original_first_thunk, _stamp, _chain, name_rva, first_thunk = fields
        dll = _cstring(data, rva_to_offset(name_rva))

        thunk_rva = original_first_thunk or first_thunk
        index = 0
        while True:
            entry = rva_to_offset(thunk_rva + index * thunk_size)
            value = struct.unpack_from(thunk_fmt, data, entry)[0]
            if value == 0:
                break
            if not value & flag:
                name_offset = rva_to_offset(value)
                function = _cstring(data, name_offset + 2)
                slot_rva = first_thunk + index * thunk_size
                imports.append(
                    (dll, function, slot_rva, rva_to_offset(slot_rva))
                )
            index += 1
        descriptor += 20

    return imports


def patch_is_debugger_present(module_name=None):
    if os.name != "nt":
        return False, "windows only"
    if module_name is None:
        module_name = "pyarmor_runtime"

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
    kernel32.GetModuleHandleW.restype = ctypes.c_void_p

    base = None
    for candidate in (module_name, os.path.basename(module_name),
                      os.path.splitext(os.path.basename(module_name))[0]):
        base = kernel32.GetModuleHandleW(candidate)
        if base:
            break
    if not base:
        return False, "runtime module is not loaded"

    try:
        header = ctypes.string_at(base, 0x400)
        image = ctypes.string_at(base, _image_size(header))
        imports = _pe_imports(image, memory=True)
    except (ValueError, OSError) as exc:
        return False, "cannot parse import table: %s" % exc

    slots = [slot for _dll, name, slot, _off in imports
             if name == "IsDebuggerPresent"]
    if not slots:
        return False, "IsDebuggerPresent is not imported"
    if not _DEBUGGER_STUB:
        return False, "cannot allocate the debugger stub"

    stub = _DEBUGGER_STUB
    pointer_size = ctypes.sizeof(ctypes.c_void_p)
    kernel32.VirtualProtect.argtypes = [
        ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    kernel32.VirtualProtect.restype = ctypes.c_int

    patched = 0
    for slot_rva in slots:
        address = base + slot_rva
        old = ctypes.c_uint32()
        if not kernel32.VirtualProtect(address, pointer_size, 0x04,
                                       ctypes.byref(old)):
            continue
        ctypes.c_void_p.from_address(address).value = stub
        kernel32.VirtualProtect(address, pointer_size, old.value,
                                ctypes.byref(old))
        patched += 1

    return patched > 0, "patched %d IAT slot(s)" % patched
