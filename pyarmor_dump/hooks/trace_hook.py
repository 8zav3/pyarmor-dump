from __future__ import annotations

import os
import sys
import threading
import types


DEFAULT_MAX_OBJECTS = 20000
MAX_WALK_DEPTH = 64


class CodeCollector:
    def __init__(self, accept=None, walk_nested=True, max_objects=DEFAULT_MAX_OBJECTS):
        self.accept = accept if accept is not None else (lambda filename: True)
        self.walk_nested = walk_nested
        self.max_objects = max_objects

        self._seen = {}
        self._order = []
        self._roots = {}
        self._filename_cache = {}
        self._lock = threading.RLock()
        self._settrace = None
        self._installed = False

        self.hits = 0
        self.rejected = 0
        self.truncated = False

    def add(self, code):
        if not isinstance(code, types.CodeType):
            return
        with self._lock:
            if id(code) in self._seen:
                return
            if len(self._seen) >= self.max_objects:
                self.truncated = True
                return
            if not self._accepts(code):
                return

            self._remember(code)
            if self.walk_nested:
                self._walk(code)

    def _accepts(self, code):
        filename = code.co_filename
        cached = self._filename_cache.get(filename)
        if cached is None:
            try:
                cached = bool(self.accept(filename))
            except Exception:
                cached = False
            self._filename_cache[filename] = cached
        if not cached:
            self.rejected += 1
        return cached

    def _remember(self, code):
        self._seen[id(code)] = code
        self._order.append(code)
        if code.co_name == "<module>":
            key = code.co_filename
            current = self._roots.get(key)
            if current is None or len(code.co_code) > len(current.co_code):
                self._roots[key] = code

    def _walk(self, root):
        stack = [(root, 0)]
        while stack:
            code, depth = stack.pop()
            if depth >= MAX_WALK_DEPTH:
                continue
            for const in code.co_consts:
                if not isinstance(const, types.CodeType):
                    continue
                if id(const) in self._seen:
                    continue
                if len(self._seen) >= self.max_objects:
                    self.truncated = True
                    return
                if not self._accepts(const):
                    continue
                self._remember(const)
                stack.append((const, depth + 1))

    def tracer(self, frame, event, arg):
        if event == "call":
            self.hits += 1
            try:
                self.add(frame.f_code)
            except Exception:
                pass
        return None

    def install(self, settrace=None):
        if self._installed:
            return
        self._settrace = settrace or sys.settrace
        self._settrace(self.tracer)

        if hasattr(threading, "settrace"):
            threading.settrace(self.tracer)
        self._installed = True

    def uninstall(self):
        if not self._installed:
            return
        settrace = self._settrace or sys.settrace
        settrace(None)
        if hasattr(threading, "settrace"):
            threading.settrace(None)
        self._installed = False

    def code_objects(self):
        return list(self._order)

    def roots(self):
        return dict(self._roots)

    def stats(self):
        return {
            "captured": len(self._seen),
            "roots": len(self._roots),
            "hits": self.hits,
            "rejected": self.rejected,
            "truncated": self.truncated,
        }


def make_accept(roots, module_names=()):
    root_paths = tuple(
        os.path.normcase(os.path.abspath(root)).rstrip(os.sep) for root in roots
    )
    names = frozenset(module_names)

    def accept(filename):
        if not filename:
            return False

        if filename.startswith("<"):
            if not (filename.startswith("<frozen ") and filename.endswith(">")):
                return False
            name = filename[8:-1].strip()
            return name in names

        path = os.path.normcase(os.path.abspath(filename))
        parts = path.split(os.sep)

        if any(
            part == "pytransform"
            or part.startswith("pytransform_")
            or part.startswith("pyarmor_runtime")
            for part in parts
        ):
            return False

        for root in root_paths:
            if path == root or path.startswith(root + os.sep):
                return True
        return False

    return accept
