from __future__ import annotations

import importlib.abc
import os
import sys


class ImportRecorder(importlib.abc.MetaPathFinder):
    def __init__(self, roots):
        self.roots = tuple(
            os.path.normcase(os.path.abspath(root)).rstrip(os.sep) for root in roots
        )
        self.records = {}
        self.order = []
        self._installed = False

    def owns(self, origin):
        if not origin or origin.startswith("<"):
            return False
        path = os.path.normcase(os.path.abspath(origin))
        parts = path.split(os.sep)
        if any(
            part == "pytransform"
            or part.startswith("pytransform_")
            or part.startswith("pyarmor_runtime")
            for part in parts
        ):
            return False
        for root in self.roots:
            if path.startswith(root + os.sep):
                return True
        return False

    def find_spec(self, fullname, path=None, target=None):
        for finder in tuple(sys.meta_path):
            if finder is self:
                continue
            find_spec = getattr(finder, "find_spec", None)
            if find_spec is None:
                continue
            try:
                spec = find_spec(fullname, path, target)
            except (ImportError, AttributeError):
                continue
            if spec is None:
                continue
            origin = getattr(spec, "origin", None)
            if self.owns(origin):
                if fullname not in self.records:
                    self.order.append(fullname)
                self.records[fullname] = origin
            return spec
        return None

    def install(self):
        if self._installed:
            return
        sys.meta_path.insert(0, self)
        self._installed = True

    def uninstall(self):
        if not self._installed:
            return
        try:
            sys.meta_path.remove(self)
        except ValueError:
            pass
        self._installed = False

    def modules(self):
        return dict(self.records)
