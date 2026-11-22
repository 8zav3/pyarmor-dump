from __future__ import annotations

import builtins
import types


class ExecRecorder:
    def __init__(self, sink):
        self.sink = sink
        self._saved = {}
        self._installed = False
        self.calls = 0

    def _record(self, code):
        if isinstance(code, types.CodeType):
            self.calls += 1
            try:
                self.sink(code)
            except Exception:
                pass

    def _exec(self, source, globals=None, locals=None, **kwargs):
        self._record(source)
        return self._saved["exec"](source, globals, locals, **kwargs)

    def _eval(self, source, globals=None, locals=None, **kwargs):
        self._record(source)
        return self._saved["eval"](source, globals, locals, **kwargs)

    def _compile(self, source, filename, mode, flags=0, dont_inherit=False,
                 optimize=-1, **kwargs):
        code = self._saved["compile"](
            source, filename, mode, flags, dont_inherit, optimize, **kwargs
        )
        self._record(code)
        return code

    def install(self):
        if self._installed:
            return
        self._saved["exec"] = builtins.exec
        self._saved["eval"] = builtins.eval
        self._saved["compile"] = builtins.compile
        builtins.exec = self._exec
        builtins.eval = self._eval
        builtins.compile = self._compile
        self._installed = True

    def uninstall(self):
        if not self._installed:
            return

        if builtins.exec is self._exec:
            builtins.exec = self._saved["exec"]
        if builtins.eval is self._eval:
            builtins.eval = self._saved["eval"]
        if builtins.compile is self._compile:
            builtins.compile = self._saved["compile"]
        self._installed = False
