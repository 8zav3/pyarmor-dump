from __future__ import annotations

import importlib
import json
import os
import runpy
import sys
import time
import traceback

from .hooks.antidebug_patch import AntiDebugPatch, patch_is_debugger_present
from .hooks.exec_hook import ExecRecorder
from .hooks.import_hook import ImportRecorder
from .hooks.trace_hook import CodeCollector, make_accept
from .pyc.writer import PycWriter, armor_markers

DEFAULT_MAX_OBJECTS = 20000


def discover_modules(dist):
    found = {}
    for root, dirs, files in os.walk(dist):
        dirs[:] = sorted(
            name
            for name in dirs
            if name != "__pycache__"
            and name != "pytransform"
            and not name.startswith(("pyarmor_runtime", "pytransform_"))
        )
        for name in sorted(files):
            if not name.endswith(".py"):
                continue
            path = os.path.join(root, name)
            relative = os.path.relpath(path, dist)
            parts = relative[:-3].split(os.sep)
            if parts and parts[-1] == "__init__":
                parts = parts[:-1]
            if not parts:
                continue
            found[".".join(parts)] = path
    return found


def entry_module(script, known):
    target = os.path.normcase(os.path.abspath(script))
    for name, path in known.items():
        if os.path.normcase(os.path.abspath(path)) == target:
            return name
    stem = os.path.splitext(os.path.basename(script))[0]
    if stem == "__init__":
        return os.path.basename(os.path.dirname(script))
    return stem


def _under(root, path):
    root = os.path.normcase(os.path.abspath(root)).rstrip(os.sep)
    path = os.path.normcase(os.path.abspath(path))
    return path == root or path.startswith(root + os.sep)


def module_key(filename, dist, known):
    if not filename:
        return None

    if filename.startswith("<"):
        if not (filename.startswith("<frozen ") and filename.endswith(">")):
            return None
        name = filename[8:-1].strip()
        return name if name in known else None

    if not _under(dist, filename):
        return None

    relative = os.path.relpath(os.path.abspath(filename), dist)
    for suffix in (".pyc", ".py"):
        if relative.endswith(suffix):
            relative = relative[: -len(suffix)]
            break
    parts = relative.split(os.sep)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    name = ".".join(parts)
    top = name.split(".")[0]
    if (
        not name
        or top == "pytransform"
        or top.startswith(("pyarmor_runtime", "pytransform_"))
    ):
        return None
    return name


def is_bootstrap_root(code):
    names = set(code.co_names)
    if "__pyarmor__" in names:
        if any(
            name.startswith("pyarmor_runtime") or name.startswith("pytransform")
            for name in names
        ):
            return True
    if "pyarmor" in names and "pytransform" in names:
        return True
    return False


def root_rank(code):
    return (
        0 if is_bootstrap_root(code) else 1,
        len(code.co_code),
        1 if code.co_filename.startswith("<frozen ") else 0,
    )


def count_nested(code):
    seen = set()
    stack = [code]
    kind = type(code)
    while stack:
        current = stack.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        for const in current.co_consts:
            if isinstance(const, kind):
                stack.append(const)
    return max(0, len(seen) - 1)


def is_package(name, known):
    source = known.get(name)
    if source and os.path.basename(source) == "__init__.py":
        return True
    prefix = name + "."
    return any(other.startswith(prefix) for other in known)


def find_runtime_package(dist):
    try:
        entries = sorted(os.listdir(dist))
    except OSError:
        return None
    for name in entries:
        dick = os.path.join(dist, name)
        if not os.path.isdir(dick):
            continue
        if name == "pytransform" or name.startswith(
            ("pyarmor_runtime_", "pytransform_")
        ):
            return name
    return None


def _format_exc(exc):
    text = "".join(traceback.format_exception_only(type(exc), exc)).strip()
    frames = traceback.extract_tb(exc.__traceback__)
    if frames:
        last = frames[-1]
        text += " (at %s:%s)" % (os.path.basename(last.filename), last.lineno)
    return text


def _prepare_runtime(runtime_package, errors):
    if not runtime_package:
        return {"ok": False, "message": "no runtime package next to the script"}
    try:
        importlib.import_module(runtime_package)
    except BaseException as exc:
        errors["runtime"] = _format_exc(exc)
        return {"ok": False, "message": "runtime import failed"}

    message = "no runtime extension module found"
    for candidate in ("pyarmor_runtime.pyd", "pytransform.pyd", "_pytransform.dll"):
        ok, message = patch_is_debugger_present(candidate)
        if ok:
            return {"ok": True, "message": message}
    return {"ok": False, "message": message}


def run(config):
    started = time.monotonic()

    script = os.path.abspath(config["script"])
    dist = os.path.abspath(config.get("dist") or os.path.dirname(script))
    output = os.path.abspath(config["output"])
    os.makedirs(output, exist_ok=True)

    sys.dont_write_bytecode = True

    known = discover_modules(dist)
    module = config.get("module") or entry_module(script, known)
    max_objects = int(config.get("max_objects") or DEFAULT_MAX_OBJECTS)

    collector = CodeCollector(
        make_accept([dist], known.keys()), max_objects=max_objects
    )
    patch = AntiDebugPatch(assert_stubs=bool(config.get("assert_stubs")))
    importer = ImportRecorder([dist])
    executor = ExecRecorder(collector.add)

    errors = {}
    debug_patch = None
    runtime_package = find_runtime_package(dist)
    previous_argv = sys.argv

    sys.argv = [script]
    if dist not in sys.path:
        sys.path.insert(0, dist)

    try:
        collector.install(settrace=patch.real_settrace)
        patch.install()

        if config.get("patch_debug_flag"):
            debug_patch = _prepare_runtime(runtime_package, errors)

        importer.install()
        executor.install()

        try:
            importlib.import_module(module)
        except BaseException as exc:
            errors["import"] = _format_exc(exc)

        if config.get("run_main"):
            try:
                runpy.run_path(script, run_name="__main__")
            except BaseException as exc:
                errors["run_main"] = _format_exc(exc)

        if config.get("sweep"):
            for name in sorted(known):
                if name in sys.modules:
                    continue
                try:
                    importlib.import_module(name)
                except BaseException as exc:
                    errors["sweep:" + name] = _format_exc(exc)
    finally:
        executor.uninstall()
        importer.uninstall()
        patch.uninstall()
        collector.uninstall()
        sys.argv = previous_argv

    roots = {}
    for code in collector.code_objects():
        if code.co_name != "<module>":
            continue
        key = module_key(code.co_filename, dist, known)
        if key is None:
            continue
        current = roots.get(key)
        if current is None or root_rank(code) > root_rank(current):
            roots[key] = code

    writer = PycWriter(output, magic=config.get("magic"))
    modules = []
    armored = []
    failures = []

    for name in sorted(roots):
        code = roots[name]
        source = known.get(name)

        if is_bootstrap_root(code):
            failures.append(
                {
                    "module": name,
                    "path": "",
                    "size": 0,
                    "armored": False,
                    "nested": count_nested(code),
                    "error": (
                        "only the PyArmor bootstrap was captured; the runtime "
                        "did not expose a decrypted module"
                    ),
                }
            )
            continue

        markers = armor_markers(code)

        if markers:
            armored.append(
                {
                    "module": name,
                    "source": source,
                    "markers": markers,
                    "nested": count_nested(code),
                }
            )
            continue

        result = writer.write(
            name, code, is_package=is_package(name, known), source=source
        )
        entry = result.to_dict()
        entry["nested"] = count_nested(code)
        if result.error:
            failures.append(entry)
        else:
            modules.append(entry)

    manifest = {

        "ok": bool(modules or armored) and not failures,
        "python": sys.version.split()[0],
        "script": script,
        "dist": dist,
        "output": output,
        "module": module,
        "modules": modules,
        "armored": armored,
        "failures": failures,
        "errors": errors,
        "stats": collector.stats(),
        "imported": list(importer.order),
        "runtime_package": runtime_package,
        "debug_patch": debug_patch,
        "elapsed": round(time.monotonic() - started, 3),
    }
    return manifest


def write_json(path, data):
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    temp = path + ".tmp"
    with open(temp, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=False)
        handle.write("\n")
    os.replace(temp, path)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) != 1:
        sys.stderr.write("usage: python -m pyarmor_dump.worker <config.json>\n")
        return 2

    try:
        with open(argv[0], "r", encoding="utf-8") as handle:
            config = json.load(handle)
    except (OSError, ValueError) as exc:
        sys.stderr.write("cannot read worker config: %s\n" % exc)
        return 2

    try:
        manifest = run(config)
    except BaseException as exc:
        manifest = {
            "ok": False,
            "fatal": "%s: %s" % (type(exc).__name__, exc),
            "traceback": traceback.format_exc(),
        }

    path = config.get("manifest") or os.path.join(
        config.get("output", "."), "manifest.json"
    )
    try:
        write_json(path, manifest)
    except OSError as exc:
        sys.stderr.write("cannot write manifest: %s\n" % exc)
        return 2

    return 0 if manifest.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
