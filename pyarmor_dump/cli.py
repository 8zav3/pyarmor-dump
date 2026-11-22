from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile

from . import __version__
from .super_mode import describe as describe_super
from .super_mode import detect as detect_super
from .version_detect import PyArmorVersion, detect_file

DEFAULT_TIMEOUT = 180
IDK = 0.2
OMG = 10.0
GAP = 2
DICK = "-"


def idk(value, fallback=DICK):
    return fallback if value is None or value == "" else value


def omg(seconds):
    return "%.1fs" % seconds


def _read_text(path):
    with open(path, "rb") as handle:
        return handle.read(4 * 1024 * 1024).decode("utf-8", errors="replace")


def _parse_python(text):
    parts = str(text or "").split(".")
    if len(parts) < 2:
        return None
    try:
        return int(parts[0]), int(parts[1])
    except ValueError:
        return None


def _human_size(size):
    if size < 1024:
        return "%d B" % size
    value = float(size)
    for unit in ("kB", "MB", "GB"):
        value /= 1024.0
        if value < 1024.0 or unit == "GB":
            return "%.1f %s" % (value, unit)
    return "%d B" % size


def _table(headers, rows):
    widths = [len(header) for header in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(str(cell)))

    template = (" " * GAP).join("{:<%d}" % width for width in widths)
    lines = [template.format(*headers)]
    lines.append((" " * GAP).join("-" * width for width in widths))
    for row in rows:
        lines.append(template.format(*[str(cell) for cell in row]))
    return "\n".join(lines)


def find_dist(script):
    start = os.path.dirname(os.path.abspath(script))
    current = start
    for _ in range(4):
        try:
            entries = os.listdir(current)
        except OSError:
            break
        if any(
            entry == "pytransform"
            or entry.startswith(("pyarmor_runtime_", "pytransform_"))
            for entry in entries
        ):
            return current
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return start


def _print_version(info, super_info):
    rows = [
        ("version", info.version.label),
        ("confidence", "%.2f" % info.confidence),
        ("header", idk(info.header)),
        ("markers", idk(", ".join(info.markers))),
        ("super mode", describe_super(super_info)),
    ]
    if info.payload:
        payload = info.payload
        if payload.py_version:
            python = ".".join(str(part) for part in payload.py_version)
        else:
            python = "?"
        if payload.marshal_magic is not None:
            marshal = "0x%04x" % payload.marshal_magic
        else:
            marshal = "?"
        rows.append(
            ("payload", "%s, Python %s, marshal %s" % (payload.magic, python, marshal))
        )
    print(_table(("field", "value"), rows))


def _print_manifest(manifest):
    rows = []
    for entry in manifest.get("modules", []):
        rows.append(
            (
                entry["module"],
                "written",
                _human_size(entry.get("size", 0)),
                entry.get("nested", 0),
            )
        )
    for entry in manifest.get("armored", []):
        rows.append((entry["module"], "armored", "-", entry.get("nested", 0)))
    for entry in manifest.get("failures", []):
        rows.append((entry["module"], "failed", "-", entry.get("nested", 0)))

    print()
    if rows:
        print(_table(("module", "status", "size", "nested"), rows))
    else:
        print("no modules captured")

    armored = manifest.get("armored", [])
    if armored:
        print()
        print(
            "note: %d module(s) are armored. PyArmor's default --obf-code 1"
            % len(armored)
        )
        print("      decrypts into a private C buffer; no Python code object")
        print("      exists to serialize. Regenerate with --obf-code 0 to make")
        print("      those modules extractable.")

    for entry in manifest.get("failures", []):
        print()
        print("failed: %s: %s" % (entry["module"], entry.get("error", "")))

    errors = manifest.get("errors") or {}
    if errors:
        print()
        for name, message in errors.items():
            print("worker note: %s: %s" % (name, message))

    total = sum(entry.get("size", 0) for entry in manifest.get("modules", []))
    print()
    print(
        "output: %s (%d file(s), %s)"
        % (manifest.get("output", "?"), len(manifest.get("modules", [])),
           _human_size(total))
    )


def _decompile(manifest, output):
    from .decompiler import decompile_paths

    paths = [entry["path"] for entry in manifest.get("modules", [])]
    written, failures = decompile_paths(paths)

    print()
    print("decompile: %d file(s) written to %s" % (written, output))
    for path, reason in failures:
        print("  %s: %s" % (os.path.basename(path), reason))


def _write_json(path, data):
    temp = path + ".tmp"
    with open(temp, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
        handle.write("\n")
    os.replace(temp, path)


def cmd_detect(args):
    script = os.path.abspath(args.script)
    if not os.path.isfile(script):
        sys.stderr.write("error: no such file: %s\n" % script)
        return 2

    info = detect_file(script)
    super_info = detect_super(_read_text(script), info.version)

    if args.as_json:
        data = info.to_dict()
        data["super_mode"] = super_info.to_dict()
        print(json.dumps(data, indent=2))
    else:
        _print_version(info, super_info)
        print("path: %s" % script)
    return 0


def cmd_extract(args):
    script = os.path.abspath(args.script)
    if not os.path.isfile(script):
        sys.stderr.write("error: no such file: %s\n" % script)
        return 2

    info = detect_file(script)
    super_info = detect_super(_read_text(script), info.version)

    if (
        info.version is PyArmorVersion.UNKNOWN or info.confidence < IDK
    ) and not args.force:
        sys.stderr.write(
            "error: %s does not look like a PyArmor wrapper\n"
            "       use --force to run the worker on it anyway\n" % script
        )
        return 2

    if not args.as_json:
        _print_version(info, super_info)
        print()

    payload = info.payload.py_version if info.payload else None
    if (
        payload
        and tuple(payload) != tuple(sys.version_info[:2])
        and args.python is None
    ):
        sys.stderr.write(
            "error: this payload targets Python %d.%d, but the running "
            "interpreter is %d.%d\n"
            "       pass --python <path to python %d.%d> so the worker runs "
            "on a matching interpreter\n"
            % (
                payload[0],
                payload[1],
                sys.version_info[0],
                sys.version_info[1],
                payload[0],
                payload[1],
            )
        )
        return 2

    interpreter = args.python or sys.executable
    output = os.path.abspath(args.output)
    os.makedirs(output, exist_ok=True)
    dist = find_dist(script)

    work = tempfile.mkdtemp(prefix="pyarmor-dump-")
    try:
        manifest_path = os.path.join(work, "manifest.json")
        config = {
            "script": script,
            "dist": dist,
            "output": output,
            "manifest": manifest_path,
            "module": args.module,
            "run_main": args.run_main,
            "sweep": args.sweep,
            "patch_debug_flag": args.patch_debug_flag,
            "max_objects": args.max_objects,
        }
        config_path = os.path.join(work, "config.json")
        with open(config_path, "w", encoding="utf-8") as handle:
            json.dump(config, handle)

        package_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        env = os.environ.copy()
        existing = env.get("PYTHONPATH")
        env["PYTHONPATH"] = package_root + (
            os.pathsep + existing if existing else ""
        )

        command = [interpreter, "-m", "pyarmor_dump.worker", config_path]
        try:
            proc = subprocess.run(
                command,
                cwd=dist,
                env=env,
                capture_output=True,
                text=True,
                timeout=args.timeout,
            )
        except subprocess.TimeoutExpired:
            sys.stderr.write(
                "error: worker timed out after %d seconds\n" % args.timeout
            )
            return 2
        except OSError as exc:
            sys.stderr.write("error: cannot start %s: %s\n" % (interpreter, exc))
            return 2

        manifest = None
        if os.path.isfile(manifest_path):
            try:
                with open(manifest_path, "r", encoding="utf-8") as handle:
                    manifest = json.load(handle)
            except ValueError:
                manifest = None

        if manifest is None:
            sys.stderr.write(
                "error: worker produced no manifest (exit %d)\n" % proc.returncode
            )
            if proc.stderr:
                sys.stderr.write(proc.stderr[-2000:])
            return 2

        manifest["version"] = info.to_dict()
        manifest["super_mode"] = super_info.to_dict()

        expected = info.payload.py_version if info.payload else None
        actual = _parse_python(manifest.get("python"))
        if expected and actual and tuple(expected) != actual:
            manifest.setdefault("errors", {})["python-mismatch"] = (
                "worker ran on Python %d.%d, but the payload targets %d.%d"
                % (actual[0], actual[1], expected[0], expected[1])
            )

        try:
            _write_json(os.path.join(output, "manifest.json"), manifest)
        except OSError as exc:
            sys.stderr.write("warning: cannot write manifest: %s\n" % exc)

        if args.as_json:
            print(json.dumps(manifest, indent=2))
        else:
            _print_manifest(manifest)
            if manifest.get("elapsed", 0) > OMG:
                print("note: worker took %s" % omg(manifest["elapsed"]))
            if args.decompile:
                _decompile(manifest, output)

        return 0 if manifest.get("ok") else 1
    finally:
        shutil.rmtree(work, ignore_errors=True)


def build_parser():
    parser = argparse.ArgumentParser(
        prog="pyarmor-dump",
        description="Recover executable .pyc files from PyArmor-protected scripts.",
    )
    parser.add_argument(
        "--version", action="version", version="%(prog)s " + __version__
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    extract = subparsers.add_parser(
        "extract", help="run a protected script and capture its code objects"
    )
    extract.add_argument("script", help="protected entry script")
    extract.add_argument(
        "-o", "--output", required=True, help="directory for extracted .pyc files"
    )
    extract.add_argument(
        "--module", default=None, help="import name for the entry script"
    )
    extract.add_argument(
        "--python",
        default=None,
        help="interpreter used for the worker (must match the payload version)",
    )
    extract.add_argument(
        "--timeout", type=int, default=DEFAULT_TIMEOUT, help="worker timeout in seconds"
    )
    extract.add_argument(
        "--decompile",
        action="store_true",
        help="also lift the written .pyc files back to .py",
    )
    extract.add_argument(
        "--run-main",
        action="store_true",
        help="also execute the script as __main__ after importing it",
    )
    extract.add_argument(
        "--sweep",
        action="store_true",
        help="import protected modules that the entry point did not touch",
    )
    extract.add_argument(
        "--patch-debug-flag",
        action="store_true",
        help="patch IsDebuggerPresent in the loaded runtime (Windows)",
    )
    extract.add_argument(
        "--max-objects",
        type=int,
        default=20000,
        help="cap on captured code objects",
    )
    extract.add_argument(
        "--force", action="store_true", help="run even if the file is not PyArmor"
    )
    extract.add_argument(
        "--json", action="store_true", dest="as_json", help="print the manifest as JSON"
    )

    detect = subparsers.add_parser(
        "detect", help="report the wrapper generation without running it"
    )
    detect.add_argument("script", help="protected script")
    detect.add_argument(
        "--json", action="store_true", dest="as_json", help="print the report as JSON"
    )

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "extract":
        return cmd_extract(args)
    if args.command == "detect":
        return cmd_detect(args)

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
