<div align="center">
  <img src="banner.svg" alt="pyarmor-dump — PyArmor .pyc Extractor" width="100%">
  <br>

  <p>
    <a href="doc/versions.md"><strong>Supported Versions</strong></a>
    ·
    <a href="doc/example.md"><strong>Example Output</strong></a>
    ·
    <a href="#architecture"><strong>Architecture</strong></a>
  </p>

  <p>
    <img src="https://img.shields.io/badge/Python-3.8--3.12-3776AB?logo=python&logoColor=white" alt="Python 3.8-3.12">
    <img src="https://img.shields.io/badge/PyArmor-7%20%7C%208%20%7C%209-6E4AFF" alt="PyArmor 7 | 8 | 9">
    <img src="https://img.shields.io/badge/Tests-15%20passing-brightgreen" alt="15 tests passing">
    <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green" alt="MIT"></a>
  </p>
</div>

---

## Overview

- **Runtime Capture, Not Cryptanalysis**: Runs the protected script in an isolated worker and records the code objects PyArmor's own runtime hands to CPython. No payload parsing, no key recovery, no VM emulation.
- **Real `.pyc` Output**: Writes a 16-byte CPython header plus marshalled bytecode. The result executes on the matching interpreter with no PyArmor runtime on disk.
- **Version Detection**: Reads the banner, the bootstrap import, and the `__pyarmor__` payload header to classify PyArmor 7.x, 8.x RFT and 9.x. Headerless v8/v9 files are reported as ambiguous instead of guessed.
- **Nested Code Included**: Every captured module root is walked through `co_consts`, so functions and classes that are defined but never called still land in the output.
- **Built-In Bytecode Lifter**: `--decompile` runs a deterministic stack-based `.pyc` to `.py` lifter, threaded across the output tree. No model downloads, no external decompiler. Cross-version loading goes through `xdis` when the magic does not match the running interpreter.
- **Armored Output Reported, Never Faked**: PyArmor's default `--obf-code 1` shells are detected by their native constants and listed as `armored`. The tool does not write a `.pyc` that cannot load.
- **Process Isolation**: The worker runs in its own interpreter. Protected scripts that replace builtins, install import hooks or call `sys.exit` at module level cannot poison the CLI.

## Documentation

- **[Supported Versions (`doc/versions.md`)](doc/versions.md)** — CPython magic table, PyArmor generation matrix, payload header layout, armored vs plain output.
- **[Example Output (`doc/example.md`)](doc/example.md)** — Sample `detect` / `extract` runs, output tree and manifest.

## Installation & Usage

```bash
git clone https://github.com/8zav3/pyarmor-dump.git
cd pyarmor-dump
python -m pip install .
```

Editable install with test and decompiler extras:

```bash
python -m pip install -e ".[dev,decompile]"
```

### Detect a wrapper without running it

```bash
python dump.py detect dist/sample.py
```

### Extract the `.pyc` tree

```bash
python dump.py extract dist/sample.py -o extracted
```

### Run the extracted module

```bash
python extracted/sample.pyc
```

### CLI Options

| Flag | Description |
|---|---|
| `-o`, `--output` | Output directory for extracted `.pyc` files (required) |
| `--python PATH` | Interpreter used for the worker; must match the payload version |
| `--module NAME` | Import name for the entry script when the filename is ambiguous |
| `--run-main` | Also execute the script as `__main__` after importing it |
| `--sweep` | Import protected modules the entry point did not touch |
| `--decompile` | Lift every written `.pyc` back to `.py` |
| `--patch-debug-flag` | Patch `IsDebuggerPresent` in the loaded runtime's IAT (Windows) |
| `--max-objects N` | Cap on captured code objects (default `20000`) |
| `--timeout SECONDS` | Worker timeout (default `180`) |
| `--force` | Run the worker on a file that does not look like a PyArmor wrapper |
| `--json` | Print the manifest as JSON |

The entry script's directory must contain the runtime package: `pyarmor_runtime_<serial>` for PyArmor 8/9, `pytransform` for PyArmor 7. `find_dist` walks up to four levels when the entry point is nested.

## Testing

```bash
python -m pytest -q
```

Three layers:

1. **Synthetic signatures** — v7, v8, v9 and headerless wrappers classified from text, including the v8/v9 ambiguity case and the v7 super-mode bootstrap.
2. **Unprotected fixtures** — `plain_sample.py` and `long_sample.py` go through the real worker, tracer and `.pyc` writer, so the pipeline is covered on a machine without PyArmor.
3. **Real PyArmor fixtures** — `short_sample.py`, `long_sample.py` and a package tree are protected with `--obf-code 0`, extracted, and compared by stdout against the original protected script. The default armored mode is generated too, and the test asserts it is reported rather than written.

Behavioural equivalence is deliberate. Comparing `.pyc` bytes would fail on timestamp headers and would not prove the extracted code runs.

## Architecture

```
pyarmor_dump/
├── cli.py                 argument parsing, version gate, subprocess, report
├── worker.py              hook orchestration, module discovery, manifest
├── version_detect.py      wrapper classification + cached file lookup
├── super_mode.py          PyArmor 7 super-mode detection
├── signatures/
│   ├── v7.py              pytransform bootstrap, PYARMOR payload
│   ├── v8_rft.py          pyarmor_runtime_<serial> bootstrap, PY payload
│   └── v9.py              same bootstrap as v8, different banner
├── hooks/
│   ├── trace_hook.py      sys.settrace capture + co_consts walk
│   ├── exec_hook.py       builtins.exec / eval / compile wrappers
│   ├── import_hook.py     meta-path recorder for protected modules
│   └── antidebug_patch.py hide the tracer, optional IAT patch
├── pyc/
│   ├── writer.py          header + marshal, armor detection, atomic write
│   └── magic_numbers.py   CPython magic table, 3.7 through 3.13
└── __main__.py
```

Capture sequence:

```
CLI
 │  detect_file() -> PyArmorVersion + payload Python version
 │  spawn: python -m pyarmor_dump.worker config.json
 ▼
worker
 │  discover_modules(dist)        every .py under the protected tree
 │  CodeCollector.install()       real sys.settrace, before any patching
 │  AntiDebugPatch.install()      gettrace -> None, settrace -> no-op
 │  ImportRecorder.install()      sys.meta_path[0]
 │  ExecRecorder.install()        builtins.exec / eval / compile
 │  importlib.import_module()     runtime decrypts, CPython evaluates
 │  collector walks co_consts     nested functions and classes included
 │  teardown in reverse order
 ▼
pyc.writer
   root selection: decrypted root beats wrapper root
   armor scan: native consts / __assert_armored__
   marshal + 16-byte header + atomic replace
```

Root selection matters. With `--obf-code 0` the tracer sees two `<module>` objects for the same file: the small wrapper that calls `__pyarmor__`, and the decrypted module the runtime evaluates. Both map to the same key, and the decrypted one wins because it is not a bootstrap frame and carries more bytecode.

The manifest is a file, not stdout. Protected scripts print things, and mixing their output with machine-readable results is how parsers get written badly.

## Limitations

**Default PyArmor 8/9 output is armored.** `--obf-code 1` wraps every code object in a shell whose `co_consts` holds native functions such as `C_ENTER_CO_OBJECT_INDEX` and `C_ASSERT_ARMORED_INDEX`, plus an encrypted `bytes` blob. `sys.settrace`, `builtins.exec`, `builtins.compile` and `gc.get_objects()` all see the shell. The decrypted bytecode runs inside the runtime's VM and never becomes a Python code object, and `marshal.dumps` refuses the shell because native function objects are not marshalable. The tool reports this shape and writes nothing. Regenerate with:

```bash
pyarmor gen --obf-code 0 -O dist src/sample.py
```

**The interpreter must match the payload.** PyArmor embeds the target Python version and marshal magic. The runtime extension is built for one ABI. The CLI refuses a mismatch unless `--python` names another interpreter; if that one still does not match, the manifest records a `python-mismatch` note and the runtime import is reported as the failure.

**Dynamic code is only captured if it executes or is nested.** The collector walks `co_consts` from every captured module root, so functions and classes defined but never called are included. Code built by `exec` inside a function that never runs is not.

**Decompilation is best-effort.** The built-in lifter reconstructs assignments, calls, arithmetic, imports, `if` / `for` skeletons and nested functions from the instruction stream. It is not a control-flow-aware decompiler: complex branching, comprehensions, `try` blocks and class bodies come out approximate. The `.pyc` remains the authoritative artifact. Install `xdis` (`pip install "pyarmor-dump[decompile]"`) to lift bytecode from a Python version other than the one running the tool.

**PyPy uses different magic numbers.** The table in `magic_numbers.py` is CPython. PyPy-produced `.pyc` files will not match it.

**PyArmor 7 is unvalidated in this build.** The signatures come from the 7.7.4 wheel (`entry_lines`, `make_super_bootstrap`, `protect_code.pt`) and the worker path is the same as 8/9, but no live 7.x runtime was available to confirm extraction.

## Support & Contributing

Need help with a protected file, found a bug, or want to contribute?

- **Open an Issue**: [github.com/8zav3/pyarmor-dump/issues](https://github.com/8zav3/pyarmor-dump/issues)
- **Open a Pull Request**: [github.com/8zav3/pyarmor-dump/pulls](https://github.com/8zav3/pyarmor-dump/pulls)
- **Contact**: [![GitHub](https://img.shields.io/badge/GitHub-8zav3-181717?style=flat&logo=github&logoColor=white)](https://github.com/8zav3) [![Discord](https://img.shields.io/badge/Discord-Contact-5865F2?style=flat&logo=discord&logoColor=white)](https://discord.com/users/1516402914267234382)

## License

MIT. See [LICENSE](LICENSE).

PyArmor is a commercial product by Dashingsoft. This project is not affiliated with or endorsed by Dashingsoft. It does not redistribute PyArmor code or bypass license validation: the shipped runtime still checks its own license and refuses to run without one.

> **Authorized use only.** Use this on software you own or are authorized to analyze. Recovering bytecode from someone else's product may violate their license or local law, and that decision is yours.

<div align="center">
  <p><strong>pyarmor-dump</strong> · PyArmor runtime capture &amp; .pyc extractor</p>
  <p><a href="doc/versions.md">Supported Versions</a> · <a href="doc/example.md">Example Output</a> · <a href="LICENSE">License</a> · <a href="https://github.com/8zav3">GitHub</a> · <a href="https://discord.com/users/1516402914267234382">Discord</a></p>
</div>
