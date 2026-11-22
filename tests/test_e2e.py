from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from pyarmor_dump.pyc.magic_numbers import magic_bytes
from pyarmor_dump.super_mode import detect as detect_super
from pyarmor_dump.version_detect import PyArmorVersion, detect_text

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).resolve().parent / "fixtures"
PYTHON = sys.executable

V7_TEXT = r"""# Pyarmor 7.7.4 (trial), 000000, non-profits, 2020-01-01T00:00:00
from pytransform import pyarmor_runtime
pyarmor_runtime()
__pyarmor__(__name__, __file__, b'PYARMOR\x00\x01\x02')
"""

V8_TEXT = r"""# Pyarmor 8.5.12 (trial), 000000, non-profits, 2024-01-01T00:00:00
from pyarmor_runtime_000000 import __pyarmor__
__pyarmor__(__name__, __file__, b'PY000000\x00\x03\x0b\x00\xa7\r\r\n')
"""

V9_TEXT = r"""# Pyarmor 9.3.0 (trial), 000000, non-profits, 2026-01-01T00:00:00
from pyarmor_runtime_000000 import __pyarmor__
__pyarmor__(__name__, __file__, b'PY000000\x00\x03\x0b\x00\xa7\r\r\n')
"""

NO_HEADER_TEXT = r"""from pyarmor_runtime_000000 import __pyarmor__
__pyarmor__(__name__, __file__, b'PY000000\x00\x03\x0b\x00\xa7\r\r\n')
"""

SUPER_TEXT = r"""# Pyarmor 7.7.4 (trial), 000000
from .pytransform_vax_000000 import pyarmor
pyarmor(__name__, __file__, b'PYARMOR\x00\x01\x02')
"""


def _run(args, cwd=None, timeout=240):
    return subprocess.run(
        [str(arg) for arg in args],
        cwd=str(cwd) if cwd else str(ROOT),
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _pyarmor_exe():
    found = shutil.which("pyarmor")
    if found:
        return found
    for name in ("pyarmor.exe", "pyarmor"):
        candidate = Path(sys.executable).with_name(name)
        if candidate.is_file():
            return str(candidate)
    pytest.skip("pyarmor is not installed")


def _generate(tmp_path, source, *flags):
    dist = tmp_path / "dist"
    result = _run(
        [_pyarmor_exe(), "gen", *flags, "-O", dist, source], cwd=tmp_path
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        pytest.skip("pyarmor gen refused this mode: " + detail[-400:])
    return dist


def _extract(script, output, *flags):
    return _run(
        [PYTHON, "-m", "pyarmor_dump", "extract", script, "-o", output, *flags]
    )


def test_magic_numbers():
    assert magic_bytes((3, 8)) == b"\x55\r\r\n"
    assert magic_bytes((3, 9)) == b"\x61\r\r\n"
    assert magic_bytes((3, 10)) == b"\x6f\r\r\n"
    assert magic_bytes((3, 11)) == b"\xa7\r\r\n"
    assert magic_bytes((3, 12)) == b"\xcb\r\r\n"


def test_detect_v7():
    info = detect_text(V7_TEXT)
    assert info.version is PyArmorVersion.V7
    assert info.confidence >= 0.9
    assert info.payload.magic == "PYARMOR"


def test_detect_v8():
    info = detect_text(V8_TEXT)
    assert info.version is PyArmorVersion.V8_RFT
    assert info.payload.py_version == (3, 11)
    assert info.payload.marshal_magic == 3495


def test_detect_v9():
    info = detect_text(V9_TEXT)
    assert info.version is PyArmorVersion.V9
    assert "header:v9" in info.markers


def test_detect_without_header_is_ambiguous():
    info = detect_text(NO_HEADER_TEXT)
    assert info.version is PyArmorVersion.V8_RFT
    assert "ambiguous-v8-v9" in info.markers


def test_detect_plain_is_unknown():
    info = detect_text("print('hello')\n")
    assert info.version is PyArmorVersion.UNKNOWN
    assert not info.is_protected


def test_super_mode_markers():
    info = detect_super(SUPER_TEXT)
    assert info.enabled
    assert info.generation == "v7"
    assert "bootstrap:pyarmor-import" in info.markers
    assert "call:pyarmor" in info.markers


def test_super_mode_absent_in_v9():
    info = detect_super(V9_TEXT, PyArmorVersion.V9)
    assert not info.enabled


def test_cli_rejects_plain_without_force(tmp_path):
    result = _extract(FIXTURES / "plain_sample.py", tmp_path / "out")
    assert result.returncode == 2
    assert "does not look like a PyArmor wrapper" in result.stderr


def test_plain_pipeline(tmp_path):
    output = tmp_path / "out"
    result = _extract(FIXTURES / "plain_sample.py", output, "--force")
    assert result.returncode == 0, result.stdout + result.stderr

    pyc = output / "plain_sample.pyc"
    assert pyc.is_file()

    original = _run([PYTHON, FIXTURES / "plain_sample.py"])
    extracted = _run([PYTHON, pyc])
    assert original.returncode == 0
    assert extracted.returncode == 0
    assert extracted.stdout == original.stdout

    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["modules"][0]["module"] == "plain_sample"
    assert manifest["modules"][0]["nested"] >= 1


def test_plain_long_capture(tmp_path):
    output = tmp_path / "out"
    result = _extract(FIXTURES / "long_sample.py", output, "--force")
    assert result.returncode == 0, result.stdout + result.stderr

    pyc = output / "long_sample.pyc"
    assert pyc.is_file()

    original = _run([PYTHON, FIXTURES / "long_sample.py"])
    extracted = _run([PYTHON, pyc])
    assert extracted.returncode == 0
    assert extracted.stdout == original.stdout

    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    entry = manifest["modules"][0]
    assert entry["module"] == "long_sample"
    assert entry["nested"] >= 20, entry


def test_pyarmor_obf_code_0_short(tmp_path):
    dist = _generate(tmp_path, FIXTURES / "short_sample.py", "--obf-code", "0")
    output = tmp_path / "out"

    result = _extract(dist / "short_sample.py", output)
    assert result.returncode == 0, result.stdout + result.stderr
    assert (output / "short_sample.pyc").is_file()

    original = _run([PYTHON, dist / "short_sample.py"])
    extracted = _run([PYTHON, output / "short_sample.pyc"])
    assert original.returncode == 0
    assert extracted.returncode == 0
    assert extracted.stdout == original.stdout


def test_pyarmor_obf_code_0_long(tmp_path):
    dist = _generate(tmp_path, FIXTURES / "long_sample.py", "--obf-code", "0")
    output = tmp_path / "out"

    result = _extract(dist / "long_sample.py", output)
    assert result.returncode == 0, result.stdout + result.stderr
    assert (output / "long_sample.pyc").is_file()

    original = _run([PYTHON, dist / "long_sample.py"])
    extracted = _run([PYTHON, output / "long_sample.pyc"])
    assert extracted.returncode == 0
    assert extracted.stdout == original.stdout

    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["modules"][0]["nested"] >= 20


def test_pyarmor_package_obf_code_0(tmp_path):
    dist = _generate(
        tmp_path, FIXTURES / "pkgproj", "-r", "--obf-code", "0"
    )
    output = tmp_path / "out"

    result = _extract(dist / "pkgproj" / "app.py", output)
    assert result.returncode == 0, result.stdout + result.stderr

    for relative in (
        "pkgproj/app.pyc",
        "pkgproj/pkg/__init__.pyc",
        "pkgproj/pkg/mod.pyc",
    ):
        assert (output / relative).is_file(), relative

    original = _run([PYTHON, "-m", "pkgproj.app"], cwd=dist)
    extracted = _run([PYTHON, "-m", "pkgproj.app"], cwd=output)
    assert original.returncode == 0
    assert extracted.returncode == 0
    assert extracted.stdout == original.stdout


def test_pyarmor_default_reports_armored(tmp_path):
    dist = _generate(tmp_path, FIXTURES / "short_sample.py")
    output = tmp_path / "out"

    result = _extract(dist / "short_sample.py", output)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "armored" in result.stdout.lower()

    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["armored"], manifest
    assert manifest["modules"] == []
    assert not list(output.glob("*.pyc"))
