# Supported Versions & Modes

## Python Runtimes

| Python | Magic Int | Magic Bytes (LE) | Extract | Run `.pyc` | `--decompile` |
|---|---|---|---|---|---|
| 3.8 | 3413 | `55 0d 0d 0a` | Supported | Supported | Supported |
| 3.9 | 3425 | `61 0d 0d 0a` | Supported | Supported | Supported |
| 3.10 | 3439 | `6f 0d 0d 0a` | Supported | Supported | Supported |
| 3.11 | 3495 | `a7 0d 0d 0a` | Supported | Supported | Supported |
| 3.12 | 3531 | `cb 0d 0d 0a` | Supported | Supported | Supported |
| 3.13 | 3571 | `f3 0d 0d 0a` | Header table only | — | — |

The lifter reads the `.pyc` with `marshal` when the magic matches the running interpreter, and through `xdis` otherwise. Install the extra with `pip install "pyarmor-dump[decompile]"`.

## PyArmor Generations

| Wrapper | Detection | `--obf-code 0` | Default `--obf-code 1` |
|---|---|---|---|
| PyArmor 9.x | header, `pyarmor_runtime_<serial>`, `__pyarmor__` payload | Full extraction | Armored shell detected and reported |
| PyArmor 8.x RFT | same bootstrap as 9.x, different banner | Full extraction | Armored shell detected and reported |
| PyArmor 7.x | header, `pytransform` bootstrap, super-mode markers | Worker path implemented, not validated live | Same |

## Payload Header

PyArmor 8/9 embed the target interpreter in the `bytes` literal passed to `__pyarmor__`:

```
0..1    b'PY'
2..7    six ASCII digits (license serial)
8       NUL
9       Python major
10      Python minor
11      flags
12..13  marshal magic, little endian
```

PyArmor 7 uses a closed format. Detection records `PYARMOR` and stops there.

## Armored vs Plain

`--obf-code 0` emits real code objects. `sys.settrace`, `builtins.exec` and `gc.get_objects()` see them, and the tool serializes them.

`--obf-code 1` wraps every function in a shell whose `co_consts` holds native runtime functions (`C_ENTER_CO_OBJECT_INDEX`, `C_ASSERT_ARMORED_INDEX`) plus an encrypted buffer. The decrypted bytecode is interpreted inside PyArmor's own VM and never becomes a Python object, so there is nothing to marshal. The tool reports the module as `armored` and writes no file.
