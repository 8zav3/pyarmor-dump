# Example Output

## Detect

```bash
python dump.py detect dist/sample.py
```

```
field       value
----------  ------------------------------------------------------------------------
version     PyArmor 9.x
confidence  0.98
header      # Pyarmor 9.3.0 (trial), 000000, non-profits, 2026-11-22T02:11:41.847753
markers     header:v9, bootstrap:pyarmor_runtime_000000, call:__pyarmor__
super mode  not enabled
payload     PY000000, Python 3.11, marshal 0x0da7

path: /project/dist/sample.py
```

## Extract

```bash
python dump.py extract dist/sample.py -o extracted
```

```
module  status   size    nested
------  -------  ------  ------
sample  written  1.0 kB  4

output: /project/extracted (1 file(s), 1.0 kB)
```

## Output Tree

```
extracted/
├── manifest.json
└── sample.pyc
```

The `.pyc` runs on the matching interpreter with no PyArmor runtime on disk:

```bash
python extracted/sample.pyc
```

## Decompile

```bash
python dump.py extract dist/sample.py -o extracted --decompile
```

```
decompile: 1 file(s) written to /project/extracted
```

```
extracted/
├── manifest.json
├── sample.py
└── sample.pyc
```

The lifter walks the instruction stream per code object and rebuilds statements, calls, arithmetic, imports and nested functions. Branching and `try` blocks are approximated; the `.pyc` is the artifact that runs.

## Armored Module

```
module  status   size    nested
------  -------  ------  ------
sample  armored  -       4

note: 1 module(s) are armored. PyArmor's default --obf-code 1
      decrypts into a private C buffer; no Python code object
      exists to serialize. Regenerate with --obf-code 0 to make
      those modules extractable.
```

## Manifest

```json
{
  "ok": true,
  "python": "3.11.9",
  "module": "sample",
  "modules": [
    {
      "module": "sample",
      "path": "extracted/sample.pyc",
      "size": 1042,
      "nested": 4
    }
  ],
  "armored": [],
  "failures": [],
  "errors": {},
  "imported": ["sample"]
}
```
