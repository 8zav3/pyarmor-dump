import dis
import io
import marshal
import struct
import sys
import types
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


def _load_code_object(pyc_path: Path):
    raw = pyc_path.read_bytes()
    if len(raw) < 17:
        return None
    magic_int = struct.unpack("<H", raw[:2])[0]
    body = raw[16:]
    cur_magic = int.from_bytes(
        __import__("importlib").util.MAGIC_NUMBER[:2], "little"
    )
    if magic_int == cur_magic:
        try:
            return marshal.loads(body)
        except Exception:
            pass
    try:
        from xdis.load import load_module_from_file_object

        _, _, _, code, _, _, _ = load_module_from_file_object(io.BytesIO(raw))
        return code
    except Exception:
        return None


def _get_instructions(code):
    try:
        return list(dis.get_instructions(code))
    except Exception:
        return []


def _fmt_const(val) -> str:
    if isinstance(val, (str, bytes, int, float, bool, type(None))):
        return repr(val)
    if isinstance(val, tuple):
        return "(" + ", ".join(_fmt_const(x) for x in val) + ("," if len(val) == 1 else "") + ")"
    if isinstance(val, frozenset):
        return "frozenset({" + ", ".join(_fmt_const(x) for x in val) + "})"
    return repr(val)


def _decompile_code(code, indent: int = 0) -> list[str]:
    pad = "    " * indent
    lines: list[str] = []
    insns = _get_instructions(code)
    if not insns:
        lines.append(f"{pad}pass")
        return lines

    stack: list[str] = []
    kw_names: tuple[str, ...] = ()
    pending_null = False

    def pop1(default: str = "_unknown") -> str:
        return stack.pop() if stack else default

    def popn(n: int) -> list[str]:
        if n <= 0:
            return []
        if len(stack) >= n:
            items = stack[-n:]
            del stack[-n:]
            return items
        res = ["_unknown"] * (n - len(stack)) + list(stack)
        stack.clear()
        return res

    i = 0
    n_insns = len(insns)
    while i < n_insns:
        ins = insns[i]
        op = ins.opname
        argval = ins.argval
        arg = ins.arg

        if op in ("RESUME", "NOP", "CACHE", "EXTENDED_ARG", "PRECALL", "PUSH_NULL"):
            if op == "PUSH_NULL":
                pending_null = True
            i += 1
            continue

        if op in ("LOAD_CONST", "RETURN_CONST"):
            val_str = _fmt_const(argval)
            if op == "RETURN_CONST":
                lines.append(f"{pad}return {val_str}")
            else:
                stack.append(val_str)

        elif op in ("LOAD_NAME", "LOAD_GLOBAL", "LOAD_FAST", "LOAD_DEREF", "LOAD_CLOSURE"):
            stack.append(str(argval))

        elif op in ("STORE_NAME", "STORE_GLOBAL", "STORE_FAST", "STORE_DEREF"):
            val = pop1("None")
            if val.startswith("<code object ") and i > 0:
                lines.append(f"{pad}# {argval} = {val}")
            else:
                lines.append(f"{pad}{argval} = {val}")

        elif op in ("DELETE_NAME", "DELETE_GLOBAL", "DELETE_FAST", "DELETE_DEREF"):
            lines.append(f"{pad}del {argval}")

        elif op == "LOAD_ATTR" or op == "LOAD_METHOD":
            obj = pop1("obj")
            stack.append(f"{obj}.{argval}")

        elif op == "STORE_ATTR":
            obj = pop1("obj")
            val = pop1("None")
            lines.append(f"{pad}{obj}.{argval} = {val}")

        elif op == "DELETE_ATTR":
            obj = pop1("obj")
            lines.append(f"{pad}del {obj}.{argval}")

        elif op == "BINARY_SUBSCR":
            idx = pop1("0")
            obj = pop1("obj")
            stack.append(f"{obj}[{idx}]")

        elif op == "STORE_SUBSCR":
            idx = pop1("0")
            obj = pop1("obj")
            val = pop1("None")
            lines.append(f"{pad}{obj}[{idx}] = {val}")

        elif op == "KW_NAMES":
            if isinstance(argval, tuple):
                kw_names = argval
            elif hasattr(code, "co_consts") and isinstance(arg, int) and arg < len(code.co_consts):
                c = code.co_consts[arg]
                if isinstance(c, tuple):
                    kw_names = c

        elif op in ("CALL", "CALL_FUNCTION", "CALL_METHOD"):
            argc = int(arg or 0)
            args = popn(argc)
            fn = pop1("fn")
            if pending_null and stack and stack[-1] == "NULL":
                stack.pop()
            pending_null = False
            if kw_names and len(kw_names) <= len(args):
                pos_count = len(args) - len(kw_names)
                pos_parts = args[:pos_count]
                kw_parts = [f"{k}={v}" for k, v in zip(kw_names, args[pos_count:])]
                call_str = f"{fn}({', '.join(pos_parts + kw_parts)})"
                kw_names = ()
            else:
                call_str = f"{fn}({', '.join(args)})"
            stack.append(call_str)

        elif op == "CALL_FUNCTION_KW":
            argc = int(arg or 0)
            pop1("()")
            args = popn(argc)
            fn = pop1("fn")
            stack.append(f"{fn}({', '.join(args)})")

        elif op == "CALL_FUNCTION_EX":
            has_kw = bool(arg and (arg & 1))
            kwargs = pop1("{}") if has_kw else None
            pargs = pop1("()")
            fn = pop1("fn")
            parts = [f"*{pargs}"]
            if kwargs:
                parts.append(f"**{kwargs}")
            stack.append(f"{fn}({', '.join(parts)})")

        elif op == "POP_TOP":
            expr = pop1("")
            if expr and expr not in ("None", "_unknown"):
                lines.append(f"{pad}{expr}")

        elif op == "DUP_TOP":
            if stack:
                stack.append(stack[-1])

        elif op == "COPY":
            n = int(arg or 1)
            if len(stack) >= n:
                stack.append(stack[-n])

        elif op == "SWAP":
            n = int(arg or 2)
            if len(stack) >= n:
                stack[-1], stack[-n] = stack[-n], stack[-1]

        elif op == "BUILD_TUPLE":
            items = popn(int(arg or 0))
            stack.append("(" + ", ".join(items) + ("," if len(items) == 1 else "") + ")")

        elif op == "BUILD_LIST":
            items = popn(int(arg or 0))
            stack.append("[" + ", ".join(items) + "]")

        elif op == "BUILD_SET":
            items = popn(int(arg or 0))
            stack.append("{" + ", ".join(items) + "}" if items else "set()")

        elif op == "BUILD_MAP":
            n = int(arg or 0)
            pairs = popn(2 * n)
            kv = [f"{pairs[j]}: {pairs[j+1]}" for j in range(0, len(pairs), 2)]
            stack.append("{" + ", ".join(kv) + "}")

        elif op == "BUILD_CONST_KEY_MAP":
            n = int(arg or 0)
            keys_str = pop1("()")
            vals = popn(n)
            stack.append(f"dict(zip({keys_str}, [{', '.join(vals)}]))")

        elif op == "BUILD_SLICE":
            items = popn(int(arg or 2))
            stack.append(":".join(items))

        elif op == "FORMAT_VALUE":
            pop1("") if (arg and (arg & 4)) else None
            val = pop1("''")
            stack.append(f"f'{{{val}}}'")

        elif op == "BUILD_STRING":
            parts = popn(int(arg or 0))
            stack.append(" + ".join(parts) if parts else "''")

        elif op == "BINARY_OP":
            rhs = pop1("0")
            lhs = pop1("0")
            sym = getattr(ins, "argrepr", "+") or "+"
            if sym.endswith("="):
                sym = sym[:-1]
            stack.append(f"({lhs} {sym} {rhs})")

        elif op.startswith("BINARY_"):
            rhs = pop1("0")
            lhs = pop1("0")
            op_map = {
                "BINARY_ADD": "+", "BINARY_SUBTRACT": "-", "BINARY_MULTIPLY": "*",
                "BINARY_TRUE_DIVIDE": "/", "BINARY_FLOOR_DIVIDE": "//", "BINARY_MODULO": "%",
                "BINARY_POWER": "**", "BINARY_LSHIFT": "<<", "BINARY_RSHIFT": ">>",
                "BINARY_AND": "&", "BINARY_OR": "|", "BINARY_XOR": "^",
                "BINARY_MATRIX_MULTIPLY": "@",
            }
            sym = op_map.get(op, "+")
            stack.append(f"({lhs} {sym} {rhs})")

        elif op.startswith("UNARY_"):
            val = pop1("0")
            u_map = {"UNARY_POSITIVE": "+", "UNARY_NEGATIVE": "-", "UNARY_NOT": "not ", "UNARY_INVERT": "~"}
            stack.append(f"({u_map.get(op, '')}{val})")

        elif op in ("COMPARE_OP", "IS_OP", "CONTAINS_OP"):
            rhs = pop1("None")
            lhs = pop1("None")
            cmp_str = str(argval)
            if op == "IS_OP":
                cmp_str = "is not" if arg else "is"
            elif op == "CONTAINS_OP":
                cmp_str = "not in" if arg else "in"
            stack.append(f"({lhs} {cmp_str} {rhs})")

        elif op == "IMPORT_NAME":
            fromlist = pop1("None")
            pop1("0")
            mod_name = str(argval)
            if fromlist in ("None", "()"):
                lines.append(f"{pad}import {mod_name}")
                stack.append(mod_name.split(".")[0])
            else:
                stack.append(f"__import__({mod_name!r})")

        elif op == "IMPORT_FROM":
            mod = stack[-1] if stack else "module"
            stack.append(f"{mod}.{argval}")

        elif op == "IMPORT_STAR":
            mod = pop1("module")
            lines.append(f"{pad}from {mod} import *")

        elif op == "MAKE_FUNCTION":
            if sys.version_info < (3, 11):
                pop1("'fn'")
            fn_code = None
            for prev_idx in range(i - 1, max(-1, i - 6), -1):
                if insns[prev_idx].opname == "LOAD_CONST" and isinstance(insns[prev_idx].argval, types.CodeType):
                    fn_code = insns[prev_idx].argval
                    break
            pop1("")
            if fn_code is not None:
                fn_name = fn_code.co_name
                if fn_name == "<lambda>":
                    stack.append("lambda *args, **kwargs: None")
                else:
                    args_list = list(fn_code.co_varnames[:fn_code.co_argcount])
                    lines.append(f"{pad}def {fn_name}({', '.join(args_list)}):")
                    lines.extend(_decompile_code(fn_code, indent + 1))
                    stack.append(fn_name)
            else:
                stack.append("lambda *args, **kwargs: None")

        elif op == "RETURN_VALUE":
            val = pop1("None")
            if not (indent == 0 and val == "None"):
                lines.append(f"{pad}return {val}")

        elif op == "RAISE_VARARGS":
            if arg == 0:
                lines.append(f"{pad}raise")
            elif arg == 1:
                lines.append(f"{pad}raise {pop1('Exception()')}")
            else:
                cause = pop1("None")
                exc = pop1("Exception()")
                lines.append(f"{pad}raise {exc} from {cause}")

        elif op == "YIELD_VALUE":
            val = pop1("None")
            stack.append(f"(yield {val})")

        elif op in ("POP_JUMP_IF_FALSE", "POP_JUMP_FORWARD_IF_FALSE", "POP_JUMP_BACKWARD_IF_FALSE"):
            cond = pop1("True")
            lines.append(f"{pad}if not {cond}:")
            lines.append(f"{pad}    pass")

        elif op in ("POP_JUMP_IF_TRUE", "POP_JUMP_FORWARD_IF_TRUE", "POP_JUMP_BACKWARD_IF_TRUE"):
            cond = pop1("False")
            lines.append(f"{pad}if {cond}:")
            lines.append(f"{pad}    pass")

        elif op == "FOR_ITER":
            it = stack[-1] if stack else "iter_obj"
            lines.append(f"{pad}for _item in {it}:")
            lines.append(f"{pad}    pass")

        elif op == "LOAD_BUILD_CLASS":
            stack.append("__build_class__")

        i += 1

    if not lines:
        lines.append(f"{pad}pass")
    return lines


def decompile_pyc_file(pyc_path: Path, out_py_path: Path) -> tuple[bool, str | None]:
    code = _load_code_object(Path(pyc_path))
    if code is None:
        return False, "could not load a code object from this .pyc"
    try:
        src_lines = _decompile_code(code, indent=0)
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"
    out_py_path = Path(out_py_path)
    out_py_path.parent.mkdir(parents=True, exist_ok=True)
    out_py_path.write_text("\n".join(src_lines) + "\n", encoding="utf-8")
    return True, None


def decompile_paths(paths, max_workers: int = 8) -> tuple[int, list[tuple[str, str]]]:
    files = [Path(p) for p in paths]
    if not files:
        return 0, []

    def task(path: Path):
        ok, error = decompile_pyc_file(path, path.with_suffix(".py"))
        return path, ok, error

    written = 0
    failures: list[tuple[str, str]] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        for path, ok, error in pool.map(task, files):
            if ok:
                written += 1
            else:
                failures.append((str(path), error or "unknown error"))
    return written, failures


def decompile_tree(root: Path, max_workers: int = 8) -> tuple[int, list[tuple[str, str]]]:
    root = Path(root)
    files = sorted(p for p in root.rglob("*.pyc"))
    if not files:
        return 0, []

    def task(path: Path):
        ok, error = decompile_pyc_file(path, path.with_suffix(".py"))
        return path, ok, error

    written = 0
    failures: list[tuple[str, str]] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        for path, ok, error in pool.map(task, files):
            if ok:
                written += 1
            else:
                failures.append((str(path.relative_to(root)), error or "unknown error"))
    return written, failures
