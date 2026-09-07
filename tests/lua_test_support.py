"""Compile and compare our own synthetic Lua fixtures, never game scripts.

Evaluation runs in a separate process with a timeout so a broken reconstructed
loop cannot hang the test suite. Production dumping only compiles source.
"""

from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


PROJECT = Path(__file__).resolve().parents[1]
RUNTIME = PROJECT.parent / "Ananta_Data/Plugins/x86_64/tolua.dll"
VENDOR = PROJECT / "vendor/ljd"
NATIVE_AVAILABLE = os.name == "nt" and RUNTIME.is_file() and ctypes.sizeof(ctypes.c_void_p) == 8


class NativeCompiler:
    def __init__(self):
        from ananta_lua.normalize import RuntimeCipher, SyntaxChecker
        from ananta_lua.opcodes import recover_opcode_map
        self.cipher = RuntimeCipher(RUNTIME)
        self.checker = SyntaxChecker(self.cipher)
        self.opcodes = recover_opcode_map(RUNTIME)
        self.writer_type = ctypes.CFUNCTYPE(
            ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
        )
        self.checker.library.lua_dump.argtypes = [ctypes.c_void_p, self.writer_type, ctypes.c_void_p]
        self.checker.library.lua_dump.restype = ctypes.c_int

    def compile(self, source: str, name: str = "@synthetic_fixture.lua") -> bytes:
        from ananta_lua.normalize import normalize_chunk
        library = self.checker.library
        data = source.encode("utf-8")
        buffer = ctypes.create_string_buffer(data)
        status = library.luaL_loadbuffer(self.checker.state, buffer, len(data), name.encode("utf-8"))
        if status:
            library.lua_settop(self.checker.state, 0)
            raise ValueError("Synthetic fixture does not compile: " + str(self.checker.check(data, name)))
        output = bytearray()

        @self.writer_type
        def writer(state, pointer, length, opaque):
            output.extend(ctypes.string_at(pointer, length))
            return 0

        try:
            if library.lua_dump(self.checker.state, writer, None):
                raise ValueError("Could not dump synthetic fixture bytecode")
        finally:
            library.lua_settop(self.checker.state, 0)
        return normalize_chunk(bytes(output), self.cipher, self.opcodes)

    def close(self):
        self.checker.close()


def evaluate(source: str, timeout: float = 10) -> list:
    """Evaluate a hand-authored fixture or its decompiled form in isolation.

    Return tagged primitive results. Strings use hex to preserve arbitrary
    bytes; table/function results are rejected, so fixtures should return
    concrete traces, counters, or scalar values describing their behavior.
    """
    with tempfile.TemporaryDirectory(prefix="ananta-lua-fixture-") as temporary:
        script = Path(temporary) / "fixture.lua"
        script.write_text(source, encoding="utf-8")
        result = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), str(script)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout, check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if result.returncode:
            raise AssertionError(result.stderr.decode("utf-8", "replace")[-8192:])
        return json.loads(result.stdout)


def exercise(source: str, calls: str) -> str:
    """Wrap source returning a function/table, then exercise it as ``fixture``."""
    return "local fixture = (function()\n" + source + "\nend)()\n" + calls


def _evaluate_child(path: Path) -> list:
    from ananta_lua.normalize import RuntimeCipher, SyntaxChecker
    checker = SyntaxChecker(RuntimeCipher(RUNTIME))
    lib, state = checker.library, checker.state
    lib.luaL_openlibs.argtypes = [ctypes.c_void_p]
    lib.luaL_openlibs.restype = None
    lib.lua_pcall.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_int]
    lib.lua_pcall.restype = ctypes.c_int
    lib.lua_gettop.argtypes = [ctypes.c_void_p]
    lib.lua_gettop.restype = ctypes.c_int
    lib.lua_type.argtypes = [ctypes.c_void_p, ctypes.c_int]
    lib.lua_type.restype = ctypes.c_int
    lib.lua_toboolean.argtypes = [ctypes.c_void_p, ctypes.c_int]
    lib.lua_toboolean.restype = ctypes.c_int
    lib.lua_tonumber.argtypes = [ctypes.c_void_p, ctypes.c_int]
    lib.lua_tonumber.restype = ctypes.c_double

    def string(index):
        length = ctypes.c_size_t()
        pointer = lib.lua_tolstring(state, index, ctypes.byref(length))
        return ctypes.string_at(pointer, length.value) if pointer else b""

    try:
        lib.luaL_openlibs(state)
        source = path.read_bytes()
        buffer = ctypes.create_string_buffer(source)
        status = lib.luaL_loadbuffer(state, buffer, len(source), b"@synthetic_fixture.lua")
        if not status:
            status = lib.lua_pcall(state, 0, -1, 0)
        if status:
            raise AssertionError(string(-1).decode("utf-8", "replace"))
        values = []
        for index in range(1, lib.lua_gettop(state) + 1):
            kind = lib.lua_type(state, index)
            if kind == 0:
                values.append(["nil", None])
            elif kind == 1:
                values.append(["boolean", bool(lib.lua_toboolean(state, index))])
            elif kind == 3:
                values.append(["number", lib.lua_tonumber(state, index)])
            elif kind == 4:
                values.append(["string", string(index).hex()])
            else:
                raise AssertionError(f"Synthetic fixture returned unsupported Lua type {kind}")
        return values
    finally:
        checker.close()


if __name__ == "__main__":
    sys.path.insert(0, str(PROJECT))
    print(json.dumps(_evaluate_child(Path(sys.argv[1]))))
