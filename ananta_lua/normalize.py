"""Translate this game's bytecode into standard LuaJIT 2.1 bytecode.

Native lj_bcread decrypts only the chunk name and standalone KGC strings.
Strings inside constant tables and debug variable names are already plaintext.
The cipher uses a shared native buffer, so use one instance on one thread.
"""

from __future__ import annotations

import ctypes
from pathlib import Path, PurePosixPath

from .carve import _Reader, _table_constant, parse_chunk


class RuntimeCipher:
    def __init__(self, runtime_path: Path):
        self.path = Path(runtime_path).resolve()
        if not self.path.is_file():
            raise ValueError(f"Lua runtime does not exist: {self.path}")
        if ctypes.sizeof(ctypes.c_void_p) != 8:
            raise ValueError("The game runtime requires 64-bit Python")
        self.library = ctypes.CDLL(str(self.path))
        self._transform = self.library.lj_str_encrypt
        self._transform.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        self._transform.restype = ctypes.c_void_p

    def transform(self, data: bytes) -> bytes:
        if not data:
            return data
        buffer = ctypes.create_string_buffer(data)
        pointer = self._transform(buffer, len(data))
        if not pointer:
            raise ValueError("Runtime string transformation returned a null buffer")
        return ctypes.string_at(pointer, len(data))


class SyntaxChecker:
    """Compile recovered Lua with the matching engine; never call the chunk."""

    def __init__(self, runtime: RuntimeCipher):
        self.library = runtime.library
        library = self.library
        library.luaL_newstate.argtypes = []
        library.luaL_newstate.restype = ctypes.c_void_p
        library.luaL_loadbuffer.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                          ctypes.c_size_t, ctypes.c_char_p]
        library.luaL_loadbuffer.restype = ctypes.c_int
        library.lua_tolstring.argtypes = [ctypes.c_void_p, ctypes.c_int,
                                         ctypes.POINTER(ctypes.c_size_t)]
        library.lua_tolstring.restype = ctypes.c_void_p
        library.lua_settop.argtypes = [ctypes.c_void_p, ctypes.c_int]
        library.lua_settop.restype = None
        library.lua_close.argtypes = [ctypes.c_void_p]
        library.lua_close.restype = None
        self.state = library.luaL_newstate()
        if not self.state:
            raise ValueError("Could not create offline Lua compiler state")

    def check(self, source: bytes, name: str) -> str | None:
        buffer = ctypes.create_string_buffer(source)
        status = self.library.luaL_loadbuffer(self.state, buffer, len(source), name.encode("utf-8"))
        error = None
        if status:
            size = ctypes.c_size_t()
            pointer = self.library.lua_tolstring(self.state, -1, ctypes.byref(size))
            error = ctypes.string_at(pointer, size.value).decode("utf-8", errors="replace") if pointer else f"Lua error {status}"
        self.library.lua_settop(self.state, 0)
        return error

    def close(self):
        if self.state:
            self.library.lua_close(self.state)
            self.state = None


def source_path(chunk_name: bytes) -> Path:
    """Map a chunk name to a safe relative Lua source path."""
    name = chunk_name.decode("utf-8", errors="strict").replace("\\", "/")
    name = name.removeprefix("@").removeprefix("Lua/").removeprefix("LuaFiles/")
    if (not name or name.startswith("/") or any(c in name for c in '<>:"|?*')
            or any(ord(c) < 32 for c in name)):
        raise ValueError(f"Unsafe or unsupported chunk name: {chunk_name!r}")
    parts = name.split("/")
    if any(part in ("", ".", "..") or part.endswith((" ", ".")) for part in parts):
        raise ValueError(f"Unsafe chunk path: {name!r}")
    reserved = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
                *(f"LPT{i}" for i in range(1, 10))}
    if any(part.split(".")[0].upper() in reserved for part in parts):
        raise ValueError(f"Reserved chunk path: {name!r}")
    path = PurePosixPath(name)
    if path.suffix != ".lua":
        raise ValueError(f"Chunk name is not a Lua script: {name!r}")
    return Path(*path.parts)


def normalize_chunk(raw: bytes, cipher: RuntimeCipher, opcode_map: dict[int, int]) -> bytes:
    chunk = parse_chunk(raw)
    if chunk.size != len(raw) or chunk.version != 2 or chunk.flags & 1:
        raise ValueError("Expected one complete little-endian LuaJIT v2 chunk")
    output = bytearray(raw)
    reader = _Reader(raw, 4, len(raw))
    flags = reader.uleb()

    def transform_string(size):
        start = reader.position
        reader.skip(size)
        transformed = cipher.transform(raw[start:reader.position])
        if len(transformed) != size:
            raise ValueError("String transformation changed the bytecode size")
        output[start:reader.position] = transformed

    if not flags & 2:
        transform_string(reader.uleb())
    while True:
        size = reader.uleb()
        if size == 0:
            break
        end = reader.position + size
        reader.skip(3)  # flags, parameter count, frame size
        upvalues = reader.byte()
        constants = reader.uleb()
        reader.uleb()  # numeric count; validated by parse_chunk, unmodified
        instructions = reader.uleb()
        if not flags & 2:
            debug_size = reader.uleb()
            if debug_size:
                reader.uleb()
                reader.uleb()
        for _ in range(instructions):
            position = reader.position
            opcode = reader.byte()
            if opcode not in opcode_map:
                raise ValueError(f"Unmapped opcode {opcode:#x} at {position:#x}")
            output[position] = opcode_map[opcode]
            reader.skip(3)
        reader.skip(upvalues * 2)
        for _ in range(constants):
            kind = reader.uleb()
            if kind >= 5:
                transform_string(kind - 5)
            elif kind == 1:
                array_size = reader.uleb()
                hash_size = reader.uleb()
                for _ in range(array_size + hash_size * 2):
                    _table_constant(reader)
            elif kind in (2, 3, 4):
                for _ in range(4 if kind == 4 else 2):
                    reader.uleb()
        reader.position = end
    parse_chunk(output)
    return bytes(output)
