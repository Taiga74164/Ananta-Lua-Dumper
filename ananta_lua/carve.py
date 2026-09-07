"""Locate complete LuaJIT bytecode chunks without executing game code.

The container-independent parser follows LuaJIT's ``lj_bcdump.h`` layout.
Encrypted string bytes remain opaque: their encoded lengths still delimit
the chunk names and constants in Ananta's bytecode.
"""

from dataclasses import dataclass
import mmap
from pathlib import Path
from typing import Iterator


MAGIC = b"\x1bLJ"
SUPPORTED_VERSIONS = (1, 2)
KNOWN_FLAGS = 0x0F
STRIPPED = 0x02


@dataclass(frozen=True)
class Chunk:
    offset: int
    size: int
    version: int
    flags: int
    raw_name: bytes
    prototype_count: int


class _Reader:
    def __init__(self, data, position: int, end: int):
        self.data = data
        self.position = position
        self.end = end

    def skip(self, size: int) -> None:
        if size < 0 or size > self.end - self.position:
            raise ValueError(f"Truncated bytecode at offset {self.position}")
        self.position += size

    def byte(self) -> int:
        position = self.position
        self.skip(1)
        return self.data[position]

    def uleb(self, bits: int = 32) -> int:
        value = 0
        for shift in range(0, bits, 7):
            byte = self.byte()
            value |= (byte & 0x7F) << shift
            if value >= 1 << bits:
                raise ValueError("ULEB128 value exceeds its integer width")
            if not byte & 0x80:
                if shift and byte == 0:
                    raise ValueError("Noncanonical ULEB128 value")
                return value
        raise ValueError("Unterminated ULEB128 value")

    def require_items(self, count: int) -> None:
        # Every constant occupies at least one byte. This also bounds loops
        # before following counts from damaged or unrelated binary data.
        if count > self.end - self.position:
            raise ValueError("Constant count exceeds remaining prototype data")


def _table_constant(reader: _Reader) -> None:
    kind = reader.uleb()
    if kind >= 5:
        reader.skip(kind - 5)
    elif kind == 3:
        reader.uleb()
    elif kind == 4:
        reader.uleb()
        reader.uleb()
    # The other values are nil, false, and true with no additional payload.


def _prototype(reader: _Reader, stripped: bool) -> int:
    reader.byte()  # Prototype flags; instruction semantics are not interpreted.
    parameters = reader.byte()
    frame_size = reader.byte()
    upvalues = reader.byte()
    if parameters > frame_size:
        raise ValueError("Prototype parameters exceed frame size")
    gc_constants = reader.uleb()
    numeric_constants = reader.uleb()
    instructions = reader.uleb()
    if instructions == 0:
        raise ValueError("Prototype has no instructions")
    debug_size = 0
    if not stripped:
        debug_size = reader.uleb()
        if debug_size:
            reader.uleb()  # First source line.
            reader.uleb()  # Source line count.
    reader.skip(instructions * 4 + upvalues * 2)
    payload_end = reader.end - debug_size
    if payload_end < reader.position:
        raise ValueError("Debug data exceeds prototype size")
    reader.end = payload_end
    reader.require_items(gc_constants + numeric_constants)
    children = 0
    for _ in range(gc_constants):
        kind = reader.uleb()
        if kind >= 5:
            reader.skip(kind - 5)
        elif kind == 0:
            children += 1
        elif kind == 1:
            array_count = reader.uleb()
            hash_count = reader.uleb()
            reader.require_items(array_count + hash_count * 2)
            for _ in range(array_count + hash_count * 2):
                _table_constant(reader)
        else:
            # int64, uint64, or a complex number (two doubles).
            for _ in range(4 if kind == 4 else 2):
                reader.uleb()
    for _ in range(numeric_constants):
        low = reader.uleb(bits=33)
        if low & 1:
            reader.uleb()
    if reader.position != payload_end:
        raise ValueError("Prototype length does not match its contents")
    return children


def parse_chunk(data, offset: int = 0) -> Chunk:
    """Parse one bounded chunk in bytes, bytearray, or a read-only mmap.

    Return its exact on-disk extent, excluding container padding. Raise
    ``ValueError`` on unsupported, malformed, or incomplete bytecode. This
    validates container structure, not VM instruction behavior.
    """
    if offset < 0 or offset > len(data) - 4 or data[offset:offset + 3] != MAGIC:
        raise ValueError(f"No LuaJIT bytecode header at offset {offset}")
    reader = _Reader(data, offset + 3, len(data))
    version = reader.byte()
    if version not in SUPPORTED_VERSIONS:
        raise ValueError(f"Unsupported LuaJIT bytecode version {version}")
    flags = reader.uleb()
    if flags & ~KNOWN_FLAGS:
        raise ValueError(f"Unsupported LuaJIT bytecode flags 0x{flags:x}")
    raw_name = b""
    if not flags & STRIPPED:
        name_size = reader.uleb()
        start = reader.position
        reader.skip(name_size)
        raw_name = bytes(data[start:reader.position])
    prototype_count = 0
    pending_prototypes = 0
    while True:
        size = reader.uleb()
        if size == 0:
            if pending_prototypes != 1:
                raise ValueError("Bytecode must contain one complete root prototype")
            break
        start = reader.position
        reader.skip(size)
        children = _prototype(_Reader(data, start, reader.position), bool(flags & STRIPPED))
        if children > pending_prototypes:
            raise ValueError("Prototype references an unavailable child")
        pending_prototypes += 1 - children
        prototype_count += 1
    return Chunk(offset, reader.position - offset, version, flags, raw_name, prototype_count)


def iter_chunks(path: Path) -> Iterator[Chunk]:
    """Scan a file for complete, nonoverlapping chunks using a read-only mmap."""
    with Path(path).open("rb") as stream:
        if stream.seek(0, 2) == 0:
            return
        with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
            position = 0
            while True:
                position = data.find(MAGIC, position)
                if position < 0:
                    return
                try:
                    chunk = parse_chunk(data, position)
                except ValueError:
                    position += len(MAGIC)
                    continue
                yield chunk
                position += chunk.size


def read_chunk(path: Path, chunk: Chunk) -> bytes:
    """Read and revalidate a previously located chunk from the input file."""
    if chunk.offset < 0 or chunk.size <= 0:
        raise ValueError("Invalid chunk extent")
    with Path(path).open("rb") as stream:
        stream.seek(chunk.offset)
        data = stream.read(chunk.size)
    parsed = parse_chunk(data)
    if Chunk(chunk.offset, parsed.size, parsed.version, parsed.flags,
             parsed.raw_name, parsed.prototype_count) != chunk:
        raise ValueError("Chunk changed since it was located")
    return data
