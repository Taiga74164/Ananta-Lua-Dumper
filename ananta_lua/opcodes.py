"""Recover LuaJIT 2.1 opcode numbers from the supplied Windows runtime.

Ananta rearranges opcodes. The exported ``lj_bc_ofs`` table indexes interpreter
handlers relative to ``lj_vm_asm_begin``; named ``lj_BC_*`` exports identify
those handlers without executing the DLL. FUNCV and IFUNCV can share a handler.
For that pair, the native dispatch initializer provides independent evidence:
it copies dispatch[IFUNCV] to dispatch[FUNCV].

See LuaJIT's src/lj_bc.h and src/lj_dispatch.c:
https://github.com/LuaJIT/LuaJIT/blob/v2.1/src/lj_dispatch.c
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
import re
import struct


# Standard LuaJIT 2.1 order, also used by LJD's v2_1/luajit_opcode.py.
STANDARD_OPCODE_NAMES = tuple("""
ISLT ISGE ISLE ISGT ISEQV ISNEV ISEQS ISNES ISEQN ISNEN ISEQP ISNEP
ISTC ISFC IST ISF ISTYPE ISNUM MOV NOT UNM LEN
ADDVN SUBVN MULVN DIVVN MODVN ADDNV SUBNV MULNV DIVNV MODNV
ADDVV SUBVV MULVV DIVVV MODVV POW CAT
KSTR KCDATA KSHORT KNUM KPRI KNIL UGET USETV USETS USETN USETP UCLO FNEW
TNEW TDUP GGET GSET TGETV TGETS TGETB TGETR TSETV TSETS TSETB TSETM TSETR
CALLM CALL CALLMT CALLT ITERC ITERN VARG ISNEXT RETM RET RET0 RET1
FORI JFORI FORL IFORL JFORL ITERL IITERL JITERL LOOP ILOOP JLOOP JMP
FUNCF IFUNCF JFUNCF FUNCV IFUNCV JFUNCV FUNCC FUNCCW
""".split())


class OpcodeRecoveryError(ValueError):
    """The runtime cannot establish a complete, unambiguous opcode map."""


class _PEImage:
    """The small PE32+ subset needed to inspect named exports and their data."""

    def __init__(self, data: bytes):
        self.data = data
        if self._bytes(0, 2) != b"MZ":
            raise OpcodeRecoveryError("Runtime is not a PE executable")
        pe = self._unpack("I", 0x3C)[0]
        if self._bytes(pe, 4) != b"PE\0\0":
            raise OpcodeRecoveryError("Invalid PE signature")
        machine, count = self._unpack("HH", pe + 4)
        optional_size = self._unpack("H", pe + 20)[0]
        optional = pe + 24
        if machine != 0x8664 or self._unpack("H", optional)[0] != 0x20B:
            raise OpcodeRecoveryError("Opcode recovery requires an x64 PE32+ runtime")
        if optional_size < 120 or self._unpack("I", optional + 108)[0] < 1:
            raise OpcodeRecoveryError("Runtime has no export directory")
        self.header_size = self._unpack("I", optional + 60)[0]
        self.export_rva, self.export_size = self._unpack("II", optional + 112)
        self.sections = []
        for i in range(count):
            section = optional + optional_size + i * 40
            _, rva, raw_size, raw_offset = self._unpack("IIII", section + 8)
            self.sections.append((rva, raw_size, raw_offset))
        if not self.export_rva or self.export_size < 40:
            raise OpcodeRecoveryError("Runtime has no export directory")
        directory = self.read(self.export_rva, 40)
        function_count, name_count, functions, names, ordinals = struct.unpack_from(
            "<IIIII", directory, 20
        )
        function_data = self.read(functions, function_count * 4)
        name_data = self.read(names, name_count * 4)
        ordinal_data = self.read(ordinals, name_count * 2)
        self.exports: dict[str, int] = {}
        for i in range(name_count):
            name_rva = struct.unpack_from("<I", name_data, i * 4)[0]
            ordinal = struct.unpack_from("<H", ordinal_data, i * 2)[0]
            if ordinal >= function_count:
                raise OpcodeRecoveryError("Invalid PE export ordinal")
            name = self._cstring(name_rva)
            address = struct.unpack_from("<I", function_data, ordinal * 4)[0]
            if name in self.exports:
                raise OpcodeRecoveryError(f"Duplicate PE export: {name}")
            self.exports[name] = address

    def _bytes(self, offset: int, length: int) -> bytes:
        if offset < 0 or length < 0 or offset + length > len(self.data):
            raise OpcodeRecoveryError("Truncated PE data")
        return self.data[offset:offset + length]

    def _unpack(self, fmt: str, offset: int) -> tuple:
        return struct.unpack("<" + fmt, self._bytes(offset, struct.calcsize("<" + fmt)))

    def read(self, rva: int, length: int) -> bytes:
        if 0 <= rva and rva + length <= self.header_size:
            return self._bytes(rva, length)
        for section_rva, raw_size, raw_offset in self.sections:
            relative = rva - section_rva
            if 0 <= relative and relative + length <= raw_size:
                return self._bytes(raw_offset + relative, length)
        raise OpcodeRecoveryError(f"PE RVA 0x{rva:x} is not backed by file data")

    def _cstring(self, rva: int) -> str:
        value = bytearray()
        for i in range(4096):
            byte = self.read(rva + i, 1)[0]
            if not byte:
                try:
                    return value.decode("ascii")
                except UnicodeDecodeError as error:
                    raise OpcodeRecoveryError("Non-ASCII PE export name") from error
            value.append(byte)
        raise OpcodeRecoveryError("Unterminated PE export name")

    def export(self, name: str) -> int:
        address = self.exports.get(name)
        if address is None:
            raise OpcodeRecoveryError(f"Missing runtime export: {name}")
        if not address or self.export_rva <= address < self.export_rva + self.export_size:
            raise OpcodeRecoveryError(f"Unsupported null or forwarded export: {name}")
        return address

    def function_bytes(self, name: str) -> bytes:
        start = self.export(name)
        following = [rva for rva in self.exports.values() if rva > start]
        if not following:
            raise OpcodeRecoveryError(f"Cannot bound runtime function: {name}")
        return self.read(start, min(min(following) - start, 4096))


def _resolve_function_aliases(
    image: _PEImage, resolved: dict[int, str], ambiguous: dict[int, set[str]]
) -> None:
    # The current x64 initializer uses these instructions:
    #   mov rax, [rcx + source_disp32]
    #   mov [rcx + destination_disp32], rax
    # The first copy can have a LEA RDX and two MOV imm32 instructions between
    # them; those do not modify RAX. A changed sequence is not silently guessed.
    candidates = {"FUNCV", "IFUNCV"}
    if len(ambiguous) != 2 or any(names != candidates for names in ambiguous.values()):
        raise OpcodeRecoveryError(f"Unsupported aliased opcode handlers: {ambiguous}")
    code = image.function_bytes("lj_dispatch_init")
    copies = [
        (struct.unpack("<i", match[1])[0], struct.unpack("<i", match[2])[0])
        for match in re.finditer(
            b"\x48\x8b\x81(.{4})"
            b"(?:\x48\x8d\x91.{4}(?:\xc7\x81.{8}){2})?"
            b"\x48\x89\x81(.{4})", code, re.DOTALL
        )
    ]
    by_name = {name: opcode for opcode, name in resolved.items()}
    evidence: dict[int, set[str]] = defaultdict(set)
    for destination in ("FORL", "ITERL", "LOOP", "FUNCF"):
        source = "I" + destination
        if source not in by_name or destination not in by_name:
            continue
        for source_offset, destination_offset in copies:
            base = source_offset - 8 * by_name[source]
            if base >= 0 and destination_offset - 8 * by_name[destination] == base:
                evidence[base].add(destination)
    # Several independent known opcode assignments must establish one base.
    bases = [base for base, names in evidence.items() if len(names) == 4]
    if len(bases) != 1:
        raise OpcodeRecoveryError("Cannot establish dispatch base for FUNCV/IFUNCV aliases")
    base = bases[0]
    assignments = set()
    for source_offset, destination_offset in copies:
        if (source_offset - base) % 8 or (destination_offset - base) % 8:
            continue
        source = (source_offset - base) // 8
        destination = (destination_offset - base) // 8
        if source != destination and {source, destination} == set(ambiguous):
            assignments.add((source, destination))
    if len(assignments) != 1:
        raise OpcodeRecoveryError("Cannot distinguish FUNCV and IFUNCV in dispatch initializer")
    source, destination = assignments.pop()
    resolved[source] = "IFUNCV"
    resolved[destination] = "FUNCV"


def recover_opcode_map(runtime_path: Path) -> dict[int, int]:
    """Return game opcode -> standard LuaJIT 2.1 opcode, without loading the DLL.

    Recovery fails on missing exports, unexpected handlers, unsupported native
    alias patterns, or any incomplete/non-bijective result.
    """
    image = _PEImage(Path(runtime_path).read_bytes())
    standard = {name: opcode for opcode, name in enumerate(STANDARD_OPCODE_NAMES)}
    names_by_address: dict[int, set[str]] = defaultdict(set)
    for name in STANDARD_OPCODE_NAMES:
        names_by_address[image.export("lj_BC_" + name)].add(name)
    base = image.export("lj_vm_asm_begin")
    offsets = struct.unpack(
        "<" + "H" * len(standard),
        image.read(image.export("lj_bc_ofs"), 2 * len(standard)),
    )
    resolved: dict[int, str] = {}
    ambiguous: dict[int, set[str]] = {}
    for opcode, offset in enumerate(offsets):
        names = names_by_address.get(base + offset)
        if not names:
            raise OpcodeRecoveryError(f"Unidentified opcode handler at game opcode 0x{opcode:02x}")
        if len(names) == 1:
            resolved[opcode] = next(iter(names))
        else:
            ambiguous[opcode] = names
    if ambiguous:
        _resolve_function_aliases(image, resolved, ambiguous)
    if len(resolved) != len(standard) or set(resolved.values()) != set(standard):
        raise OpcodeRecoveryError("Runtime opcode table is incomplete or not bijective")
    return {opcode: standard[resolved[opcode]] for opcode in range(len(standard))}
