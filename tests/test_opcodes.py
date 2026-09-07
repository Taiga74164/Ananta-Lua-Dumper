from pathlib import Path
import random
import struct
import tempfile
import unittest

from ananta_lua.opcodes import (
    OpcodeRecoveryError,
    STANDARD_OPCODE_NAMES,
    recover_opcode_map,
)


def make_runtime(*, aliases=True, initializer=True, shuffle=True):
    """Build a tiny PE fixture with real export tables and dispatch evidence."""
    names = list(STANDARD_OPCODE_NAMES)
    if shuffle:
        random.Random(8127).shuffle(names)
    game_ids = {name: opcode for opcode, name in enumerate(names)}
    handler_base = 0x5000
    handlers = {name: handler_base + i * 16 for i, name in enumerate(STANDARD_OPCODE_NAMES)}
    if aliases:
        handlers["IFUNCV"] = handlers["FUNCV"]
    exports = {"lj_BC_" + name: address for name, address in handlers.items()}
    exports.update({
        "lj_vm_asm_begin": handler_base,
        "lj_bc_ofs": 0x3400,
        "lj_dispatch_init": 0x3800,
        "fixture_function_end": 0x3C00,
    })
    data = bytearray(0x9200)

    def put(rva, value):
        offset = rva - 0x1000 + 0x200
        data[offset:offset + len(value)] = value

    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HH", data, 0x84, 0x8664, 1)
    struct.pack_into("<H", data, 0x94, 0xF0)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<I", data, optional + 60, 0x200)
    struct.pack_into("<I", data, optional + 108, 16)
    struct.pack_into("<II", data, optional + 112, 0x1000, 0x2000)
    section = optional + 0xF0
    data[section:section + 8] = b".fixture"
    struct.pack_into("<IIII", data, section + 8, 0x9000, 0x1000, 0x9000, 0x200)
    directory = bytearray(40)
    struct.pack_into("<IIIII", directory, 20, len(exports), len(exports), 0x1100, 0x1300, 0x1500)
    put(0x1000, directory)
    name_rva = 0x1600
    for ordinal, (name, address) in enumerate(exports.items()):
        put(0x1100 + ordinal * 4, struct.pack("<I", address))
        put(0x1300 + ordinal * 4, struct.pack("<I", name_rva))
        put(0x1500 + ordinal * 2, struct.pack("<H", ordinal))
        encoded = name.encode("ascii") + b"\0"
        put(name_rva, encoded)
        name_rva += len(encoded)
    put(0x3400, b"".join(struct.pack("<H", handlers[name] - handler_base) for name in names))
    if initializer:
        code = bytearray()
        for i, destination in enumerate(("FORL", "ITERL", "LOOP", "FUNCF", "FUNCV")):
            source = "I" + destination
            code += b"\x48\x8b\x81" + struct.pack("<i", 0xFD8 + game_ids[source] * 8)
            if i == 0:
                # The shipped compiler places unrelated instructions in this copy.
                code += b"\x48\x8d\x91" + struct.pack("<I", 0x1770)
                for offset in (0x1D0, 0x1D4):
                    code += b"\xc7\x81" + struct.pack("<II", offset, 0x145F)
            code += b"\x48\x89\x81" + struct.pack("<i", 0xFD8 + game_ids[destination] * 8)
        put(0x3800, code + b"\xc3")
    expected = {opcode: STANDARD_OPCODE_NAMES.index(name) for opcode, name in enumerate(names)}
    return data, expected


class OpcodeRecoveryTests(unittest.TestCase):
    def recover(self, data):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory) / "tolua.dll"
            runtime.write_bytes(data)
            return recover_opcode_map(runtime)

    def test_recovers_permutation_including_relocated_aliases(self):
        data, expected = make_runtime()
        self.assertNotEqual(expected[0x5C], 0x5C)
        self.assertEqual(self.recover(data), expected)

    def test_unique_handlers_need_no_native_initializer(self):
        data, expected = make_runtime(aliases=False, initializer=False)
        self.assertEqual(self.recover(data), expected)

    def test_standard_runtime_maps_to_identity(self):
        data, expected = make_runtime(shuffle=False)
        self.assertEqual(self.recover(data), expected)
        self.assertTrue(all(game == standard for game, standard in expected.items()))

    def test_aliases_without_native_evidence_are_rejected(self):
        data, _ = make_runtime(initializer=False)
        with self.assertRaisesRegex(OpcodeRecoveryError, "dispatch base"):
            self.recover(data)

    def test_missing_handler_export_is_rejected(self):
        data, _ = make_runtime()
        data = data.replace(b"lj_BC_UGET\0", b"xx_BC_UGET\0")
        with self.assertRaisesRegex(OpcodeRecoveryError, "Missing runtime export: lj_BC_UGET"):
            self.recover(data)

    def test_unidentified_handler_is_rejected(self):
        data, _ = make_runtime()
        struct.pack_into("<H", data, 0x3400 - 0x1000 + 0x200, 0x7000)
        with self.assertRaisesRegex(OpcodeRecoveryError, "Unidentified opcode"):
            self.recover(data)

    def test_repeated_handler_is_rejected(self):
        data, _ = make_runtime(aliases=False)
        offset = 0x3400 - 0x1000 + 0x200
        data[offset:offset + 2] = data[offset + 2:offset + 4]
        with self.assertRaisesRegex(OpcodeRecoveryError, "not bijective"):
            self.recover(data)

    def test_invalid_and_truncated_images_are_rejected(self):
        data, _ = make_runtime()
        for broken in (b"", b"not a PE", data[:0x100], data[:0x1600]):
            with self.subTest(size=len(broken)):
                with self.assertRaises(OpcodeRecoveryError):
                    self.recover(broken)

    def test_unsupported_machine_is_rejected(self):
        data, _ = make_runtime()
        struct.pack_into("<H", data, 0x84, 0x14C)
        with self.assertRaisesRegex(OpcodeRecoveryError, "x64 PE32\\+"):
            self.recover(data)


if __name__ == "__main__":
    unittest.main()
