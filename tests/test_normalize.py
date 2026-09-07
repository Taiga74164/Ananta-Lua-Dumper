from pathlib import Path
import unittest

from ananta_lua.carve import parse_chunk
from ananta_lua.normalize import normalize_chunk, source_path
from test_carve import chunk, prototype, uleb


class XorCipher:
    def transform(self, data):
        return bytes(byte ^ 0xAA for byte in data)


class NormalizeTests(unittest.TestCase):
    def test_decrypts_header_and_kgc_but_preserves_table_and_debug(self):
        cipher = XorCipher()
        name = b"@Lua\\LuaFiles\\Core\\Boot.lua"
        constant = b"SomeGlobal"
        # Table constant strings are plaintext in this runtime.
        table = b"\x01\x00\x01\x08key\x0avalue"
        constants = table + uleb(len(constant) + 5) + cipher.transform(constant)
        raw = chunk(cipher.transform(name), prototype(constants, 2, debug=b"plaintext_debug"))
        normalized = normalize_chunk(raw, cipher, {0x4B: 0x4C})
        self.assertEqual(parse_chunk(normalized).raw_name, name)
        self.assertIn(table, normalized)
        self.assertIn(constant, normalized)
        self.assertIn(b"plaintext_debug", normalized)
        self.assertIn(b"\x4c\x00\x01\x00", normalized)
        self.assertEqual(len(normalized), len(raw))

    def test_rejects_unmapped_opcode(self):
        with self.assertRaisesRegex(ValueError, "Unmapped opcode"):
            normalize_chunk(chunk(), XorCipher(), {})

    def test_stripped_nested_prototypes_preserve_binary_and_numeric_payloads(self):
        cipher = XorCipher()
        plaintext = b"\x00\xff\x1bLJ\x80"
        string_constant = uleb(len(plaintext) + 5) + cipher.transform(plaintext)
        # Child, int64, uint64, complex, and a standalone binary string.
        constants = (b"\x00\x02\x01\x02\x03\x03\x04"
                     b"\x04\x01\x02\x03\x04" + string_constant)
        numbers = uleb(0xFFFFFFFF << 1) + uleb((123 << 1) | 1) + uleb(456)
        raw = chunk(protos=prototype() + prototype(constants, 5, numbers, 2))
        normal = normalize_chunk(raw, cipher, {0x4B: 0x4C})
        expected_constants = constants[:-len(plaintext)] + plaintext
        expected = chunk(protos=prototype() + prototype(expected_constants, 5, numbers, 2))
        # The two instruction opcodes are the only nonstring changes.
        expected = expected.replace(b"\x4b\x00\x01\x00", b"\x4c\x00\x01\x00")
        self.assertEqual(normal, expected)
        self.assertEqual(parse_chunk(normal).prototype_count, 2)

    def test_rejects_wrong_bytecode_version_endian_and_trailing_data(self):
        original = chunk()
        version_one = original[:3] + b"\x01" + original[4:]
        big_endian = original[:4] + bytes([original[4] | 1]) + original[5:]
        for raw in (version_one, big_endian, original + b"padding", original + original):
            with self.subTest(raw=raw), self.assertRaisesRegex(ValueError, "complete little-endian"):
                normalize_chunk(raw, XorCipher(), {0x4B: 0x4C})

    def test_preserves_expected_tree_and_blocks_path_escape(self):
        self.assertEqual(source_path(b"@Lua\\LuaFiles\\Core\\Boot.lua"), Path("Core/Boot.lua"))
        self.assertEqual(source_path(b"@Lua\\LuaGen\\AutoGen\\RPCEnum.lua"), Path("LuaGen/AutoGen/RPCEnum.lua"))
        for name in (b"../../file.lua", b"C:/file.lua", b"@/absolute.lua", b"Core/../file.lua",
                     b"Core/NUL.lua", b"Core/file.lua.", b"Core/file.lua\x00"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                source_path(name)


if __name__ == "__main__":
    unittest.main()
