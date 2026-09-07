import ctypes
from pathlib import Path
import tempfile
import unittest

from ananta_lua.carve import _Reader
from ananta_lua.decompile import decompile_file
from ananta_lua.ljd_runner import lua_string_literal
from ananta_lua.normalize import RuntimeCipher, SyntaxChecker, normalize_chunk
from ananta_lua.opcodes import recover_opcode_map
from test_carve import chunk, uleb


PROJECT = Path(__file__).resolve().parents[1]
VENDOR = PROJECT / "vendor" / "ljd"
RUNTIME = PROJECT.parent / "Ananta_Data/Plugins/x86_64/tolua.dll"


def returning_constant(payload: bytes, *, table: bool = False) -> bytes:
    opcode = 0x35 if table else 0x27  # TDUP or KSTR, followed by RET1.
    body = b"\x00\x00\x01\x00\x01\x00\x02"
    body += bytes([opcode, 0, 0, 0, 0x4C, 0, 2, 0]) + payload
    return chunk(protos=uleb(len(body)) + body)


class LiteralTests(unittest.TestCase):
    def test_binary_bytes_and_following_digits_are_unambiguous(self):
        text = b"\xff1\x002\x7f3".decode("utf-8", "surrogateescape")
        self.assertEqual(lua_string_literal(text), '"\\2551\\0002\\1273"')

    def test_literal_escape_text_is_distinct_from_a_binary_byte(self):
        binary = b"\xff".decode("utf-8", "surrogateescape")
        self.assertEqual(lua_string_literal(binary), '"\\255"')
        self.assertEqual(lua_string_literal(r"\xff"), '"\\\\xff"')

    def test_unicode_and_multiline_strings_keep_their_contents(self):
        self.assertEqual(lua_string_literal("é雪"), '"é雪"')
        self.assertEqual(lua_string_literal('a\r\nb\n]]\n"'), '"a\\r\\nb\\n]]\\n\\\""')

    def test_unpaired_nonbyte_surrogate_is_rejected(self):
        with self.assertRaises(ValueError):
            lua_string_literal("\ud800")


@unittest.skipUnless((VENDOR / "main.py").is_file(), "LJD checkout unavailable")
class RunnerTests(unittest.TestCase):
    def decompile(self, raw):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "fixture.luajit"
            destination = Path(directory) / "fixture.lua"
            source.write_bytes(raw)
            result = decompile_file(source, destination, VENDOR)
            self.assertEqual(result["status"], "ok", result)
            return destination.read_text(encoding="utf-8")

    def test_binary_kgc_constant_survives_parser_ast_and_writer(self):
        # The actual CommonBombStore ASCII-counting pattern.
        value = b"[^\x80-\xff]"
        source = self.decompile(returning_constant(uleb(len(value) + 5) + value))
        self.assertIn('"[^\\128-\\255]"', source)
        self.assertNotIn(r"\\x80", source)

    def test_binary_table_keys_survive_parser_ast_and_writer(self):
        # The actual csv.lua UTF-16 byte-order mark keys.
        payload = b"\x01\x00\x02\x07\xff\xfe\x02\x07\xfe\xff\x02"
        source = self.decompile(returning_constant(payload, table=True))
        self.assertIn('["\\255\\254"] = true', source)
        self.assertIn('["\\254\\255"] = true', source)


@unittest.skipUnless(RUNTIME.is_file() and ctypes.sizeof(ctypes.c_void_p) == 8,
                     "Local x64 game compiler unavailable")
class NativeLiteralRoundTripTests(unittest.TestCase):
    def test_all_byte_values_and_actual_binary_constants_roundtrip(self):
        # Only compile generated constant expressions; no Lua program is called.
        cipher = RuntimeCipher(RUNTIME)
        checker = SyntaxChecker(cipher)
        library = checker.library
        opcode_map = recover_opcode_map(RUNTIME)
        writer_type = ctypes.CFUNCTYPE(
            ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p
        )
        library.lua_dump.argtypes = [ctypes.c_void_p, writer_type, ctypes.c_void_p]
        library.lua_dump.restype = ctypes.c_int
        values = (bytes(range(256)), b"\xff\xfe", b"\xfe\xff", b"[^\x80-\xff]",
                  b"literal \\xff and \\255", "雪\r\n]]\né".encode("utf-8"))
        try:
            for value in values:
                with self.subTest(length=len(value)):
                    source = ("return " + lua_string_literal(value.decode("utf-8", "surrogateescape"))).encode("utf-8")
                    buffer = ctypes.create_string_buffer(source)
                    status = library.luaL_loadbuffer(checker.state, buffer, len(source), b"literal_roundtrip")
                    self.assertEqual(status, 0)
                    output = bytearray()

                    @writer_type
                    def writer(state, pointer, length, opaque):
                        output.extend(ctypes.string_at(pointer, length))
                        return 0

                    self.assertEqual(library.lua_dump(checker.state, writer, None), 0)
                    library.lua_settop(checker.state, 0)
                    standard = normalize_chunk(bytes(output), cipher, opcode_map)
                    reader = _Reader(standard, 4, len(standard))
                    flags = reader.uleb()
                    if not flags & 2:
                        reader.skip(reader.uleb())
                    reader.uleb()
                    reader.skip(3)
                    upvalues = reader.byte()
                    self.assertEqual(reader.uleb(), 1)
                    self.assertEqual(reader.uleb(), 0)
                    instructions = reader.uleb()
                    if not flags & 2:
                        debug = reader.uleb()
                        if debug:
                            reader.uleb()
                            reader.uleb()
                    reader.skip(instructions * 4 + upvalues * 2)
                    length = reader.uleb() - 5
                    recovered = standard[reader.position:reader.position + length]
                    self.assertEqual(recovered, value)
        finally:
            checker.close()


if __name__ == "__main__":
    unittest.main()
