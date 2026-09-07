from dataclasses import replace
from pathlib import Path
import tempfile
import unittest

from ananta_lua.carve import iter_chunks, parse_chunk, read_chunk


def uleb(value):
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def prototype(constants=b"", gc_count=0, numbers=b"", numeric_count=0, debug=None):
    data = b"\x00\x00\x02\x00" + uleb(gc_count) + uleb(numeric_count) + b"\x01"
    if debug is not None:
        data += uleb(len(debug)) + (b"\x00\x01" if debug else b"")
    data += b"\x4b\x00\x01\x00" + constants + numbers
    if debug is not None:
        data += debug
    return uleb(len(data)) + data


def chunk(name=None, protos=None):
    flags = 10 if name is None else 8
    head = b"\x1bLJ\x02" + bytes([flags])
    if name is not None:
        head += uleb(len(name)) + name
    if protos is None:
        protos = prototype(debug=None if name is None else b"\x00")
    return head + protos + b"\x00"


class CarveTests(unittest.TestCase):
    def test_extracts_exact_extent_and_preserves_encrypted_name(self):
        name = b"\xff\x00\x81\xa7script"
        raw = chunk(name)
        parsed = parse_chunk(b"prefix" + raw + b"padding", 6)
        self.assertEqual((parsed.offset, parsed.size), (6, len(raw)))
        self.assertEqual((parsed.version, parsed.flags, parsed.raw_name), (2, 8, name))
        self.assertEqual(parsed.prototype_count, 1)

    def test_parses_child_table_and_numeric_constant_payloads(self):
        # Child reference, table with one array value and one string/bool pair,
        # encrypted string, int64, uint64, and complex constants.
        constants = (b"\x00\x01\x01\x01\x03\x7b\x08key\x02"
                     b"\x08\xff\xfe\xfd\x02\x01\x02\x03\x03\x04\x04\x01\x02\x03\x04")
        numbers = uleb(0xFFFFFFFF << 1) + uleb((123 << 1) | 1) + uleb(456)
        raw = chunk(protos=prototype() + prototype(constants, 6, numbers, 2))
        parsed = parse_chunk(raw)
        self.assertEqual(parsed.prototype_count, 2)
        self.assertEqual(parsed.size, len(raw))

    def test_rejects_every_truncated_prefix(self):
        raw = chunk(b"@test.lua")
        for length in range(len(raw)):
            with self.subTest(length=length), self.assertRaises(ValueError):
                parse_chunk(raw[:length])

    def test_rejects_invalid_header_and_uleb(self):
        invalid = [b"", b"\x1bLJ\x7f\x02", b"\x1bLJ\x02\x20",
                   b"\x1bLJ\x02\x80\x00", b"\x1bLJ\x02\x80\x80\x80\x80\x10",
                   b"\x1bLJ\x02\x80\x80\x80\x80\x80\x00",
                   b"\x1bLJ\x02\x08\xff\xff\xff\xff\x0f"]
        for raw in invalid:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                parse_chunk(raw)
        with self.assertRaises(ValueError):
            parse_chunk(chunk(), -1)

    def test_rejects_invalid_prototype_contents_and_trees(self):
        invalid = [chunk(protos=b""), chunk(protos=prototype() * 2),
                   chunk(protos=prototype(b"\x00", 1)),
                   chunk(protos=prototype(b"\x7f", 1)),
                   chunk(protos=prototype(b"\x01\xff\xff\xff\xff\x0f\x00", 1)),
                   chunk(protos=prototype(numbers=b"\xff\xff\xff\xff\x20", numeric_count=1)),
                   chunk(protos=prototype(b"extra"))]
        for raw in invalid:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                parse_chunk(raw)

    def test_scanner_skips_false_headers_and_embedded_magic(self):
        inside = chunk()
        first = chunk(name=inside)
        second = chunk(b"@second.lua")
        prefix = b"noise\x1bLJ\x7f\xffgarbage"
        data = prefix + first + b"\x00" * 7 + second + b"\x1bLJ"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "block"
            path.write_bytes(data)
            result = list(iter_chunks(path))
            self.assertEqual(len(result), 2)
            self.assertEqual(result[0].offset, len(prefix))
            self.assertEqual(read_chunk(path, result[0]), first)
            self.assertEqual(read_chunk(path, result[1]), second)
            with self.assertRaises(ValueError):
                read_chunk(path, replace(result[0], size=result[0].size + 1))
            path.write_bytes(b"")
            self.assertEqual(list(iter_chunks(path)), [])
            with self.assertRaises(ValueError):
                read_chunk(path, result[0])


if __name__ == "__main__":
    unittest.main()
