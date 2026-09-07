from contextlib import ExitStack, redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from ananta_lua.cli import _decompiler_info, _target, main


def uleb(value):
    data = bytearray()
    while value >= 128:
        data.append((value & 127) | 128)
        value >>= 7
    data.append(value)
    return bytes(data)


def script(name, value=1):
    # A complete unstripped standard LuaJIT chunk with a debug terminator.
    name = name.encode("utf-8")
    prototype = (b"\x00\x00\x02\x00\x00\x00\x02\x01\x00\x01"
                 + b"\x29\x00" + value.to_bytes(2, "little")
                 + b"\x4b\x00\x01\x00\x00")
    return b"\x1bLJ\x02\x08" + uleb(len(name)) + name + uleb(len(prototype)) + prototype + b"\x00"


class CliTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name).resolve()
        self.block = self.root / "vfc_1"
        self.block.write_bytes(script("@Lua/LuaFiles/Core/Main.lua"))
        self.runtime = self.root / "tolua.dll"
        self.runtime.write_bytes(b"test runtime")
        self.vendor = self.root / "vendor"
        self.vendor.mkdir()
        (self.vendor / "main.py").write_text("# test vendor\n", encoding="utf-8")
        self.output = self.root / "output"
        self.calls = []
        self.failures = {}
        self.cipher = Mock()
        self.cipher.transform.side_effect = lambda data: data
        self.checker = Mock()
        self.checker.check.return_value = None
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch("ananta_lua.cli.recover_opcode_map", return_value={75: 75}))
        self.stack.enter_context(patch("ananta_lua.cli.RuntimeCipher", return_value=self.cipher))
        self.checker_constructor = self.stack.enter_context(
            patch("ananta_lua.cli.SyntaxChecker", return_value=self.checker))
        self.stack.enter_context(patch("ananta_lua.cli.normalize_chunk", side_effect=lambda raw, *_: raw))
        self.stack.enter_context(patch("ananta_lua.cli.decompile_file", side_effect=self.decompile))

    def decompile(self, bytecode, destination, vendor, timeout):
        self.calls.append(bytecode.name)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(b"return 1\n")
        return self.failures.get(bytecode.name, {"status": "ok", "output_bytes": 9}).copy()

    def run_cli(self, *extra):
        args = ["--block", str(self.block), "--runtime", str(self.runtime),
                "--ljd", str(self.vendor), "--output", str(self.output), "--workers", "1", *extra]
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return main(args)

    def manifest(self):
        return json.loads((self.output / "manifest.json").read_text(encoding="utf-8"))

    def test_added_or_changed_compatibility_module_invalidates_decompiler_cache(self):
        package = self.root / "package"
        package.mkdir()
        (package / "ljd_runner.py").write_text("# runner\n")
        with patch("ananta_lua.cli.__file__", str(package / "cli.py")):
            first = _decompiler_info(self.vendor)
            patch_file = package / "ljd_new_recovery.py"
            patch_file.write_text("# first recovery\n")
            added = _decompiler_info(self.vendor)
            patch_file.write_text("# changed recovery\n")
            changed = _decompiler_info(self.vendor)
        self.assertEqual(first["python_sha256"], changed["python_sha256"])
        self.assertNotEqual(first["compatibility_sha256"], added["compatibility_sha256"])
        self.assertNotEqual(added["compatibility_sha256"], changed["compatibility_sha256"])

    def test_publishes_source_only_after_successful_syntax_check(self):
        destination = self.output / "lua/Core/Main.lua"
        expected = b"return 1\n"

        def check(source, name):
            self.assertEqual(source, expected)
            self.assertEqual(name, "Core/Main.lua")
            self.assertFalse(destination.exists())
            return None

        self.checker.check.side_effect = check
        self.assertEqual(self.run_cli(), 0)
        record = self.manifest()["scripts"][0]
        self.assertEqual(record["status"], "ok")
        self.assertEqual(destination.read_bytes(), expected)
        self.assertEqual(record["output_bytes"], len(expected))
        self.assertEqual(record["source_sha256"], hashlib.sha256(expected).hexdigest())
        self.assertEqual((self.output / record["raw_file"]).read_bytes(), self.block.read_bytes())
        self.assertEqual((self.output / record["normalized_file"]).read_bytes(), self.block.read_bytes())
        self.assertEqual(list(self.output.glob(".decompile-*")), [])
        self.checker.close.assert_called_once()

    def test_syntax_failure_keeps_bytecode_but_never_publishes_source(self):
        self.checker.check.return_value = "unexpected token near end"
        self.assertEqual(self.run_cli(), 2)
        record = self.manifest()["scripts"][0]
        self.assertEqual(record["status"], "syntax_failed")
        self.assertIn("unexpected token", record["error"])
        self.assertTrue((self.output / record["raw_file"]).is_file())
        self.assertTrue((self.output / record["normalized_file"]).is_file())
        self.assertFalse((self.output / "lua/Core/Main.lua").exists())
        self.assertEqual(list(self.output.glob(".decompile-*")), [])

    def test_decompiler_failure_records_timeout_and_discards_partial_source(self):
        self.failures["Main.luajit"] = {"status": "timeout", "error": "timeout", "stderr": "details"}
        self.assertEqual(self.run_cli(), 2)
        record = self.manifest()["scripts"][0]
        self.assertEqual(record["status"], "timeout")
        self.assertEqual(record["stderr"], "details")
        self.assertTrue((self.output / record["raw_file"]).is_file())
        self.assertTrue((self.output / record["normalized_file"]).is_file())
        self.assertFalse((self.output / "lua/Core/Main.lua").exists())
        self.checker.check.assert_not_called()

    def test_resume_reuses_matching_checked_source_and_retries_failed_scripts(self):
        self.block.write_bytes(script("@Lua/LuaFiles/Core/Main.lua")
                               + script("@Lua/LuaFiles/Core/Second.lua"))
        self.failures["Second.luajit"] = {"status": "failed", "error": "AST failure"}
        self.assertEqual(self.run_cli(), 2)
        # Simulate checked output from a run that added provenance headers.
        legacy = (b"-- Original chunk: @Lua/LuaFiles/Core/Main.lua\n"
                  b"-- Decompiled from: normalized/Core/Main.luajit\n\nreturn 1\n")
        destination = self.output / "lua/Core/Main.lua"
        destination.write_bytes(legacy)
        manifest = self.manifest()
        manifest["scripts"][0].update(source_sha256=hashlib.sha256(legacy).hexdigest(),
                                      output_bytes=len(legacy))
        (self.output / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        self.calls.clear()
        self.failures.clear()
        self.checker.reset_mock()
        self.assertEqual(self.run_cli("--resume"), 0)
        self.assertEqual(self.calls, ["Second.luajit"])
        records = {r["path"]: r for r in self.manifest()["scripts"]}
        self.assertTrue(records["Core/Main.lua"]["resumed"])
        self.assertNotIn("resumed", records["Core/Second.lua"])
        self.assertEqual(self.checker.check.call_count, 2)
        updated = destination.read_bytes()
        self.assertEqual(updated, b"return 1\n")
        self.assertEqual(records["Core/Main.lua"]["source_sha256"], hashlib.sha256(updated).hexdigest())
        self.assertEqual(records["Core/Main.lua"]["output_bytes"], len(updated))
        # Further resumes preserve the source without rerunning the decompiler.
        self.calls.clear()
        self.assertEqual(self.run_cli("--resume"), 0)
        self.assertEqual(self.calls, [])
        self.assertEqual(destination.read_bytes(), updated)

    def test_resume_rechecks_changed_source_runtime_vendor_and_bytecode(self):
        self.assertEqual(self.run_cli(), 0)
        mutations = {
            "source": lambda: (self.output / "lua/Core/Main.lua").write_bytes(b"return 99\n"),
            "runtime": lambda: self.runtime.write_bytes(b"changed runtime"),
            "vendor": lambda: (self.vendor / "main.py").write_text("# changed vendor\n"),
            "bytecode": lambda: self.block.write_bytes(script("@Lua/LuaFiles/Core/Main.lua", 2)),
        }
        for name, mutation in mutations.items():
            with self.subTest(changed=name):
                mutation()
                self.calls.clear()
                self.assertEqual(self.run_cli("--resume"), 0)
                self.assertEqual(self.calls, ["Main.luajit"])
                self.assertNotIn("resumed", self.manifest()["scripts"][0])

    def test_failure_retires_unchanged_generated_source_but_preserves_user_edits(self):
        self.assertEqual(self.run_cli(), 0)
        destination = self.output / "lua/Core/Main.lua"
        self.failures["Main.luajit"] = {"status": "failed", "error": "AST failure"}
        self.assertEqual(self.run_cli(), 2)
        self.assertFalse(destination.exists())
        self.failures.clear()
        self.assertEqual(self.run_cli(), 0)
        destination.write_bytes(b"-- user notes\n")
        self.failures["Main.luajit"] = {"status": "failed", "error": "AST failure"}
        self.assertEqual(self.run_cli(), 2)
        self.assertEqual(destination.read_bytes(), b"-- user notes\n")

    def test_normalization_failure_retires_old_source_and_keeps_current_raw_bytes(self):
        self.assertEqual(self.run_cli(), 0)
        self.block.write_bytes(script("@Lua/LuaFiles/Core/Main.lua", 2))
        with patch("ananta_lua.cli.normalize_chunk", side_effect=ValueError("unknown opcode")):
            self.assertEqual(self.run_cli(), 2)
        record = self.manifest()["scripts"][0]
        self.assertEqual(record["status"], "extraction_failed")
        self.assertEqual(record["error"], "unknown opcode")
        self.assertEqual((self.output / record["raw_file"]).read_bytes(), self.block.read_bytes())
        self.assertNotIn("normalized_file", record)
        self.assertFalse((self.output / "lua/Core/Main.lua").exists())

    def test_changed_archive_retires_missing_generated_source(self):
        self.assertEqual(self.run_cli(), 0)
        self.block.write_bytes(script("@Lua/LuaFiles/Core/Second.lua"))
        self.assertEqual(self.run_cli(), 0)
        self.assertFalse((self.output / "lua/Core/Main.lua").exists())
        self.assertTrue((self.output / "lua/Core/Second.lua").is_file())

    def test_extract_only_does_not_require_or_invoke_decompiler_or_syntax_checker(self):
        (self.vendor / "main.py").unlink()
        self.assertEqual(self.run_cli("--extract-only"), 0)
        record = self.manifest()["scripts"][0]
        self.assertEqual(record["status"], "extracted")
        self.assertIsNone(self.manifest()["decompiler"])
        self.assertEqual(self.calls, [])
        self.checker_constructor.assert_not_called()
        self.assertFalse((self.output / "lua").exists())

    def test_unsafe_chunk_path_retains_only_unnamed_raw_evidence(self):
        self.block.write_bytes(script("@Lua/../../escape.lua"))
        self.assertEqual(self.run_cli(), 2)
        record = self.manifest()["scripts"][0]
        self.assertEqual(record["status"], "extraction_failed")
        self.assertNotIn("path", record)
        self.assertTrue(record["raw_file"].startswith("raw/_unnamed/"))
        self.assertEqual((self.output / record["raw_file"]).read_bytes(), self.block.read_bytes())
        self.assertFalse((self.root / "escape.lua").exists())
        self.assertEqual(self.calls, [])

    def test_duplicate_case_insensitive_paths_keep_second_raw_without_overwriting_first(self):
        first = script("@Lua/LuaFiles/Core/Main.lua")
        second = script("@Lua/LuaFiles/core/main.lua", 2)
        self.block.write_bytes(first + second)
        self.assertEqual(self.run_cli(), 2)
        records = self.manifest()["scripts"]
        self.assertEqual([r["status"] for r in records], ["ok", "extraction_failed"])
        self.assertEqual((self.output / records[0]["raw_file"]).read_bytes(), first)
        self.assertEqual((self.output / records[1]["raw_file"]).read_bytes(), second)

    def test_protected_input_overlap_fails_before_native_initialization(self):
        self.assertEqual(self.run_cli("--output", str(self.root)), 1)
        self.assertEqual(self.run_cli("--output", str(self.vendor / "output")), 1)
        self.cipher.transform.assert_not_called()
        self.assertFalse((self.root / "manifest.json").exists())

    def test_invalid_worker_and_timeout_values_fail_before_native_initialization(self):
        for option, value in (("--workers", "0"), ("--workers", "-1"),
                              ("--timeout", "0"), ("--timeout", "-1"),
                              ("--timeout", "nan"), ("--timeout", "inf")):
            with self.subTest(option=option, value=value):
                self.assertEqual(self.run_cli(option, value), 1)
        self.cipher.transform.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_escaping_raw_symlink_keeps_unnamed_evidence_and_preserves_outside_file(self):
        outside = self.root / "outside"
        outside.mkdir()
        sentinel = outside / "Main.luajit"
        sentinel.write_bytes(b"user data")
        (self.output / "raw").mkdir(parents=True)
        try:
            os.symlink(outside, self.output / "raw/Core", target_is_directory=True)
        except OSError as exc:
            self.skipTest(f"Directory symlinks unavailable: {exc}")
        self.assertEqual(self.run_cli(), 2)
        record = self.manifest()["scripts"][0]
        self.assertEqual(record["status"], "extraction_failed")
        self.assertTrue(record["raw_file"].startswith("raw/_unnamed/"))
        self.assertEqual((self.output / record["raw_file"]).read_bytes(), self.block.read_bytes())
        self.assertEqual(sentinel.read_bytes(), b"user data")

    def test_no_complete_chunks_reports_error(self):
        self.block.write_bytes(b"not Lua bytecode")
        self.assertEqual(self.run_cli(), 1)
        self.assertEqual(self.manifest()["scripts"], [])
        self.assertEqual(self.calls, [])


@unittest.skipUnless(os.name == "nt", "Windows extended path regression")
class TargetPathTests(unittest.TestCase):
    def test_extended_dos_and_unc_paths_within_root_keep_original_resolved_spelling(self):
        cases = [
            (r"D:\Ananta\output", r"\\?\D:\Ananta\output\Core\Main.lua"),
            (r"\\?\D:\Ananta\output", r"D:\Ananta\output\Core\Main.lua"),
            (r"D:\Ananta\output", r"\\?\d:\ANANTA\OUTPUT\Core\Main.lua"),
            (r"\\server\share\output", r"\\?\UNC\server\share\output\Core\Main.lua"),
            (r"\\?\UNC\server\share\output", r"\\server\share\output\Core\Main.lua"),
        ]
        for root, resolved in cases:
            with self.subTest(root=root, resolved=resolved):
                resolved = Path(resolved)
                with patch.object(Path, "resolve", return_value=resolved) as resolver:
                    self.assertIs(_target(Path(root), "Core/Main.lua"), resolved)
                resolver.assert_called_once_with()

    def test_extended_resolved_paths_outside_root_remain_rejected(self):
        cases = [
            (r"D:\Ananta\output", r"\\?\D:\Ananta\outside\Main.lua"),
            (r"D:\Ananta\output", r"\\?\D:\Ananta\output-other\Main.lua"),
            (r"D:\Ananta\output", r"\\?\E:\Ananta\output\Main.lua"),
            (r"D:\Ananta\output", r"\\?\D:\Ananta\output"),
            (r"\\?\D:\Ananta\output", r"D:\Ananta\outside\Main.lua"),
            (r"\\server\share\output", r"\\?\UNC\server\share\outside\Main.lua"),
            (r"\\server\share\output", r"\\?\UNC\server\other-share\output\Main.lua"),
            (r"\\server\share\output", r"\\?\UNC\other-server\share\output\Main.lua"),
            (r"\\server\share\output", r"\\?\UNC\server\share\output"),
            (r"D:\Ananta\output", r"\\?\GLOBALROOT\Device\HarddiskVolume1\Main.lua"),
        ]
        for root, resolved in cases:
            with self.subTest(root=root, resolved=resolved):
                with patch.object(Path, "resolve", return_value=Path(resolved)):
                    with self.assertRaises(ValueError):
                        _target(Path(root), "Core/Main.lua")


if __name__ == "__main__":
    unittest.main()
