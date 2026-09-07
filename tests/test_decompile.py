from pathlib import Path
import tempfile
import unittest
from unittest.mock import call, patch

from ananta_lua.decompile import DIAGNOSTIC_LIMIT, decompile_file


class DecompileTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.vendor = self.root / "test decompiler"
        self.vendor.mkdir()
        self.source = self.root / "input $(unused).luajit"
        self.source.write_bytes(b"bytecode")
        self.destination = self.root / "output" / "example.lua"
        # This lightweight runner isolates the subprocess contract from the
        # separately tested, pinned LJD compatibility transformations.
        runner = self.root / "test_runner.py"
        runner.write_text(
            "import pathlib, runpy, sys\n"
            "entrypoint = pathlib.Path(sys.argv[1]) / 'main.py'\n"
            "sys.argv = [str(entrypoint), *sys.argv[2:]]\n"
            "runpy.run_path(str(entrypoint), run_name='__main__')\n",
            encoding="utf-8",
        )
        runner_patch = patch("ananta_lua.decompile.RUNNER_PATH", runner)
        runner_patch.start()
        self.addCleanup(runner_patch.stop)

    def tool(self, behavior):
        (self.vendor / "main.py").write_text(
            "import pathlib, sys, time\n"
            "assert sys.argv[-2:] == ['--function_def_sugar', 'false']\n"
            "assert '--catch_asserts' not in sys.argv\n"
            "output = pathlib.Path(sys.argv[sys.argv.index('-o') + 1])\n"
            "source = pathlib.Path(sys.argv[sys.argv.index('-f') + 1])\n"
            "assert source.is_file()\n" + behavior,
            encoding="utf-8",
        )

    def run_tool(self, timeout=10):
        result = decompile_file(self.source, self.destination, self.vendor, timeout)
        self.assertEqual(list(self.destination.parent.glob(".*.tmp.lua")), [])
        return result

    def preserve_old_output(self):
        self.destination.parent.mkdir()
        self.destination.write_text("old output", encoding="utf-8")

    def test_success_replaces_output_atomically_and_passes_literal_paths(self):
        self.preserve_old_output()
        self.tool("output.write_text('return 123\\n', encoding='utf-8')\n")
        result = self.run_tool()
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["output_bytes"], self.destination.stat().st_size)
        self.assertEqual(self.destination.read_text(), "return 123\n")

    def test_transient_windows_sharing_and_lock_violations_retry_atomic_publication(self):
        self.preserve_old_output()
        self.tool("output.write_text('return 123\\n', encoding='utf-8')\n")
        original_replace = Path.replace
        for code in (32, 33):
            with self.subTest(winerror=code):
                self.destination.write_text("old output", encoding="utf-8")
                attempts = 0

                def replace(source, destination):
                    nonlocal attempts
                    attempts += 1
                    self.assertEqual(destination.read_text(), "old output")
                    self.assertEqual(source.read_text(), "return 123\n")
                    if attempts <= 2:
                        error = OSError("temporary Windows file lock")
                        error.winerror = code
                        raise error
                    return original_replace(source, destination)

                with patch.object(Path, "replace", autospec=True, side_effect=replace) as publication:
                    with patch("ananta_lua.decompile.time.sleep") as sleep:
                        result = self.run_tool()
                self.assertEqual(result["status"], "ok", result)
                self.assertEqual(result["returncode"], 0)
                self.assertEqual(publication.call_count, 3)
                self.assertEqual(sleep.call_args_list, [call(0.05), call(0.1)])
                self.assertEqual(self.destination.read_text(), "return 123\n")

    def test_persistent_windows_file_lock_exhausts_bounded_retries_and_preserves_old_output(self):
        self.preserve_old_output()
        self.tool("output.write_text('return 123\\n', encoding='utf-8')\n")
        error = OSError("persistent Windows file lock")
        error.winerror = 32
        with patch.object(Path, "replace", side_effect=error) as publication:
            with patch("ananta_lua.decompile.time.sleep") as sleep:
                result = self.run_tool()
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["returncode"], 0)
        self.assertIn("persistent Windows file lock", result["error"])
        self.assertEqual(publication.call_count, 6)
        self.assertEqual(sleep.call_args_list, [call(delay) for delay in (0.05, 0.1, 0.2, 0.4, 0.8)])
        self.assertEqual(self.destination.read_text(), "old output")

    def test_other_publication_errors_fail_immediately_without_retry(self):
        self.preserve_old_output()
        self.tool("output.write_text('return 123\\n', encoding='utf-8')\n")
        for code in (None, 5, 112):
            with self.subTest(winerror=code):
                error = OSError("non-lock publication failure")
                if code is not None:
                    error.winerror = code
                with patch.object(Path, "replace", side_effect=error) as publication:
                    with patch("ananta_lua.decompile.time.sleep") as sleep:
                        result = self.run_tool()
                self.assertEqual(result["status"], "failed")
                self.assertIn("non-lock publication failure", result["error"])
                self.assertEqual(publication.call_count, 1)
                sleep.assert_not_called()
                self.assertEqual(self.destination.read_text(), "old output")

    def test_failed_writer_keeps_old_output_and_discards_partial_source(self):
        self.preserve_old_output()
        self.tool("output.write_text('partial')\nraise RuntimeError('failed writer')\n")
        result = self.run_tool()
        self.assertEqual(result["status"], "failed")
        self.assertIn("failed writer", result["stderr"])
        self.assertEqual(self.destination.read_text(), "old output")

    def test_timeout_discards_partial_output(self):
        self.preserve_old_output()
        self.tool("output.write_text('partial')\ntime.sleep(10)\n")
        result = self.run_tool(timeout=0.2)
        self.assertEqual(result["status"], "timeout")
        self.assertEqual(self.destination.read_text(), "old output")

    def test_success_exit_without_output_or_with_empty_output_fails(self):
        for behavior in ("pass\n", "output.write_text('')\n"):
            with self.subTest(behavior=behavior):
                self.tool(behavior)
                self.assertEqual(self.run_tool()["status"], "failed")
                self.assertFalse(self.destination.exists())

    def test_success_exit_with_error_diagnostics_fails(self):
        self.tool(
            "output.write_text('return 1')\n"
            "print('-- Decompilation Error: broken AST')\n"
        )
        result = self.run_tool()
        self.assertEqual(result["status"], "failed")
        self.assertFalse(self.destination.exists())

    def test_partial_reconstruction_in_file_is_rejected(self):
        self.tool("output.write_text('-- Decompilation error in this vicinity:\\nreturn nil')\n")
        self.assertEqual(self.run_tool()["status"], "failed")
        self.assertFalse(self.destination.exists())

    def test_application_error_strings_do_not_fail_decompilation(self):
        self.tool("output.write_text('print(\"Exception in client handler\")')\n")
        self.assertEqual(self.run_tool()["status"], "ok")

    def test_large_diagnostics_are_bounded_but_middle_errors_still_detected(self):
        self.tool(
            "output.write_text('return 1')\n"
            "print('A' * 10000)\n"
            "print('-- Decompilation Error: in omitted middle')\n"
            "print('Z' * 10000)\n"
        )
        result = self.run_tool()
        self.assertEqual(result["status"], "failed")
        self.assertLess(len(result["stdout"]), DIAGNOSTIC_LIMIT + 100)
        self.assertIn("truncated", result["stdout"])

    def test_invalid_inputs_do_not_overwrite_source(self):
        self.tool("output.write_text('return 1')\n")
        result = decompile_file(self.source, self.source, self.vendor)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(self.source.read_bytes(), b"bytecode")
        missing = decompile_file(self.root / "missing", self.destination, self.vendor)
        self.assertEqual(missing["status"], "failed")
        self.assertFalse(self.destination.exists())


if __name__ == "__main__":
    unittest.main()
