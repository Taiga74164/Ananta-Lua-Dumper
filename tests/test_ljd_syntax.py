import io
import os
from pathlib import Path
import sys
import unittest

from ananta_lua.ljd_syntax import install_syntax_patches


VENDOR = Path(__file__).resolve().parents[1] / "vendor" / "ljd"


@unittest.skipUnless((VENDOR / "ljd" / "lua" / "writer.py").is_file(), "LJD checkout not installed")
class LjdSyntaxTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(VENDOR))
        from ljd.ast import nodes
        from ljd.lua import writer
        cls.nodes = nodes
        cls.writer = writer
        install_syntax_patches()

    def render(self, *statements):
        ast = self.nodes.FunctionDefinition()
        ast.statements.contents.extend(statements)
        output = io.StringIO()
        self.writer.write(output, ast)
        return output.getvalue()

    def function_call(self, function):
        call = self.nodes.FunctionCall()
        call.function = function
        return call

    def identifier(self, name):
        result = self.nodes.Identifier()
        result.type = result.T_BUILTIN
        result.name = name
        return result

    def boolean_return(self, value):
        result = self.nodes.Return()
        primitive = self.nodes.Primitive()
        primitive.type = primitive.T_TRUE if value else primitive.T_FALSE
        result.returns.contents.append(primitive)
        return result

    def anonymous_call(self):
        function = self.nodes.FunctionDefinition()
        function.statements.contents.append(self.boolean_return(True))
        return self.function_call(function)

    def test_anonymous_call_has_parenthesized_function_expression(self):
        result = self.render(self.anonymous_call())
        self.assertIn("(function ()", result)
        self.assertIn("end)()", result)
        self.assertFalse(result.startswith(";"))

    def test_anonymous_call_in_condition_keeps_expression_grouping(self):
        condition = self.nodes.If()
        condition.expression = self.anonymous_call()
        condition.then_block.contents.append(self.boolean_return(True))
        result = self.render(condition)
        self.assertIn("if (function ()", result)
        self.assertIn("end)() then", result)

    def test_new_call_cannot_attach_to_preceding_call(self):
        result = self.render(self.function_call(self.identifier("before")), self.anonymous_call())
        self.assertIn("before();", result)
        self.assertIn("(function ()", result)

    def test_nonfinal_return_preserves_dead_statements_in_do_block(self):
        result = self.render(self.boolean_return(False),
                             self.function_call(self.identifier("unreachable")),
                             self.boolean_return(True))
        self.assertIn("do\n\treturn false\nend", result)
        self.assertIn("unreachable()", result)
        self.assertTrue(result.rstrip().endswith("return true"))
        self.assertEqual(result.count("do\n"), 1)

    def test_final_return_and_regular_calls_remain_ordinary_lua(self):
        result = self.render(self.function_call(self.identifier("before")), self.boolean_return(True))
        self.assertEqual(result, "before()\n\nreturn true\n")
        install_syntax_patches()
        self.assertEqual(self.render(self.boolean_return(False)), "return false\n")

    def loop_with_consecutive_breaks(self):
        loop = self.nodes.While()
        loop.expression = self.identifier("keep_going")
        loop.statements.contents.extend([self.nodes.Break(), self.nodes.Break()])
        return loop

    def test_nonfinal_break_still_exits_enclosing_loop_and_retains_dead_break(self):
        result = self.render(self.loop_with_consecutive_breaks())
        self.assertEqual(result, "while keep_going do\n\tdo\n\t\tbreak\n\tend\n\tbreak\nend\n")
        self.assertEqual(result.count("while"), 1)
        self.assertEqual(result.count("break"), 2)

    def test_generated_fixtures_compile_with_matching_runtime_when_available(self):
        runtime_path = VENDOR.parents[2] / "Ananta_Data" / "Plugins" / "x86_64" / "tolua.dll"
        if os.name != "nt" or not runtime_path.is_file():
            self.skipTest("Matching Windows Lua runtime not installed")
        from ananta_lua.normalize import RuntimeCipher, SyntaxChecker
        checker = SyntaxChecker(RuntimeCipher(runtime_path))
        self.addCleanup(checker.close)
        condition = self.nodes.If()
        condition.expression = self.anonymous_call()
        condition.then_block.contents.append(self.boolean_return(True))
        fixtures = [
            self.render(self.anonymous_call()),
            self.render(condition),
            self.render(self.function_call(self.identifier("before")), self.anonymous_call()),
            self.render(self.boolean_return(False),
                        self.function_call(self.identifier("unreachable")),
                        self.boolean_return(True)),
            self.render(self.loop_with_consecutive_breaks()),
        ]
        for source in fixtures:
            with self.subTest(source=source):
                self.assertIsNone(checker.check(source.encode("utf-8"), "@writer_fixture.lua"))


if __name__ == "__main__":
    unittest.main()
