"""Behavior checks for control flow, side effects, and captured locals.

Only these hand-authored fixtures execute. Game scripts remain compile-only.
"""

from pathlib import Path
import tempfile
import unittest

from ananta_lua.decompile import decompile_file
from lua_test_support import NATIVE_AVAILABLE, VENDOR, NativeCompiler, evaluate, exercise


@unittest.skipUnless(NATIVE_AVAILABLE and (VENDOR / "main.py").is_file(),
                     "Matching Lua compiler and LJD checkout required")
class DecompilerSemanticsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compiler = NativeCompiler()

    @classmethod
    def tearDownClass(cls):
        cls.compiler.close()

    def assert_equivalent(self, source, calls):
        with tempfile.TemporaryDirectory(prefix="ananta-semantic-test-") as temporary:
            raw = Path(temporary) / "input.luajit"
            output = Path(temporary) / "output.lua"
            raw.write_bytes(self.compiler.compile(source))
            result = decompile_file(raw, output, VENDOR, timeout=20)
            self.assertEqual(result["status"], "ok", result)
            recovered = output.read_text(encoding="utf-8")
        self.assertEqual(evaluate(exercise(recovered, calls)), evaluate(exercise(source, calls)), recovered)

    def test_comparison_operators_and_branch_polarity(self):
        source = '''return function(a, b)
    local x, y = 0, 0
    if a < b then x = 1 else x = 2 end
    if a >= b then y = 3 else y = 4 end
    return a == b, a ~= b, a < b, a <= b, a > b, a >= b, x, y
end'''
        calls = '''local trace = {}
for a = -2, 2 do
    for b = -2, 2 do
        local result = {fixture(a,b)}
        for i = 1, 8 do trace[#trace+1] = tostring(result[i]) end
    end
end
return table.concat(trace, ",")'''
        self.assert_equivalent(source, calls)

    def test_short_circuit_preserves_side_effect_count_and_order(self):
        source = '''return function(a,b,c)
    local trace = ""
    local function take(value, name)
        trace = trace .. name
        return value
    end
    local result = take(a,"a") and (take(b,"b") or take(c,"c"))
    if result then trace = trace .. "T" else trace = trace .. "F" end
    return trace, result
end'''
        calls = '''local trace = {}
local values = {false, true, 0, ""}
for _,a in ipairs(values) do
    for _,b in ipairs(values) do
        for _,c in ipairs(values) do
            local order, result = fixture(a,b,c)
            trace[#trace+1] = order .. ":" .. tostring(result)
        end
    end
end
return table.concat(trace, ";")'''
        self.assert_equivalent(source, calls)

    def test_register_reuse_keeps_loop_closures_and_shadowing(self):
        source = '''return function(n)
    local functions = {}
    local value = 100
    for i = 1,n do
        local value = i * 3
        functions[i] = function() return value end
    end
    local sum = value
    for i = 1,n do sum = sum + functions[i]() end
    return sum
end'''
        self.assert_equivalent(source, "return fixture(0), fixture(1), fixture(5)")

    def test_parallel_assignment_preserves_rhs_evaluation_and_old_values(self):
        source = '''return function(a,b)
    local count = 0
    local function values(x,y)
        count = count + 1
        return x+y, x-y, nil
    end
    local x,y,z = a,b,99
    x,y,z = values(y,x)
    x,y = y,x
    return x,y,z,count
end'''
        self.assert_equivalent(source, "return fixture(3,7)")


if __name__ == "__main__":
    unittest.main()
