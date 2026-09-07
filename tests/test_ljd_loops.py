from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from ananta_lua.ljd_loops import remove_orphan_jumps
from lua_test_support import NATIVE_AVAILABLE, NativeCompiler, PROJECT, VENDOR, evaluate, exercise


RUN = """
import sys
sys.path.insert(0, sys.argv.pop(1))
sys.path.insert(0, sys.argv[1])
from ananta_lua.ljd_loops import install_loop_patches
from ananta_lua.ljd_conditionals import install_conditionals_patches
from ananta_lua.ljd_locals import install_locals_patches
from ananta_lua.ljd_runner import main
install_locals_patches()
install_loop_patches()
install_conditionals_patches()
raise SystemExit(main())
"""


@unittest.skipUnless((VENDOR / "main.py").is_file(), "LJD checkout unavailable")
class OrphanJumpTests(unittest.TestCase):
    def test_only_unreferenced_empty_forward_trampoline_is_removed(self):
        sys.path.insert(0, str(VENDOR))
        from ljd.ast import nodes
        blocks = [nodes.Block() for _ in range(6)]
        for index, block in enumerate(blocks):
            block.index = index
            block.warp = nodes.UnconditionalWarp()
            block.warp.type = nodes.UnconditionalWarp.T_JUMP
            block.warp.target = blocks[-1]
        # Entry, referenced empty jump, orphan with work, and backward loop
        # marker must survive; only block 4 is an orphan forward trampoline.
        blocks[0].warp.target = blocks[1]
        blocks[2].contents.append(nodes.NoOp())
        blocks[3].warp.target = blocks[0]
        blocks[-1].warp = nodes.EndWarp()
        blocks[-1].warpins_count = 4
        result = remove_orphan_jumps(blocks)
        self.assertEqual(result, [blocks[i] for i in (0, 1, 2, 3, 5)])
        self.assertEqual([block.index for block in result], list(range(5)))
        self.assertEqual(blocks[-1].warpins_count, 3)


@unittest.skipUnless(NATIVE_AVAILABLE and (VENDOR / "main.py").is_file(), "Local Lua toolchain unavailable")
class LoopSemanticTests(unittest.TestCase):
    def setUp(self):
        self.compiler = NativeCompiler()
        self.addCleanup(self.compiler.close)

    def roundtrip(self, source, calls):
        with tempfile.TemporaryDirectory() as directory:
            bytecode = Path(directory) / "fixture.luajit"
            lua = Path(directory) / "fixture.lua"
            bytecode.write_bytes(self.compiler.compile(source))
            result = subprocess.run(
                [sys.executable, "-c", RUN, str(PROJECT), str(VENDOR), "-f", str(bytecode),
                 "-o", str(lua), "--function_def_sugar", "false"],
                capture_output=True, timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace"))
            generated = lua.read_text(encoding="utf-8")
            self.assertEqual(evaluate(exercise(generated, calls)), evaluate(exercise(source, calls)))
            return generated

    def test_numeric_loop_nonlocal_exit_skips_post_loop_side_effects(self):
        source = """
return function(skip)
    local trace = {}
    for i = 1, 4 do
        for j = 1, 3 do
            trace[#trace+1] = i .. ':' .. j
            if i+j == skip then goto next_i end
        end
        trace[#trace+1] = 'post' .. i
        ::next_i::
    end
    return table.concat(trace, ',')
end
"""
        generated = self.roundtrip(source, "local r={} for i=1,9 do r[i]=fixture(i) end return table.concat(r,'|')")
        self.assertIn("goto __ananta_pc_", generated)

    def test_iterator_exit_leaves_two_nested_loops(self):
        source = """
return function(skip)
    local trace = {}
    for _, outer in ipairs({2, 4, 6}) do
        for _, middle in ipairs({1, 3}) do
            for _, inner in ipairs({5, 7}) do
                trace[#trace+1] = outer+middle+inner
                if outer+middle+inner == skip then goto next_outer end
            end
            trace[#trace+1] = 'middle'
        end
        trace[#trace+1] = 'outer'
        ::next_outer::
    end
    return table.concat(trace, ',')
end
"""
        generated = self.roundtrip(source, "local r={} for i=6,18 do r[#r+1]=fixture(i) end return table.concat(r,'|')")
        self.assertIn("goto __ananta_pc_", generated)

    def test_loop_local_value_and_skipped_creation_remain_in_scope(self):
        source = """
return function(blocked)
    local sum = 0
    for q = 1, 5 do
        local object = { value = q*7 }
        for _, value in ipairs(blocked) do
            if value == q then goto next_q end
        end
        sum = sum + object.value
        ::next_q::
    end
    return sum
end
"""
        self.roundtrip(source, "return fixture({}), fixture({2}), fixture({1,3,5}), fixture({1,2,3,4,5})")

    def test_nested_conditional_exit_keeps_join_and_side_effect_order(self):
        source = """
return function(a, b, c)
    local total = 0
    for i = 1, 3 do
        local x, y = 0, 0
        if a then
            x, y = i, 10
        elseif b and c then
            x, y = i*2, 20
        else
            total = total+1
            goto next_i
        end
        total = total+x+y
        ::next_i::
    end
    return total
end
"""
        calls = "local r={} for a=0,1 do for b=0,1 do for c=0,1 do r[#r+1]=fixture(a==1,b==1,c==1) end end end return table.concat(r,',')"
        self.roundtrip(source, calls)

    def test_threaded_continue_branches_preserve_probe_call_trace(self):
        source = """
return function(red, threshold)
    local trace, result = '', ''
    local function probe(dir)
        trace = trace .. dir .. ','
        return dir >= threshold
    end
    for dir = -2, 2 do
        if red then
            if dir == -1 then goto next_dir end
            if probe(dir) and math.abs(dir) ~= 1 then goto next_dir end
        else
            if dir == 1 then goto next_dir end
            if not probe(dir) and math.abs(dir) ~= 1 then goto next_dir end
        end
        result = result .. dir .. ','
        ::next_dir::
    end
    return result .. '/' .. trace
end
"""
        calls = "local r={} for red=0,1 do for threshold=-3,3 do r[#r+1]=fixture(red==1,threshold) end end return table.concat(r,'|')"
        self.roundtrip(source, calls)

    def test_conditional_breaks_keep_native_loop_exit_anchors(self):
        source = """
return function(stop, mode)
    local sum, trace = 0, ''
    for outer = 1, 4 do
        local i = 0
        while i < 5 do
            i = i+1
            if mode then
                if i == stop or outer == stop then
                    trace = trace .. 'a'
                    break
                end
            elseif i > stop then
                trace = trace .. 'b'
                break
            end
            sum = sum+i*outer
            trace = trace .. i
        end
        trace = trace .. '|'
    end
    return sum .. '/' .. trace
end
"""
        calls = "local r={} for mode=0,1 do for stop=0,6 do r[#r+1]=fixture(stop,mode==1) end end return table.concat(r,',')"
        self.roundtrip(source, calls)


if __name__ == "__main__":
    unittest.main()
