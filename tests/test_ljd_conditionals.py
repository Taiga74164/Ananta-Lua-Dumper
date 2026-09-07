from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from lua_test_support import NativeCompiler, NATIVE_AVAILABLE, VENDOR, evaluate, exercise

PROJECT = Path(__file__).resolve().parents[1]


class ConditionalRetryTests(unittest.TestCase):
    def test_success_uses_fast_mode_and_restores_context(self):
        from ananta_lua.ljd_conditionals import decompile_with_conditional_retry, _transactional_recovery
        seen = []

        def parse(path, *, option):
            seen.append((path, option, _transactional_recovery.get()))
            return 'fresh AST'

        self.assertEqual(decompile_with_conditional_retry(parse,'input',option=7),'fresh AST')
        self.assertEqual(seen,[('input',7,False)])
        self.assertTrue(_transactional_recovery.get())

    def test_conditional_failure_reparses_once_with_recovery(self):
        from ananta_lua.ljd_conditionals import ConditionalRecoveryRequired, decompile_with_conditional_retry, _transactional_recovery
        attempts = []

        def parse():
            ast = {'instructions': ['original']}
            attempts.append((ast, _transactional_recovery.get()))
            if len(attempts) == 1:
                ast['instructions'].append('failed mutation')
                raise ConditionalRecoveryRequired('unsupported shape')
            self.assertEqual(sys.exc_info(),(None,None,None))
            return ast

        result = decompile_with_conditional_retry(parse)
        self.assertEqual(result,{'instructions':['original']})
        self.assertEqual([mode for _,mode in attempts],[False,True])
        self.assertIsNot(attempts[0][0],attempts[1][0])
        self.assertTrue(_transactional_recovery.get())

    def test_other_errors_propagate_without_retry(self):
        from ananta_lua.ljd_conditionals import decompile_with_conditional_retry, _transactional_recovery
        attempts = []

        def parse():
            attempts.append(1)
            raise AssertionError('unrelated validation failure')

        with self.assertRaisesRegex(AssertionError,'unrelated validation'):
            decompile_with_conditional_retry(parse)
        self.assertEqual(len(attempts),1)
        self.assertTrue(_transactional_recovery.get())

    def test_second_failure_propagates_and_restores_previous_mode(self):
        from ananta_lua.ljd_conditionals import ConditionalRecoveryRequired, decompile_with_conditional_retry, _transactional_recovery
        attempts = []

        def parse():
            attempts.append(_transactional_recovery.get())
            raise ConditionalRecoveryRequired('still unsupported')

        token = _transactional_recovery.set(False)
        try:
            with self.assertRaisesRegex(ConditionalRecoveryRequired,'still unsupported'):
                decompile_with_conditional_retry(parse)
            self.assertEqual(attempts,[False,True])
            self.assertFalse(_transactional_recovery.get())
        finally:
            _transactional_recovery.reset(token)


@unittest.skipUnless((VENDOR/'ljd/ast/unwarper.py').is_file(), 'LJD not installed')
class ConditionalGraphTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(VENDOR))
        from ljd.ast import nodes
        cls.nodes = nodes

    def block(self):
        block = self.nodes.Block()
        block.warp = self.nodes.EndWarp()
        return block

    def test_snapshot_isolates_expression_and_statement_mutations(self):
        from ananta_lua.ljd_conditionals import _snapshot
        start, end = self.block(), self.block()
        assignment = self.nodes.Assignment()
        constant = self.nodes.Constant()
        constant.type, constant.value = constant.T_INTEGER, 10
        assignment.expressions.contents.append(constant)
        start.contents.append(assignment)
        warp = start.warp = self.nodes.ConditionalWarp()
        warp.condition = constant
        warp.true_target = warp.false_target = end
        saved = _snapshot([start, end])
        constant.value = 99
        assignment.expressions.contents.clear()
        start.contents.clear()
        start.warp = self.nodes.EndWarp()
        self.assertEqual(saved[0].warp.condition.value, 10)
        self.assertEqual(saved[0].contents[0].expressions.contents[0].value, 10)
        self.assertIs(saved[0].warp.true_target, saved[1])

    def test_fast_attempt_does_not_snapshot_normal_regions(self):
        from ljd.ast import unwarper
        from ananta_lua.ljd_conditionals import install_conditionals_patches, decompile_with_conditional_retry
        install_conditionals_patches()
        blocks = [self.block()]
        with patch('ananta_lua.ljd_conditionals._snapshot',side_effect=AssertionError('unexpected snapshot')):
            result = decompile_with_conditional_retry(unwarper._unwarp_ifs,blocks)
        self.assertEqual(result,blocks)

    def test_rejects_cycles_and_unrepresented_exits(self):
        from ananta_lua.ljd_conditionals import structure_dag
        block = self.block()
        block.warp = self.nodes.UnconditionalWarp()
        block.warp.target = block
        with self.assertRaisesRegex(ValueError, 'cyclic'):
            structure_dag([block])
        block.warp.target = self.block()
        with self.assertRaisesRegex(ValueError, 'unrepresented'):
            structure_dag([block])

    def test_rejects_shared_tail_that_would_duplicate_a_label(self):
        from ananta_lua.ljd_conditionals import structure_dag
        from ananta_lua.ljd_loops import Label, install_loop_patches
        install_loop_patches()
        entry,left,right,tail,end = [self.block() for _ in range(5)]
        for block,true,false in [(entry,left,right),(left,tail,end),(right,tail,end)]:
            block.warp = self.nodes.ConditionalWarp()
            condition = self.nodes.Primitive()
            condition.type = condition.T_TRUE
            block.warp.condition = condition
            block.warp.true_target,block.warp.false_target = true,false
        tail.contents.append(Label('fixture_target'))
        tail.warp = self.nodes.UnconditionalWarp()
        tail.warp.target = end
        with self.assertRaisesRegex(ValueError,'externally addressable label'):
            structure_dag([entry,left,right,tail,end])


@unittest.skipUnless(NATIVE_AVAILABLE and (VENDOR/'main.py').is_file(), 'Matching runtime/LJD unavailable')
class ConditionalSemanticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compiler = NativeCompiler()

    @classmethod
    def tearDownClass(cls):
        cls.compiler.close()

    def assert_roundtrip(self, source, calls, force=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bytecode = root/'fixture.luajit'
            output = root/'fixture.lua'
            bytecode.write_bytes(self.compiler.compile(source))
            runner = root/'runner.py'
            runner.write_text(
                'import sys\n'
                f'sys.path.insert(0, {str(PROJECT)!r})\n'
                f'sys.path.insert(0, {str(VENDOR)!r})\n'
                'from ananta_lua.ljd_conditionals import install_conditionals_patches, structure_dag, _snapshot\n'
                'from ananta_lua.ljd_runner import main\n'
                'from ananta_lua.ljd_locals import install_locals_patches\n'
                'from ananta_lua.ljd_loops import install_loop_patches\n'
                'install_locals_patches()\n'
                'install_loop_patches()\n'
                'install_conditionals_patches()\n'
                + ('from ljd.ast import unwarper\nunwarper._unwarp_ifs = lambda blocks, *args, **kwargs: structure_dag(_snapshot(blocks))\n' if force else '')
                + f'raise SystemExit(main([{str(VENDOR)!r}, *sys.argv[1:]]))\n',
                encoding='utf-8')
            result = subprocess.run([sys.executable,str(runner),'-f',str(bytecode),'-o',str(output),
                                     '--function_def_sugar','false'],capture_output=True,timeout=30)
            self.assertEqual(result.returncode,0,result.stderr.decode('utf-8','replace'))
            recovered = output.read_text(encoding='utf-8')
            self.assertEqual(evaluate(exercise(recovered,calls)),evaluate(exercise(source,calls)))
            return recovered

    def test_shared_suffix_early_exits_and_branch_locals(self):
        source = '''return function(a, b, c)
            local trace = ""
            local value = 0
            if a then
                if b then trace = "abortA"; goto finish end
                trace = "A"
            else
                if c then trace = "abortB"; goto finish end
                trace = "B"
            end
            do
                local captured = a and 10 or 20
                local get = function() return captured end
                value = get()
                trace = trace .. "tail"
            end
            ::finish::
            return trace, value
        end'''
        calls = '''local a,b=fixture(false,false,false)
        local c,d=fixture(false,false,true)
        local e,f=fixture(true,false,false)
        local g,h=fixture(true,true,false)
        return a,b,c,d,e,f,g,h,_G.captured==nil,_G.get==nil'''
        self.assert_roundtrip(source,calls,force=True)

    def test_loop_iteration_closures_survive_conditional_structuring(self):
        source = '''return function(a)
            local callbacks={}
            for i=1,3 do
                local value=i*10
                if a then
                    local suffix="L"
                    callbacks[i]=function() return value..suffix end
                else
                    local suffix="R"
                    callbacks[i]=function() return value..suffix end
                end
            end
            return callbacks[1]()..","..callbacks[2]()..","..callbacks[3]()
        end'''
        self.assert_roundtrip(source,'return fixture(false),fixture(true),_G.suffix==nil',force=True)

    def test_effectful_short_circuit_conditions(self):
        source = '''return function(a,b,c)
            local trace = ""
            local function check(name,value) trace=trace..name; return value end
            local result
            if check("a",a) and (check("b",b) or check("c",c)) then result=1 else result=2 end
            return trace..":"..result
        end'''
        calls = 'return fixture(false,true,true),fixture(true,false,true),fixture(true,true,false),fixture(nil,true,true),fixture(0,false,false)'
        self.assert_roundtrip(source,calls,force=True)

    def test_iife_condition_has_nested_control_flow(self):
        source = '''return function(a,b)
            local result=0
            if (function() if a then return b else return not b end end)() then result=1 else result=2 end
            return result
        end'''
        calls = 'return fixture(false,false),fixture(false,true),fixture(true,false),fixture(true,true)'
        self.assert_roundtrip(source,calls,force=True)

    def test_join_retains_outer_local_and_branch_shadow(self):
        source = '''return function(a,b)
            local value=3
            local out=""
            if a then
                value=4
                local branch="left"
                out=branch
            else
                value=5
                local branch="right"
                out=branch
            end
            if b then local value=9; out=out..value end
            return out..":"..value
        end'''
        calls = 'return fixture(false,false),fixture(false,true),fixture(true,false),fixture(true,true)'
        self.assert_roundtrip(source,calls,force=True)


if __name__ == '__main__':
    unittest.main()
