from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from ananta_lua.decompile import decompile_file
from lua_test_support import NATIVE_AVAILABLE, NativeCompiler, VENDOR, evaluate, exercise


PROJECT = Path(__file__).resolve().parents[1]


@unittest.skipUnless((VENDOR / "main.py").is_file(), "LJD checkout unavailable")
class ReachingDefinitionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(VENDOR))
        from ananta_lua.ljd_locals import install_locals_patches
        install_locals_patches()

    def register(self, *, identify, ids, slot_id=111):
        from ljd.ast import nodes, slotworks
        collector = slotworks._SlotsCollector(identify_slots=identify)
        info = slotworks.SlotInfo(slot_id)
        info.slot = 8
        node = nodes.Identifier()
        node.type = nodes.Identifier.T_SLOT
        node.slot = 8
        node.id = -1
        node._ids = list(ids)
        collector._register_slot_reference(info, node, update_id=False)
        return info, node

    def test_recollection_does_not_attach_a_later_ambiguous_read_to_an_earlier_register_use(self):
        info, node = self.register(identify=False, ids=[135, 139])
        self.assertEqual(info.references, [])
        self.assertEqual(node._ids, [135, 139])
        self.assertEqual(node.id, -1)

    def test_recollection_keeps_both_existing_reaching_definitions(self):
        for slot_id in (135, 139):
            with self.subTest(slot_id=slot_id):
                info, node = self.register(identify=False, ids=[135, 139], slot_id=slot_id)
                self.assertEqual(len(info.references), 1)
                self.assertIs(info.references[0].identifier, node)
                self.assertEqual(node._ids, [135, 139])

    def test_initial_collection_can_still_discover_another_reaching_definition(self):
        info, node = self.register(identify=True, ids=[135, 139])
        self.assertEqual(len(info.references), 1)
        self.assertEqual(node._ids, [111, 135, 139])

    def test_an_unidentified_reference_is_not_discarded(self):
        info, node = self.register(identify=False, ids=[])
        self.assertEqual(len(info.references), 1)
        self.assertIs(info.references[0].identifier, node)


@unittest.skipUnless((VENDOR / "main.py").is_file(), "LJD checkout unavailable")
class SlotGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(VENDOR))
        from ananta_lua.ljd_locals import install_locals_patches
        install_locals_patches()

    def candidate(self, function, slot_id, *, clobber=False):
        from ljd.ast import nodes, slotworks
        holder = function.statements

        def identifier(kind, slot, name=None, identifier_id=-1):
            node = nodes.Identifier()
            node.type, node.slot, node.name, node.id = kind, slot, name, identifier_id
            return node

        assignment = nodes.Assignment()
        destination = identifier(nodes.Identifier.T_SLOT, 7, identifier_id=slot_id)
        assignment.destinations.contents = [destination]
        assignment.expressions.contents = [identifier(nodes.Identifier.T_LOCAL, 1, "x")]
        consumer = nodes.Return()
        read = identifier(nodes.Identifier.T_SLOT, 7, identifier_id=slot_id)
        consumer.returns.contents = [read]
        definition = slotworks.SlotReference()
        definition.identifier = destination
        definition.path = [function, holder, assignment, assignment.destinations, destination]
        reference = slotworks.SlotReference()
        reference.identifier = read
        reference.path = [function, holder, consumer, consumer.returns, read]
        info = slotworks.SlotInfo(slot_id)
        info.assignment, info.function = assignment, function
        info.references = [definition, reference]
        holder.contents.append(assignment)
        if clobber:
            write = nodes.Assignment()
            write.destinations.contents = [identifier(nodes.Identifier.T_LOCAL, 1, "x")]
            write.expressions.contents = [nodes.Primitive()]
            holder.contents.append(write)
        holder.contents.append(consumer)
        return info, reference, None

    def test_many_candidates_share_one_statement_position_scan(self):
        from ljd.ast import nodes, slotworks

        class CountedList(list):
            scans = 0

            def __iter__(self):
                self.scans += 1
                return super().__iter__()

            def __contains__(self, item):
                self.scans += 1
                return super().__contains__(item)

            def index(self, item, *args):
                self.scans += 1
                return super().index(item, *args)

        function = nodes.FunctionDefinition()
        function.statements.contents = CountedList()
        candidates = [self.candidate(function, slot_id) for slot_id in range(300)]
        slotworks._eliminate_simple_cases(candidates)
        self.assertLessEqual(function.statements.contents.scans, 2)
        for info, reference, _ in candidates:
            self.assertTrue(slotworks._is_invalidated(info.assignment))
            self.assertIs(reference.path[-2].contents[0], info.assignment.expressions.contents[0])

    def test_snapshot_rejects_stale_ids_beside_a_different_definite_id(self):
        from ljd.ast import nodes, slotworks
        candidate = self.candidate(nodes.FunctionDefinition(), 11, clobber=True)
        candidate[1].identifier.id = 99
        candidate[1].identifier._ids = [11]
        with self.assertRaisesRegex(AssertionError, "ambiguous reaching definition"):
            slotworks._eliminate_simple_cases([candidate])
        self.assertEqual(candidate[1].identifier.type, nodes.Identifier.T_SLOT)

    def test_snapshot_requires_an_explicit_owning_function(self):
        from ljd.ast import nodes, slotworks
        candidate = self.candidate(nodes.FunctionDefinition(), 11, clobber=True)
        candidate[0].function = None
        with self.assertRaisesRegex(AssertionError, "no owning function"):
            slotworks._eliminate_simple_cases([candidate])
        self.assertEqual(candidate[1].identifier.type, nodes.Identifier.T_SLOT)


@unittest.skipUnless(NATIVE_AVAILABLE and (VENDOR / "main.py").is_file(),
                     "Matching native compiler or pinned LJD unavailable")
class LocalsBehaviorTests(unittest.TestCase):
    def setUp(self):
        self.compiler = NativeCompiler()
        self.addCleanup(self.compiler.close)

    def decompile(self, source):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bytecode = root / "fixture.luajit"
            output = root / "fixture.lua"
            bytecode.write_bytes(self.compiler.compile(source))
            bridge = root / "runner.py"
            bridge.write_text(
                "import sys\n"
                f"sys.path[:0] = [{str(PROJECT)!r}, {str(VENDOR)!r}]\n"
                "from ananta_lua.ljd_locals import install_locals_patches\n"
                "from ananta_lua import ljd_runner\n"
                "install_locals_patches()\n"
                "raise SystemExit(ljd_runner.main())\n",
                encoding="utf-8",
            )
            with patch("ananta_lua.decompile.RUNNER_PATH", bridge):
                result = decompile_file(bytecode, output, VENDOR)
            self.assertEqual(result["status"], "ok", result)
            return output.read_text(encoding="utf-8")

    def assert_behavior(self, source, calls):
        recovered = self.decompile(source)
        self.assertEqual(evaluate(exercise(source, calls)), evaluate(exercise(recovered, calls)))
        return recovered

    def test_mixed_knil_clears_existing_local_and_introduces_new_local(self):
        source = '''return function(use, produce)
    local path = 23
    use(path)
    path = nil
    local renderType
    if produce then
        renderType, path = produce()
    end
    return path, renderType
end'''
        calls = '''local trace = 0
local function use(x) trace = trace + x end
local a, b = fixture(use, function() return "walk", 42 end)
local c, d = fixture(use, false)
return trace, a, b, c, d'''
        recovered = self.assert_behavior(source, calls)
        self.assertIn("__ananta_result_", recovered)

    def test_multiresult_calls_preserve_rhs_scope_single_evaluation_and_captured_local(self):
        source = '''local new = 50
return function(f, observe)
    local old = 11
    local getOld = function() return old end
    observe(old)
    local value, new = f(old, new)
    old = value
    return old, new, getOld()
end'''
        calls = '''local count = 0
local seen = 0
local function f(a, b) count = count + 1; return a + b, nil end
local a, b, c = fixture(f, function(x) seen = x end)
return count, seen, a, b, c'''
        self.assert_behavior(source, calls)

    def test_generated_temporary_does_not_shadow_existing_name(self):
        source = '''return function(use)
    local __ananta_result_0 = 7
    local path = 23
    use(path)
    path = nil
    local renderType
    return __ananta_result_0, path, renderType
end'''
        recovered = self.assert_behavior(source, "return fixture(function() end)")
        self.assertIn("__ananta_result_1", recovered)

    def test_mixed_assignment_updates_old_binding_before_declaring_its_shadow(self):
        source = '''return function(save)
    local x = 23
    save(function() return x end)
    x = nil
    local x
    return x
end'''
        calls = '''local get
local current = fixture(function(f) get = f end)
return get(), current'''
        self.assert_behavior(source, calls)

    def test_snapshots_avoid_existing_names_and_each_other(self):
        source = '''return function(a, b)
    local __ananta_snapshot_0 = 37
    local x, y = a, b
    x, y = y, x
    x, y = y + 1, x + 2
    return x, y, __ananta_snapshot_0
end'''
        recovered = self.assert_behavior(source, "return fixture(3, 7)")
        self.assertIn("__ananta_snapshot_1", recovered)
        self.assertIn("__ananta_snapshot_2", recovered)

    def test_loop_register_reuse_with_later_conditional_read(self):
        source = '''return function(groups, which, requested)
    local selected = 0
    for difficulty, values in ipairs(groups) do
        for index, value in ipairs(values) do
            if value == requested then selected = index; break end
        end
    end
    local restored = 1
    for index, value in ipairs(groups[which]) do
        if value == requested then restored = index; break end
    end
    local value = groups[which] and groups[which][restored]
    return selected, restored, value
end'''
        calls = '''local groups = {{2, 4}, {5, 8, 9}}
local a, b, c = fixture(groups, 2, 8)
local d, e, f = fixture(groups, 1, 99)
return a, b, c, d, e, f'''
        self.assert_behavior(source, calls)

    def test_parallel_swaps_preserve_values_before_intervening_local_writes(self):
        source = '''return function(a, b)
    local count = 0
    local function values(x, y)
        count = count + 1
        return x + y, x - y, nil
    end
    local x, y, z = a, b, 99
    x, y, z = values(y, x)
    x, y = y, x
    return x, y, z, count
end'''
        recovered = self.assert_behavior(source, "return fixture(3, 7)")
        self.assertIn("__ananta_snapshot_", recovered)

    def test_parallel_rotation_with_expressions_preserves_every_original_value(self):
        source = '''return function(a, b, c)
    local x, y, z = a, b, c
    x, y, z = y + 1, z + 2, x + 3
    return x, y, z
end'''
        self.assert_behavior(source, "return fixture(2, 4, 8)")


if __name__ == "__main__":
    unittest.main()
