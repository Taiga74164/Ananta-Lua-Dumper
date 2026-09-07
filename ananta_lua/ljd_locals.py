"""Keep reaching definitions and mixed local assignments intact in pinned LJD."""

from __future__ import annotations

import copy


def install_locals_patches() -> None:
    from ljd.ast import locals as local_names
    from ljd.ast import nodes, slotworks, traverse

    if getattr(slotworks, "_ananta_locals_patched", False):
        return

    original_reference = slotworks._SlotsCollector._register_slot_reference
    original_elimination = slotworks._eliminate_simple_cases
    original_function = local_names._LocalDefinitionsMarker.visit_function_definition
    original_assignment = local_names._LocalDefinitionsMarker.visit_assignment

    def register_reference(self, info, node, update_id=True):
        # Preserve the first pass's reaching-definition IDs when registers are
        # reused; later collection must not attach reads to unrelated writes.
        possible = getattr(node, "_ids", ())
        if (not self._identify and node.id == -1 and possible
                and info.slot_id not in possible):
            return
        return original_reference(self, info, node, update_id)

    class UsedNames(traverse.Visitor):
        def __init__(self):
            super().__init__()
            self.names = set()

        def visit_identifier(self, node):
            if node.name:
                self.names.add(node.name)

        def visit_constant(self, node):
            if node.type == nodes.Constant.T_STRING:
                self.names.add(node.value)

    def binding(identifier):
        info = getattr(identifier, "_varinfo", None)
        return (identifier.type, id(info)) if info is not None else (
            identifier.type, identifier.slot, identifier.name)

    class LocalReads(traverse.Visitor):
        def __init__(self):
            super().__init__()
            self.bindings = set()

        def _visit(self, node):
            # A closure's body runs later; it is not a value read at creation.
            if not isinstance(node, nodes.FunctionDefinition):
                super()._visit(node)

        def visit_identifier(self, node):
            if node.type == nodes.Identifier.T_LOCAL:
                self.bindings.add(binding(node))

    def crosses_local_write(info, reference, expression, position_cache):
        if isinstance(expression, (nodes.Primitive, nodes.Constant, nodes.FunctionDefinition)):
            return False
        reads = LocalReads()
        traverse.traverse(reads, expression)
        if not reads.bindings:
            return False
        for holder in reversed(info.references[0].path):
            if not isinstance(holder, (nodes.Block, nodes.StatementsList)):
                continue
            contents = holder.contents
            positions = position_cache.get(holder)
            if positions is None:
                # Elimination leaves statement positions stable until cleanup.
                # Cache first/last positions in case the list shares AST nodes.
                positions = {}
                for index, statement in enumerate(contents):
                    key = id(statement)
                    first = positions.get(key, (index, index))[0]
                    positions[key] = (first, index)
                position_cache[holder] = positions
            start = positions.get(id(info.assignment))
            if start is None:
                continue
            consumers = [positions[id(item)][1] for item in reference.path if id(item) in positions]
            if not consumers:
                continue
            start, end = start[0], max(consumers)
            for statement in contents[start + 1:end]:
                if slotworks._is_invalidated(statement) or not isinstance(statement, nodes.Assignment):
                    continue
                if any(isinstance(destination, nodes.Identifier)
                       and binding(destination) in reads.bindings
                       for destination in statement.destinations.contents):
                    return True
            return False
        return False

    def keep_snapshot(info):
        assert isinstance(info.assignment, nodes.Assignment)
        assert len(info.assignment.destinations.contents) == 1
        # Every reference must reach the same definition before naming it.
        assert all(reference.identifier.id == info.slot_id
                   or (reference.identifier.id == -1
                       and getattr(reference.identifier, "_ids", ()) == [info.slot_id])
                   for reference in info.references), "Snapshot has an ambiguous reaching definition"
        function = info.function
        assert isinstance(function, nodes.FunctionDefinition), "Snapshot has no owning function"
        names = getattr(function, "_ananta_snapshot_names", None)
        if names is None:
            collector = UsedNames()
            traverse.traverse(collector, function)
            names = collector.names
            function._ananta_snapshot_names = names
        serial = getattr(function, "_ananta_snapshot_serial", 0)
        while f"__ananta_snapshot_{serial}" in names:
            serial += 1
        name = f"__ananta_snapshot_{serial}"
        names.add(name)
        function._ananta_snapshot_serial = serial + 1
        for reference in info.references:
            identifier = reference.identifier
            identifier.type = nodes.Identifier.T_LOCAL
            identifier.name = name
            identifier._varinfo = None
        info.assignment.type = nodes.Assignment.T_LOCAL_DEFINITION
        info.assignment._ananta_introduced_locals = []
        info._ananta_kept_snapshot = True

    def eliminate_simple_cases(cases):
        position_cache = {}
        for info, reference, replacement in cases:
            if getattr(info, "_ananta_kept_snapshot", False):
                continue
            source = replacement if replacement is not None else info.assignment.expressions.contents[0]
            # Preserve MOV snapshots in parallel assignments: inlining
            # `saved = y; y = x; x = saved` as `y = x; x = y` changes the result.
            if (isinstance(info.assignment, nodes.Assignment)
                    and crosses_local_write(info, reference, source, position_cache)):
                keep_snapshot(info)
            else:
                original_elimination([(info, reference, replacement)])

    def visit_function(self, node):
        original_function(self, node)
        self._state()._ananta_function = node
        self._state()._ananta_used_names = None
        self._state()._ananta_result_serial = 0

    def visit_assignment(self, node):
        state = self._state()
        introduced = getattr(node, "_ananta_introduced_locals", None)
        if introduced is not None:
            # Synthetic temporaries share the result registers but are distinct
            # lexical bindings. Only original debug locals enter bookkeeping.
            for local in introduced:
                self._update_known_locals(local, getattr(node, "_addr", state.addr))
            node.type = nodes.Assignment.T_LOCAL_DEFINITION
            return

        destinations = node.destinations.contents
        if len(destinations) < 2 or not all(
                isinstance(item, nodes.Identifier) and item.type == nodes.Identifier.T_LOCAL
                for item in destinations):
            return original_assignment(self, node)
        address = getattr(destinations[0], "_addr", state.addr)
        known = [state.known_locals[item.slot] is not None
                 and state.known_locals[item.slot].end_addr > address
                 for item in destinations]
        if all(known) or not any(known):
            return original_assignment(self, node)

        # Split mixed existing/new locals without changing RHS evaluation or arity:
        #   old, new = f()  ->  local result, new = f(); old = result
        # Evaluate before declaring new, since the RHS may read an outer new.
        parent = self._path[-2]
        assert isinstance(parent, nodes.StatementsList)
        following = nodes.Assignment()
        following.type = nodes.Assignment.T_NORMAL
        following._addr = getattr(node, "_addr", address)
        following._line = getattr(node, "_line", 0)
        introduced = []
        used_names = state._ananta_used_names
        if used_names is None:
            collector = UsedNames()
            traverse.traverse(collector, state._ananta_function)
            used_names = state._ananta_used_names = collector.names
        serial = state._ananta_result_serial
        old_names = {destination.name for destination, was_known in zip(destinations, known) if was_known}
        new_names = {destination.name for destination, was_known in zip(destinations, known) if not was_known}
        shadowing = bool(old_names & new_names)
        declaration = nodes.Assignment() if shadowing else None
        if declaration is not None:
            # Capture the RHS once, then assign old bindings before declaring
            # shadowing locals so existing closures observe the original write.
            declaration.type = nodes.Assignment.T_LOCAL_DEFINITION
            declaration._addr = following._addr
            declaration._line = following._line
            declaration._ananta_introduced_locals = []
        for index, (destination, was_known) in enumerate(zip(destinations, known)):
            if not was_known and not shadowing:
                introduced.append(destination)
                continue
            while f"__ananta_result_{serial}" in used_names:
                serial += 1
            temporary = copy.copy(destination)
            temporary.name = f"__ananta_result_{serial}"
            used_names.add(temporary.name)
            serial += 1
            temporary.id = -1
            temporary._varinfo = None
            destinations[index] = temporary
            target = following if was_known else declaration
            target.destinations.contents.append(destination)
            target.expressions.contents.append(copy.copy(temporary))
            if not was_known:
                declaration._ananta_introduced_locals.append(destination)
        state._ananta_result_serial = serial
        node._ananta_introduced_locals = introduced
        node.type = nodes.Assignment.T_LOCAL_DEFINITION
        insertion = parent.contents.index(node) + 1
        parent.contents[insertion:insertion] = [following] if declaration is None else [following, declaration]
        state.addr = address
        for destination in introduced:
            self._update_known_locals(destination, address)

    slotworks._SlotsCollector._register_slot_reference = register_reference
    slotworks._eliminate_simple_cases = eliminate_simple_cases
    local_names._LocalDefinitionsMarker.visit_function_definition = visit_function
    local_names._LocalDefinitionsMarker.visit_assignment = visit_assignment
    slotworks._ananta_locals_patched = True
