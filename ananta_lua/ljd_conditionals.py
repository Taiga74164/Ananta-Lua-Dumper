"""Recover acyclic condition regions rejected by LJD's else-boundary heuristic."""

import copy
from contextvars import ContextVar


class ConditionalRecoveryRequired(AssertionError):
    """Conditional reconstruction requires a fresh parse with CFG recovery."""


_transactional_recovery = ContextVar('ananta_conditional_recovery', default=True)


def decompile_with_conditional_retry(decompile, *args, **kwargs):
    """Retry conditional failures once with rollback snapshots and CFG recovery.

    The callable must build a fresh AST on each call, as LJD Main.decompile does.
    Successful first attempts skip the snapshot cost.
    """
    token = _transactional_recovery.set(False)
    try:
        try:
            return decompile(*args, **kwargs)
        except ConditionalRecoveryRequired:
            pass
        # Release the failed AST's exception traceback before reparsing.
        _transactional_recovery.set(True)
        return decompile(*args, **kwargs)
    finally:
        _transactional_recovery.reset(token)


def _snapshot(blocks):
    from ljd.ast import nodes, traverse

    clones = {block: copy.copy(block) for block in blocks}
    memo = {id(block): clone for block, clone in clones.items()}

    class PreserveNestedRegions(traverse.Visitor):
        def _visit(self, node):
            if isinstance(node, (nodes.FunctionDefinition, nodes.IteratorFor,
                                 nodes.NumericFor, nodes.While, nodes.RepeatUntil)):
                # The outer pipeline already collected these regions. Preserve
                # their identity; the current conditional pass leaves them intact.
                memo[id(node)] = node
                return
            super()._visit(node)

    collector = PreserveNestedRegions()
    for block in blocks:
        for statement in block.contents:
            collector._visit(statement)
        condition = getattr(block.warp, 'condition', None)
        if condition is not None:
            collector._visit(condition)
        for key in ('target', 'true_target', 'false_target', '_target'):
            target = getattr(block.warp, key, None)
            if target is not None and target not in clones:
                memo[id(target)] = target
    for block, clone in clones.items():
        clone.contents = copy.deepcopy(block.contents, memo)
        clone.warp = copy.deepcopy(block.warp, memo)
    return [clones[block] for block in blocks]


def structure_dag(blocks):
    from ljd.ast import nodes, traverse, unwarper

    if not blocks:
        return []
    exit_node = object()
    members = set(blocks)
    edges = {}
    for block in blocks:
        warp = block.warp
        if isinstance(warp, nodes.ConditionalWarp):
            successors = (warp.true_target, warp.false_target)
        elif isinstance(warp, nodes.UnconditionalWarp):
            successors = (warp.target,)
        elif isinstance(warp, nodes.EndWarp):
            successors = (getattr(warp, '_target', None),)
        else:
            raise ValueError('Conditional recovery requires already structured loops')
        edges[block] = tuple(exit_node if target is None else target for target in successors)
        if any(target is not exit_node and target not in members for target in edges[block]):
            raise ValueError('Conditional graph exits to an unrepresented block')

    order = []
    active = set()
    visited = {exit_node}

    def visit(block):
        if block in active:
            raise ValueError('Conditional recovery does not rewrite cyclic graphs')
        if block in visited:
            return
        active.add(block)
        for target in edges[block]:
            visit(target)
        active.remove(block)
        visited.add(block)
        order.append(block)

    visit(blocks[0])
    postdominators = {exit_node: {exit_node}}
    for block in order:
        common = set.intersection(*(postdominators[target] for target in edges[block]))
        postdominators[block] = common | {block}
    rank = {block: index for index, block in enumerate(reversed(order))}
    rank[exit_node] = len(order)
    expanded = 0
    occurrences = {}

    def wrap(contents):
        if not contents:
            return []
        block = nodes.Block()
        block.index = 0
        block.contents = contents
        block.warp = nodes.EndWarp()
        return [block]

    def emit(block, stop):
        nonlocal expanded
        result = []
        while block is not stop:
            if block is exit_node:
                raise ValueError('Branch bypasses its selected join')
            expanded += 1
            if expanded > 100000:
                raise ValueError('Conditional graph expansion exceeds its safety bound')
            count = occurrences.get(block, 0)
            occurrences[block] = count + 1
            if count:
                # Repeating an externally addressable label would change its
                # meaning. Outgoing gotos may retain their original target.
                class FindLabels(traverse.Visitor):
                    found = False

                    def _visit(self, node):
                        if type(node).__name__ == 'Label' and type(node).__module__.endswith('.ljd_loops'):
                            self.found = True
                        super()._visit(node)

                labels = FindLabels()
                for statement in block.contents:
                    labels._visit(statement)
                if labels.found:
                    raise ValueError('Cannot duplicate an externally addressable label')
                contents = copy.deepcopy(block.contents)
                for statement in contents:
                    # The outer pipeline has not collected these copies;
                    # finish their conditional pass before global stages.
                    unwarper._run_step(unwarper._unwarp_ifs, statement)
            else:
                contents = block.contents
            result.extend(contents)
            successors = edges[block]
            if len(successors) == 1:
                block = successors[0]
                continue
            true, false = successors
            shared = postdominators[true] & postdominators[false]
            join = min(shared, key=rank.__getitem__)
            node = nodes.If()
            node.expression = copy.deepcopy(block.warp.condition) if count else block.warp.condition
            if count:
                unwarper._run_step(unwarper._unwarp_ifs, node.expression)
            node.then_block.contents = wrap(emit(true, join))
            node.else_block.contents = wrap(emit(false, join))
            node.then_block._ananta_cfg_branch = True
            node.else_block._ananta_cfg_branch = True
            result.append(node)
            block = join
        return result

    return wrap(emit(blocks[0], exit_node))


def install_conditionals_patches():
    from ljd.ast import unwarper as u
    from ljd.ast import locals as local_names

    if getattr(u, '_ananta_conditionals_patched', False):
        return
    original_extract = u._extract_if_expression
    original_ifs = u._unwarp_ifs
    depth = 0

    def extract(start, body, end, topmost_end):
        try:
            return original_extract(start, body, end, topmost_end)
        except AssertionError as exc:
            # Retry only conditional reconstruction failures. Recovery must
            # validate a closed DAG; other pipeline assertions still propagate.
            raise ConditionalRecoveryRequired('Conditional heuristic rejected this region') from exc

    def unwarp_ifs(blocks, top_end=None, topmost_end=None):
        nonlocal depth
        outermost = depth == 0
        recovery_enabled = _transactional_recovery.get()
        snapshot = _snapshot(blocks) if outermost and recovery_enabled else None
        depth += 1
        try:
            return original_ifs(blocks, top_end, topmost_end)
        except ConditionalRecoveryRequired:
            if not outermost or not recovery_enabled:
                raise
            depth = 0
            try:
                return structure_dag(snapshot)
            finally:
                depth = 1
        finally:
            depth -= 1

    u._extract_if_expression = extract
    u._unwarp_ifs = unwarp_ifs
    marker = local_names._LocalDefinitionsMarker
    original_enter = marker.visit_statements_list
    original_leave = marker.leave_statements_list

    def enter_branch(self, node):
        if getattr(node, '_ananta_cfg_branch', False):
            scopes = getattr(self, '_ananta_cfg_scopes', None)
            if scopes is None:
                scopes = self._ananta_cfg_scopes = []
            scopes.append((node, list(self._state().known_locals), self._state().addr))
        return original_enter(self, node)

    def leave_branch(self, node):
        result = original_leave(self, node)
        if getattr(node, '_ananta_cfg_branch', False):
            scope_node, known_locals, address = self._ananta_cfg_scopes.pop()
            assert scope_node is node
            self._state().known_locals = known_locals
            self._state().addr = address
        return result

    marker.visit_statements_list = enter_branch
    marker.leave_statements_list = leave_branch
    u._ananta_conditionals_patched = True
