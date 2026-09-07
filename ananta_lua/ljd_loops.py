"""Preserve nonlocal loop edges and enclosing branch context in pinned LJD."""

from __future__ import annotations


class Label:
    def __init__(self, name):
        self.name = name

    def _accept(self, visitor):
        visitor._visit_node(visitor.visit_ananta_transfer, self)
        visitor._leave_node(visitor.leave_ananta_transfer, self)


class Goto(Label):
    pass


def remove_orphan_jumps(blocks):
    """Remove only empty forward JMPs that no control-flow edge can enter."""
    from ljd.ast import nodes

    referenced = {blocks[0]} if blocks else set()
    for block in blocks:
        for attribute in ("target", "true_target", "false_target", "body", "way_out", "_target"):
            target = getattr(block.warp, attribute, None)
            if target is not None:
                referenced.add(target)
    retained = [block for block in blocks if not (
        block not in referenced and not block.contents
        and isinstance(block.warp, nodes.UnconditionalWarp)
        and block.warp.type == nodes.UnconditionalWarp.T_JUMP
        and block.warp.target.index > block.index
    )]
    if len(retained) != len(blocks):
        kept = set(retained)
        for block in blocks:
            if block not in kept:
                target = block.warp.target
                if target.warpins_count:
                    target.warpins_count -= 1
        for index, block in enumerate(retained):
            if block.index != index:
                block.former_index = block.index
                block.index = index
    return retained


def install_loop_patches():
    from ljd.ast import nodes, traverse, validator, unwarper
    from ljd.lua import writer

    if getattr(unwarper, "_ananta_loops_patched", False):
        return
    traverse.Visitor.visit_ananta_transfer = lambda self, node: None
    traverse.Visitor.leave_ananta_transfer = lambda self, node: None
    validator.STATEMENT_TYPES += (Label, Goto)

    def write_transfer(self, node):
        self._start_statement(writer.STATEMENT_BREAK)
        if isinstance(node, Goto):
            self._write("goto " + node.name)
        else:
            self._write("::" + node.name + "::")
        self._end_statement(writer.STATEMENT_BREAK)

    writer.Visitor.visit_ananta_transfer = write_transfer
    counter = 0

    def label_for(block):
        nonlocal counter
        label = getattr(block, "_ananta_label", None)
        if label is None:
            counter += 1
            label = Label(f"__ananta_pc_{block.first_address}_{counter}")
            block._ananta_label = label
            block.contents.insert(0, label)
        return label.name

    original_breaks = unwarper._unwarp_breaks
    original_expressions = unwarper._unwarp_expressions

    def unwarp_expressions(blocks):
        # Jump threading leaves unreferenced JMPs that confuse expression
        # grouping. Remove them only after loop construction, which uses them
        # as placeholders for conditional breaks.
        return original_expressions(remove_orphan_jumps(blocks))

    def unwarp_breaks(start, blocks, next_block):
        internal = set([start, *blocks])
        ordinary_exits = unwarper._gather_possible_ends(next_block)
        # Preserve the exact target of exits beyond the normal continuation.
        for i, block in enumerate(blocks):
            warp = block.warp
            if not isinstance(warp, nodes.UnconditionalWarp):
                continue
            if warp.target in internal or warp.target in ordinary_exits:
                continue
            block.contents.append(Goto(label_for(warp.target)))
            if i + 1 < len(blocks):
                unwarper._set_flow_to(block, blocks[i + 1])
            else:
                unwarper._set_end(block, force_no_target=True)
        return original_breaks(start, blocks, next_block)

    original_if = unwarper._unwarp_if_statement

    def unwarp_if(start, body, end, topmost_end):
        body_set = set(body)
        exits = {
            block.warp.target for block in body
            if isinstance(block.warp, nodes.UnconditionalWarp)
            and block.warp.target not in body_set
            and block.warp.target not in (end, topmost_end)
            and block.warp.target.index >= end.index
        }
        if len(exits) == 1:
            topmost_end = next(iter(exits))
        return original_if(start, body, end, topmost_end)

    unwarper._unwarp_breaks = unwarp_breaks
    unwarper._unwarp_expressions = unwarp_expressions
    unwarper._unwarp_if_statement = unwarp_if
    unwarper._ananta_loops_patched = True
