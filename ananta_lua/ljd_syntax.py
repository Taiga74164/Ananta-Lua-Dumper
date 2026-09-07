"""Correct LJD's Lua syntax while preserving control flow and all statements."""


def install_syntax_patches() -> None:
    from ljd.ast import nodes
    from ljd.lua import writer

    if getattr(writer.Visitor, "_ananta_syntax_patched", False):
        return
    original_call = writer.Visitor.visit_function_call
    original_return = writer.Visitor.visit_return
    original_break = writer.Visitor.visit_break

    def visit_function_call(self, node):
        if node.is_method or not isinstance(node.function, nodes.FunctionDefinition):
            return original_call(self, node)
        is_statement = self._state().current_statement == writer.STATEMENT_NONE
        if is_statement:
            # A new parenthesized call can otherwise continue the preceding
            # call/assignment across a newline: f() (function() ... end)().
            if self.print_queue and self.print_queue[-1][0] == writer.CMD_END_STATEMENT:
                self.print_queue.insert(-1, (writer.CMD_WRITE, ";", (), {}))
            self._start_statement(writer.STATEMENT_FUNCTION_CALL)
        self._write("(")
        self._visit(node.function)
        self._write(")(")
        self._visit(node.arguments)
        self._write(")")
        if is_statement:
            self._end_statement(writer.STATEMENT_FUNCTION_CALL)

    def visit_last_statement(self, node, original, statement_kind):
        parent = self._path[-2] if len(self._path) > 1 else None
        nonfinal = (isinstance(parent, nodes.StatementsList)
                    and parent.contents and parent.contents[-1] is not node)
        if not nonfinal:
            return original(self, node)
        # Lua 5.1 requires return/break to end its block. Wrap it in do/end
        # to retain following statements without changing its return/exit target.
        self._start_statement(statement_kind)
        self._write("do")
        self._end_line()
        self._start_block()
        self._push_state()
        original(self, node)
        self._pop_state()
        self._end_block()
        self._write("end")
        self._end_statement(statement_kind)

    def visit_return(self, node):
        return visit_last_statement(self, node, original_return, writer.STATEMENT_RETURN)

    def visit_break(self, node):
        return visit_last_statement(self, node, original_break, writer.STATEMENT_BREAK)

    writer.Visitor.visit_function_call = visit_function_call
    writer.Visitor.visit_return = visit_return
    writer.Visitor.visit_break = visit_break
    writer.Visitor._ananta_syntax_patched = True
