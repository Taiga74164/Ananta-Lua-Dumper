"""Run the pinned LJD with local compatibility fixes, leaving vendor files intact.

Usage: python ljd_runner.py <LJD directory> <ordinary LJD arguments...>
"""

from __future__ import annotations

from pathlib import Path
import runpy
import sys


def lua_string_literal(value: str) -> str:
    """Quote UTF-8 text and surrogateescaped bytes without losing byte values.

    Three-digit decimal escapes cannot consume following decimal characters.
    Quoted literals also avoid Lua's newline normalization in long strings.
    """
    replacements = {"\\": "\\\\", '"': '\\"', "\n": "\\n", "\r": "\\r", "\t": "\\t"}
    pieces = ['"']
    for character in value:
        code = ord(character)
        if character in replacements:
            pieces.append(replacements[character])
        elif 0xDC80 <= code <= 0xDCFF:
            pieces.append(f"\\{code - 0xDC00:03d}")
        elif code < 32 or code == 127:
            pieces.append(f"\\{code:03d}")
        elif 0xD800 <= code <= 0xDFFF:
            raise ValueError("String contains an unsupported Unicode surrogate")
        else:
            pieces.append(character)
    pieces.append('"')
    return "".join(pieces)


class _ConstantBytes(bytes):
    def decode(self, encoding="utf-8", errors="strict"):
        if encoding == "utf-8" and errors == "backslashreplace":
            errors = "surrogateescape"
        return super().decode(encoding, errors)


class _ConstantStream:
    """Change string decoding only while LJD reads the KGC constant section."""

    def __init__(self, stream):
        self.stream = stream

    def __getattr__(self, name):
        return getattr(self.stream, name)

    def read_bytes(self, size=1):
        return _ConstantBytes(self.stream.read_bytes(size))


def install_string_patches() -> None:
    import ljd.ast.nodes as nodes
    import ljd.lua.writer as writer
    import ljd.rawdump.constants as constants

    if getattr(constants, "_ananta_strings_patched", False):
        return
    original_read = constants._read_complex_constants
    original_visit = writer.Visitor.visit_constant

    def read_constants(parser, values):
        original_stream = parser.stream
        parser.stream = _ConstantStream(original_stream)
        try:
            return original_read(parser, values)
        finally:
            parser.stream = original_stream

    def visit_constant(self, node):
        if node.type == nodes.Constant.T_STRING:
            self._write(lua_string_literal(node.value))
        else:
            original_visit(self, node)

    constants._read_complex_constants = read_constants
    writer.Visitor.visit_constant = visit_constant
    constants._ananta_strings_patched = True


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if not arguments:
        raise ValueError("Expected the LJD directory followed by its arguments")
    vendor = Path(arguments[0]).resolve(strict=True)
    entrypoint = vendor / "main.py"
    if not entrypoint.is_file():
        raise ValueError(f"LJD main.py is missing: {entrypoint}")
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    sys.path.insert(0, str(vendor))
    # Large generated tables need a higher AST recursion limit.
    sys.setrecursionlimit(max(sys.getrecursionlimit(), 10000))
    install_string_patches()
    from ananta_lua.ljd_syntax import install_syntax_patches
    install_syntax_patches()
    from ananta_lua.ljd_locals import install_locals_patches
    from ananta_lua.ljd_loops import install_loop_patches
    from ananta_lua.ljd_conditionals import (
        decompile_with_conditional_retry, install_conditionals_patches,
    )
    install_locals_patches()
    install_loop_patches()
    install_conditionals_patches()
    entry = runpy.run_path(str(entrypoint), run_name="_ananta_ljd_main")
    main_class = entry["Main"]
    original_decompile = main_class.decompile

    def decompile(self, *args, **kwargs):
        return decompile_with_conditional_retry(original_decompile, self, *args, **kwargs)

    main_class.decompile = decompile
    original_arguments = sys.argv
    try:
        sys.argv = [str(entrypoint), *arguments[1:]]
        return main_class().main()
    finally:
        sys.argv = original_arguments


if __name__ == "__main__":
    raise SystemExit(main())
