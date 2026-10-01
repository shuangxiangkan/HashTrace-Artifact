"""Tree-sitter mechanics for step 2 (code_scan).

Low-level and domain-free: parse C/C++ text, walk the tree, pull node text, and
normalise / split expression strings. The C-construct query API (functions,
calls, memory accesses, guards, ...) lives in :mod:`code_scan.query`.

Decompiler pseudocode is parsed as C by default; regular C++ source is parsed
with ``tree-sitter-cpp`` and keeps namespaces, classes, templates, and C++
expression node types.

    pip install tree-sitter tree-sitter-c tree-sitter-cpp
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, Literal

try:
    import tree_sitter
    import tree_sitter_c
except ImportError as exc:  # pragma: no cover - environment problem, not logic
    raise ImportError(
        "code_scan needs tree-sitter: pip install tree-sitter tree-sitter-c"
    ) from exc

if TYPE_CHECKING:
    from tree_sitter import Node, Tree

_C_LANGUAGE = tree_sitter.Language(tree_sitter_c.language())
_c_parser = tree_sitter.Parser(_C_LANGUAGE)

try:
    import tree_sitter_cpp

    _CPP_LANGUAGE = tree_sitter.Language(tree_sitter_cpp.language())
    _cpp_parser: tree_sitter.Parser | None = tree_sitter.Parser(_CPP_LANGUAGE)
except ImportError:
    _cpp_parser = None

LanguageName = Literal["c", "cpp"]

C_EXTENSIONS = frozenset({".c", ".h", ".i"})
CPP_EXTENSIONS = frozenset(
    {".cpp", ".cxx", ".cc", ".hpp", ".hxx", ".hh", ".ii", ".ipp", ".tpp", ".inl"}
)
SOURCE_EXTENSIONS = C_EXTENSIONS | CPP_EXTENSIONS

# --- node taxonomy (tree-sitter-c grammar facts) --------------------------- #

# Types that introduce a loop body.
LOOP_TYPES = frozenset(
    {"for_statement", "while_statement", "do_statement", "for_range_loop"}
)

# Bodies that can host function definitions at (effectively) file scope.
FUNCTION_HOST_TYPES = frozenset(
    {
        "linkage_specification",  # extern "C" { ... }
        "namespace_definition",
        "class_specifier",
        "struct_specifier",
        "template_declaration",
    }
)

# Node types that count as a full statement.
STATEMENT_TYPES = frozenset(
    {
        "expression_statement", "declaration", "return_statement",
        "if_statement", "for_statement", "while_statement", "do_statement",
        "switch_statement", "labeled_statement", "goto_statement",
        "break_statement", "continue_statement", "compound_statement",
    }
)


def cpp_available() -> bool:
    return _cpp_parser is not None


# --------------------------------------------------------------------------- #
# parsing
# --------------------------------------------------------------------------- #
def parser_for_language(language: LanguageName = "c"):
    """Return the requested parser, failing clearly if C++ support is absent."""
    if language == "c":
        return _c_parser
    if language == "cpp":
        if _cpp_parser is None:
            raise RuntimeError(
                "C++ scanning needs tree-sitter-cpp: pip install tree-sitter-cpp"
            )
        return _cpp_parser
    raise ValueError(f"unsupported language: {language!r} (expected 'c' or 'cpp')")


def parse(
    source: str | bytes,
    *,
    language: LanguageName = "c",
    cpp: bool | None = None,
) -> Tree:
    """Parse C or C++ source into a tree.

    ``cpp`` remains as a compatibility spelling; new callers should pass an
    explicit ``language`` so that it can be propagated through the whole scan.
    """
    if cpp is not None:
        language = "cpp" if cpp else "c"
    data = source.encode("utf-8") if isinstance(source, str) else source
    return parser_for_language(language).parse(data)


def language_for_path(path: Path, override: str = "auto") -> LanguageName:
    """Resolve ``auto`` from a conventional C/C++ filename extension."""
    if override in ("c", "cpp"):
        return override
    if override != "auto":
        raise ValueError(f"unsupported language: {override!r}")
    # Uppercase .C is conventionally C++, while lowercase .c is C.
    return "cpp" if path.suffix == ".C" or path.suffix.lower() in CPP_EXTENSIONS else "c"


def parser_for_path(path: Path, *, language: str = "auto"):
    return parser_for_language(language_for_path(path, language))


def parse_path(path: Path, *, language: str = "auto") -> tuple[Tree, bytes]:
    src = path.read_bytes()
    return parser_for_path(path, language=language).parse(src), src


# --------------------------------------------------------------------------- #
# traversal
# --------------------------------------------------------------------------- #
def node_text(node: Node, src: bytes) -> str:
    return src[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def line_of(node: Node) -> int:
    """1-indexed start line."""
    return node.start_point[0] + 1


def walk(node: Node, type_filter: str | None = None):
    """Yield ``node`` and every descendant, optionally filtered by ``type``."""
    cursor = node.walk()
    retracing = False
    while True:
        if not retracing:
            cur = cursor.node
            if type_filter is None or cur.type == type_filter:
                yield cur
            if cursor.goto_first_child():
                continue
        if cursor.goto_next_sibling():
            retracing = False
            continue
        if cursor.goto_parent():
            retracing = True
            continue
        return


def find_nodes(node: Node, *types: str):
    """Yield descendants whose type is any of ``types``."""
    want = frozenset(types)
    for cur in walk(node):
        if cur.type in want:
            yield cur


def enclosing_statement(node: Node) -> Node:
    """Nearest ancestor that is a full statement (or ``node`` itself)."""
    cur = node
    while cur.parent is not None and cur.type not in STATEMENT_TYPES:
        cur = cur.parent
    return cur


def declarator_name(node: Node, src: bytes) -> str | None:
    """Peel pointer/array/paren/function declarators down to the identifier."""
    if node.type in ("identifier", "field_identifier", "type_identifier"):
        return node_text(node, src)
    child = node.child_by_field_name("declarator")
    if child is not None:
        name = declarator_name(child, src)
        if name:
            return name
    for child in node.children:
        if child.type in ("identifier", "field_identifier"):
            return node_text(child, src)
        name = declarator_name(child, src)
        if name:
            return name
    return None


# --------------------------------------------------------------------------- #
# expression string utilities (balanced, string/char aware)
# --------------------------------------------------------------------------- #
_COPY_WRITERS = frozenset(
    {"memcpy", "memmove", "strcpy", "strncpy", "strcat", "strncat", "stpcpy", "stpncpy"}
)


def _dest_identifier(node: "Node", src: bytes) -> str | None:
    """Identifier written through a copy destination argument: ``&x``, ``x``,
    ``x.data()`` / ``x.begin()``. Returns ``x``."""
    if node.type == "pointer_expression":  # &x
        inner = node.child_by_field_name("argument")
        return _dest_identifier(inner, src) if inner is not None else None
    if node.type == "identifier":
        return node_text(node, src)
    if node.type in ("field_expression", "call_expression"):
        # x.data() -> the receiver x
        base = node.child_by_field_name("argument")
        if base is None and node.type == "field_expression":
            base = node.child_by_field_name("field")
        if base is None:
            base = node.children[0] if node.children else None
        return _dest_identifier(base, src) if base is not None else None
    return None


def derived_defs(node: "Node", src: bytes):
    """(lhs_identifier, rhs_node) definitions that plain assignment/init parsing
    misses but that still propagate a value into a scalar we track:

    * **constructor-initialisation** ``T k(a, b);`` — tree-sitter reports this as
      a declaration with a ``function_declarator`` (the most-vexing parse), so
      the initialising arguments hide inside a ``parameter_list``; and
    * **copy-style out-parameter writes** ``memcpy(&id, src, n)`` and the
      ``str*cpy``/``str*cat`` family, where the destination (arg 0) receives the
      source (arg 1).

    The ``rhs_node`` is a subtree whose identifiers are the value's inputs, so a
    caller taking ``used_idents(rhs_node)`` sees the right provenance.
    """
    out: list[tuple[str, "Node"]] = []

    for decl in walk(node, "declaration"):
        declarator = decl.child_by_field_name("declarator")
        if declarator is None or declarator.type != "function_declarator":
            continue
        params = declarator.child_by_field_name("parameters")
        if params is None:
            continue
        # Vexing parse only: every "parameter" is a bare identifier (no type +
        # name), i.e. a constructor argument mis-read as a type.
        decls = [c for c in params.named_children if c.type == "parameter_declaration"]
        if not decls or any(
            pd.named_child_count != 1 or pd.named_children[0].type != "type_identifier"
            for pd in decls
        ):
            continue
        name = declarator_name(declarator.child_by_field_name("declarator"), src) \
            if declarator.child_by_field_name("declarator") is not None else None
        if name:
            out.append((name, params))

    # Constructor call with expression arguments, ``std::string s(buf + i, n)``,
    # parses as an init_declarator whose value is an argument_list (no "value"
    # field), so the plain init handling skips it.
    for decl in walk(node, "init_declarator"):
        inner = decl.child_by_field_name("declarator")
        if inner is None or inner.type != "identifier":
            continue
        args = next((c for c in decl.children if c.type == "argument_list"), None)
        if args is not None:
            out.append((node_text(inner, src), args))

    for call in walk(node, "call_expression"):
        fn = call.child_by_field_name("function")
        if fn is None:
            continue
        fn_name = node_text(fn, src).rsplit("::", 1)[-1].rsplit(".", 1)[-1]
        if fn_name not in _COPY_WRITERS:
            continue
        args = call.child_by_field_name("arguments")
        if args is None:
            continue
        named = args.named_children
        if len(named) < 2:
            continue
        dest = _dest_identifier(named[0], src)
        if dest:
            out.append((dest, named[1]))  # source argument feeds the destination

    return out


def split_args(text: str) -> list[str]:
    """Split a comma-separated argument list, respecting nesting and strings.

    ``memcpy(a, f(b, c), "x,y")`` -> ``["a", "f(b, c)", '"x,y"']``.
    Empty / whitespace input -> ``[]``.
    """
    if not text.strip():
        return []
    args: list[str] = []
    depth = 0
    start = 0
    quote: str | None = None
    escaped = False
    for i, ch in enumerate(text):
        if quote is not None:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
            continue
        if ch in ('"', "'"):
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            args.append(text[start:i].strip())
            start = i + 1
    args.append(text[start:].strip())
    return args


def balanced_args(text: str, open_paren: int) -> tuple[str | None, int]:
    """Content between ``text[open_paren] == '('`` and its match; end index after."""
    if open_paren >= len(text) or text[open_paren] != "(":
        return None, open_paren
    depth = 1
    i = start = open_paren + 1
    quote: str | None = None
    escaped = False
    while i < len(text):
        ch = text[i]
        if quote is not None:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = None
        elif ch in ('"', "'"):
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[start:i], i + 1
        i += 1
    return None, i


_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_LINE_COMMENT_RE = re.compile(r"//[^\n]*")
_NAMED_CAST_RE = re.compile(r"\b(?:static|reinterpret|const|dynamic)_cast\s*<")
_C_POINTER_CAST_RE = re.compile(
    r"\(\s*[A-Za-z_][\w\s:<>,]*?\*+(?:\s+(?:const|volatile|restrict))*\s*\)"
)


def strip_comments(source: str) -> str:
    return _LINE_COMMENT_RE.sub(" ", _BLOCK_COMMENT_RE.sub(" ", source))


def strip_casts(text: str) -> str:
    """Drop C pointer casts and C++ named casts so matchers see the inner expr.

    ``(int *)(param_1 + 0x10)`` -> ``(param_1 + 0x10)``,
    ``static_cast<Foo*>(p)`` -> ``p``. Value casts like ``(uint)`` and grouping
    parens are left alone. Ghidra output is cast-heavy, so run this first.
    """
    return _C_POINTER_CAST_RE.sub("", _strip_named_casts(text))


def _strip_named_casts(text: str) -> str:
    while True:
        match = _NAMED_CAST_RE.search(text)
        if not match:
            return text
        i = match.end()
        depth = 1
        while i < len(text) and depth:
            if text[i] == "<":
                depth += 1
            elif text[i] == ">":
                depth -= 1
            i += 1
        while i < len(text) and text[i].isspace():
            i += 1
        if i >= len(text) or text[i] != "(":
            return text
        inner, end = balanced_args(text, i)
        if inner is None:
            return text
        text = text[: match.start()] + inner + text[end:]


__all__ = [
    "derived_defs",
    "CPP_EXTENSIONS",
    "C_EXTENSIONS",
    "SOURCE_EXTENSIONS",
    "FUNCTION_HOST_TYPES",
    "LanguageName",
    "LOOP_TYPES",
    "STATEMENT_TYPES",
    "balanced_args",
    "cpp_available",
    "declarator_name",
    "enclosing_statement",
    "find_nodes",
    "line_of",
    "language_for_path",
    "node_text",
    "parse",
    "parse_path",
    "parser_for_path",
    "parser_for_language",
    "split_args",
    "strip_casts",
    "strip_comments",
    "walk",
]
