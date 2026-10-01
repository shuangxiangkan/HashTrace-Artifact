"""Tree-sitter extraction of C++ hash-container declarations and operations."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Iterable

from code_scan import cst, query

from .model import HashContainerFact, HashOperationFact, TypeAliasFact

if TYPE_CHECKING:
    from tree_sitter import Node


@dataclass(frozen=True)
class _ContainerSpec:
    family: str
    value_arg: int | None
    hasher_arg: int


@dataclass(frozen=True)
class _ResolvedType:
    kind: str
    spec: _ContainerSpec
    key_type: str | None
    value_type: str | None
    hasher_type: str | None


@dataclass(frozen=True)
class HashTranslationUnitIndex:
    """Hash-container aliases and non-local declarations from one source file."""

    aliases: tuple[TypeAliasFact, ...]
    containers: tuple[HashContainerFact, ...]


# Hash-container families keyed by the *terminal* template name (tree-sitter
# exposes ``std::unordered_map`` / ``boost::unordered_map`` alike as
# ``unordered_map``). Third-party open-addressing/hash maps share the standard
# ``<Key,[Value,]Hash,...>`` argument layout, so they reuse the map/set specs.
# Only distinctive names are listed — never a bare ``map``/``set`` (that would
# match the *ordered* ``std::map``). Bespoke per-project wrappers (oatpp
# ``LazyStringMultimap``, brpc ``CaseIgnoredMultiFlatMap``) are not covered here.
_MAP_SPEC = _ContainerSpec("map", 1, 2)
_SET_SPEC = _ContainerSpec("set", None, 1)
_CONTAINER_SPECS = {
    # std (also matches boost::unordered_* — same terminal name)
    "unordered_map": _MAP_SPEC,
    "unordered_multimap": _MAP_SPEC,
    "unordered_set": _SET_SPEC,
    "unordered_multiset": _SET_SPEC,
    # boost::unordered_flat_* (C++03 name-distinct variant)
    "unordered_flat_map": _MAP_SPEC,
    "unordered_flat_set": _SET_SPEC,
    "unordered_node_map": _MAP_SPEC,
    "unordered_node_set": _SET_SPEC,
    # abseil / parallel-hashmap (phmap) / google dense-hash
    "flat_hash_map": _MAP_SPEC,
    "node_hash_map": _MAP_SPEC,
    "parallel_flat_hash_map": _MAP_SPEC,
    "parallel_node_hash_map": _MAP_SPEC,
    "dense_hash_map": _MAP_SPEC,
    "sparse_hash_map": _MAP_SPEC,
    "flat_hash_set": _SET_SPEC,
    "node_hash_set": _SET_SPEC,
    "parallel_flat_hash_set": _SET_SPEC,
    "parallel_node_hash_set": _SET_SPEC,
    "dense_hash_set": _SET_SPEC,
    "sparse_hash_set": _SET_SPEC,
    # folly F14
    "F14FastMap": _MAP_SPEC,
    "F14ValueMap": _MAP_SPEC,
    "F14NodeMap": _MAP_SPEC,
    "F14VectorMap": _MAP_SPEC,
    "F14FastSet": _SET_SPEC,
    "F14ValueSet": _SET_SPEC,
    "F14NodeSet": _SET_SPEC,
    "F14VectorSet": _SET_SPEC,
    # Intel TBB
    "concurrent_unordered_map": _MAP_SPEC,
    "concurrent_hash_map": _MAP_SPEC,
    "concurrent_unordered_set": _SET_SPEC,
    # (robin_hood::unordered_map / unordered_flat_map already match via their
    #  terminal names above; ankerl::unordered_dense::map's terminal is the
    #  ambiguous "map", deliberately excluded.)
}

_METHODS: dict[str, tuple[str, bool, int]] = {
    "emplace": ("insert", True, 0),
    "try_emplace": ("insert", True, 0),
    "insert_or_assign": ("insert", True, 0),
    "emplace_hint": ("insert", True, 1),
    "find": ("lookup", False, 0),
    "contains": ("lookup", False, 0),
    "count": ("lookup", False, 0),
    "equal_range": ("lookup", False, 0),
    "at": ("lookup", False, 0),
    "erase": ("erase", False, 0),
}

_SCOPE_NODES = {
    "namespace_definition",
    "class_specifier",
    "struct_specifier",
    "union_specifier",
}


def _scope_parts(node: "Node", source: bytes) -> tuple[str, ...]:
    parts: list[str] = []
    current = node.parent
    while current is not None:
        if current.type in _SCOPE_NODES:
            name = current.child_by_field_name("name")
            if name is not None:
                parts.append(cst.node_text(name, source))
        current = current.parent
    parts.reverse()
    return tuple(parts)


def _scope_name(node: "Node", source: bytes) -> str | None:
    parts = _scope_parts(node, source)
    return "::".join(parts) if parts else None


def _inside(node: "Node", node_type: str) -> bool:
    current = node.parent
    while current is not None:
        if current.type == node_type:
            return True
        current = current.parent
    return False


def _template_info(type_node: "Node", source: bytes) -> _ResolvedType | None:
    """Resolve a template type to a hash-container family.

    Matches the outermost known container (``std::unordered_map<...>``) directly,
    and also a container **nested** inside a wrapper's template arguments — e.g.
    ``LazyStringMapTemplate<K, std::unordered_multimap<K,V>>`` — so a wrapper alias
    over an ``unordered_*`` is recognised. For a nested match the reported ``kind``
    is the container's own name (terminal in :data:`_CONTAINER_SPECS`) so downstream
    resolution works.
    """
    for index, template in enumerate(cst.walk(type_node, "template_type")):
        name_node = template.child_by_field_name("name")
        terminal = cst.node_text(name_node, source) if name_node is not None else ""
        spec = _CONTAINER_SPECS.get(terminal)
        if spec is None:
            continue
        arguments = template.child_by_field_name("arguments")
        args = (
            [cst.node_text(child, source) for child in arguments.named_children]
            if arguments is not None
            else []
        )
        if index == 0:
            kind = cst.node_text(type_node, source).strip().split("<", 1)[0].strip()
        else:  # nested container inside a wrapper — report the container's name
            kind = terminal
        return _ResolvedType(
            kind=kind,
            spec=spec,
            key_type=args[0] if args else None,
            value_type=(
                args[spec.value_arg]
                if spec.value_arg is not None and len(args) > spec.value_arg
                else None
            ),
            hasher_type=(
                args[spec.hasher_arg] if len(args) > spec.hasher_arg else None
            ),
        )
    return None


def _outermost_template(type_node: "Node", source: bytes) -> tuple[str, list[str]]:
    """``(outer_template_name, [arg_texts])`` of the first (outermost) template."""
    for template in cst.walk(type_node, "template_type"):
        name_node = template.child_by_field_name("name")
        arguments = template.child_by_field_name("arguments")
        args = (
            [cst.node_text(child, source) for child in arguments.named_children]
            if arguments is not None
            else []
        )
        return (
            cst.node_text(name_node, source) if name_node is not None else ""
        ), args
    return "", []


def find_type_aliases(
    root: "Node",
    source: bytes,
    *,
    include_local: bool = True,
    extra_aliases: Iterable[TypeAliasFact] = (),
) -> list[TypeAliasFact]:
    """Find using/typedef aliases of hash containers.

    Handles direct aliases (``using M = std::unordered_map<...>``), wrapper aliases
    whose target embeds an ``unordered_*`` (``using LazyStringMultimap =
    LazyStringMapTemplate<K, std::unordered_multimap<K,V>>``), and **chains** of
    aliases (``using Headers = LazyStringMultimap<StringKeyLabelCI>``) — resolving
    the chain to the underlying family and substituting the concrete key type.

    ``extra_aliases`` seeds the chain resolver with aliases from other files of the
    same scan (only used to resolve chains — they are not re-emitted), so a chain
    whose wrapper is declared in a different header still resolves.
    """
    entries: list[tuple[str, "Node", "Node"]] = []  # (name, type_node, decl node)
    for node in cst.walk(root):
        if node.type == "alias_declaration":
            name_node = node.child_by_field_name("name")
            type_node = node.child_by_field_name("type")
        elif node.type == "type_definition":
            name_node = node.child_by_field_name("declarator")
            type_node = node.child_by_field_name("type")
        else:
            continue
        if not include_local and _inside(node, "function_definition"):
            continue
        if name_node is None or type_node is None:
            continue
        name = cst.declarator_name(name_node, source)
        if name:
            entries.append((name, type_node, node))

    def make(name: str, node: "Node", type_node: "Node", resolved: _ResolvedType) -> TypeAliasFact:
        return TypeAliasFact(
            name=name,
            kind=resolved.kind,
            target_type_text=cst.node_text(type_node, source).strip(),
            key_type=resolved.key_type,
            value_type=resolved.value_type,
            hasher_type=resolved.hasher_type,
            scope=_scope_name(node, source),
            line=cst.line_of(node),
            byte=node.start_byte,
        )

    aliases: list[TypeAliasFact] = []
    by_name: dict[str, TypeAliasFact] = {}
    # Seed the chain resolver with cross-file aliases (used, not re-emitted). Only
    # those resolvable to a container family are useful for chaining.
    for extra in extra_aliases:
        if extra.kind.rsplit("::", 1)[-1] in _CONTAINER_SPECS:
            by_name.setdefault(extra.name, extra)
            by_name.setdefault(extra.name.rsplit("::", 1)[-1], extra)

    def register(fact: TypeAliasFact) -> None:
        aliases.append(fact)
        by_name[fact.name] = fact
        by_name.setdefault(fact.name.rsplit("::", 1)[-1], fact)

    # Object-like macros that alias a hash-container family, e.g. reSIProcate's
    # ``#define HashMap std::unordered_map``. Tree-sitter does not expand macros,
    # so a ``HashMap<Data, ...>`` container would otherwise be invisible. Register
    # the macro name as a family alias; the concrete key type is taken from each
    # use site by :func:`_resolve_type`'s template-alias-instantiation path. Only
    # unordered/hash families in ``_CONTAINER_SPECS`` qualify, so a ``#define M
    # std::map`` (ordered, immune) is correctly ignored.
    for macro in cst.walk(root, "preproc_def"):
        name_node = macro.child_by_field_name("name")
        value_node = macro.child_by_field_name("value")
        if name_node is None or value_node is None:
            continue
        if not include_local and _inside(macro, "function_definition"):
            continue
        macro_name = cst.node_text(name_node, source).strip()
        value_text = "".join(cst.node_text(value_node, source).split()).lstrip(":")
        terminal = value_text.split("<", 1)[0].rsplit("::", 1)[-1]
        if not macro_name or _CONTAINER_SPECS.get(terminal) is None:
            continue
        register(
            TypeAliasFact(
                name=macro_name,
                kind=value_text.split("<", 1)[0],
                target_type_text=cst.node_text(value_node, source).strip(),
                key_type=None,
                value_type=None,
                hasher_type=None,
                scope=None,
                line=cst.line_of(macro),
                byte=macro.start_byte,
            )
        )

    pending: list[tuple[str, "Node", "Node"]] = []
    for name, type_node, node in entries:
        resolved = _template_info(type_node, source)
        if resolved is not None:
            register(make(name, node, type_node, resolved))
        else:
            pending.append((name, type_node, node))

    # Chain pass: an alias whose target names an already-known container alias
    # inherits its family, with the alias's own first template argument as the key.
    for _ in range(4):  # bounded: resolves chains a few levels deep
        still: list[tuple[str, "Node", "Node"]] = []
        for name, type_node, node in pending:
            outer, args = _outermost_template(type_node, source)
            ref = by_name.get(outer) or by_name.get(outer.rsplit("::", 1)[-1])
            if ref is None:
                # a bare alias (`using X = KnownAlias;`) with no template args
                bare = "".join(cst.node_text(type_node, source).split()).lstrip(":")
                ref = by_name.get(bare) or by_name.get(bare.rsplit("::", 1)[-1])
            if ref is not None:
                register(
                    make(
                        name,
                        node,
                        type_node,
                        _ResolvedType(
                            kind=ref.kind,
                            spec=_CONTAINER_SPECS[ref.kind.rsplit("::", 1)[-1]],
                            key_type=(
                                args[0]
                                if args
                                and (
                                    not ref.key_type
                                    or _looks_like_type_param(ref.key_type)
                                )
                                else ref.key_type
                            ),
                            value_type=ref.value_type,
                            hasher_type=ref.hasher_type,
                        ),
                    )
                )
            else:
                still.append((name, type_node, node))
        if len(still) == len(pending):
            break  # no progress
        pending = still
    return aliases


# Types that are concrete (not a template parameter), so a template-alias's fixed
# key of this shape must NOT be overridden by the use-site's first template arg.
_PRIMITIVE_KEY_TYPES = frozenset(
    {
        "bool", "char", "wchar_t", "char8_t", "char16_t", "char32_t",
        "short", "int", "long", "unsigned", "signed", "float", "double", "void",
        "size_t", "ssize_t", "intptr_t", "uintptr_t", "ptrdiff_t",
        "int8_t", "int16_t", "int32_t", "int64_t",
        "uint8_t", "uint16_t", "uint32_t", "uint64_t",
        # bare string type names that projects alias without the ``std::`` prefix
        # (duckdb's ``using string = std::string`` etc.) — concrete keys, never a
        # template parameter to substitute a use-site arg into.
        "string", "wstring", "sstring", "u16string", "u32string",
        "string_view", "basic_string", "basic_string_view",
    }
)


def _looks_like_type_param(type_text: str | None) -> bool:
    """True when a type name is a bare identifier that looks like a template
    parameter (``T``, ``Key``, ``ValueT``) rather than a concrete type.

    A template alias ``using M = unordered_map<std::string, T, Hash>`` fixes the
    key as ``std::string`` while templating the *value* ``T``; at a use site
    ``M<Foo>`` the ``Foo`` must not replace the concrete ``std::string`` key. Only
    when the alias's key is itself a template parameter (a bare identifier) does
    the use-site argument substitute for it (e.g. ``using SMap =
    unordered_map<K, V>`` used as ``SMap<std::string>``)."""
    if not type_text:
        return False
    compact = "".join(type_text.split())
    if "::" in compact or "<" in compact or "*" in compact or "&" in compact:
        return False
    if compact in _PRIMITIVE_KEY_TYPES:
        return False
    return bool(re.fullmatch(r"[A-Za-z_]\w*", compact))


def _alias_candidates(type_text: str, scope: str | None) -> list[str]:
    clean = "".join(type_text.split()).lstrip(":")
    if "::" in clean:
        return [clean]
    scope_parts = scope.split("::") if scope else []
    return [
        "::".join([*scope_parts[:depth], clean])
        for depth in range(len(scope_parts), -1, -1)
    ]


def _from_alias(
    alias: TypeAliasFact, key_override: str | None
) -> _ResolvedType | None:
    spec = _CONTAINER_SPECS.get(alias.kind.rsplit("::", 1)[-1])
    if spec is None:
        return None
    return _ResolvedType(
        kind=alias.kind,
        spec=spec,
        key_type=key_override or alias.key_type,
        value_type=alias.value_type,
        hasher_type=alias.hasher_type,
    )


def _resolve_type(
    type_node: "Node",
    source: bytes,
    aliases: Iterable[TypeAliasFact],
    scope: str | None,
) -> _ResolvedType | None:
    direct = _template_info(type_node, source)
    if direct is not None:
        return direct
    alias_list = list(aliases)
    by_name = {alias.qualified_name: alias for alias in alias_list}
    type_text = cst.node_text(type_node, source).strip()
    for candidate in _alias_candidates(type_text, scope):
        alias = by_name.get(candidate)
        if alias is not None:
            return _from_alias(alias, None)
    # A template-alias instantiation used directly (``MultiMap<std::string> h``):
    # resolve the base alias and substitute the concrete first template argument.
    base, args = _outermost_template(type_node, source)
    if base:
        by_terminal: dict[str, TypeAliasFact] = {}
        for alias in alias_list:
            by_terminal.setdefault(alias.qualified_name, alias)
            by_terminal.setdefault(alias.qualified_name.rsplit("::", 1)[-1], alias)
        for candidate in _alias_candidates(base, scope):
            alias = by_terminal.get(candidate) or by_terminal.get(
                candidate.rsplit("::", 1)[-1]
            )
            if alias is not None:
                key_override = (
                    args[0]
                    if args
                    and (not alias.key_type or _looks_like_type_param(alias.key_type))
                    else None
                )
                return _from_alias(alias, key_override)
    return None


def _containers_from_declaration(
    declaration: "Node",
    source: bytes,
    aliases: Iterable[TypeAliasFact],
    storage: str,
) -> list[HashContainerFact]:
    type_node = declaration.child_by_field_name("type")
    if type_node is None:
        return []
    scope = _scope_name(declaration, source)
    resolved = _resolve_type(type_node, source, aliases, scope)
    if resolved is None:
        return []
    actual_storage = storage
    if storage == "local" and any(
        child.type == "storage_class_specifier"
        and cst.node_text(child, source).strip() == "static"
        for child in declaration.children
    ):
        actual_storage = "static-local"
    facts: list[HashContainerFact] = []
    for declarator in declaration.children_by_field_name("declarator"):
        name = cst.declarator_name(declarator, source)
        if not name:
            continue
        facts.append(
            HashContainerFact(
                name=name,
                kind=resolved.kind,
                type_text=cst.node_text(type_node, source).strip(),
                key_type=resolved.key_type,
                value_type=resolved.value_type,
                hasher_type=resolved.hasher_type,
                line=cst.line_of(declaration),
                byte=declarator.start_byte,
                storage=actual_storage,
                scope=scope,
            )
        )
    return facts


def find_hash_containers(
    node: "Node",
    source: bytes,
    aliases: Iterable[TypeAliasFact] = (),
) -> list[HashContainerFact]:
    """Find hash containers declared locally below node."""
    facts: list[HashContainerFact] = []
    for declaration in cst.walk(node, "declaration"):
        facts.extend(
            _containers_from_declaration(
                declaration, source, aliases, storage="local"
            )
        )
    return facts


def build_translation_unit_index(
    root: "Node",
    source: bytes,
    extra_aliases: Iterable[TypeAliasFact] = (),
) -> HashTranslationUnitIndex:
    """Index aliases, global containers, and class/struct container fields.

    ``extra_aliases`` supplies aliases declared in *other* files of the same scan
    (the tool scans files independently and does not follow ``#include``), so a
    container whose type is a ``using``/``typedef`` defined in a header — e.g.
    ``using ci_map = std::unordered_multimap<...>`` in one header, used as a field
    ``ci_map headers;`` in another — is still resolved to a hash container.
    """
    aliases = (
        *extra_aliases,
        *find_type_aliases(
            root, source, include_local=False, extra_aliases=extra_aliases
        ),
    )
    containers: list[HashContainerFact] = []
    for declaration in cst.walk(root, "declaration"):
        if _inside(declaration, "function_definition"):
            continue
        containers.extend(
            _containers_from_declaration(
                declaration, source, aliases, storage="global"
            )
        )
    for field in cst.walk(root, "field_declaration"):
        containers.extend(
            _containers_from_declaration(field, source, aliases, storage="member")
        )
    return HashTranslationUnitIndex(tuple(aliases), tuple(containers))


def _function_scope(function: query.Function, source: bytes) -> str | None:
    qualified = function.qualified_name or function.name
    if "::" in qualified:
        return qualified.rsplit("::", 1)[0]
    return _scope_name(function.node, source)


def _scope_is_visible(container_scope: str | None, function_scope: str | None) -> bool:
    if container_scope is None:
        return True
    if function_scope is None:
        return False
    container_parts = container_scope.split("::")
    function_parts = function_scope.split("::")
    return function_parts[: len(container_parts)] == container_parts


def _same_class_scope(container_scope: str | None, function_scope: str | None) -> bool:
    """Whether a member container's class matches a method's class, tolerant of
    namespace-qualification differences between a header and its .cpp.

    ``served::request`` (field in request.hpp) matches ``request`` or
    ``served::request`` (``request::set_header`` defined in request.cpp). Requires
    a suffix relationship so an unrelated same-named class elsewhere is not pulled
    in wholesale — the member name must still match at the operation site."""
    if not container_scope or not function_scope:
        return False
    if container_scope == function_scope:
        return True
    cp = container_scope.split("::")
    fp = function_scope.split("::")
    if cp[-1] != fp[-1]:
        return False
    shorter, longer = (cp, fp) if len(cp) <= len(fp) else (fp, cp)
    return longer[-len(shorter):] == shorter


def containers_for_function(
    function: query.Function,
    source: bytes,
    index: HashTranslationUnitIndex,
    extra_containers: Iterable[HashContainerFact] = (),
) -> list[HashContainerFact]:
    """Return visible global/member containers followed by local containers.

    ``extra_containers`` supplies member/global containers pooled from *other*
    files of the scan, so a container declared as a class field in a header
    (``header_list _headers;``) is visible to a method that operates on it in a
    separate .cpp (``request::set_header`` doing ``_headers[h] = v``) — the
    single most common reason a real finding in a non-header-only library was
    missed (the tool does not expand ``#include``)."""
    function_scope = _function_scope(function, source)
    visible: list[HashContainerFact] = []
    for container in index.containers:
        if container.storage == "member" and container.scope == function_scope:
            visible.append(container)
        elif container.storage == "global" and _scope_is_visible(
            container.scope, function_scope
        ):
            visible.append(container)
    # Project-wide member/global containers declared in another file (e.g. a
    # header). Dedupe against what the local index already provided.
    seen = {(c.storage, c.scope, c.name) for c in visible}
    for container in extra_containers:
        key = (container.storage, container.scope, container.name)
        if key in seen:
            continue
        if container.storage == "member" and _same_class_scope(
            container.scope, function_scope
        ):
            visible.append(container)
            seen.add(key)
        elif container.storage == "global" and _scope_is_visible(
            container.scope, function_scope
        ):
            visible.append(container)
            seen.add(key)
    local_aliases = find_type_aliases(function.node, source)
    visible.extend(
        find_hash_containers(
            function.body_node,
            source,
            aliases=(*index.aliases, *local_aliases),
        )
    )
    return visible


def _argument_nodes(call: query.Call) -> list["Node"]:
    arguments = call.node.child_by_field_name("arguments")
    return list(arguments.named_children) if arguments is not None else []


def _insert_key(node: "Node", source: bytes, family: str) -> str:
    if family == "map" and node.type == "initializer_list":
        elements = list(node.named_children)
        if elements:
            return cst.node_text(elements[0], source)
    return cst.node_text(node, source)


def resolve_container(
    receiver: str, containers: list[HashContainerFact]
) -> HashContainerFact | None:
    text = receiver.strip()
    if text.startswith("this->"):
        name = text[6:].strip()
        return next(
            (
                container
                for container in reversed(containers)
                if container.storage == "member" and container.name == name
            ),
            None,
        )
    if "::" in text:
        qualified = text.lstrip(":")
        return next(
            (
                container
                for container in reversed(containers)
                if container.qualified_name == qualified
            ),
            None,
        )
    priority = {"global": 1, "member": 2, "local": 3, "static-local": 3}
    matches = [container for container in containers if container.name == text]
    return max(matches, key=lambda item: priority[item.storage], default=None)


def find_hash_operations(
    node: "Node",
    source: bytes,
    containers: list[HashContainerFact],
) -> list[HashOperationFact]:
    """Find key-based operations and bind each receiver to a visible container."""
    out: list[HashOperationFact] = []

    for call in query.find_calls(node, source):
        container = resolve_container(call.receiver or "", containers)
        if container is None:
            continue
        terminal = container.kind.rsplit("::", 1)[-1]
        spec = _CONTAINER_SPECS.get(terminal)
        if spec is None:
            continue
        args = _argument_nodes(call)
        category: str
        may_grow: bool
        key_index: int
        if call.name == "insert":
            if len(args) != 1:
                continue
            category, may_grow, key_index = "insert", True, 0
        else:
            method = _METHODS.get(call.name)
            if method is None:
                continue
            category, may_grow, key_index = method
        if len(args) <= key_index:
            continue
        key_node = args[key_index]
        out.append(
            HashOperationFact(
                container=container.qualified_name,
                operation=call.name,
                category=category,
                key_expr=_insert_key(key_node, source, spec.family),
                may_grow=may_grow,
                line=call.line,
                byte=call.node.start_byte,
                container_byte=container.byte,
                end_byte=call.node.end_byte,
            )
        )

    for access in query.find_mem_accesses(node, source):
        if access.index is None:
            continue
        container = resolve_container(access.base, containers)
        if container is None:
            continue
        terminal = container.kind.rsplit("::", 1)[-1]
        spec = _CONTAINER_SPECS.get(terminal)
        if spec is None or spec.family != "map":
            continue
        out.append(
            HashOperationFact(
                container=container.qualified_name,
                operation="operator[]",
                category="insert",
                key_expr=access.index,
                may_grow=True,
                line=access.line,
                byte=access.node.start_byte,
                container_byte=container.byte,
                end_byte=access.node.end_byte,
            )
        )

    out.sort(key=lambda fact: (fact.byte, fact.operation))
    return out


__all__ = [
    "HashTranslationUnitIndex",
    "build_translation_unit_index",
    "containers_for_function",
    "find_hash_containers",
    "find_hash_operations",
    "find_type_aliases",
    "resolve_container",
]
