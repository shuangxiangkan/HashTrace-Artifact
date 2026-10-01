"""Static risk analysis for C++ hash functors used by unordered containers."""

from __future__ import annotations

import re
import math
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Iterable

from code_scan import cst

from .model import HashContainerFact, HasherRiskFact

if TYPE_CHECKING:
    from tree_sitter import Node


_TYPE_NODES = {"class_specifier", "struct_specifier"}
_SCOPE_NODES = {"namespace_definition", *_TYPE_NODES}
_SEED_NAME = re.compile(
    r"(?:seed|salt|secret|fixed_?random|hash_?key)", re.IGNORECASE
)
_SECURE_RANDOM = (
    "random_device",
    "getrandom",
    "getentropy",
    "RAND_bytes",
    "arc4random",
    "BCryptGenRandom",
    "CCRandomGenerateBytes",
)
_OUTPUT_RANDOM = {
    "getrandom",
    "getentropy",
    "RAND_bytes",
    "BCryptGenRandom",
    "CCRandomGenerateBytes",
}
_RUNTIME_RANDOM = ("rand", "random", "time", "clock")
# Matches a CSPRNG or a common secure-random *wrapper* name as a word, so a hasher
# seeded from ``secureRandomBytes()`` / ``generate_random_key()`` / a
# ``std::random_device`` (even one declared in another scope) is recognised as
# randomized rather than weak/deterministic.
_SECURE_RANDOM_WORD_RE = re.compile(
    r"(?<![\w])(?:"
    + "|".join(re.escape(a) for a in _SECURE_RANDOM)
    + r"|RAND_priv_bytes|arc4random\w*|secure_?random\w*|generate_?random\w*"
    + r"|gen_?random\w*|random_?bytes|random_?key|random_?alphanum)(?![\w])",
    re.IGNORECASE,
)
_RISK_PRIORITY = {
    "weak": 6,
    "fixed-seed": 5,
    "deterministic": 4,
    "unknown": 3,
    "runtime-seeded": 2,
    "randomized": 1,
    "default": 0,
}
_TYPE_WIDTHS = {
    "bool": 1,
    "char": 8,
    "signed char": 8,
    "unsigned char": 8,
    "int8_t": 8,
    "uint8_t": 8,
    "short": 16,
    "unsigned short": 16,
    "int16_t": 16,
    "uint16_t": 16,
    "int": 32,
    "unsigned": 32,
    "unsigned int": 32,
    "int32_t": 32,
    "uint32_t": 32,
}
_CPP_INTEGER = re.compile(r"^(?:0[xX][0-9a-fA-F]+|\d+)[uUlL]*$")
# A user-provided ``std::hash`` specialization, e.g. ``std::hash<oatpp::...Key>``.
_STD_HASH_SPEC_RE = re.compile(r"^(?:std::)?hash<(.+)>$")


def _type_terminal(type_name: str) -> str:
    """Last path/template component of a type name, normalized for matching.

    ``oatpp::data::share::StringKeyLabel const&`` -> ``StringKeyLabel``.
    """
    compact = "".join(type_name.replace("const", "").split()).strip("&*:")
    compact = compact.split("<", 1)[0]
    return compact.rsplit("::", 1)[-1]


@dataclass(frozen=True)
class HasherIndex:
    """Hasher definitions visible across the files in one scan."""

    definitions: tuple[HasherRiskFact, ...] = ()

    def _std_specialization(self, key_type: str | None) -> HasherRiskFact | None:
        """A user-provided ``std::hash<KeyType>`` specialization, if one exists.

        A container with an *implicit* hasher over a custom key type (e.g. oatpp's
        ``unordered_map<StringKeyLabel, ...>``) does not use the standard default
        hash — it uses the project's own ``std::hash<StringKeyLabel>`` with a fixed
        polynomial. Recognising the specialization reclassifies such a container
        from (wrong) ``default`` to its real risk (deterministic/fixed-seed)."""
        if not key_type:
            return None
        target = _type_terminal(key_type)
        best: HasherRiskFact | None = None
        for fact in self.definitions:
            name = "".join((fact.definition or "").split()).lstrip(":")
            match = _STD_HASH_SPEC_RE.match(name)
            if match is None or _type_terminal(match.group(1)) != target:
                continue
            if best is None or _RISK_PRIORITY[fact.risk] > _RISK_PRIORITY[best.risk]:
                best = fact
        return best

    def resolve(
        self, hasher_type: str | None, key_type: str | None, scope: str | None
    ) -> HasherRiskFact:
        if hasher_type is None or _is_std_hash(hasher_type):
            specialization = self._std_specialization(key_type)
            if specialization is not None:
                return replace(
                    specialization,
                    hasher_type=hasher_type or f"std::hash<{key_type or '?'}>",
                )
            rendered = hasher_type or f"std::hash<{key_type or '?'}>"
            return HasherRiskFact(
                hasher_type=rendered,
                kind="default",
                risk="default",
                score_adjustment=0.0,
                evidence=(
                    "container uses the standard default hash; no explicit "
                    "per-container seed is visible",
                ),
            )

        candidates = _type_candidates(hasher_type, scope)
        by_name: dict[str, list[HasherRiskFact]] = {}
        for fact in self.definitions:
            name = _normal_type_name(fact.definition or fact.hasher_type)
            by_name.setdefault(name, []).append(fact)
        for candidate in candidates:
            matches = by_name.get(candidate, [])
            if matches:
                match = max(matches, key=lambda fact: _RISK_PRIORITY[fact.risk])
                return replace(match, hasher_type=hasher_type)

        terminal = _normal_type_name(hasher_type).rsplit("::", 1)[-1]
        matches = [
            fact
            for fact in self.definitions
            if _normal_type_name(fact.definition or fact.hasher_type).rsplit(
                "::", 1
            )[-1]
            == terminal
        ]
        if matches:
            match = max(matches, key=lambda fact: _RISK_PRIORITY[fact.risk])
            return replace(match, hasher_type=hasher_type)
        return HasherRiskFact(
            hasher_type=hasher_type,
            kind="custom",
            risk="unknown",
            score_adjustment=0.0,
            evidence=(
                f"custom hasher {hasher_type} has no operator() definition in "
                "the scanned sources",
            ),
        )


@dataclass(frozen=True)
class _Initializer:
    name: str
    node: "Node"
    line: int


def _nearest_type(node: "Node") -> "Node | None":
    current = node.parent
    while current is not None:
        if current.type in _TYPE_NODES:
            return current
        current = current.parent
    return None


def _scope_parts(node: "Node", source: bytes) -> list[str]:
    parts: list[str] = []
    current = node.parent
    while current is not None:
        if current.type in _SCOPE_NODES:
            name = current.child_by_field_name("name")
            if name is not None:
                parts.append(cst.node_text(name, source))
        current = current.parent
    parts.reverse()
    return parts


def _qualified_type(specifier: "Node", source: bytes) -> str | None:
    name = specifier.child_by_field_name("name")
    if name is None:
        return None
    return "::".join([*_scope_parts(specifier, source), cst.node_text(name, source)])


def _normal_type_name(type_name: str) -> str:
    compact = "".join(type_name.split()).lstrip(":")
    return compact.split("<", 1)[0]


def _type_candidates(type_name: str, scope: str | None) -> list[str]:
    clean = _normal_type_name(type_name)
    if "::" in clean:
        return [clean]
    parts = scope.split("::") if scope else []
    return [
        "::".join([*parts[:depth], clean])
        for depth in range(len(parts), -1, -1)
    ]


def _is_std_hash(type_name: str) -> bool:
    compact = "".join(type_name.split()).lstrip(":")
    return compact == "std::hash" or compact.startswith("std::hash<")


def _operator_name(function: "Node", source: bytes) -> "Node | None":
    declarator = function.child_by_field_name("declarator")
    if declarator is None:
        return None
    return next(
        (
            node
            for node in cst.walk(declarator, "operator_name")
            if cst.node_text(node, source) == "operator()"
        ),
        None,
    )


def _operator_owner(function: "Node", source: bytes) -> str | None:
    specifier = _nearest_type(function)
    if specifier is not None:
        return _qualified_type(specifier, source)
    declarator = function.child_by_field_name("declarator")
    if declarator is None:
        return None
    text = cst.node_text(declarator, source)
    marker = text.find("operator")
    if marker < 0:
        return None
    owner = text[:marker].rstrip(" :\t*&")
    if not owner:
        return None
    if "::" in owner:
        return owner.lstrip(":")
    return "::".join([*_scope_parts(function, source), owner])


def _function_declarator(function: "Node") -> "Node | None":
    declarator = function.child_by_field_name("declarator")
    if declarator is None:
        return None
    return next(cst.walk(declarator, "function_declarator"), None)


def _parameter_names(function: "Node", source: bytes) -> set[str]:
    declarator = _function_declarator(function)
    parameters = (
        declarator.child_by_field_name("parameters")
        if declarator is not None
        else None
    )
    if parameters is None:
        return set()
    names: set[str] = set()
    for parameter in cst.walk(parameters, "parameter_declaration"):
        declarator_node = parameter.child_by_field_name("declarator")
        if declarator_node is None:
            continue
        name = cst.declarator_name(declarator_node, source)
        if name:
            names.add(name)
    return names


def _identifiers(node: "Node") -> set[str]:
    return {
        child.text.decode("utf-8", errors="replace")
        for child in cst.find_nodes(node, "identifier", "field_identifier")
    }


def _return_expressions(body: "Node") -> list["Node"]:
    expressions: list["Node"] = []
    for statement in cst.walk(body, "return_statement"):
        expression = next(
            (
                child
                for child in statement.named_children
                if child.type != "comment"
            ),
            None,
        )
        if expression is not None:
            expressions.append(expression)
    return expressions


def _is_constant_expression(node: "Node") -> bool:
    forbidden = {"identifier", "field_identifier", "call_expression"}
    if any(child.type in forbidden for child in cst.walk(node)):
        return False
    return any(
        child.type in {"number_literal", "char_literal", "true", "false", "null"}
        for child in cst.walk(node)
    )


def _integer_value(text: str) -> int | None:
    clean = text.strip()
    if not _CPP_INTEGER.fullmatch(clean):
        return None
    try:
        return int(re.sub(r"[uUlL]+$", "", clean), 0)
    except ValueError:
        return None


def _type_width(type_text: str) -> int | None:
    clean = " ".join(type_text.replace("const", "").split())
    direct = _TYPE_WIDTHS.get(clean)
    if direct is not None:
        return direct
    match = re.search(r"\b(?:u?int)(8|16|32)_t\b", clean)
    return int(match.group(1)) if match else None


def _outermost_value(node: "Node") -> "Node":
    """Strip enclosing parentheses to the single value node they wrap."""
    current = node
    while current.type == "parenthesized_expression":
        inner = [
            child for child in current.named_children if child.type != "comment"
        ]
        if len(inner) != 1:
            break
        current = inner[0]
    return current


def _collision_shape(
    operators: list["Node"], returns: list["Node"], source: bytes
) -> tuple[str | None, int | None]:
    shapes: list[tuple[int, str]] = []
    # Only a narrow return type (<=16 bits) genuinely restricts the output
    # domain. A uint32_t/size_t return is the hash's natural width, not a
    # collision-enabling restriction, so it is not counted as evidence.
    for function in operators:
        type_node = function.child_by_field_name("type")
        if type_node is not None:
            width = _type_width(cst.node_text(type_node, source))
            if width is not None and width <= 16:
                shapes.append((width, f"{width}-bit return type"))

    # A mask/modulo/cast only bounds the returned value's width when it is the
    # OUTERMOST operation producing that value. A masked or truncated
    # sub-expression (e.g. ``(k.a & 0xFF) | (k.b << 16)``) does not constrain the
    # final output, so walking the whole return subtree would over-report.
    for expression in returns:
        top = _outermost_value(expression)
        if top.type == "binary_expression":
            operator = top.child_by_field_name("operator")
            left = top.child_by_field_name("left")
            right = top.child_by_field_name("right")
            if operator is None or left is None or right is None:
                continue
            op = cst.node_text(operator, source)
            left_value = _integer_value(cst.node_text(left, source))
            right_value = _integer_value(cst.node_text(right, source))
            if op == "%" and right_value is not None and right_value > 0:
                bits = max(0, math.ceil(math.log2(right_value)))
                shapes.append((bits, f"modulo {right_value}"))
            elif op == "&":
                mask = right_value if right_value is not None else left_value
                if mask is not None and mask >= 0:
                    shapes.append((mask.bit_count(), f"bit mask {hex(mask)}"))
        elif top.type == "cast_expression":
            type_node = top.child_by_field_name("type")
            if type_node is not None:
                width = _type_width(cst.node_text(type_node, source))
                if width is not None:
                    shapes.append((width, f"cast to {width}-bit integer"))
        else:
            # C++ named casts (static_cast<T>(...)) parse as a call-like node;
            # anchor the match at the start so only a top-level cast counts.
            match = re.match(
                r"\s*static_cast\s*<\s*([^>]+?)\s*>", cst.node_text(top, source)
            )
            if match:
                width = _type_width(match.group(1))
                if width is not None:
                    shapes.append((width, f"cast to {width}-bit integer"))

    if shapes:
        bits, pattern = min(shapes, key=lambda item: item[0])
        return pattern, bits
    if returns and all(
        re.search(r"\.(?:size|length)\s*\(\s*\)", cst.node_text(expr, source))
        for expr in returns
    ):
        return "key length only", None
    return None, None


def _field_names(specifier: "Node | None", source: bytes) -> set[str]:
    if specifier is None:
        return set()
    names: set[str] = set()
    for declaration in cst.walk(specifier, "field_declaration"):
        if _nearest_type(declaration) != specifier:
            continue
        for declarator in declaration.children_by_field_name("declarator"):
            name = cst.declarator_name(declarator, source)
            if name:
                names.add(name)
    return names


def _plain_assigned_name(node: "Node", source: bytes) -> str | None:
    text = cst.node_text(node, source).strip()
    text = text.rsplit("->", 1)[-1].rsplit(".", 1)[-1]
    return text if re.fullmatch(r"[A-Za-z_]\w*", text) else None


def _initializers(
    specifier: "Node | None",
    operators: list["Node"],
    source: bytes,
) -> list[_Initializer]:
    out: list[_Initializer] = []
    if specifier is not None:
        for declaration in cst.walk(specifier, "field_declaration"):
            if _nearest_type(declaration) != specifier:
                continue
            value = declaration.child_by_field_name("default_value")
            if value is None:
                continue
            for declarator in declaration.children_by_field_name("declarator"):
                name = cst.declarator_name(declarator, source)
                if name:
                    out.append(_Initializer(name, value, cst.line_of(declaration)))
        for initializer in cst.walk(specifier, "field_initializer"):
            if _nearest_type(initializer) != specifier:
                continue
            children = [
                child for child in initializer.named_children if child.type != "comment"
            ]
            if len(children) < 2:
                continue
            name = cst.declarator_name(children[0], source)
            if name:
                out.append(_Initializer(name, children[1], cst.line_of(initializer)))
        assignment_roots = [specifier]
    else:
        assignment_roots = []

    for root in [*assignment_roots, *operators]:
        for assignment in cst.walk(root, "assignment_expression"):
            if root == specifier and _nearest_type(assignment) != specifier:
                continue
            left = assignment.child_by_field_name("left")
            right = assignment.child_by_field_name("right")
            if left is None or right is None:
                continue
            name = _plain_assigned_name(left, source)
            if name:
                out.append(_Initializer(name, right, cst.line_of(assignment)))
        for declaration in cst.walk(root, "init_declarator"):
            if root == specifier and _nearest_type(declaration) != specifier:
                continue
            declarator = declaration.child_by_field_name("declarator")
            value = declaration.child_by_field_name("value")
            if declarator is None or value is None:
                continue
            name = cst.declarator_name(declarator, source)
            if name:
                out.append(_Initializer(name, value, cst.line_of(declaration)))

    unique: dict[tuple[str, int], _Initializer] = {}
    for initializer in out:
        unique[(initializer.name, initializer.node.start_byte)] = initializer
    return list(unique.values())


def _contains_api(text: str, names: Iterable[str]) -> str | None:
    for name in names:
        if re.search(rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])", text):
            return name
    return None


def _random_generator_names(
    specifier: "Node | None", operators: list["Node"], source: bytes
) -> set[str]:
    names: set[str] = set()
    roots = [*([specifier] if specifier is not None else []), *operators]
    for root in roots:
        for declaration in cst.walk(root):
            if declaration.type not in {"declaration", "field_declaration"}:
                continue
            if root == specifier and _nearest_type(declaration) != specifier:
                continue
            type_node = declaration.child_by_field_name("type")
            if type_node is None or "random_device" not in cst.node_text(
                type_node, source
            ):
                continue
            for declarator in declaration.children_by_field_name("declarator"):
                name = cst.declarator_name(declarator, source)
                if name:
                    names.add(name)
    return names


def _initializer_kind(
    node: "Node", source: bytes, random_generators: set[str]
) -> tuple[str, str] | None:
    text = cst.node_text(node, source)
    secure = _contains_api(text, _SECURE_RANDOM)
    if secure:
        return "secure", secure
    for generator in random_generators:
        if re.search(rf"\b{re.escape(generator)}\s*\(", text):
            return "secure", f"std::random_device variable {generator}"
    if "chrono" in text and re.search(r"\bnow\s*\(", text):
        return "runtime", "chrono::...::now"
    runtime = _contains_api(text, _RUNTIME_RANDOM)
    if runtime and re.search(rf"\b{re.escape(runtime)}\s*\(", text):
        return "runtime", runtime
    if _is_constant_expression(node):
        return "fixed", text.strip()
    return None


def _randomized_seed_names(root: "Node", source: bytes) -> set[str]:
    """Names of variables whose initializer draws from a secure random source.

    Covers the cross-scope case the field-level analysis misses: a hasher that
    mixes a per-process random seed *defined elsewhere* — e.g. drogon's
    ``const size_t fixedRandomNumber = [](){ secureRandomBytes(...); }()`` or
    lithium's ``static const std::string siphashkey = generate_random_key(16)``
    (where ``generate_random_key`` itself uses ``std::random_device``). Without
    this such hashers are mis-reported as deterministic/weak (false positive).
    """
    # Functions whose body uses a secure RNG (so a seed initialised by calling
    # them is itself randomized).
    random_funcs: set[str] = set()
    for function in cst.walk(root, "function_definition"):
        body = function.child_by_field_name("body")
        if body is None or not _SECURE_RANDOM_WORD_RE.search(cst.node_text(body, source)):
            continue
        declarator = _function_declarator(function)
        name_node = (
            declarator.child_by_field_name("declarator")
            if declarator is not None
            else None
        )
        name = cst.declarator_name(name_node, source) if name_node is not None else None
        if name:
            random_funcs.add(name)
    func_call_re = (
        re.compile(
            r"(?<![\w])(?:"
            + "|".join(re.escape(f) for f in random_funcs)
            + r")\s*\("
        )
        if random_funcs
        else None
    )

    names: set[str] = set()
    for declaration in cst.walk(root, "init_declarator"):
        value = declaration.child_by_field_name("value")
        declarator = declaration.child_by_field_name("declarator")
        if value is None or declarator is None:
            continue
        name = cst.declarator_name(declarator, source)
        if not name:
            continue
        value_text = cst.node_text(value, source)
        if _SECURE_RANDOM_WORD_RE.search(value_text) or (
            func_call_re is not None and func_call_re.search(value_text)
        ):
            names.add(name)
    return names


def _definition_fact(
    owner: str,
    operators: list["Node"],
    specifier: "Node | None",
    source: bytes,
    path: str | None,
    randomized_names: set[str] = frozenset(),
) -> HasherRiskFact:
    bodies = [
        body
        for function in operators
        if (body := function.child_by_field_name("body")) is not None
    ]
    parameters = set().union(
        *(_parameter_names(function, source) for function in operators)
    )
    used = set().union(*(_identifiers(body) for body in bodies)) if bodies else set()
    returns = [expression for body in bodies for expression in _return_expressions(body)]
    constant_returns = bool(returns) and all(
        _is_constant_expression(expression) for expression in returns
    )
    ignores_key = bool(parameters) and not bool(parameters & used)

    fields = _field_names(specifier, source)
    random_generators = _random_generator_names(specifier, operators, source)
    relevant_initializers = [
        initializer
        for initializer in _initializers(specifier, operators, source)
        if initializer.name in used
        and (initializer.name in fields or _SEED_NAME.search(initializer.name))
        and initializer.name not in parameters
    ]
    fixed_seed: list[_Initializer] = []
    secure_seed: list[tuple[_Initializer, str]] = []
    runtime_seed: list[tuple[_Initializer, str]] = []
    for initializer in relevant_initializers:
        kind = _initializer_kind(initializer.node, source, random_generators)
        if kind is None:
            continue
        category, detail = kind
        if category == "fixed" and _SEED_NAME.search(initializer.name):
            fixed_seed.append(initializer)
        elif category == "secure":
            secure_seed.append((initializer, detail))
        elif category == "runtime":
            runtime_seed.append((initializer, detail))

    roots = [*([specifier] if specifier is not None else []), *operators]
    for root in roots:
        for call in cst.walk(root, "call_expression"):
            if root == specifier and _nearest_type(call) != specifier:
                continue
            text = cst.node_text(call, source)
            api = _contains_api(text, _OUTPUT_RANDOM)
            if api is None:
                continue
            state_names = {
                name
                for name in _identifiers(call)
                if name in used
                and name not in parameters
                and (name in fields or _SEED_NAME.search(name))
            }
            for name in state_names:
                secure_seed.append(
                    (_Initializer(name, call, cst.line_of(call)), api)
                )

    # Randomized state reached from another scope: the hasher body mixes a
    # per-process random seed (name in ``randomized_names``) or calls a secure RNG
    # directly. This is the standard HashDoS defense — recognise it so a properly
    # protected hasher is not mis-reported as weak/deterministic.
    body_text = " ".join(cst.node_text(body, source) for body in bodies)
    random_refs = (used & randomized_names) - parameters
    if random_refs or _SECURE_RANDOM_WORD_RE.search(body_text):
        detail = (
            f"per-process random seed {', '.join(sorted(random_refs))}"
            if random_refs
            else "secure random source in hash body"
        )
        anchor = bodies[0] if bodies else operators[0]
        seed_name = next(iter(sorted(random_refs)), "hash state")
        secure_seed.append(
            (_Initializer(seed_name, anchor, cst.line_of(anchor)), detail)
        )

    constants = sorted(
        {
            cst.node_text(node, source)
            for body in bodies
            for node in cst.walk(body, "number_literal")
            if cst.node_text(node, source).lower().rstrip("ul") not in {"0", "1"}
        }
    )
    collision_pattern, output_bits = _collision_shape(operators, returns, source)
    definition_line = cst.line_of(specifier or operators[0])

    if constant_returns or ignores_key:
        reason = (
            "returns only compile-time constants"
            if constant_returns
            else "does not reference its key parameter"
        )
        risk, adjustment = "weak", 3.0
        evidence = (f"custom hasher {owner} {reason}",)
        collision_pattern = (
            "constant output" if constant_returns else "key-independent output"
        )
        output_bits = 0
    elif secure_seed:
        apis = ", ".join(sorted({detail for _, detail in secure_seed}))
        risk, adjustment = "randomized", -2.0
        evidence = (f"custom hasher {owner} seeds hash state from {apis}",)
    elif runtime_seed:
        apis = ", ".join(sorted({detail for _, detail in runtime_seed}))
        risk, adjustment = "runtime-seeded", -1.0
        evidence = (
            f"custom hasher {owner} varies hash state using predictable runtime "
            f"source(s): {apis}",
        )
    elif fixed_seed:
        rendered = ", ".join(
            f"{item.name}={cst.node_text(item.node, source).strip()}"
            for item in fixed_seed
        )
        risk, adjustment = "fixed-seed", 2.0
        evidence = (f"custom hasher {owner} uses fixed seed state: {rendered}",)
    else:
        risk, adjustment = "deterministic", 1.0
        detail = (
            f"; fixed numeric constants include {', '.join(constants[:4])}"
            if constants
            else ""
        )
        evidence = (
            f"custom hasher {owner} has no recognized per-process seed{detail}",
        )

    return HasherRiskFact(
        hasher_type=owner,
        kind="custom",
        risk=risk,
        score_adjustment=adjustment,
        evidence=evidence,
        definition=owner,
        line=definition_line,
        path=path,
        collision_pattern=collision_pattern,
        output_bits=output_bits,
    )


def build_hasher_index(
    root: "Node",
    source: bytes,
    *,
    path: str | None = None,
    extra_randomized_names: Iterable[str] = (),
) -> HasherIndex:
    """Index custom hash functors defined in one parsed C++ source buffer.

    ``extra_randomized_names`` supplies random-seed variable names collected from
    *other* files of the same scan (via :func:`collect_randomized_seed_names`), so
    a hasher whose per-process random seed is *defined in a different file* than
    its ``operator()`` (e.g. drogon's ``fixedRandomNumber`` in Utilities.cc) is
    still recognised as randomized rather than weak.
    """
    specifiers: dict[str, "Node"] = {}
    for specifier in cst.walk(root):
        if specifier.type not in _TYPE_NODES:
            continue
        qualified = _qualified_type(specifier, source)
        if qualified:
            specifiers[qualified] = specifier

    operators: dict[str, list["Node"]] = {}
    for function in cst.walk(root, "function_definition"):
        if _operator_name(function, source) is None:
            continue
        owner = _operator_owner(function, source)
        if owner:
            operators.setdefault(owner, []).append(function)

    randomized_names = _randomized_seed_names(root, source) | set(extra_randomized_names)
    definitions = [
        _definition_fact(
            owner,
            functions,
            specifiers.get(owner),
            source,
            path,
            randomized_names,
        )
        for owner, functions in operators.items()
    ]
    # Transparent std::hash-wrapper aliases (heterogeneous-lookup idiom): register
    # them as default-hash facts unless a real ``operator()`` of the same name was
    # found (a concrete definition always wins).
    for fact in _hash_delegating_aliases(root, source, path):
        if fact.hasher_type not in operators:
            definitions.append(fact)
    definitions.sort(key=lambda fact: (fact.definition or "", fact.line or 0))
    return HasherIndex(tuple(definitions))


_ALIAS_NODES = {"alias_declaration", "type_definition"}
# A type-alias RHS that names a hash container (not a hasher) — skip those.
_CONTAINER_HINT = (
    "unordered_",
    "flat_hash",
    "node_hash",
    "F14",
    "concurrent_hash",
    "map<",
    "set<",
    "vector<",
    "array<",
)


def _hash_delegating_aliases(
    root: "Node", source: bytes, path: str | None
) -> list[HasherRiskFact]:
    """Aliases that are transparent wrappers delegating entirely to ``std::hash``.

    The modern C++ heterogeneous-lookup idiom aliases a hasher to an overload set
    over ``std::hash`` (e.g. DarkflameServer's
    ``using transparent_string_hash = overload<std::hash<std::string>, ...>`` or a
    plain ``using H = std::hash<std::string>``). Such a hasher's collision
    behaviour is *identical* to the standard default hash, so it is neither a
    novel weakness nor an opaque ``unknown`` — classify it as ``default`` so the
    container is scored (and dynamically verified) as a std::hash container rather
    than being skipped as an un-analysable custom functor.
    """
    facts: list[HasherRiskFact] = []
    for node in cst.walk(root):
        if node.type not in _ALIAS_NODES:
            continue
        name_node = node.child_by_field_name("name")
        rhs = next(
            (
                child
                for child in node.named_children
                if child.type in {"type_descriptor", "template_type", "qualified_identifier"}
                and child is not name_node
            ),
            None,
        )
        if name_node is None or rhs is None:
            continue
        rhs_text = cst.node_text(rhs, source)
        compact = "".join(rhs_text.split())
        if "std::hash" not in compact:
            continue
        if any(hint in compact for hint in _CONTAINER_HINT):
            continue
        if _SEED_NAME.search(compact):
            continue
        qualified = "::".join(
            [*_scope_parts(node, source), cst.node_text(name_node, source)]
        )
        facts.append(
            HasherRiskFact(
                hasher_type=qualified,
                kind="default",
                risk="default",
                score_adjustment=0.0,
                evidence=(
                    f"{qualified} is a transparent wrapper delegating to "
                    "std::hash; its collision behaviour is identical to the "
                    "standard default hash",
                ),
                definition=qualified,
                line=cst.line_of(node),
                path=path,
            )
        )
    return facts


def collect_randomized_seed_names(root: "Node", source: bytes) -> set[str]:
    """Public wrapper: names seeded from a secure RNG in one parsed file (for the
    scanner to pool project-wide and feed back via ``extra_randomized_names``)."""
    return _randomized_seed_names(root, source)


def merge_hasher_indexes(indexes: Iterable[HasherIndex]) -> HasherIndex:
    definitions = [fact for index in indexes for fact in index.definitions]
    definitions.sort(
        key=lambda fact: (fact.definition or "", fact.path or "", fact.line or 0)
    )
    return HasherIndex(tuple(definitions))


def analyze_container_hasher(
    container: HashContainerFact, index: HasherIndex
) -> HasherRiskFact:
    return index.resolve(container.hasher_type, container.key_type, container.scope)


__all__ = [
    "HasherIndex",
    "analyze_container_hasher",
    "build_hasher_index",
    "collect_randomized_seed_names",
    "merge_hasher_indexes",
]
