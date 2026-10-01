"""Configurable external-input source rules."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class InputSourceRule:
    """Describe where one API exposes externally controlled data."""

    name: str
    output: str
    kind: str
    argument_index: int | None = None

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("source rule name must not be empty")
        if self.output not in ("argument", "return"):
            raise ValueError(
                f"source rule {self.name!r}: output must be 'argument' or 'return'"
            )
        if self.output == "argument" and (
            self.argument_index is None or self.argument_index < 0
        ):
            raise ValueError(
                f"source rule {self.name!r}: a non-negative argument_index is required"
            )


@dataclass(frozen=True)
class SourceRules:
    sources: tuple[InputSourceRule, ...]

    def matching(self, name: str) -> tuple[InputSourceRule, ...]:
        spellings = {name, name.lstrip("_")}
        return tuple(rule for rule in self.sources if rule.name in spellings)


DEFAULT_SOURCE_RULES = SourceRules(
    (
        InputSourceRule("recv", "argument", "network", 1),
        InputSourceRule("recvfrom", "argument", "network", 1),
        InputSourceRule("SSL_read", "argument", "network", 1),
        InputSourceRule("SSL_read_ex", "argument", "network", 1),
        InputSourceRule("evbuffer_remove", "argument", "network", 1),
        InputSourceRule("read", "argument", "stream", 1),
        InputSourceRule("pread", "argument", "stream", 1),
        InputSourceRule("BIO_read", "argument", "stream", 1),
        InputSourceRule("fread", "argument", "stream", 0),
        InputSourceRule("fgets", "argument", "stream", 0),
        InputSourceRule("getline", "argument", "stream", 1),
        InputSourceRule("getdelim", "argument", "stream", 0),
        InputSourceRule("getenv", "return", "environment"),
    )
)


def _rule_from_dict(value: object, index: int) -> InputSourceRule:
    if not isinstance(value, dict):
        raise ValueError(f"sources[{index}] must be an object")
    allowed = {"name", "output", "kind", "argument_index"}
    unknown = set(value) - allowed
    if unknown:
        raise ValueError(
            f"sources[{index}] has unknown fields: {', '.join(sorted(unknown))}"
        )
    name = value.get("name")
    output = value.get("output")
    kind = value.get("kind")
    argument_index = value.get("argument_index")
    if not isinstance(name, str) or not isinstance(output, str):
        raise ValueError(f"sources[{index}]: name and output must be strings")
    if not isinstance(kind, str) or not kind:
        raise ValueError(f"sources[{index}]: kind must be a non-empty string")
    if argument_index is not None and not isinstance(argument_index, int):
        raise ValueError(f"sources[{index}]: argument_index must be an integer")
    return InputSourceRule(name, output, kind, argument_index)


def load_source_rules(path: str | Path | None = None) -> SourceRules:
    """Load custom rules, augmenting defaults unless replace_defaults is true."""
    if path is None:
        return DEFAULT_SOURCE_RULES
    rule_path = Path(path).expanduser()
    try:
        data = json.loads(rule_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"source rules are not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("the top level of a source-rules file must be an object")
    unknown = set(data) - {"replace_defaults", "sources"}
    if unknown:
        raise ValueError(f"source-rules file has unknown fields: {', '.join(sorted(unknown))}")
    values = data.get("sources")
    if not isinstance(values, list):
        raise ValueError("source-rules file must contain a sources array")
    replace_defaults = data.get("replace_defaults", False)
    if not isinstance(replace_defaults, bool):
        raise ValueError("replace_defaults must be a boolean")
    custom = tuple(_rule_from_dict(value, i) for i, value in enumerate(values))
    base = () if replace_defaults else DEFAULT_SOURCE_RULES.sources
    merged: dict[tuple[str, str, int | None], InputSourceRule] = {}
    for rule in (*base, *custom):
        merged[(rule.name, rule.output, rule.argument_index)] = rule
    return SourceRules(tuple(merged.values()))


__all__ = [
    "DEFAULT_SOURCE_RULES",
    "InputSourceRule",
    "SourceRules",
    "load_source_rules",
]
