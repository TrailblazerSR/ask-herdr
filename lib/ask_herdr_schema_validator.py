"""Dependency-free validation for the Machine Core JSON Schema subset.

The public seam deliberately returns only stable codes and RFC 6901 instance
pointers.  Caller values, schema fragments, regex failures, and exception text
never cross the boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
import re
from typing import Any, List, Mapping, Optional, Sequence, Tuple
from urllib.parse import unquote
import uuid


@dataclass(frozen=True, order=True)
class SchemaViolation:
    """One content-redacted schema violation."""

    pointer: str
    code: str


_SUPPORTED_KEYWORDS = frozenset(
    {
        "$comment",
        "$defs",
        "$id",
        "$ref",
        "$schema",
        "additionalProperties",
        "allOf",
        "anyOf",
        "const",
        "default",
        "dependentRequired",
        "deprecated",
        "description",
        "else",
        "enum",
        "examples",
        "format",
        "if",
        "items",
        "maxItems",
        "maxLength",
        "maxProperties",
        "maximum",
        "minItems",
        "minLength",
        "minProperties",
        "minimum",
        "not",
        "oneOf",
        "pattern",
        "properties",
        "readOnly",
        "required",
        "then",
        "title",
        "type",
        "uniqueItems",
        "writeOnly",
    }
)


def _json_equal(left: Any, right: Any) -> bool:
    if isinstance(left, bool) or isinstance(right, bool):
        return type(left) is type(right) and left == right
    if left is None or right is None:
        return left is None and right is None
    if isinstance(left, (int, float)) and isinstance(right, (int, float)):
        return left == right
    if type(left) is not type(right):
        return False
    if isinstance(left, list):
        return len(left) == len(right) and all(
            _json_equal(a, b) for a, b in zip(left, right)
        )
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(
            _json_equal(left[key], right[key]) for key in left
        )
    return left == right


def _is_number(instance: Any) -> bool:
    return (
        not isinstance(instance, bool)
        and isinstance(instance, (int, float))
        and (not isinstance(instance, float) or math.isfinite(instance))
    )


def _matches_type(instance: Any, type_name: str) -> bool:
    matchers = {
        "null": lambda value: value is None,
        "boolean": lambda value: isinstance(value, bool),
        "object": lambda value: isinstance(value, dict),
        "array": lambda value: isinstance(value, list),
        "string": lambda value: isinstance(value, str),
        "number": _is_number,
        "integer": lambda value: _is_number(value)
        and (isinstance(value, int) or value.is_integer()),
    }
    matcher = matchers.get(type_name)
    return matcher is not None and matcher(instance)


def _uuid_is_valid(value: str) -> bool:
    if re.fullmatch(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        value,
    ) is None:
        return False
    try:
        uuid.UUID(value)
    except (ValueError, AttributeError):
        return False
    return True


def _join_pointer(pointer: str, token: Any) -> str:
    escaped = str(token).replace("~", "~0").replace("/", "~1")
    return pointer + "/" + escaped


class _Validator:
    def __init__(self, root_schema: Any) -> None:
        self.root_schema = root_schema

    @staticmethod
    def _violation(pointer: str, code: str) -> List[SchemaViolation]:
        return [SchemaViolation(pointer, code)]

    def _resolve_ref(self, reference: Any) -> Optional[Any]:
        if not isinstance(reference, str) or not reference.startswith("#"):
            return None
        fragment = unquote(reference[1:])
        if fragment == "":
            return self.root_schema
        if not fragment.startswith("/"):
            return None
        current: Any = self.root_schema
        for encoded in fragment[1:].split("/"):
            if re.search(r"~(?:[^01]|$)", encoded):
                return None
            token = encoded.replace("~1", "/").replace("~0", "~")
            if isinstance(current, Mapping) and token in current:
                current = current[token]
            elif isinstance(current, list) and token.isdigit():
                index = int(token)
                if index >= len(current):
                    return None
                current = current[index]
            else:
                return None
        return current

    def evaluate(
        self, instance: Any, schema: Any, pointer: str, depth: int = 0
    ) -> List[SchemaViolation]:
        if depth > 256:
            return self._violation(pointer, "schema.depth")
        if schema is True:
            return []
        if schema is False:
            return self._violation(pointer, "schema.false_schema")
        if not isinstance(schema, Mapping):
            return self._violation(pointer, "schema.definition")

        violations: List[SchemaViolation] = []
        if set(schema) - _SUPPORTED_KEYWORDS:
            return self._violation(pointer, "schema.unsupported_keyword")

        if "$ref" in schema:
            resolved = self._resolve_ref(schema["$ref"])
            if resolved is None:
                return self._violation(pointer, "schema.ref")
            violations.extend(
                self.evaluate(instance, resolved, pointer, depth + 1)
            )
            schema = {key: value for key, value in schema.items() if key != "$ref"}

        if "oneOf" in schema:
            matching = sum(
                not self.evaluate(instance, branch, pointer, depth + 1)
                for branch in schema["oneOf"]
            )
            if matching != 1:
                violations.extend(self._violation(pointer, "schema.one_of"))

        if "anyOf" in schema and not any(
            not self.evaluate(instance, branch, pointer, depth + 1)
            for branch in schema["anyOf"]
        ):
            violations.extend(self._violation(pointer, "schema.any_of"))

        for branch in schema.get("allOf", []):
            violations.extend(
                self.evaluate(instance, branch, pointer, depth + 1)
            )

        if "not" in schema and not self.evaluate(
            instance, schema["not"], pointer, depth + 1
        ):
            violations.extend(self._violation(pointer, "schema.not"))

        if "if" in schema:
            condition_matches = not self.evaluate(
                instance, schema["if"], pointer, depth + 1
            )
            selected = "then" if condition_matches else "else"
            if selected in schema:
                violations.extend(
                    self.evaluate(
                        instance, schema[selected], pointer, depth + 1
                    )
                )

        if "type" in schema:
            expected = schema["type"]
            names: Sequence[str] = (
                expected if isinstance(expected, list) else [expected]
            )
            if not any(_matches_type(instance, name) for name in names):
                violations.extend(self._violation(pointer, "schema.type"))

        if "const" in schema and not _json_equal(instance, schema["const"]):
            violations.extend(self._violation(pointer, "schema.const"))

        if "enum" in schema and not any(
            _json_equal(instance, candidate) for candidate in schema["enum"]
        ):
            violations.extend(self._violation(pointer, "schema.enum"))

        if isinstance(instance, str):
            if "minLength" in schema and len(instance) < schema["minLength"]:
                violations.extend(
                    self._violation(pointer, "schema.min_length")
                )
            if "maxLength" in schema and len(instance) > schema["maxLength"]:
                violations.extend(
                    self._violation(pointer, "schema.max_length")
                )
            if "pattern" in schema:
                try:
                    matched = re.search(schema["pattern"], instance) is not None
                except (re.error, TypeError):
                    return self._violation(pointer, "schema.definition")
                if not matched:
                    violations.extend(
                        self._violation(pointer, "schema.pattern")
                    )
            if "format" in schema:
                if schema["format"] != "uuid":
                    violations.extend(
                        self._violation(pointer, "schema.unsupported_format")
                    )
                elif not _uuid_is_valid(instance):
                    violations.extend(
                        self._violation(pointer, "schema.format.uuid")
                    )

        if _is_number(instance):
            if "minimum" in schema and instance < schema["minimum"]:
                violations.extend(self._violation(pointer, "schema.minimum"))
            if "maximum" in schema and instance > schema["maximum"]:
                violations.extend(self._violation(pointer, "schema.maximum"))

        if isinstance(instance, dict):
            if (
                "minProperties" in schema
                and len(instance) < schema["minProperties"]
            ):
                violations.extend(
                    self._violation(pointer, "schema.min_properties")
                )
            if (
                "maxProperties" in schema
                and len(instance) > schema["maxProperties"]
            ):
                violations.extend(
                    self._violation(pointer, "schema.max_properties")
                )

            for name in schema.get("required", []):
                if name not in instance:
                    violations.extend(
                        self._violation(
                            _join_pointer(pointer, name), "schema.required"
                        )
                    )

            properties = schema.get("properties", {})
            for name, subschema in properties.items():
                if name in instance:
                    violations.extend(
                        self.evaluate(
                            instance[name],
                            subschema,
                            _join_pointer(pointer, name),
                            depth + 1,
                        )
                    )

            extras = sorted(set(instance) - set(properties))
            additional = schema.get("additionalProperties", True)
            if additional is False:
                for name in extras:
                    violations.extend(
                        self._violation(
                            _join_pointer(pointer, name),
                            "schema.additional_properties",
                        )
                    )
            elif isinstance(additional, Mapping):
                for name in extras:
                    violations.extend(
                        self.evaluate(
                            instance[name],
                            additional,
                            _join_pointer(pointer, name),
                            depth + 1,
                        )
                    )

            for trigger, dependencies in schema.get(
                "dependentRequired", {}
            ).items():
                if trigger in instance:
                    for dependency in dependencies:
                        if dependency not in instance:
                            violations.extend(
                                self._violation(
                                    _join_pointer(pointer, dependency),
                                    "schema.dependent_required",
                                )
                            )

        if isinstance(instance, list):
            if "minItems" in schema and len(instance) < schema["minItems"]:
                violations.extend(
                    self._violation(pointer, "schema.min_items")
                )
            if "maxItems" in schema and len(instance) > schema["maxItems"]:
                violations.extend(
                    self._violation(pointer, "schema.max_items")
                )
            if schema.get("uniqueItems") is True:
                for index, item in enumerate(instance):
                    if any(
                        _json_equal(item, earlier)
                        for earlier in instance[:index]
                    ):
                        violations.extend(
                            self._violation(
                                _join_pointer(pointer, index),
                                "schema.unique_items",
                            )
                        )
            items = schema.get("items")
            if isinstance(items, Mapping) or isinstance(items, bool):
                for index, item in enumerate(instance):
                    violations.extend(
                        self.evaluate(
                            item,
                            items,
                            _join_pointer(pointer, index),
                            depth + 1,
                        )
                    )

        return violations


def validate(instance: Any, schema: Any) -> Tuple[SchemaViolation, ...]:
    """Return stable, content-redacted violations for ``instance``."""

    validator = _Validator(schema)
    violations = validator.evaluate(instance, schema, "")
    return tuple(sorted(set(violations)))


def is_valid(instance: Any, schema: Any) -> bool:
    """Return whether ``instance`` satisfies ``schema``."""

    return not validate(instance, schema)
