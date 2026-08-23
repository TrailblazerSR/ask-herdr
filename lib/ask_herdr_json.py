"""Dependency-free strict JSON primitives for the Machine Core Contract."""

from __future__ import annotations

import json
from typing import Any, Dict, List


SAFE_INTEGER_MAX = 9_007_199_254_740_991


class StrictJsonError(ValueError):
    """A stable, content-redacted strict-JSON rejection."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _quoted(value: str) -> bytes:
    _validate_unicode_scalars(value)
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    )


def canonical_json(value: Any) -> bytes:
    """Serialize the project's integer-only RFC 8785 JSON subset."""

    if value is None:
        return b"null"
    if type(value) is bool:
        return b"true" if value else b"false"
    if type(value) is int:
        if not -SAFE_INTEGER_MAX <= value <= SAFE_INTEGER_MAX:
            raise StrictJsonError("json.integer_out_of_range")
        return str(value).encode("ascii")
    if type(value) is str:
        return _quoted(value)
    if type(value) is list:
        return b"[" + b",".join(canonical_json(item) for item in value) + b"]"
    if type(value) is dict:
        for key in value:
            if type(key) is not str:
                raise StrictJsonError("json.object_key_not_string")
            _validate_unicode_scalars(key)
        keys = sorted(value, key=lambda key: key.encode("utf-16-be"))
        return b"{" + b",".join(
            _quoted(key) + b":" + canonical_json(value[key]) for key in keys
        ) + b"}"
    raise StrictJsonError("json.unsupported_type")


def _reject_duplicate_keys(pairs: List[Any]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StrictJsonError("json.duplicate_key")
        result[key] = value
    return result


def _parse_integer(token: str) -> int:
    negative = token.startswith("-")
    magnitude = token[1:] if negative else token
    limit = str(SAFE_INTEGER_MAX)
    if len(magnitude) > len(limit) or (
        len(magnitude) == len(limit) and magnitude > limit
    ):
        raise StrictJsonError("json.integer_out_of_range")
    return int(token)


def _reject_float(_token: str) -> None:
    raise StrictJsonError("json.float_forbidden")


def _reject_constant(_token: str) -> None:
    raise StrictJsonError("json.nonfinite_forbidden")


def _validate_unicode_scalars(value: Any) -> None:
    if isinstance(value, str):
        if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
            raise StrictJsonError("json.invalid_unicode_scalar")
        return
    if isinstance(value, list):
        for item in value:
            _validate_unicode_scalars(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            _validate_unicode_scalars(key)
            _validate_unicode_scalars(item)


def parse_json_object(payload: bytes) -> Dict[str, Any]:
    """Parse one strict JSON object without accepting lossy number forms."""

    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeError as error:
        raise StrictJsonError("json.invalid_utf8") from error
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_int=_parse_integer,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except StrictJsonError:
        raise
    except (ValueError, json.JSONDecodeError, RecursionError) as error:
        raise StrictJsonError("json.invalid") from error
    if not isinstance(value, dict):
        raise StrictJsonError("json.not_object")
    _validate_unicode_scalars(value)
    return value
