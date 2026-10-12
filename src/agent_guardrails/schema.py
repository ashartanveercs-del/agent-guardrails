"""A small, strict subset of JSON Schema for validating model-supplied tool arguments.

Strict on purpose: objects reject properties the schema doesn't list unless it says
``"additionalProperties": true``. That closes the "smuggle an extra ``role`` or
``confirmed`` field into the call" trick at the door. Booleans are not accepted as
integers (``True`` is an ``int`` in Python).

Supported keywords: type, properties, required, additionalProperties, enum, minLength,
maxLength, pattern, minimum, maximum, items, minItems, maxItems.
"""

from __future__ import annotations

import copy
import re
from typing import Any

_TYPES = {
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, int | float) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "null": lambda v: v is None,
}


def validate(value: Any, schema: dict[str, Any], path: str = "$") -> list[str]:
    """Return a list of human-readable problems; empty means valid."""
    expected = schema.get("type")
    if expected is not None:
        types = [expected] if isinstance(expected, str) else list(expected)
        if not any(_TYPES.get(t, lambda _v: False)(value) for t in types):
            return [f"{path}: expected {' or '.join(types)}"]

    errors: list[str] = []
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: not one of the allowed values")
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            errors.append(f"{path}: too short")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            errors.append(f"{path}: too long")
        if "pattern" in schema and not re.search(schema["pattern"], value):
            errors.append(f"{path}: does not match the expected format")
    if _TYPES["number"](value):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{path}: below minimum")
        if "maximum" in schema and value > schema["maximum"]:
            errors.append(f"{path}: above maximum")
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            errors.append(f"{path}: too few items")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            errors.append(f"{path}: too many items")
        if isinstance(schema.get("items"), dict):
            for i, item in enumerate(value):
                errors += validate(item, schema["items"], f"{path}[{i}]")
    if isinstance(value, dict):
        props = schema.get("properties", {})
        for name in schema.get("required", []):
            if name not in value:
                errors.append(f"{path}.{name}: required")
        extra = schema.get("additionalProperties", False)
        for key, item in value.items():
            if key in props:
                errors += validate(item, props[key], f"{path}.{key}")
            elif extra is False:
                errors.append(f"{path}.{key}: unexpected property")
            elif isinstance(extra, dict):
                errors += validate(item, extra, f"{path}.{key}")
    return errors


def strict_schema(parameters: dict[str, Any] | None) -> dict[str, Any]:
    """The schema shown to the model: an object schema with ``additionalProperties: false``
    made explicit wherever it was left implicit (several providers require that)."""
    schema = copy.deepcopy(parameters) if parameters else {}
    schema.setdefault("type", "object")
    schema.setdefault("properties", {})

    def harden(node: dict[str, Any]) -> None:
        if node.get("type") == "object":
            node.setdefault("additionalProperties", False)
            for child in node.get("properties", {}).values():
                if isinstance(child, dict):
                    harden(child)
        if isinstance(node.get("items"), dict):
            harden(node["items"])

    harden(schema)
    return schema
