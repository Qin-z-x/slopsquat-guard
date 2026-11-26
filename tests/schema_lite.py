"""A tiny JSON-Schema subset validator used by the tests.

Supports the keywords used by the schemas shipped in ``docs/``: type,
properties, required, additionalProperties (bool or schema), items, enum,
const, minimum, minLength, maxLength, pattern, oneOf. It is intentionally small
and dependency-free; the shipped schemas are kept within this subset.
"""

from __future__ import annotations

import re

TYPES = {
    "object": dict,
    "array": list,
    "string": str,
    "boolean": bool,
    "integer": int,
    "number": (int, float),
}


def _type_ok(value, expected: str) -> bool:
    if expected == "null":
        return value is None
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    return isinstance(value, TYPES[expected])


def validate(instance, schema, path="$") -> list[str]:
    errors: list[str] = []
    if "oneOf" in schema:
        matches = [candidate for candidate in schema["oneOf"] if not validate(instance, candidate, path)]
        if len(matches) != 1:
            errors.append("%s: oneOf matched %d schemas" % (path, len(matches)))
        return errors
    expected = schema.get("type")
    if expected is not None:
        if isinstance(expected, list):
            if not any(_type_ok(instance, item) for item in expected):
                errors.append("%s: expected one of %r, got %r" % (path, expected, type(instance).__name__))
                return errors
        elif not _type_ok(instance, expected):
            errors.append("%s: expected %s, got %r" % (path, expected, type(instance).__name__))
            return errors
    if "const" in schema and instance != schema["const"]:
        errors.append("%s: expected const %r" % (path, schema["const"]))
    if "enum" in schema and instance not in schema["enum"]:
        errors.append("%s: %r not in enum" % (path, instance))
    if isinstance(instance, str):
        if "minLength" in schema and len(instance) < schema["minLength"]:
            errors.append("%s: shorter than minLength" % path)
        if "maxLength" in schema and len(instance) > schema["maxLength"]:
            errors.append("%s: longer than maxLength" % path)
        if "pattern" in schema and not re.search(schema["pattern"], instance):
            errors.append("%s: %r does not match pattern %r" % (path, instance, schema["pattern"]))
    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            errors.append("%s: below minimum %r" % (path, schema["minimum"]))
    if isinstance(instance, dict):
        properties = schema.get("properties", {})
        for name in schema.get("required", []):
            if name not in instance:
                errors.append("%s: missing required property %r" % (path, name))
        for name, value in instance.items():
            if name in properties:
                errors.extend(validate(value, properties[name], "%s.%s" % (path, name)))
            elif schema.get("additionalProperties") is False:
                errors.append("%s: unexpected property %r" % (path, name))
            elif isinstance(schema.get("additionalProperties"), dict):
                errors.extend(validate(value, schema["additionalProperties"], "%s.%s" % (path, name)))
    if isinstance(instance, list) and isinstance(schema.get("items"), dict):
        for index, value in enumerate(instance):
            errors.extend(validate(value, schema["items"], "%s[%d]" % (path, index)))
    return errors
