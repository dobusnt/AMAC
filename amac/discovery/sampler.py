from __future__ import annotations

import datetime as _dt
from typing import Any, Dict, Optional

_UUID = "00000000-0000-4000-8000-000000000000"
_EMAIL = "user@example.com"
_DATE = _dt.date(2024, 1, 2).isoformat()
_DATETIME = _dt.datetime(2024, 1, 2, 3, 4, 5).isoformat() + "Z"


def _pick_enum(values: list[Any]) -> Any:
    # prefer a non-empty string/number, else first
    for v in values:
        if isinstance(v, (str, int, float)) and str(v):
            return v
    return values[0] if values else None


def _coerce_number(schema: Dict[str, Any], fallback: int | float = 1) -> int | float:
    if "example" in schema and isinstance(schema["example"], (int, float)):
        return schema["example"]
    if "default" in schema and isinstance(schema["default"], (int, float)):
        return schema["default"]
    mn = schema.get("minimum")
    mx = schema.get("maximum")
    if isinstance(mn, (int, float)) and isinstance(mx, (int, float)):
        try:
            return (mn + mx) / 2
        except Exception:
            return mn
    if isinstance(mn, (int, float)):
        return mn
    if isinstance(mx, (int, float)):
        return mx
    return fallback


def _coerce_string(schema: Dict[str, Any], name_hint: str | None = None) -> str:
    fmt = str(schema.get("format") or "").lower()
    ex = schema.get("example")
    if isinstance(ex, str) and ex:
        return ex
    if "enum" in schema and isinstance(schema["enum"], list) and schema["enum"]:
        v = _pick_enum(schema["enum"])
        return str(v)
    if fmt == "uuid":
        return _UUID
    if fmt in ("date",):
        return _DATE
    if fmt in ("date-time", "datetime", "rfc3339"):
        return _DATETIME
    if fmt in ("email",):
        return _EMAIL
    if fmt in ("uri", "url"):
        return "https://example.com"
    # if a hint suggests id/user/page, bias to simple demo values
    if name_hint:
        n = name_hint.lower()
        if n in ("id", "user_id", "uid"):
            return "1"
        if n in ("page", "p"):
            return "1"
        if "name" in n:
            return "alice"
        if "query" in n or n in ("q", "search"):
            return "test"
    # minLength/maximumHints ignored for MVP
    return "1"


def _coerce_boolean(schema: Dict[str, Any]) -> bool:
    if "example" in schema and isinstance(schema["example"], bool):
        return schema["example"]
    if "default" in schema and isinstance(schema["default"], bool):
        return schema["default"]
    return True


def sample_param_value(param: Dict[str, Any]) -> str:
    """
    Produce a realistic demo value for a parameter using schema hints.
    """
    schema = param.get("schema") or {}
    typ = str(schema.get("type") or "").lower()
    name = str(param.get("name") or "")
    if "enum" in schema and isinstance(schema["enum"], list) and schema["enum"]:
        return str(_pick_enum(schema["enum"]))
    if typ in ("integer", "number"):
        return str(_coerce_number(schema))
    if typ in ("boolean",):
        return "true" if _coerce_boolean(schema) else "false"
    # Handle oneOf/anyOf quickly
    for key in ("oneOf", "anyOf"):
        if key in schema and isinstance(schema[key], list) and schema[key]:
            first = schema[key][0] or {}
            if "type" in first:
                return sample_param_value({"name": name, "schema": first})
    # string or unknown
    return _coerce_string(schema, name_hint=name)


def sample_schema_value(schema: Dict[str, Any], name_hint: str | None = None, doc: Dict[str, Any] | None = None) -> Any:
    """
    Sample a value for a JSON schema object (for request bodies).
    Enhanced to handle complex schemas: allOf, anyOf, oneOf, additionalProperties, etc.
    
    Args:
        schema: The JSON schema to sample
        name_hint: Optional hint for field name (used for better value generation)
        doc: Optional full OpenAPI document for resolving $ref
    """
    # Handle $ref if present
    if "$ref" in schema and doc:
        from .openapi import _deref
        schema = _deref(schema, doc)
        if not isinstance(schema, dict):
            return None
    
    # Handle enum first (highest priority)
    if "enum" in schema and isinstance(schema["enum"], list) and schema["enum"]:
        return _pick_enum(schema["enum"])
    
    # Handle allOf - merge all schemas
    if "allOf" in schema and isinstance(schema["allOf"], list) and schema["allOf"]:
        merged = {}
        for sub_schema in schema["allOf"]:
            if isinstance(sub_schema, dict):
                if "$ref" in sub_schema and doc:
                    from .openapi import _deref
                    sub_schema = _deref(sub_schema, doc)
                if isinstance(sub_schema, dict):
                    # Merge properties
                    props = sub_schema.get("properties") or {}
                    merged.update(props)
                    # Sample the merged schema
                    temp_schema = {**schema, "properties": merged, "type": sub_schema.get("type", schema.get("type"))}
                    return sample_schema_value(temp_schema, name_hint, doc)
    
    # Handle oneOf - pick first valid
    if "oneOf" in schema and isinstance(schema["oneOf"], list) and schema["oneOf"]:
        for sub_schema in schema["oneOf"]:
            if isinstance(sub_schema, dict):
                if "$ref" in sub_schema and doc:
                    from .openapi import _deref
                    sub_schema = _deref(sub_schema, doc)
                if isinstance(sub_schema, dict):
                    result = sample_schema_value(sub_schema, name_hint, doc)
                    if result is not None:
                        return result
    
    # Handle anyOf - pick first
    if "anyOf" in schema and isinstance(schema["anyOf"], list) and schema["anyOf"]:
        first = schema["anyOf"][0] or {}
        if isinstance(first, dict):
            if "$ref" in first and doc:
                from .openapi import _deref
                first = _deref(first, doc)
            if isinstance(first, dict):
                return sample_schema_value(first, name_hint, doc)
    
    # Handle not - return None or a safe default (can't satisfy "not")
    if "not" in schema:
        # For "not", we'll just return a basic value and hope it doesn't match
        # This is a limitation - we can't guarantee it won't match
        pass
    
    typ = str(schema.get("type") or "").lower()
    
    if typ == "object":
        props = schema.get("properties") or {}
        required = schema.get("required") or []
        additional_props = schema.get("additionalProperties")
        min_props = schema.get("minProperties", 0)
        
        out: Dict[str, Any] = {}
        
        # Add required properties
        for k, v in props.items():
            if k in required or (not required and k in props):  # Include all if no required list
                if isinstance(v, dict):
                    if "$ref" in v and doc:
                        from .openapi import _deref
                        v = _deref(v, doc)
                    out[k] = sample_schema_value(v, name_hint=k, doc=doc)
        
        # Add optional properties if we haven't met minProperties
        if len(out) < min_props:
            for k, v in props.items():
                if k not in out:
                    if isinstance(v, dict):
                        if "$ref" in v and doc:
                            from .openapi import _deref
                            v = _deref(v, doc)
                        out[k] = sample_schema_value(v, name_hint=k, doc=doc)
                    if len(out) >= min_props:
                        break
        
        # Handle additionalProperties
        if additional_props is True:
            # Can add any properties - add a couple of example ones
            out["extra_field_1"] = "value1"
            out["extra_field_2"] = 42
        elif isinstance(additional_props, dict):
            # additionalProperties has a schema
            out["additional_field"] = sample_schema_value(additional_props, name_hint="additional", doc=doc)
        
        return out
    
    if typ == "array":
        items = schema.get("items") or {}
        min_items = schema.get("minItems", 0)
        max_items = schema.get("maxItems")
        
        if isinstance(items, dict):
            if "$ref" in items and doc:
                from .openapi import _deref
                items = _deref(items, doc)
            if isinstance(items, dict):
                # Generate at least minItems, but cap at maxItems or 3 (reasonable default)
                count = max(min_items, 1)
                if max_items is not None:
                    count = min(count, max_items)
                else:
                    count = min(count, 3)  # Reasonable default for arrays
                return [sample_schema_value(items, name_hint=name_hint, doc=doc) for _ in range(count)]
        return [] if min_items == 0 else [None]
    
    if typ in ("integer", "number"):
        return _coerce_number(schema)
    
    if typ == "boolean":
        return _coerce_boolean(schema)
    
    if typ == "null":
        return None
    
    # Handle string with constraints
    if typ == "string":
        result = _coerce_string(schema, name_hint)
        # Apply minLength/maxLength if specified
        min_len = schema.get("minLength")
        max_len = schema.get("maxLength")
        if min_len is not None and len(result) < min_len:
            result = result * ((min_len // len(result)) + 1)
            result = result[:min_len]
        if max_len is not None and len(result) > max_len:
            result = result[:max_len]
        return result
    
    # Fallback to string
    return _coerce_string(schema, name_hint=name_hint)


def validate_generated_body(body_data: Any, schema: Dict[str, Any], doc: Dict[str, Any] | None = None) -> tuple[bool, str | None]:
    """
    Validate that a generated request body matches the schema constraints.
    Returns (is_valid, error_message).
    
    This is a basic validation - for full validation, use a JSON Schema validator library.
    """
    # Handle $ref
    if "$ref" in schema and doc:
        from .openapi import _deref
        schema = _deref(schema, doc)
        if not isinstance(schema, dict):
            return False, "Schema reference could not be resolved"
    
    typ = str(schema.get("type") or "").lower()
    
    # Type checking
    if typ == "object":
        if not isinstance(body_data, dict):
            return False, f"Expected object, got {type(body_data).__name__}"
        props = schema.get("properties") or {}
        required = schema.get("required") or []
        
        # Check required properties
        for req_prop in required:
            if req_prop not in body_data:
                return False, f"Missing required property: {req_prop}"
        
        # Check additionalProperties
        additional_props = schema.get("additionalProperties")
        if additional_props is False:
            # No additional properties allowed
            for key in body_data:
                if key not in props:
                    return False, f"Additional property not allowed: {key}"
        
        # Validate each property
        for key, value in body_data.items():
            if key in props:
                prop_schema = props[key]
                if isinstance(prop_schema, dict):
                    if "$ref" in prop_schema and doc:
                        from .openapi import _deref
                        prop_schema = _deref(prop_schema, doc)
                    if isinstance(prop_schema, dict):
                        is_valid, error = validate_generated_body(value, prop_schema, doc)
                        if not is_valid:
                            return False, f"Property '{key}': {error}"
    
    elif typ == "array":
        if not isinstance(body_data, list):
            return False, f"Expected array, got {type(body_data).__name__}"
        
        items = schema.get("items") or {}
        if isinstance(items, dict):
            if "$ref" in items and doc:
                from .openapi import _deref
                items = _deref(items, doc)
            if isinstance(items, dict):
                min_items = schema.get("minItems", 0)
                max_items = schema.get("maxItems")
                
                if len(body_data) < min_items:
                    return False, f"Array has {len(body_data)} items, minimum is {min_items}"
                if max_items is not None and len(body_data) > max_items:
                    return False, f"Array has {len(body_data)} items, maximum is {max_items}"
                
                # Validate each item
                for i, item in enumerate(body_data):
                    is_valid, error = validate_generated_body(item, items, doc)
                    if not is_valid:
                        return False, f"Array item {i}: {error}"
    
    elif typ in ("integer", "number"):
        if not isinstance(body_data, (int, float)):
            return False, f"Expected number, got {type(body_data).__name__}"
        minimum = schema.get("minimum")
        maximum = schema.get("maximum")
        if minimum is not None and body_data < minimum:
            return False, f"Value {body_data} is less than minimum {minimum}"
        if maximum is not None and body_data > maximum:
            return False, f"Value {body_data} is greater than maximum {maximum}"
    
    elif typ == "boolean":
        if not isinstance(body_data, bool):
            return False, f"Expected boolean, got {type(body_data).__name__}"
    
    elif typ == "string":
        if not isinstance(body_data, str):
            return False, f"Expected string, got {type(body_data).__name__}"
        min_len = schema.get("minLength")
        max_len = schema.get("maxLength")
        if min_len is not None and len(body_data) < min_len:
            return False, f"String length {len(body_data)} is less than minLength {min_len}"
        if max_len is not None and len(body_data) > max_len:
            return False, f"String length {len(body_data)} is greater than maxLength {max_len}"
        # Check enum
        if "enum" in schema and isinstance(schema["enum"], list):
            if body_data not in schema["enum"]:
                return False, f"Value '{body_data}' is not in enum {schema['enum']}"
    
    elif typ == "null":
        if body_data is not None:
            return False, f"Expected null, got {type(body_data).__name__}"
    
    # If no type specified, validation passes (could be any type)
    return True, None


def fill_server_variables(server_obj: Dict[str, Any]) -> Optional[str]:
    """
    Expand a single OpenAPI server object with variables, picking the first enum/default.
    """
    url = server_obj.get("url")
    if not isinstance(url, str) or not url:
        return None
    vars = server_obj.get("variables") or {}
    for var_name, var_spec in vars.items():
        rep = None
        if isinstance(var_spec, dict):
            if "enum" in var_spec and isinstance(var_spec["enum"], list) and var_spec["enum"]:
                rep = str(var_spec["enum"][0])
            elif "default" in var_spec:
                rep = str(var_spec["default"])
        if rep is None:
            rep = ""  # fallback: empty
        url = url.replace("{" + var_name + "}", rep)
    return url
