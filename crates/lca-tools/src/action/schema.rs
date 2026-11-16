use serde_json::Value;

const KEYWORDS: &[&str] = &[
    "additionalProperties",
    "description",
    "maxLength",
    "minLength",
    "properties",
    "required",
    "type",
];

/// Rejects a schema this milestone cannot enforce.
pub(crate) fn ensure_supported(schema: &Value) -> Result<(), String> {
    check_schema(schema)
}

/// Checks `instance` against a supported schema.
pub(crate) fn validate_instance(schema: &Value, instance: &Value) -> Result<(), String> {
    ensure_supported(schema)?;
    match_instance(schema, instance, None)
}

fn check_schema(schema: &Value) -> Result<(), String> {
    let Some(object) = schema.as_object() else {
        return Err("schema must be an object".to_owned());
    };
    for key in object.keys() {
        if !KEYWORDS.contains(&key.as_str()) {
            return Err(format!("schema keyword `{key}` is not supported"));
        }
    }
    let Some(type_name) = object.get("type").and_then(Value::as_str) else {
        return Err("schema requires a string type".to_owned());
    };
    if let Some(description) = object.get("description")
        && !description.is_string()
    {
        return Err("schema description must be a string".to_owned());
    }
    match type_name {
        "object" => check_object_schema(object),
        "string" => check_string_schema(object),
        "integer" | "number" | "boolean" => {
            let extra = object
                .keys()
                .any(|key| key != "type" && key != "description");
            if extra {
                Err(format!(
                    "schema type `{type_name}` does not allow extra keywords"
                ))
            } else {
                Ok(())
            }
        }
        other => Err(format!("schema type `{other}` is not supported")),
    }
}

fn check_object_schema(object: &serde_json::Map<String, Value>) -> Result<(), String> {
    for key in object.keys() {
        if !matches!(
            key.as_str(),
            "type" | "description" | "properties" | "required" | "additionalProperties"
        ) {
            return Err(format!("schema keyword `{key}` is not supported on object"));
        }
    }
    let properties = match object.get("properties") {
        Some(value) => value
            .as_object()
            .ok_or_else(|| "schema properties must be an object".to_owned())?,
        None => return Err("object schema requires properties".to_owned()),
    };
    if properties.is_empty() {
        return Err("object schema requires at least one property".to_owned());
    }
    for (name, property) in properties {
        if name.is_empty() {
            return Err("schema property name must not be empty".to_owned());
        }
        check_schema(property).map_err(|error| format!("property `{name}`: {error}"))?;
    }
    let required = match object.get("required") {
        Some(value) => value
            .as_array()
            .ok_or_else(|| "schema required must be an array".to_owned())?,
        None => return Err("object schema requires required".to_owned()),
    };
    for item in required {
        let Some(name) = item.as_str() else {
            return Err("schema required entries must be strings".to_owned());
        };
        if !properties.contains_key(name) {
            return Err(format!("schema required field `{name}` is not a property"));
        }
    }
    match object.get("additionalProperties") {
        None => Ok(()),
        Some(Value::Bool(_)) => Ok(()),
        Some(_) => Err("schema additionalProperties must be a boolean".to_owned()),
    }
}

fn check_string_schema(object: &serde_json::Map<String, Value>) -> Result<(), String> {
    for key in object.keys() {
        if !matches!(
            key.as_str(),
            "type" | "description" | "minLength" | "maxLength"
        ) {
            return Err(format!("schema keyword `{key}` is not supported on string"));
        }
    }
    let min = length_keyword(object, "minLength")?;
    let max = length_keyword(object, "maxLength")?;
    if let (Some(min), Some(max)) = (min, max)
        && min > max
    {
        return Err("schema minLength exceeds maxLength".to_owned());
    }
    Ok(())
}

fn length_keyword(
    object: &serde_json::Map<String, Value>,
    name: &str,
) -> Result<Option<usize>, String> {
    let Some(value) = object.get(name) else {
        return Ok(None);
    };
    let Some(length) = value.as_u64() else {
        return Err(format!("schema {name} must be an integer"));
    };
    usize::try_from(length)
        .map(Some)
        .map_err(|_| format!("schema {name} is too large"))
}

fn match_instance(schema: &Value, instance: &Value, field: Option<&str>) -> Result<(), String> {
    let object = schema
        .as_object()
        .ok_or_else(|| "schema is not enforceable".to_owned())?;
    let type_name = object
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| "schema is not enforceable".to_owned())?;
    match type_name {
        "object" => match_object(object, instance, field),
        "string" => match_string(object, instance, field),
        "integer" => {
            if is_integer(instance) {
                Ok(())
            } else {
                Err(type_error(field, "integer"))
            }
        }
        "number" => {
            if instance.is_number() {
                Ok(())
            } else {
                Err(type_error(field, "number"))
            }
        }
        "boolean" => {
            if instance.is_boolean() {
                Ok(())
            } else {
                Err(type_error(field, "boolean"))
            }
        }
        _ => Err("schema is not enforceable".to_owned()),
    }
}

fn match_object(
    schema: &serde_json::Map<String, Value>,
    instance: &Value,
    field: Option<&str>,
) -> Result<(), String> {
    let Some(object) = instance.as_object() else {
        return Err(type_error(field, "object"));
    };
    let properties = schema
        .get("properties")
        .and_then(Value::as_object)
        .ok_or_else(|| "schema is not enforceable".to_owned())?;
    let required = schema
        .get("required")
        .and_then(Value::as_array)
        .ok_or_else(|| "schema is not enforceable".to_owned())?;
    for item in required {
        let Some(name) = item.as_str() else {
            return Err("schema is not enforceable".to_owned());
        };
        if !object.contains_key(name) {
            return Err(format!("missing required field `{name}`"));
        }
    }
    for (name, property) in properties {
        if let Some(value) = object.get(name) {
            match_instance(property, value, Some(name))?;
        }
    }
    let additional = schema
        .get("additionalProperties")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    if !additional {
        let mut unknown: Vec<&str> = object
            .keys()
            .filter(|name| !properties.contains_key(*name))
            .map(String::as_str)
            .collect();
        unknown.sort_unstable();
        if let Some(name) = unknown.first() {
            return Err(format!("unknown field `{name}`"));
        }
    }
    Ok(())
}

fn match_string(
    schema: &serde_json::Map<String, Value>,
    instance: &Value,
    field: Option<&str>,
) -> Result<(), String> {
    let Some(text) = instance.as_str() else {
        return Err(type_error(field, "string"));
    };
    let length = text.chars().count();
    if let Some(min) = length_keyword(schema, "minLength")?
        && length < min
    {
        return Err(length_error(field, "shorter than", min));
    }
    if let Some(max) = length_keyword(schema, "maxLength")?
        && length > max
    {
        return Err(length_error(field, "longer than", max));
    }
    Ok(())
}

fn is_integer(value: &Value) -> bool {
    value.as_i64().is_some() || value.as_u64().is_some()
}

fn type_error(field: Option<&str>, expected: &str) -> String {
    let article = if matches!(expected, "object" | "integer") {
        "an"
    } else {
        "a"
    };
    match field {
        Some(name) => format!("field `{name}` must be {article} {expected}"),
        None => format!("arguments must be {article} {expected}"),
    }
}

fn length_error(field: Option<&str>, relation: &str, limit: usize) -> String {
    match field {
        Some(name) => format!("field `{name}` is {relation} {limit} characters"),
        None => format!("arguments are {relation} {limit} characters"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn echo_schema() -> Value {
        json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["message"],
            "properties": {
                "message": { "type": "string", "maxLength": 4 }
            }
        })
    }

    #[test]
    fn schema_checks_types_required_fields_and_unknown_fields() {
        let schema = echo_schema();
        assert!(validate_instance(&schema, &json!({"message": "hey"})).is_ok());
        assert_eq!(
            validate_instance(&schema, &json!({})).expect_err("missing"),
            "missing required field `message`"
        );
        assert_eq!(
            validate_instance(&schema, &json!({"message": 1})).expect_err("type"),
            "field `message` must be a string"
        );
        assert_eq!(
            validate_instance(&schema, &json!({"message": "hello"})).expect_err("length"),
            "field `message` is longer than 4 characters"
        );
        assert_eq!(
            validate_instance(&schema, &json!({"message": "hey", "loud": true}))
                .expect_err("extra"),
            "unknown field `loud`"
        );
        assert_eq!(
            validate_instance(&schema, &json!("hey")).expect_err("root"),
            "arguments must be an object"
        );
    }

    #[test]
    fn unsupported_keywords_and_integer_values_fail_closed() {
        let pattern = json!({"type": "string", "pattern": "^a"});
        assert!(
            ensure_supported(&pattern)
                .expect_err("pattern")
                .contains("pattern")
        );

        let flag = json!({"type": "boolean"});
        assert!(validate_instance(&flag, &json!(true)).is_ok());
        assert!(validate_instance(&flag, &json!("true")).is_err());

        let count = json!({"type": "integer"});
        assert!(validate_instance(&count, &json!(2)).is_ok());
        assert!(validate_instance(&count, &json!(1.5)).is_err());
        assert!(validate_instance(&count, &json!(true)).is_err());
    }
}
