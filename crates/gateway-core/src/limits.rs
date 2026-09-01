use serde_json::Value;

use crate::GatewayError;

#[derive(Clone, Copy, Debug)]
pub struct PayloadLimits {
    pub max_encoded_bytes: usize,
    pub max_depth: usize,
    pub max_string_bytes: usize,
    pub max_array_items: usize,
    pub max_object_fields: usize,
}

impl Default for PayloadLimits {
    fn default() -> Self {
        Self {
            max_encoded_bytes: 256 * 1024,
            max_depth: 16,
            max_string_bytes: 64 * 1024,
            max_array_items: 1_000,
            max_object_fields: 200,
        }
    }
}

impl PayloadLimits {
    /// Checks encoded size, nesting, string length, collection width, and object-key length.
    ///
    /// # Errors
    ///
    /// Returns [`GatewayError::PayloadRejected`] when any configured limit is exceeded.
    pub fn validate(&self, value: &Value) -> Result<(), GatewayError> {
        let encoded = serde_json::to_vec(value)
            .map_err(|_| GatewayError::PayloadRejected("invalid JSON value"))?;
        if encoded.len() > self.max_encoded_bytes {
            return Err(GatewayError::PayloadRejected(
                "encoded payload is too large",
            ));
        }
        self.validate_at_depth(value, 0)
    }

    fn validate_at_depth(&self, value: &Value, depth: usize) -> Result<(), GatewayError> {
        if depth > self.max_depth {
            return Err(GatewayError::PayloadRejected("payload nesting is too deep"));
        }
        match value {
            Value::String(text) if text.len() > self.max_string_bytes => {
                Err(GatewayError::PayloadRejected("string is too long"))
            }
            Value::Array(values) if values.len() > self.max_array_items => {
                Err(GatewayError::PayloadRejected("array has too many items"))
            }
            Value::Object(values) if values.len() > self.max_object_fields => {
                Err(GatewayError::PayloadRejected("object has too many fields"))
            }
            Value::Array(values) => values
                .iter()
                .try_for_each(|item| self.validate_at_depth(item, depth + 1)),
            Value::Object(values) => values.iter().try_for_each(|(key, item)| {
                if key.len() > 200 {
                    return Err(GatewayError::PayloadRejected("object key is too long"));
                }
                self.validate_at_depth(item, depth + 1)
            }),
            _ => Ok(()),
        }
    }
}
