//! Strict JSON, RFC 8785 JCS, lowercase hex, and canonical decimal `u64`.

use std::collections::BTreeMap;

use serde::de::{self, DeserializeOwned, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::ser::Serialize;
use serde::Deserialize;
use serde_json::Value;

use crate::error::{ErrorCode, TvcError};

pub fn encode_lower_hex(bytes: &[u8]) -> String {
    ::hex::encode(bytes)
}

pub fn decode_lower_hex(input: &str) -> Result<Vec<u8>, TvcError> {
    let decoded = ::hex::decode(input).map_err(|_| TvcError::new(ErrorCode::InvalidHex))?;
    if ::hex::encode(&decoded) != input {
        return Err(TvcError::new(ErrorCode::InvalidHex));
    }
    Ok(decoded)
}

pub fn decode_lower_hex_array<const N: usize>(input: &str) -> Result<[u8; N], TvcError> {
    let bytes = decode_lower_hex(input)?;
    bytes
        .try_into()
        .map_err(|_| TvcError::new(ErrorCode::InvalidHex))
}

pub fn encode_decimal_u64(value: u64) -> String {
    value.to_string()
}

pub fn decode_decimal_u64(input: &str) -> Result<u64, TvcError> {
    if input.is_empty() {
        return Err(TvcError::new(ErrorCode::InvalidDecimal));
    }
    if input.as_bytes()[0] == b'+' || input.as_bytes()[0] == b'-' {
        return Err(TvcError::new(ErrorCode::InvalidDecimal));
    }
    if input.len() > 1 && input.as_bytes()[0] == b'0' {
        return Err(TvcError::new(ErrorCode::InvalidDecimal));
    }
    if !input.bytes().all(|b| b.is_ascii_digit()) {
        return Err(TvcError::new(ErrorCode::InvalidDecimal));
    }
    input
        .parse()
        .map_err(|_| TvcError::new(ErrorCode::InvalidDecimal))
}

/// `#[serde(with = "hex")]`: binary fields as lowercase hex strings, alone,
/// optional, or in an array.
pub mod hex {
    use serde::de::{self, Deserialize, Deserializer};
    use serde::ser::Serializer;

    use super::{decode_lower_hex, decode_lower_hex_array, encode_lower_hex};

    pub trait Hex: Sized {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error>;
        fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error>;
    }

    pub fn serialize<T: Hex, S: Serializer>(value: &T, serializer: S) -> Result<S::Ok, S::Error> {
        value.serialize(serializer)
    }

    pub fn deserialize<'de, T: Hex, D: Deserializer<'de>>(deserializer: D) -> Result<T, D::Error> {
        T::deserialize(deserializer)
    }

    impl Hex for Vec<u8> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_str(&encode_lower_hex(self))
        }

        fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            decode_lower_hex(&String::deserialize(deserializer)?).map_err(de::Error::custom)
        }
    }

    impl<const N: usize> Hex for [u8; N] {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_str(&encode_lower_hex(self))
        }

        fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            decode_lower_hex_array(&String::deserialize(deserializer)?).map_err(de::Error::custom)
        }
    }

    impl Hex for Option<Vec<u8>> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            match self {
                Some(bytes) => serializer.serialize_some(&encode_lower_hex(bytes)),
                None => serializer.serialize_none(),
            }
        }

        fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            Option::<String>::deserialize(deserializer)?
                .map(|value| decode_lower_hex(&value).map_err(de::Error::custom))
                .transpose()
        }
    }

    impl Hex for Vec<Vec<u8>> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.collect_seq(self.iter().map(|value| encode_lower_hex(value)))
        }

        fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            Vec::<String>::deserialize(deserializer)?
                .iter()
                .map(|value| decode_lower_hex(value).map_err(de::Error::custom))
                .collect()
        }
    }

    impl<const N: usize> Hex for Vec<[u8; N]> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.collect_seq(self.iter().map(|value| encode_lower_hex(value)))
        }

        fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            Vec::<String>::deserialize(deserializer)?
                .iter()
                .map(|value| decode_lower_hex_array(value).map_err(de::Error::custom))
                .collect()
        }
    }
}

/// `#[serde(with = "decimal_u64")]`: a `u64` as a canonical decimal string.
pub mod decimal_u64 {
    use serde::de::{self, Deserialize, Deserializer};
    use serde::ser::Serializer;

    use super::{decode_decimal_u64, encode_decimal_u64};

    pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&encode_decimal_u64(*value))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        decode_decimal_u64(&String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

#[derive(Clone, Debug)]
enum StrictValue {
    Null,
    Bool(bool),
    Number(serde_json::Number),
    String(String),
    Array(Vec<StrictValue>),
    Object(BTreeMap<String, StrictValue>),
}

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct StrictVisitor;

        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = StrictValue;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("JSON value")
            }

            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Self::Value, E> {
                Ok(StrictValue::Bool(v))
            }

            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
                Ok(StrictValue::Number(v.into()))
            }

            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(StrictValue::Number(v.into()))
            }

            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(v)
                    .map(StrictValue::Number)
                    .ok_or_else(|| de::Error::custom("non-finite number"))
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(StrictValue::String(v.to_owned()))
            }

            fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(StrictValue::String(v))
            }

            fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(StrictValue::Null)
            }

            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(StrictValue::Null)
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut out = Vec::new();
                while let Some(value) = seq.next_element()? {
                    out.push(value);
                }
                Ok(StrictValue::Array(out))
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut out = BTreeMap::new();
                while let Some((key, value)) = map.next_entry::<String, StrictValue>()? {
                    if out.contains_key(&key) {
                        return Err(de::Error::custom(ErrorCode::DuplicateJsonField.as_str()));
                    }
                    out.insert(key, value);
                }
                Ok(StrictValue::Object(out))
            }
        }

        deserializer.deserialize_any(StrictVisitor)
    }
}

impl From<StrictValue> for Value {
    fn from(value: StrictValue) -> Self {
        match value {
            StrictValue::Null => Value::Null,
            StrictValue::Bool(v) => Value::Bool(v),
            StrictValue::Number(v) => Value::Number(v),
            StrictValue::String(v) => Value::String(v),
            StrictValue::Array(v) => Value::Array(v.into_iter().map(Value::from).collect()),
            StrictValue::Object(v) => Value::Object(
                v.into_iter()
                    .map(|(k, val)| (k, Value::from(val)))
                    .collect(),
            ),
        }
    }
}

fn classify_json_error(error: &serde_json::Error) -> ErrorCode {
    let message = error.to_string();
    if message.contains(ErrorCode::DuplicateJsonField.as_str()) {
        ErrorCode::DuplicateJsonField
    } else if message.contains("unknown field") {
        ErrorCode::UnknownJsonField
    } else {
        ErrorCode::InvalidCanonicalJson
    }
}

/// Parse JSON, rejecting duplicate keys, unknown fields (via serde), and trailing data.
pub fn parse_strict_json<T: DeserializeOwned>(input: &str) -> Result<T, TvcError> {
    let mut de = serde_json::Deserializer::from_str(input);
    let strict = StrictValue::deserialize(&mut de)
        .map_err(|error| TvcError::new(classify_json_error(&error)))?;
    de.end()
        .map_err(|_| TvcError::new(ErrorCode::InvalidCanonicalJson))?;
    let value = Value::from(strict);
    serde_json::from_value(value).map_err(|error| TvcError::new(classify_json_error(&error)))
}

pub fn to_canonical_value<T: Serialize>(value: &T) -> Result<Value, TvcError> {
    serde_json::to_value(value).map_err(|_| TvcError::new(ErrorCode::InvalidCanonicalJson))
}

fn write_json_string(out: &mut Vec<u8>, value: &str) -> Result<(), TvcError> {
    serde_json::to_writer(out, value).map_err(|_| TvcError::new(ErrorCode::InvalidCanonicalJson))
}

fn append_jcs(out: &mut Vec<u8>, value: &Value) -> Result<(), TvcError> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => {
            if n.is_f64() {
                return Err(TvcError::new(ErrorCode::InvalidCanonicalJson));
            }
            out.extend_from_slice(n.to_string().as_bytes());
        }
        Value::String(s) => write_json_string(out, s)?,
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                append_jcs(out, item)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            let mut pairs: Vec<_> = map.iter().collect();
            pairs.sort_unstable_by(|(a, _), (b, _)| a.encode_utf16().cmp(b.encode_utf16()));
            out.push(b'{');
            for (i, (key, value)) in pairs.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_json_string(out, key)?;
                out.push(b':');
                append_jcs(out, value)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

/// RFC 8785 JSON Canonicalization Scheme over a JSON value.
pub fn canonicalize_json_value(value: &Value) -> Result<String, TvcError> {
    let mut out = Vec::new();
    append_jcs(&mut out, value)?;
    String::from_utf8(out).map_err(|_| TvcError::new(ErrorCode::InvalidCanonicalJson))
}

pub fn canonicalize_json_str(input: &str) -> Result<String, TvcError> {
    let mut de = serde_json::Deserializer::from_str(input);
    let strict = StrictValue::deserialize(&mut de)
        .map_err(|error| TvcError::new(classify_json_error(&error)))?;
    de.end()
        .map_err(|_| TvcError::new(ErrorCode::InvalidCanonicalJson))?;
    canonicalize_json_value(&Value::from(strict))
}

pub fn jcs_serialize<T: Serialize>(value: &T) -> Result<String, TvcError> {
    canonicalize_json_value(&to_canonical_value(value)?)
}

pub fn is_rfc8785(input: &str) -> bool {
    match canonicalize_json_str(input) {
        Ok(canonical) => canonical == input,
        Err(_) => false,
    }
}
