//! Decode the operator's JSON body without silently replacing repeated members.

use std::fmt;

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

pub(super) fn parse(input: &str) -> serde_json::Result<Value> {
    serde_json::from_str::<BodyValue>(input).map(|body| body.0)
}

struct BodyValue(Value);

impl<'de> Deserialize<'de> for BodyValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(BodyVisitor)
    }
}

struct BodyVisitor;

impl<'de> Visitor<'de> for BodyVisitor {
    type Value = BodyValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value with unique keys in each object")
    }

    fn visit_unit<E>(self) -> Result<BodyValue, E> {
        Ok(BodyValue(Value::Null))
    }

    fn visit_bool<E>(self, value: bool) -> Result<BodyValue, E> {
        Ok(BodyValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<BodyValue, E> {
        Ok(BodyValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<BodyValue, E> {
        Ok(BodyValue(Value::Number(value.into())))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<BodyValue, E> {
        let number = Number::from_f64(value).ok_or_else(|| E::custom("invalid JSON number"))?;
        Ok(BodyValue(Value::Number(number)))
    }

    fn visit_str<E>(self, value: &str) -> Result<BodyValue, E> {
        Ok(BodyValue(Value::String(value.to_owned())))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<BodyValue, A::Error> {
        let mut items = Vec::new();
        while let Some(BodyValue(value)) = sequence.next_element()? {
            items.push(value);
        }
        Ok(BodyValue(Value::Array(items)))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut members: A) -> Result<BodyValue, A::Error> {
        let mut object = Map::new();
        while let Some(key) = members.next_key::<String>()? {
            // The key is already unescaped. Compare only within this object:
            // sibling objects may use the same field name independently.
            if object.contains_key(&key) {
                return Err(de::Error::custom("duplicate JSON object key"));
            }
            let BodyValue(value) = members.next_value()?;
            object.insert(key, value);
        }
        Ok(BodyValue(Value::Object(object)))
    }
}
