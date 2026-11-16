use crate::error::{bad, Error};
use axum::{
    body::Bytes,
    extract::{FromRequest, Request},
};
use serde::{
    de::{self, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer,
};
use serde_json::{Map, Number, Value};
use std::fmt;

pub struct StrictJson(pub Value);
impl<S: Send + Sync> FromRequest<S> for StrictJson {
    type Rejection = Error;
    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let json = req
            .headers()
            .get("content-type")
            .and_then(|x| x.to_str().ok())
            .is_some_and(|x| {
                x.split(';')
                    .next()
                    .is_some_and(|v| v.trim() == "application/json")
            });
        if !json {
            return Err(bad("json_required"));
        }
        let bytes = Bytes::from_request(req, state)
            .await
            .map_err(|e| Error(e.status(), "invalid_json"))?;
        let value: UniqueValue =
            serde_json::from_slice(&bytes).map_err(|_| bad("ambiguous_or_invalid_json"))?;
        Ok(Self(value.0))
    }
}
struct UniqueValue(Value);
impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(JsonVisitor)
    }
}
struct JsonVisitor;
impl<'de> Visitor<'de> for JsonVisitor {
    type Value = UniqueValue;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "unambiguous JSON with safe integers")
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Bool(v)))
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
        if v.unsigned_abs() > 9_007_199_254_740_991 {
            return Err(E::custom("unsafe integer"));
        }
        Ok(UniqueValue(Value::Number(Number::from(v))))
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
        if v > 9_007_199_254_740_991 {
            return Err(E::custom("unsafe integer"));
        }
        Ok(UniqueValue(Value::Number(Number::from(v))))
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Self::Value, E> {
        Err(E::custom("floating point is unsupported"))
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::String(v.into())))
    }
    fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::String(v)))
    }
    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }
    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(UniqueValue(Value::Null))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut values = vec![];
        while let Some(UniqueValue(v)) = seq.next_element()? {
            values.push(v)
        }
        Ok(UniqueValue(Value::Array(values)))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom("duplicate key"));
            }
            let UniqueValue(v) = map.next_value()?;
            values.insert(key, v);
        }
        Ok(UniqueValue(Value::Object(values)))
    }
}
