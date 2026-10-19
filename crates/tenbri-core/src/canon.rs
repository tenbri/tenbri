//! RFC 8785 canonical JSON, restricted to what format v1 allows: no duplicate keys, integers of at
//! most 2^53 - 1 in magnitude, no fractions or exponents (spec/format-v1.md, section 3).

use std::cmp::Ordering;
use std::fmt;

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};

use crate::error::{Code, Error};

/// The largest integer magnitude format v1 allows: 2^53 - 1.
pub const MAX_INT: i64 = (1 << 53) - 1;

/// A parsed JSON value. Object members are kept sorted in canonical order (by UTF-16 code units)
/// and are unique.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    Arr(Vec<Value>),
    Obj(Vec<(String, Value)>),
}

impl Value {
    /// The member `key` of an object.
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Obj(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// Removes the member `key` of an object, if there is one.
    pub fn remove(&mut self, key: &str) {
        if let Value::Obj(m) = self {
            m.retain(|(k, _)| k != key);
        }
    }

    /// The member names of an object, in canonical order.
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        let m: &[(String, Value)] = match self {
            Value::Obj(m) => m,
            _ => &[],
        };
        m.iter().map(|(k, _)| k.as_str())
    }
}

/// Canonical member order: by UTF-16 code units (RFC 8785, section 3.2.3).
fn utf16_cmp(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

// serde_json reports a visitor's error with its position appended; these prefixes carry the code.
const DUP: &str = "tenbri:duplicate_key:";
const NOT_INT: &str = "tenbri:not_integer:";
const RANGE: &str = "tenbri:integer_range:";

impl<'de> Deserialize<'de> for Value {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(ValueVisitor)
    }
}

struct ValueVisitor;

impl<'de> Visitor<'de> for ValueVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_bool<E: de::Error>(self, b: bool) -> Result<Value, E> {
        Ok(Value::Bool(b))
    }

    fn visit_u64<E: de::Error>(self, n: u64) -> Result<Value, E> {
        if n > MAX_INT as u64 {
            return Err(E::custom(format!("{RANGE}{n}")));
        }
        Ok(Value::Int(n as i64))
    }

    fn visit_i64<E: de::Error>(self, n: i64) -> Result<Value, E> {
        if n < -MAX_INT {
            return Err(E::custom(format!("{RANGE}{n}")));
        }
        Ok(Value::Int(n))
    }

    // serde_json hands fractions, exponents, -0 and integers beyond 64 bits here.
    fn visit_f64<E: de::Error>(self, n: f64) -> Result<Value, E> {
        Err(E::custom(format!("{NOT_INT}{n}")))
    }

    fn visit_str<E: de::Error>(self, s: &str) -> Result<Value, E> {
        Ok(Value::Str(s.to_owned()))
    }

    fn visit_string<E: de::Error>(self, s: String) -> Result<Value, E> {
        Ok(Value::Str(s))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut out = Vec::new();
        while let Some(v) = seq.next_element()? {
            out.push(v);
        }
        Ok(Value::Arr(out))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut out: Vec<(String, Value)> = Vec::new();
        while let Some((k, v)) = map.next_entry::<String, Value>()? {
            out.push((k, v));
        }
        out.sort_by(|a, b| utf16_cmp(&a.0, &b.0));
        if let Some(w) = out.windows(2).find(|w| w[0].0 == w[1].0) {
            return Err(de::Error::custom(format!("{DUP}{}", w[0].0)));
        }
        Ok(Value::Obj(out))
    }
}

/// Parses JSON text, rejecting duplicate keys, non-integers and out-of-range integers. Whitespace
/// and member order are accepted; use [`parse_stored`] for bytes that must already be canonical.
pub fn parse(bytes: &[u8]) -> Result<Value, Error> {
    serde_json::from_slice(bytes).map_err(|e| {
        let msg = e.to_string();
        for (prefix, code) in [
            (DUP, Code::DuplicateKey),
            (NOT_INT, Code::NotInteger),
            (RANGE, Code::IntegerRange),
        ] {
            if let Some(rest) = msg.strip_prefix(prefix) {
                return Error::new(code, rest.to_owned());
            }
        }
        Error::new(Code::Parse, msg)
    })
}

/// Parses stored bytes and enforces the byte-for-byte rule: they must equal the canonical form of
/// their own parse.
pub fn parse_stored(bytes: &[u8]) -> Result<Value, Error> {
    let v = parse(bytes)?;
    if to_vec(&v) != bytes {
        return Err(Error::new(
            Code::NotCanonical,
            "the bytes differ from their canonical form",
        ));
    }
    Ok(v)
}

/// The canonical bytes of JSON text.
pub fn canonicalize(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    parse(bytes).map(|v| to_vec(&v))
}

/// The canonical value of anything serde can serialise (floats are rejected).
pub fn from_serialize<T: serde::Serialize + ?Sized>(t: &T) -> Result<Value, Error> {
    let bytes = serde_json::to_vec(t).map_err(|e| Error::new(Code::Parse, e.to_string()))?;
    parse(&bytes)
}

/// The canonical serialisation of a value.
pub fn to_vec(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    write(v, &mut out);
    out
}

fn write(v: &Value, out: &mut Vec<u8>) {
    match v {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Int(n) => out.extend_from_slice(n.to_string().as_bytes()),
        Value::Str(s) => write_str(s, out),
        Value::Arr(a) => {
            out.push(b'[');
            for (i, v) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write(v, out);
            }
            out.push(b']');
        }
        Value::Obj(m) => {
            out.push(b'{');
            for (i, (k, v)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_str(k, out);
                out.push(b':');
                write(v, out);
            }
            out.push(b'}');
        }
    }
}

fn write_str(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    let mut buf = [0u8; 4];
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{8}' => out.extend_from_slice(b"\\b"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\u{c}' => out.extend_from_slice(b"\\f"),
            '\r' => out.extend_from_slice(b"\\r"),
            c if (c as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes())
            }
            c => out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes()),
        }
    }
    out.push(b'"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sorts_by_utf16_and_rejects_what_v1_forbids() {
        let c = |s: &str| canonicalize(s.as_bytes()).map(|b| String::from_utf8(b).unwrap());
        assert_eq!(
            c(r#"{ "b": [1, true, null], "a": "A\n" }"#).unwrap(),
            r#"{"a":"A\n","b":[1,true,null]}"#
        );
        assert_eq!(
            c("{\"\u{fb33}\":1,\"\u{1f600}\":2}").unwrap(),
            "{\"\u{1f600}\":2,\"\u{fb33}\":1}"
        );
        assert_eq!(c(r#"{"a":1,"a":1}"#).unwrap_err().code, Code::DuplicateKey);
        assert_eq!(c("1.0").unwrap_err().code, Code::NotInteger);
        assert_eq!(c("-0").unwrap_err().code, Code::NotInteger);
        assert_eq!(c("9007199254740992").unwrap_err().code, Code::IntegerRange);
        assert_eq!(c("-9007199254740991").unwrap(), "-9007199254740991");
        assert_eq!(c(r#""\ud800""#).unwrap_err().code, Code::Parse);
        assert_eq!(
            parse_stored(b"{\"a\":1} ").unwrap_err().code,
            Code::NotCanonical
        );
    }
}
