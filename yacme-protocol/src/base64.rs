use std::fmt::Write;
use std::marker::PhantomData;

use base64ct::Encoding;
use serde::{de, ser, Serialize};

use crate::fmt::{self, IndentWriter};

/// Wrapper type to indicate that the inner type should be serialized
/// as bytes with a Base64 URL-safe encoding.
#[derive(Debug, Clone)]
pub struct Base64Data<T>(pub T);

impl<T> From<T> for Base64Data<T> {
    fn from(value: T) -> Self {
        Base64Data(value)
    }
}

impl<T> ser::Serialize for Base64Data<T>
where
    T: AsRef<[u8]>,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let target = base64ct::Base64UrlUnpadded::encode_string(self.0.as_ref());
        serializer.serialize_str(&target)
    }
}

impl<T> fmt::AcmeFormat for Base64Data<T>
where
    T: AsRef<[u8]>,
{
    fn fmt<W: fmt::Write>(&self, f: &mut IndentWriter<'_, W>) -> fmt::Result {
        write!(
            f,
            "b64\"{}\"",
            base64ct::Base64UrlUnpadded::encode_string(self.0.as_ref())
        )
    }
}

/// Wrapper type to indicate that the inner type should be serialized
/// as JSON and then Base64 URL-safe encoded and serialized as a string.
#[derive(Debug, Clone)]
pub struct Base64JSON<T>(pub T);

impl<T> Base64JSON<T>
where
    T: Serialize,
{
    pub(crate) fn serialized_value(&self) -> Result<String, serde_json::Error> {
        let inner = serde_json::to_vec(&self.0)?;
        Ok(base64ct::Base64UrlUnpadded::encode_string(&inner))
    }
}

impl<T> From<T> for Base64JSON<T> {
    fn from(value: T) -> Self {
        Base64JSON(value)
    }
}

impl<T> fmt::AcmeFormat for Base64JSON<T>
where
    T: Serialize,
{
    fn fmt<W: fmt::Write>(&self, f: &mut IndentWriter<'_, W>) -> fmt::Result {
        write!(f, "base64url(")?;
        f.write_json(&self.0)?;
        f.write_str(")")
    }
}

struct Base64JSONVisitor<T>(PhantomData<T>);

impl<'de, T> de::Visitor<'de> for Base64JSONVisitor<T>
where
    T: de::DeserializeOwned,
{
    type Value = Base64JSON<T>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> fmt::Result {
        formatter.write_str("a base64url encoded type")
    }

    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let data = base64ct::Base64UrlUnpadded::decode_vec(v)
            .map_err(|_| E::invalid_value(de::Unexpected::Str(v), &"invalid base64url encoding"))?;

        let data = serde_json::from_slice(&data)
            .map_err(|err| E::custom(format!("invalid JSON: {err}")))?;
        Ok(Base64JSON(data))
    }
}

impl<'de, T> de::Deserialize<'de> for Base64JSON<T>
where
    T: de::DeserializeOwned,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(Base64JSONVisitor(PhantomData))
    }
}

impl<T> ser::Serialize for Base64JSON<T>
where
    T: ser::Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::Error;
        let inner = self
            .serialized_value()
            .map_err(|err| S::Error::custom(format!("Error producing inner JSON: {err}")))?;
        serializer.serialize_str(&inner)
    }
}
