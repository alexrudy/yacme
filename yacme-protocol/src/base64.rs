use std::fmt;
use std::marker::PhantomData;

use serde::{de, ser, Serialize};

#[derive(Debug, Clone)]
pub(crate) struct Base64Data<T>(pub T);

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
        let target = base64_url::encode(&self.0);
        serializer.serialize_str(&target)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Base64JSON<T>(pub T);

impl<T> Base64JSON<T>
where
    T: Serialize,
{
    pub(crate) fn serialized_value(&self) -> Result<String, serde_json::Error> {
        let inner = serde_json::to_vec(&self.0)?;
        Ok(base64_url::encode(&inner))
    }
}

impl<T> From<T> for Base64JSON<T> {
    fn from(value: T) -> Self {
        Base64JSON(value)
    }
}

struct Base64JSONVisitor<T>(PhantomData<T>);

impl<'de, T> de::Visitor<'de> for Base64JSONVisitor<T>
where
    T: de::DeserializeOwned,
{
    type Value = Base64JSON<T>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a base64url encoded type")
    }

    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let data = base64_url::decode(v)
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