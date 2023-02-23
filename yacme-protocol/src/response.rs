use std::fmt::Write;

use serde::de::DeserializeOwned;

use crate::fmt::{self, HttpCase};
use crate::request::Encode;
use crate::AcmeError;
use crate::Url;

pub trait Decode: Sized {
    fn decode(data: &[u8]) -> Result<Self, AcmeError>;
}

impl<T> Decode for T
where
    T: DeserializeOwned,
{
    fn decode(data: &[u8]) -> Result<Self, AcmeError> {
        serde_json::from_slice(data).map_err(AcmeError::de)
    }
}

#[derive(Debug, Clone)]
pub struct Response<T> {
    url: Url,
    status: http::StatusCode,
    headers: http::HeaderMap,
    payload: T,
}

impl<T> Response<T>
where
    T: Decode,
{
    pub(crate) async fn from_decoded_response(
        response: reqwest::Response,
    ) -> Result<Self, AcmeError> {
        let url = response.url().clone().into();
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.bytes().await?;
        let payload: T = T::decode(&body)?;

        Ok(Response {
            url,
            status,
            headers,
            payload,
        })
    }
}

impl<T> Response<T> {
    pub fn status(&self) -> http::StatusCode {
        self.status
    }

    pub fn url(&self) -> &Url {
        &self.url
    }

    pub fn location(&self) -> Option<Url> {
        self.headers.get(http::header::LOCATION).map(|value| {
            value
                .to_str()
                .unwrap_or_else(|_| {
                    panic!("valid text encoding in {} header", http::header::LOCATION)
                })
                .parse()
                .unwrap_or_else(|_| panic!("valid URL in {} header", http::header::LOCATION))
        })
    }

    pub fn content_type(&self) -> Option<mime::Mime> {
        self.headers.get(http::header::CONTENT_TYPE).map(|v| {
            v.to_str()
                .unwrap_or_else(|_| {
                    panic!(
                        "valid text encoding in {} header",
                        http::header::CONTENT_TYPE
                    )
                })
                .parse()
                .unwrap_or_else(|_| {
                    panic!("valid MIME type in {} header", http::header::CONTENT_TYPE)
                })
        })
    }

    pub fn payload(&self) -> &T {
        &self.payload
    }

    pub fn into_inner(self) -> T {
        self.payload
    }
}

impl<T> fmt::AcmeFormat for Response<T>
where
    T: Encode,
{
    fn fmt<W: fmt::Write>(&self, f: &mut fmt::IndentWriter<'_, W>) -> fmt::Result {
        writeln!(
            f,
            "HTTP/1.1 {} {}",
            self.status.as_u16(),
            self.status.canonical_reason().unwrap_or("")
        )?;
        for (header, value) in self.headers.iter() {
            writeln!(f, "{}: {}", header.titlecase(), value.to_str().unwrap())?;
        }

        writeln!(f)?;

        write!(f, "{}", self.payload.encode().unwrap())
    }
}
