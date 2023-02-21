use serde::de::DeserializeOwned;
use yacme_protocol::{AcmeError, Url};

#[derive(Debug, Clone)]
pub struct Response<T> {
    url: Url,
    status: http::StatusCode,
    headers: http::HeaderMap,
    payload: T,
}

impl<T> Response<T>
where
    T: DeserializeOwned,
{
    pub(crate) async fn from_response(response: reqwest::Response) -> Result<Self, AcmeError> {
        let url = response.url().clone().into();
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.text().await?;
        let payload: T = serde_json::from_str(&body).map_err(AcmeError::de)?;

        Ok(Response {
            url,
            status,
            headers,
            payload,
        })
    }

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
}
