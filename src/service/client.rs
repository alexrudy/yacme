//! Internal, Send and Sync client wrapper.

use std::sync::Arc;

use serde::Serialize;
use tokio::sync::Mutex;

use crate::protocol::{response::Decode, AcmeError, Request, Response, Url};

#[cfg(feature = "trace-requests")]
use crate::protocol::request::Encode;

#[derive(Debug, Clone, Default)]
pub(crate) struct Client {
    inner: Arc<Mutex<crate::protocol::AcmeClient>>,
}

impl Client {
    pub(crate) fn new(client: crate::protocol::AcmeClient) -> Self {
        Client {
            inner: Arc::new(Mutex::new(client)),
        }
    }

    #[cfg(feature = "trace-requests")]
    pub(crate) async fn execute<T, K, R>(
        &self,
        request: Request<T, K>,
    ) -> Result<Response<R>, AcmeError>
    where
        K: jaws::algorithms::TokenSigner<jaws::SignatureBytes>,
        T: Serialize,
        R: Decode + Encode,
    {
        let mut client = self.inner.lock().await;
        client.execute(request).await
    }

    #[cfg(not(feature = "trace-requests"))]
    pub(crate) async fn execute<T, K, R>(
        &self,
        request: Request<T, K>,
    ) -> Result<Response<R>, AcmeError>
    where
        K: jaws::algorithms::TokenSigner<jaws::SignatureBytes>,
        T: Serialize,
        R: Decode,
    {
        let mut client = self.inner.lock().await;
        client.execute(request).await
    }

    pub(crate) async fn get<R>(&self, url: Url) -> Result<Response<R>, AcmeError>
    where
        R: Decode,
    {
        let mut client = self.inner.lock().await;
        client.get(url).await
    }
}
