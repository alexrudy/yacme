use std::sync::Arc;

use serde::Serialize;
use tokio::sync::Mutex;

use yacme_protocol::{response::Decode, AcmeError, Request, Response, Url};

#[derive(Debug, Clone, Default)]
pub(crate) struct Client {
    inner: Arc<Mutex<yacme_protocol::Client>>,
}

impl Client {
    pub(crate) fn new(client: yacme_protocol::Client) -> Self {
        Client {
            inner: Arc::new(Mutex::new(client)),
        }
    }

    pub(crate) async fn execute<T, R>(&self, request: Request<T>) -> Result<Response<R>, AcmeError>
    where
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
