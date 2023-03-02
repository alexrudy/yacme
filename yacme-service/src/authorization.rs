use std::sync::Arc;

use arc_swap::Guard;
use yacme_protocol::{AcmeError, Request, Url};
use yacme_schema::{
    authorizations::Authorization as AuthorizationSchema,
    challenges::{Challenge as ChallengeSchema, ChallengeReadyRequest},
    Identifier,
};

use crate::{account::Account, cache::Cacheable, client::Client, order::Order, Container};

#[derive(Debug, Clone)]
pub struct Authorization {
    order: Order,
    pub(crate) data: Container<AuthorizationSchema, ()>,
}

impl Authorization {
    #[inline]
    pub(crate) fn client(&self) -> &Client {
        self.order.client()
    }

    #[inline]
    pub(crate) fn account(&self) -> &Account {
        self.order.account()
    }

    pub fn schema(&self) -> Guard<Arc<AuthorizationSchema>> {
        self.data.schema()
    }

    /// Identifying URL for this authorization
    pub fn url(&self) -> &Url {
        self.data.url()
    }

    pub fn identifier(&self) -> Identifier {
        self.data.schema().identifier.clone()
    }

    pub fn challenge(&self, kind: &str) -> Option<Challenge> {
        for chall in &self.schema().challenges {
            if chall.name() == Some(kind) {
                let url = chall.url().unwrap();
                return Some(Challenge::new(self.clone(), chall.clone(), url));
            }
        }
        None
    }

    pub(crate) fn from_container(
        order: Order,
        container: Container<AuthorizationSchema, ()>,
    ) -> Self {
        Self {
            order,
            data: container,
        }
    }

    pub(crate) fn new(order: Order, info: AuthorizationSchema, url: Url) -> Self {
        Self {
            order,
            data: Container::new(info, url),
        }
    }

    pub async fn refresh(&self) -> Result<(), AcmeError> {
        self.data
            .refresh(self.client(), self.account().request_key())
            .await
    }
}

impl Cacheable<()> for Authorization {
    type Key = Identifier;
    type Value = AuthorizationSchema;

    fn key(&self) -> Self::Key {
        self.data.schema().identifier.clone()
    }

    fn container(&self) -> Container<Self::Value, ()> {
        self.data.clone()
    }
}

#[derive(Debug, Clone)]
pub struct Challenge {
    auth: Authorization,
    data: Container<ChallengeSchema, ()>,
}

impl Challenge {
    pub fn new(auth: Authorization, schema: ChallengeSchema, url: Url) -> Self {
        Self {
            auth,
            data: Container::new(schema, url),
        }
    }

    #[inline]
    pub(crate) fn client(&self) -> &Client {
        self.auth.client()
    }

    #[inline]
    pub(crate) fn account(&self) -> &Account {
        self.auth.account()
    }

    pub fn schema(&self) -> Guard<Arc<ChallengeSchema>> {
        self.data.schema()
    }

    /// Identifying URL for this authorization
    pub fn url(&self) -> &Url {
        self.data.url()
    }

    pub async fn ready(&self) -> Result<(), AcmeError> {
        let request = Request::post(
            ChallengeReadyRequest::default(),
            self.url().clone(),
            self.account().request_key(),
        );
        let response = self.client().execute::<_, ChallengeSchema>(request).await?;
        self.data.store(response.into_inner());
        Ok(())
    }
}

impl Cacheable<()> for Challenge {
    type Key = Url;
    type Value = ChallengeSchema;

    fn key(&self) -> Self::Key {
        self.data.url().clone()
    }

    fn container(&self) -> Container<Self::Value, ()> {
        self.data.clone()
    }
}
