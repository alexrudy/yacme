//! # Authorization of identifiers, and the associated challenges
//!
//! Authorizations prove that the ACME account controls the identifier (e.g. domain name) in
//! question, usually by asking the account to change some externally visible value.

use std::sync::Arc;

use arc_swap::Guard;
use yacme_protocol::{AcmeError, Request, Response, Url};
use yacme_schema::{
    authorizations::Authorization as AuthorizationSchema,
    challenges::{
        Challenge as ChallengeSchema, ChallengeKind, ChallengeReadyRequest, Dns01Challenge,
        Http01Challenge,
    },
    Identifier,
};

use crate::{account::Account, cache::Cacheable, client::Client, order::Order, Container};

/// An Authorization is a proof that the account controls the identifier
///
/// Authorizations are attached to [`Order`]s, and contain a list of challenges that the account
/// must complete in order to prove control of the identifier.
#[derive(Debug, Clone)]
pub struct Authorization {
    order: Order,
    pub(crate) data: Container<AuthorizationSchema, ()>,
}

impl Authorization {
    pub(crate) fn new(order: Order, info: AuthorizationSchema, url: Url) -> Self {
        Self {
            order,
            data: Container::new(info, url),
        }
    }

    #[inline]
    pub(crate) fn client(&self) -> &Client {
        self.order.client()
    }

    #[inline]
    pub(crate) fn account(&self) -> &Account {
        self.order.account()
    }

    /// The underlying data returned from the ACME provider.
    ///
    /// See [`yacme_schema::authorizations::Authorization`] for details.
    pub fn schema(&self) -> Guard<Arc<AuthorizationSchema>> {
        self.data.schema()
    }

    /// Identifying URL for this authorization
    pub fn url(&self) -> &Url {
        self.data.url()
    }

    /// The identifier for this authorization.
    pub fn identifier(&self) -> Identifier {
        self.data.schema().identifier.clone()
    }

    /// Get a challenge by challenge kind.
    ///
    /// Challenge kinds are supplied as a string, and are defined in the ACME spec.
    /// This method supports `http-01` and `dns-01` challenges.
    pub fn challenge(&self, kind: &ChallengeKind) -> Option<Challenge> {
        for chall in &self.schema().challenges {
            if chall.kind() == *kind {
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

    /// Refresh the authorization data from the ACME provider.
    pub async fn refresh(&self) -> Result<(), AcmeError> {
        self.data
            .refresh(self.client(), self.account().request_key())
            .await
    }

    /// Wait for this authorization to get finalized (i.e. all challenges have responses)
    pub async fn finalize(&self) -> Result<(), AcmeError> {
        tracing::debug!("Polling authorization resource to check for status updates");

        loop {
            tracing::trace!("Fetching authorization to check status");
            let info: Response<AuthorizationSchema> = self
                .client()
                .execute(Request::get(
                    self.url().clone(),
                    self.account().request_key(),
                ))
                .await?;

            let delay = info
                .retry_after()
                .unwrap_or_else(|| std::time::Duration::from_secs(1));

            self.data.store(info.into_inner());
            if self.schema().status.is_finished() {
                tracing::debug!(status=?self.schema().status, "Authorization is finished");
                break;
            }

            tracing::trace!(status=?self.schema().status, delay=?delay, "Authorization is not finished");
            tokio::time::sleep(delay).await;
        }

        if !self.schema().status.is_valid() {
            return Err(AcmeError::AuthorizationError(format!(
                "{:?}",
                self.schema().status
            )));
        }

        Ok(())
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

/// ACME Challenge
///
/// A challenge is one way to prove to the ACME service provider that
/// this account controls the identifier (e.g. domain name) in question.
#[derive(Debug, Clone)]
pub struct Challenge {
    auth: Authorization,
    data: Container<ChallengeSchema, ()>,
}

impl Challenge {
    pub(crate) fn new(auth: Authorization, schema: ChallengeSchema, url: Url) -> Self {
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

    /// Return the inner schema object.
    pub fn schema(&self) -> Guard<Arc<ChallengeSchema>> {
        self.data.schema()
    }

    /// The inner HTTP-01 challenge, if this is a HTTP-01 challenge.
    pub fn http01(&self) -> Option<Http01Challenge> {
        self.schema().http01().cloned()
    }

    /// The inner DNS-01 challenge, if this is a DNS-01 challenge.
    pub fn dns01(&self) -> Option<Dns01Challenge> {
        self.schema().dns01().cloned()
    }

    /// Identifying URL for this authorization
    pub fn url(&self) -> &Url {
        self.data.url()
    }

    /// Notify the server that the challenge is ready.
    pub async fn ready(&self) -> Result<(), AcmeError> {
        let name = self.schema().name().unwrap_or("<unknown>");
        tracing::trace!("POST to notify that challenge {} is ready", name);

        let request = Request::post(
            ChallengeReadyRequest::default(),
            self.url().clone(),
            self.account().request_key(),
        );

        let response = self.client().execute::<_, ChallengeSchema>(request).await?;
        self.data.store(response.into_inner());
        tracing::debug!("Notified that challenge {} is ready", name);

        Ok(())
    }

    /// Wait for this specific challenge to get finalized.
    pub async fn finalize(&self) -> Result<(), AcmeError> {
        tracing::debug!("Polling authorization resource to check for status updates");

        let name = self
            .schema()
            .name()
            .ok_or_else(|| AcmeError::UnknownChallenge("Unknown".into()))?;

        loop {
            tracing::trace!("Fetching authorization to check status");
            let info: Response<AuthorizationSchema> = self
                .client()
                .execute(Request::get(
                    self.auth.url().clone(),
                    self.account().request_key(),
                ))
                .await?;

            let delay = info
                .retry_after()
                .unwrap_or_else(|| std::time::Duration::from_secs(1));

            self.auth.data.store(info.into_inner());

            let chall = self
                .auth
                .challenge(&self.schema().kind())
                .ok_or_else(|| AcmeError::MissingData("challenge"))?;

            tracing::trace!("Checking challenge {name}");

            if chall.schema().is_finished() {
                tracing::debug!("Completed challenge {name}");
                break;
            }

            if self.auth.schema().status.is_finished() {
                tracing::warn!(status=?self.auth.schema().status, "Authorization is finished.\n Maybe this challenge is orphaned, or the authorization has expired. Either way, not waiting any longer");
                break;
            }

            tracing::trace!(auth_status=?self.auth.schema().status, challenge_status=?chall.schema().status(), delay=?delay, "Authorization is not finished");
            tokio::time::sleep(delay).await;
        }

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
