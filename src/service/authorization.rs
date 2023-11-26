//! # Authorization of identifiers, and the associated challenges
//!
//! Authorizations prove that the ACME account controls the identifier (e.g. domain name) in
//! question, usually by asking the account to change some externally visible value.

use crate::protocol::{AcmeError, Request, Response, Url};
use crate::schema;
use crate::schema::authorizations::AuthorizationStatus;
use crate::schema::challenges::ChallengeStatus;
use crate::schema::{
    authorizations::Authorization as AuthorizationSchema,
    challenges::{
        Challenge as ChallengeSchema, ChallengeKind, ChallengeReadyRequest, Dns01Challenge,
        Http01Challenge,
    },
    Identifier,
};

use super::{account::Account, client::Client, order::Order};

/// An Authorization is a proof that the account controls the identifier
///
/// Authorizations are attached to [`Order`]s, and contain a list of challenges that the account
/// must complete in order to prove control of the identifier.
#[derive(Debug)]
pub struct Authorization<'o, K> {
    order: &'o Order<'o, K>,
    data: schema::authorizations::Authorization,
    url: Url,
}

impl<'o, K> Authorization<'o, K> {
    pub(crate) fn new(
        order: &'o Order<'o, K>,
        data: schema::authorizations::Authorization,
        url: Url,
    ) -> Self {
        Self { order, data, url }
    }

    #[inline]
    pub(crate) fn client(&self) -> &Client
    where
        K: Clone,
    {
        self.order.client()
    }

    #[inline]
    pub(crate) fn account(&self) -> &Account<K> {
        self.order.account()
    }

    /// The underlying data returned from the ACME provider.
    ///
    /// See [`crate::schema::authorizations::Authorization`] for details.
    pub fn data(&self) -> &schema::authorizations::Authorization {
        &self.data
    }

    /// Identifying URL for this authorization
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// The identifier for this authorization.
    pub fn identifier(&self) -> &Identifier {
        &self.data.identifier
    }

    /// Get a challenge by challenge kind.
    ///
    /// Challenge kinds are supplied as a string, and are defined in the ACME spec.
    /// This method supports `http-01` and `dns-01` challenges.
    pub fn challenge<'c: 'o>(&'c self, kind: &ChallengeKind) -> Option<Challenge<'o, 'c, K>> {
        for chall in &self.data().challenges {
            if chall.kind() == *kind {
                let url = chall.url().unwrap();
                return Some(Challenge::new(self, chall.clone(), url));
            }
        }
        None
    }

    /// Refresh the authorization data from the ACME provider.
    pub async fn refresh(&mut self) -> Result<(), AcmeError>
    where
        K: jaws::algorithms::TokenSigner + jaws::key::SerializeJWK + Clone,
    {
        let response: Response<schema::authorizations::Authorization> = self
            .client()
            .execute(Request::get(
                self.url().clone(),
                self.account().request_key(),
            ))
            .await?;

        self.data = response.into_inner();
        Ok(())
    }

    /// Wait for this authorization to get finalized (i.e. all challenges have responses)
    #[tracing::instrument(skip(self), level = "debug", fields(identifier = %self.data().identifier))]
    pub async fn finalize(&mut self) -> Result<(), AcmeError>
    where
        K: jaws::algorithms::TokenSigner + jaws::key::SerializeJWK + Clone,
    {
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

            self.data = info.into_inner();
            if self.data().status.is_finished() {
                tracing::debug!(status=?self.data().status, "Authorization is finished");
                break;
            }

            tracing::trace!(status=?self.data().status, delay=?delay, "Authorization is not finished");
            tokio::time::sleep(delay).await;
        }

        if !self.data().status.is_valid() {
            if let Some(error) = self
                .data()
                .challenges
                .iter()
                .filter_map(|c| c.error())
                .next()
            {
                tracing::error!("Authorization failed with challenge error: {:?}", error);
                return Err(AcmeError::from(error.clone()));
            };

            // Fallback used if we can't find a specific error message to respond with.
            return Err(AcmeError::AuthorizationError(format!(
                "{:?}",
                self.data().status
            )));
        }

        Ok(())
    }
}

/// ACME Challenge
///
/// A challenge is one way to prove to the ACME service provider that
/// this account controls the identifier (e.g. domain name) in question.
#[derive(Debug)]
pub struct Challenge<'a, 'c, K> {
    auth: &'c Authorization<'a, K>,
    data: schema::challenges::Challenge,
    url: Url,
}

impl<'a, 'c: 'a, K> Challenge<'a, 'c, K> {
    pub(crate) fn new(
        auth: &'a Authorization<'a, K>,
        data: schema::challenges::Challenge,
        url: Url,
    ) -> Self {
        Self { auth, data, url }
    }

    #[inline]
    pub(crate) fn client(&self) -> &Client
    where
        K: Clone,
    {
        self.auth.client()
    }

    #[inline]
    pub(crate) fn account(&self) -> &Account<K> {
        self.auth.account()
    }

    /// Return the inner schema object.
    pub fn data(&self) -> &schema::challenges::Challenge {
        &self.data
    }

    /// The inner HTTP-01 challenge, if this is a HTTP-01 challenge.
    pub fn http01(&self) -> Option<Http01Challenge> {
        self.data().http01().cloned()
    }

    /// The inner DNS-01 challenge, if this is a DNS-01 challenge.
    pub fn dns01(&self) -> Option<Dns01Challenge> {
        self.data().dns01().cloned()
    }

    /// Identifying URL for this authorization
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Notify the server that the challenge is ready.
    pub async fn ready(&mut self) -> Result<(), AcmeError>
    where
        K: jaws::algorithms::TokenSigner + jaws::key::SerializeJWK + Clone,
    {
        let name = self.data().name().unwrap_or("<unknown>");
        tracing::trace!("POST to notify that challenge {} is ready", name);

        let request = Request::post(
            ChallengeReadyRequest,
            self.url().clone(),
            self.account().request_key(),
        );

        let response = self
            .client()
            .execute::<_, _, ChallengeSchema>(request)
            .await?;
        self.data = response.into_inner();
        tracing::debug!("Notified that challenge {} is ready", name);

        Ok(())
    }

    /// Wait for this specific challenge to get finalized.
    pub async fn finalize(&mut self) -> Result<(), AcmeError>
    where
        K: jaws::algorithms::TokenSigner + jaws::key::SerializeJWK + Clone,
    {
        tracing::debug!("Polling authorization resource to check for status updates");

        let name = self
            .data()
            .name()
            .ok_or_else(|| AcmeError::UnknownChallenge("Unknown".into()))?
            .to_owned();
        let kind = self.data().kind();

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

            // self.auth.data = info.into_inner();
            let chall = self
                .auth
                .challenge(&kind)
                .ok_or_else(|| AcmeError::MissingData("challenge"))?
                .data;
            let auth = info.into_inner();
            tracing::trace!("Checking challenge {name}");
            match chall.status() {
                Some(ChallengeStatus::Invalid) => {
                    tracing::warn!(status=?chall.status(), "Challenge {name} is invalid");
                    if let Some(error) = chall.error() {
                        return Err(AcmeError::from(error.clone()));
                    }
                    return Err(AcmeError::NotReady("challenge"));
                }
                Some(ChallengeStatus::Valid) => {
                    tracing::debug!("Completed challenge {name}");
                    break;
                }
                None => {
                    tracing::warn!("Unable to get status for challenge {name}");
                }
                _ => {}
            }

            if matches!(auth.status, AuthorizationStatus::Valid) {
                tracing::warn!(status=?auth.status, "Authorization is finished.\nThe challenge is not marked as complete\nMaybe this challenge is orphaned, or the authorization has expired. Either way, not waiting any longer");
                break;
            } else if auth.status.is_finished() {
                tracing::warn!(status=?auth.status, "Authorization is finished.\n Maybe this challenge is orphaned, or the authorization has expired. Either way, not waiting any longer");
                break;
            }

            tracing::trace!(auth_status=?auth.status, challenge_status=?chall.status(), delay=?delay, "Authorization is not finished");
            tokio::time::sleep(delay).await;
        }

        Ok(())
    }
}
