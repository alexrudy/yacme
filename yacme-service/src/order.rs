//! # Certificate Orders
//!
//! Each order is for a single certificate chain, but that certificate chain
//! may cover multiple DNS identities.

use std::{collections::hash_map::Entry, ops::DerefMut, sync::Arc};

use arc_swap::Guard;
use chrono::{DateTime, Utc};
use yacme_key::SigningKey;
use yacme_protocol::{AcmeError, Request, Response, Url};
use yacme_schema::{
    authorizations::Authorization as AuthorizationSchema,
    orders::{CertificateChain, FinalizeOrder, NewOrderRequest, Orders},
    orders::{Order as OrderSchema, OrderStatus},
    Identifier,
};

use crate::{
    account::Account,
    authorization::Authorization,
    cache::{Cache, Cacheable},
    client::Client,
    Container,
};

#[derive(Debug, Default)]
pub(crate) struct OrderState {
    pub authorizations: Cache<Authorization, ()>,
}

/// Order for a certificate for a set of identifiers.
#[derive(Debug, Clone)]
pub struct Order {
    account: Account,
    certificate_key: Option<Arc<SigningKey>>,
    data: Container<OrderSchema, OrderState>,
}

impl Order {
    pub(crate) fn new(
        account: Account,
        certificate_key: Option<Arc<SigningKey>>,
        info: OrderSchema,
        url: Url,
    ) -> Self {
        Self {
            account,
            certificate_key,
            data: Container::new(info, url),
        }
    }

    pub(crate) fn from_container(
        account: Account,
        container: Container<OrderSchema, OrderState>,
    ) -> Self {
        Self {
            account,
            certificate_key: None,
            data: container,
        }
    }

    #[inline]
    pub(crate) fn client(&self) -> &Client {
        self.account.client()
    }

    #[inline]
    pub(crate) fn account(&self) -> &Account {
        &self.account
    }

    /// The get URL for this order, for fetching and uniquely identifying
    /// this order.
    pub fn url(&self) -> &Url {
        self.data.url()
    }

    /// The order data, as defined by [`yacme_schema::orders::Order`].
    ///
    /// This is useful for accessing the underlying order fields.
    pub fn schema(&self) -> Guard<Arc<OrderSchema>> {
        self.data.schema()
    }

    /// Get the status of this order.
    ///
    /// This does not refresh the underlying order data. To wait for a particular
    /// status, use [`Order::refresh`] along with this method.
    pub fn status(&self) -> OrderStatus {
        *self.data.schema().status()
    }

    /// Set the signing key for certifiactes generated with this order
    ///
    /// A signing key is required to finalize an order, and must be different from the
    /// signing key used for this account.
    pub fn certificate_key(&mut self, certificate_key: Arc<SigningKey>) {
        debug_assert!(
            self.account().key() != certificate_key,
            "Account key and certificate key must be different"
        );
        self.certificate_key = Some(certificate_key);
    }

    /// Refresh the order information from the ACME provider.
    pub async fn refresh(&self) -> Result<(), AcmeError> {
        self.data
            .refresh(self.client(), self.account().request_key())
            .await
    }

    /// Fetch the authorizations for this order.
    pub async fn authorizations(&self) -> Result<Vec<Authorization>, AcmeError> {
        let client = self.client();
        let mut authorizations = Vec::new();
        for auth_url in self.data.schema().authorizations() {
            let authz: Response<AuthorizationSchema> = client
                .execute(Request::get(auth_url.clone(), self.account().request_key()))
                .await?;

            let mut cache = self.data.state().authorizations.inner();
            match cache
                .deref_mut()
                .deref_mut()
                .entry(authz.payload().identifier.clone())
            {
                Entry::Occupied(entry) => {
                    let authc = entry.get();
                    authc.store(authz.into_inner());

                    let authn = Authorization::from_container(self.clone(), authc.clone());
                    authorizations.push(authn);
                }
                Entry::Vacant(entry) => {
                    let authn =
                        Authorization::new(self.clone(), authz.into_inner(), auth_url.clone());
                    entry.insert(authn.data.clone());
                    authorizations.push(authn);
                }
            }
        }

        Ok(authorizations)
    }

    /// Fetch a single authorization by identifier, refreshing that authorization on the way.
    pub async fn authorization(&self, id: &Identifier) -> Result<Option<Authorization>, AcmeError> {
        if let Some(authc) = self.data.state().authorizations.get(id) {
            authc
                .refresh(self.client(), self.account().request_key())
                .await?;
            Ok(Some(Authorization::from_container(
                self.clone(),
                authc.clone(),
            )))
        } else {
            Ok(self
                .authorizations()
                .await?
                .into_iter()
                .find(|authn| &authn.schema().identifier == id))
        }
    }

    /// Submit a certificate signing request for this order.
    ///
    /// This does not download the certificate itself, see [`Order::download`] for that, or use the
    /// combined [`Order::finalize_and_download`] method to submit the certificate signing request,
    /// and asynchronously wait for the certificate to be ready for download.
    pub async fn finalize(&self) -> Result<(), AcmeError> {
        tracing::trace!("Creating CSR for finalization request");
        let Some(certificate_key) = self.certificate_key.as_ref() else { return Err(AcmeError::MissingKey("certificate")) };

        let body = FinalizeOrder::new(self.data.schema().as_ref(), certificate_key);
        let request = Request::post(
            body,
            self.data.schema().finalize().clone(),
            self.account().request_key(),
        );
        tracing::trace!("Sending order finalize request");
        let info: Response<yacme_schema::Order> = self.client().execute(request).await?;
        self.data.store(info.into_inner());

        Ok(())
    }

    async fn poll_for_order_ready(&self) -> Result<(), AcmeError> {
        self.refresh().await?;
        match self.schema().status() {
            OrderStatus::Valid | OrderStatus::Invalid => {
                tracing::debug!(status=?self.schema().status(), "Order was already finished");
                return Ok(());
            }
            OrderStatus::Ready | OrderStatus::Pending => {
                return Err(AcmeError::NotReady("Order is not finalized"));
            }
            OrderStatus::Processing => {
                tracing::trace!("Polling for readiness");
            }
        }

        loop {
            tracing::trace!("Fetching authorization to check status");
            let info: Response<OrderSchema> = self
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
            if matches!(
                self.schema().status(),
                OrderStatus::Valid | OrderStatus::Invalid
            ) {
                tracing::debug!(status=?self.schema().status(), "Order is finished");
                break;
            }

            tracing::trace!(status=?self.schema().status(), delay=?delay, "Order is not finished");
            tokio::time::sleep(delay).await;
        }

        Ok(())
    }

    /// Download the certificate for this order.
    ///
    /// In order for the certificate to be ready, you must have submitted a certificate signing request
    /// (see [`Order::finalize`]), and the order must have finished processing, which
    pub async fn download(&self) -> Result<CertificateChain, AcmeError> {
        let order_info = self.data.schema();
        let Some(url) = order_info.certificate() else { return Err(AcmeError::NotReady("certificate")) };

        let request = Request::get(url.clone(), self.account().request_key());
        let certificate: Response<CertificateChain> = self.client().execute(request).await?;

        Ok(certificate.into_inner())
    }

    /// Finalize the order, and download the certificate.
    ///
    /// This submits the certificate signing request, and then waits for the ACME
    /// provider to indicate that the certifiacte is done processing before returning
    /// the certificate chain.
    pub async fn finalize_and_download(&self) -> Result<CertificateChain, AcmeError> {
        self.finalize().await?;
        self.poll_for_order_ready().await?;
        self.download().await
    }
}

impl Cacheable<OrderState> for Order {
    type Key = Url;
    type Value = OrderSchema;
    fn key(&self) -> Self::Key {
        self.data.url().clone()
    }

    fn container(&self) -> Container<Self::Value, OrderState> {
        self.data.clone()
    }
}

/// Builder to create a new Certificate order.
///
/// To create an [`OrderBuilder`], use [`Account::order`].
#[derive(Debug)]
pub struct OrderBuilder {
    account: Account,
    identifiers: Vec<Identifier>,
    not_before: Option<DateTime<Utc>>,
    not_after: Option<DateTime<Utc>>,
}

impl OrderBuilder {
    pub(crate) fn new(account: Account) -> Self {
        Self {
            account,
            identifiers: Vec::new(),
            not_before: None,
            not_after: None,
        }
    }

    /// Add an identifier to to this order.
    ///
    /// Currently, YACME only supports DNS identifiers.
    pub fn push(mut self, identifier: Identifier) -> Self {
        self.identifiers.push(identifier);
        self
    }

    /// Add a DNS identifier to this order.
    ///
    /// Currently, YACME only supports DNS identifiers.
    pub fn dns<S: Into<String>>(mut self, identifier: S) -> Self {
        self.identifiers.push(Identifier::dns(identifier.into()));
        self
    }

    /// Set the start time for the certificate.
    ///
    /// This certificate will be considered invalid before this timestamp.
    pub fn start(mut self, when: DateTime<Utc>) -> Self {
        self.not_before = Some(when);
        self
    }

    /// Set the end time for this certificate.
    ///
    /// This certificate will be considered invalid after this timestamp.
    pub fn end(mut self, when: DateTime<Utc>) -> Self {
        self.not_after = Some(when);
        self
    }

    /// Send the request to create an order, returning an [`Order`].
    pub async fn create(self) -> Result<Order, AcmeError> {
        let account = self.account.clone();
        let payload = NewOrderRequest {
            identifiers: self.identifiers,
            not_before: self.not_before,
            not_after: self.not_after,
        };

        let order: Response<yacme_schema::Order> = account
            .client()
            .execute(Request::post(
                payload,
                account.directory().new_order.clone(),
                account.request_key(),
            ))
            .await?;

        let order_url = order.location().expect("New order should have a location");
        let order = Order::new(account, None, order.into_inner(), order_url);
        self.account.cache().insert(order.clone());

        Ok(order)
    }

    /// Get an existing order by URL
    pub async fn get(self, url: Url) -> Result<Order, AcmeError> {
        if let Some(order) = self.account.cache().get(&url) {
            order
                .refresh(self.account.client(), self.account.request_key())
                .await?;
            return Ok(Order::from_container(self.account, order));
        }

        let account = self.account.clone();
        let order: Response<yacme_schema::Order> = account
            .client()
            .execute(Request::get(url.clone(), account.request_key()))
            .await?;
        let order = Order::new(account, None, order.into_inner(), url);
        self.account.cache().insert(order.clone());
        Ok(order)
    }
}

pub(crate) async fn list(account: &Account, limit: Option<usize>) -> Result<Vec<Order>, AcmeError> {
    let client = account.client();
    let mut request = Request::get(account.schema().orders.clone(), account.request_key());
    let mut orders = Vec::new();
    let mut page = 0;
    loop {
        tracing::debug!("Fetching orders, page {page}");
        let response = client.execute(request.clone()).await?;
        let orders_page: Orders = response.into_inner();

        for order_url in orders_page.orders {
            let response: Response<OrderSchema> = client
                .execute(Request::get(order_url.clone(), account.request_key()))
                .await?;
            let order = Order::new(account.clone(), None, response.into_inner(), order_url);
            orders.push(order);
        }

        if let Some(lim) = limit {
            if orders.len() >= lim {
                return Ok(orders);
            }
        }

        match orders_page.next {
            Some(next_url) => {
                request = request.with_url(next_url);
            }
            None => return Ok(orders),
        }
        page += 1;
    }
}
