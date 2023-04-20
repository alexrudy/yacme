//! # Certificate Orders
//!
//! Each order is for a single certificate chain, but that certificate chain
//! may cover multiple DNS identities.

use crate::cert;
use crate::protocol::{AcmeError, Request, Response, Url};
use crate::schema;
use crate::schema::{
    authorizations::Authorization as AuthorizationSchema,
    orders::{CertificateChain, FinalizeOrder, NewOrderRequest},
    orders::{Order as OrderSchema, OrderStatus},
    Identifier,
};
use chrono::{DateTime, Utc};

use super::{account::Account, authorization::Authorization, client::Client};

const CONTENT_PEM_CHAIN: &str = "application/pem-certificate-chain";

/// Order for a certificate for a set of identifiers.
#[derive(Debug)]
pub struct Order<'a, K> {
    account: &'a Account<K>,
    data: schema::Order,
    url: Url,
}

impl<'a, K> Order<'a, K> {
    pub(crate) fn new(account: &'a Account<K>, data: schema::Order, url: Url) -> Self {
        Self { account, data, url }
    }

    #[inline]
    pub(crate) fn client(&self) -> &Client
    where
        K: Clone,
    {
        self.account.client()
    }

    #[inline]
    pub(crate) fn account(&self) -> &Account<K> {
        self.account
    }

    /// The get URL for this order, for fetching and uniquely identifying
    /// this order.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// The order data, as defined by [`crate::schema::orders::Order`].
    ///
    /// This is useful for accessing the underlying order fields.
    pub fn data(&self) -> &schema::Order {
        &self.data
    }

    /// Get the status of this order.
    ///
    /// This does not refresh the underlying order data. To wait for a particular
    /// status, use [`Order::refresh`] along with this method.
    pub fn status(&self) -> OrderStatus {
        *self.data.status()
    }

    /// Refresh the order information from the ACME provider.
    pub async fn refresh(&mut self) -> Result<(), AcmeError>
    where
        K: Clone,
        K: jaws::algorithms::SigningAlgorithm,
        K::Key: Clone,
        K::Error: std::error::Error + Send + Sync + 'static,
    {
        let response: Response<schema::Order> = self
            .client()
            .execute(Request::get(
                self.url().clone(),
                self.account().request_key(),
            ))
            .await?;

        self.data = response.into_inner();
        Ok(())
    }

    /// Fetch the authorizations for this order.
    pub async fn authorizations(&self) -> Result<Vec<Authorization<K>>, AcmeError>
    where
        K: Clone,
        K: jaws::algorithms::SigningAlgorithm,
        K::Key: Clone,
        K::Error: std::error::Error + Send + Sync + 'static,
    {
        let client = self.client();
        let mut authorizations = Vec::new();
        for auth_url in self.data.authorizations() {
            let authz: Response<AuthorizationSchema> = client
                .execute(Request::get(auth_url.clone(), self.account().request_key()))
                .await?;

            authorizations.push(Authorization::new(
                self,
                authz.into_inner(),
                auth_url.clone(),
            ));
        }

        Ok(authorizations)
    }

    /// Fetch a single authorization by identifier, refreshing that authorization on the way.
    pub async fn authorization(
        &self,
        id: &Identifier,
    ) -> Result<Option<Authorization<K>>, AcmeError>
    where
        K: Clone,
        K: jaws::algorithms::SigningAlgorithm,
        K::Key: Clone,
        K::Error: std::error::Error + Send + Sync + 'static,
    {
        Ok(self
            .authorizations()
            .await?
            .into_iter()
            .find(|authn| &authn.data().identifier == id))
    }

    /// Submit a certificate signing request for this order.
    ///
    /// This does not download the certificate itself, see [`Order::download`] for that, or use the
    /// combined [`Order::finalize_and_download`] method to submit the certificate signing request,
    /// and asynchronously wait for the certificate to be ready for download.
    pub async fn finalize<K2, S, D>(&mut self, key: &K2) -> Result<(), AcmeError>
    where
        K: Clone,
        K: jaws::algorithms::SigningAlgorithm,
        K::Key: Clone,
        K::Error: std::error::Error + Send + Sync + 'static,
        K2: cert::CertificateKey<S, D>,
        S: cert::Signature,
        D: digest::Digest,
    {
        tracing::trace!("Creating CSR for finalization request");

        let body = FinalizeOrder::new(&self.data, key);
        let request = Request::post(
            body,
            self.data.finalize().clone(),
            self.account().request_key(),
        );
        tracing::trace!("Sending order finalize request");
        let info: Response<crate::schema::Order> = self.client().execute(request).await?;
        self.data = info.into_inner();

        Ok(())
    }

    async fn poll_for_order_ready(&mut self) -> Result<(), AcmeError>
    where
        K: Clone,
        K: jaws::algorithms::SigningAlgorithm,
        K::Key: Clone,
        K::Error: std::error::Error + Send + Sync + 'static,
    {
        self.refresh().await?;
        match self.status() {
            OrderStatus::Valid | OrderStatus::Invalid => {
                tracing::debug!(status=?self.status(), "Order was already finished");
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

            self.data = info.into_inner();
            if matches!(self.status(), OrderStatus::Valid | OrderStatus::Invalid) {
                tracing::debug!(status=?self.status(), "Order is finished");
                break;
            }

            tracing::trace!(status=?self.status(), delay=?delay, "Order is not finished");
            tokio::time::sleep(delay).await;
        }

        Ok(())
    }

    /// Download the certificate for this order.
    ///
    /// In order for the certificate to be ready, you must have submitted a certificate signing request
    /// (see [`Order::finalize`]), and the order must have finished processing, which
    pub async fn download(&self) -> Result<CertificateChain, AcmeError>
    where
        K: Clone,
        K: jaws::algorithms::SigningAlgorithm,
        K::Key: Clone,
        K::Error: std::error::Error + Send + Sync + 'static,
    {
        let order_info = &self.data;
        let Some(url) = order_info.certificate() else { return Err(AcmeError::NotReady("certificate")) };

        let mut request = Request::get(url.clone(), self.account().request_key());

        request
            .headers_mut()
            .insert(http::header::ACCEPT, CONTENT_PEM_CHAIN.parse().unwrap());
        let certificate: Response<CertificateChain> = self.client().execute(request).await?;

        Ok(certificate.into_inner())
    }

    /// Finalize the order, and download the certificate.
    ///
    /// This submits the certificate signing request, and then waits for the ACME
    /// provider to indicate that the certifiacte is done processing before returning
    /// the certificate chain.
    pub async fn finalize_and_download<K2, S, D>(
        &mut self,
        key: &K2,
    ) -> Result<CertificateChain, AcmeError>
    where
        K: Clone,
        K: jaws::algorithms::SigningAlgorithm,
        K::Key: Clone,
        K::Error: std::error::Error + Send + Sync + 'static,
        K2: cert::CertificateKey<S, D>,
        S: cert::Signature,
        D: digest::Digest,
    {
        self.finalize(key).await?;
        self.poll_for_order_ready().await?;
        self.download().await
    }
}

/// Builder to create a new Certificate order.
///
/// To create an [`OrderBuilder`], use [`Account::order`].
#[derive(Debug)]
pub struct OrderBuilder<'a, K> {
    account: &'a Account<K>,
    identifiers: Vec<Identifier>,
    not_before: Option<DateTime<Utc>>,
    not_after: Option<DateTime<Utc>>,
}

impl<'a, K> OrderBuilder<'a, K> {
    pub(crate) fn new(account: &'a Account<K>) -> Self {
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
    pub async fn create(self) -> Result<Order<'a, K>, AcmeError>
    where
        K: Clone,
        K: jaws::algorithms::SigningAlgorithm,
        K::Key: Clone,
        K::Error: std::error::Error + Send + Sync + 'static,
    {
        let account = self.account;
        let payload = NewOrderRequest {
            identifiers: self.identifiers,
            not_before: self.not_before,
            not_after: self.not_after,
        };

        let order: Response<crate::schema::Order> = account
            .client()
            .execute(Request::post(
                payload,
                account.directory().new_order.clone(),
                account.request_key(),
            ))
            .await?;

        let order_url = order.location().expect("New order should have a location");
        let order = Order::new(account, order.into_inner(), order_url);

        Ok(order)
    }

    /// Get an existing order by URL
    pub async fn get(self, url: Url) -> Result<Order<'a, K>, AcmeError>
    where
        K: Clone,
        K: jaws::algorithms::SigningAlgorithm,
        K::Key: Clone,
        K::Error: std::error::Error + Send + Sync + 'static,
    {
        let order: Response<crate::schema::Order> = self
            .account
            .client()
            .execute(Request::get(url.clone(), self.account.request_key()))
            .await?;
        let order = Order::new(self.account, order.into_inner(), url);
        Ok(order)
    }
}
pub(crate) async fn list<K>(
    account: &Account<K>,
    limit: Option<usize>,
) -> Result<Vec<Order<K>>, AcmeError>
where
    K: Clone,
    K: jaws::algorithms::SigningAlgorithm,
    K::Key: Clone,
    K::Error: std::error::Error + Send + Sync + 'static,
{
    let client = account.client();
    let mut request = Request::get(
        account
            .data()
            .orders
            .as_ref()
            .ok_or_else(|| AcmeError::MissingData("orders url"))?
            .clone(),
        account.request_key(),
    );
    let mut orders = Vec::new();
    let mut page = 0;
    loop {
        tracing::debug!("Fetching orders, page {page}");
        let response = client.execute(request.clone()).await?;
        let orders_page: schema::orders::Orders = response.into_inner();

        for order_url in orders_page.orders {
            let response: Response<OrderSchema> = client
                .execute(Request::get(order_url.clone(), account.request_key()))
                .await?;
            let order = Order::new(account, response.into_inner(), order_url);
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
