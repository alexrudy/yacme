use std::{collections::hash_map::Entry, ops::DerefMut, sync::Arc};

use arc_swap::Guard;
use chrono::{DateTime, Utc};
use yacme_key::SigningKey;
use yacme_protocol::{AcmeError, Request, Response, Url};
use yacme_schema::{
    authorizations::Authorization as AuthorizationSchema,
    orders::Order as OrderSchema,
    orders::{CertificateChain, FinalizeOrder, NewOrderRequest, Orders},
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

    pub fn url(&self) -> &Url {
        self.data.url()
    }

    pub fn schema(&self) -> Guard<Arc<OrderSchema>> {
        self.data.schema()
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

    pub async fn refresh(&self) -> Result<(), AcmeError> {
        self.data
            .refresh(self.client(), self.account().request_key())
            .await
    }

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

    pub async fn finalize(&self) -> Result<(), AcmeError> {
        let Some(certificate_key) = self.certificate_key.as_ref() else { return Err(AcmeError::MissingKey("certificate")) };

        let body = FinalizeOrder::new(self.data.schema().as_ref(), certificate_key);
        let request = Request::post(
            body,
            self.data.schema().finalize().clone(),
            self.account().request_key(),
        );

        let info: Response<yacme_schema::Order> = self.client().execute(request).await?;
        self.data.store(info.into_inner());
        Ok(())
    }

    pub async fn download(&self) -> Result<CertificateChain, AcmeError> {
        let order_info = self.data.schema();
        let Some(url) = order_info.certificate() else { return Err(AcmeError::NotReady("certificate")) };

        let request = Request::get(url.clone(), self.account().request_key());
        let certificate: Response<CertificateChain> = self.client().execute(request).await?;

        Ok(certificate.into_inner())
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

    pub fn push(mut self, identifier: Identifier) -> Self {
        self.identifiers.push(identifier);
        self
    }

    pub fn dns<S: Into<String>>(mut self, identifier: S) -> Self {
        self.identifiers.push(Identifier::dns(identifier.into()));
        self
    }

    pub fn start(mut self, when: DateTime<Utc>) -> Self {
        self.not_before = Some(when);
        self
    }

    pub fn end(mut self, when: DateTime<Utc>) -> Self {
        self.not_after = Some(when);
        self
    }

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
