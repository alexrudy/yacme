use std::sync::Arc;

use arc_swap::{access::Access, ArcSwap};
use yacme_key::SigningKey;
use yacme_protocol::{AcmeError, Request, Response, Url};
use yacme_schema::{
    directory::Directory,
    orders::{CertificateChain, FinalizeOrder},
    Identifier,
};

use crate::{account::Account, client::Client};

#[derive(Debug, Clone)]
pub struct Order {
    account: Account,
    certificate_key: Arc<SigningKey>,
    data: Arc<OrderData>,
}

#[derive(Debug)]
struct OrderData {
    info: ArcSwap<yacme_schema::Order>,
    url: Url,
}

impl Order {
    fn new(
        account: Account,
        certificate_key: Arc<SigningKey>,
        url: Url,
        info: yacme_schema::Order,
    ) -> Self {
        Self {
            account,
            certificate_key,
            data: Arc::new(OrderData {
                info: ArcSwap::new(Arc::new(info)),
                url,
            }),
        }
    }

    #[inline]
    pub(crate) fn client(&self) -> &Client {
        self.account.client()
    }

    #[inline]
    pub(crate) fn directory(&self) -> &Directory {
        self.account().directory()
    }

    #[inline]
    pub(crate) fn account(&self) -> &Account {
        &self.account
    }

    pub async fn refresh(&self) -> Result<(), AcmeError> {
        let info: Response<yacme_schema::Order> = self
            .client()
            .execute(Request::get(self.data.url.clone(), self.account().key()))
            .await?;

        self.data.info.store(Arc::new(info.into_inner()));

        Ok(())
    }

    pub async fn finalize(&self) -> Result<(), AcmeError> {
        let body = FinalizeOrder::new(self.data.info.load().as_ref(), &self.certificate_key);
        let request = Request::post(
            body,
            self.data.info.load().finalize().clone(),
            self.account().key(),
        );

        let info: Response<yacme_schema::Order> = self.client().execute(request).await?;
        self.data.info.store(Arc::new(info.into_inner()));
        Ok(())
    }

    pub async fn download(&self) -> Result<CertificateChain, AcmeError> {
        let order_info = self.data.info.load();
        let Some(url) = order_info.certificate() else { return Err(AcmeError::NotReady("certificate")) };

        let request = Request::get(url.clone(), self.account().key());
        let certificate: Response<CertificateChain> = self.client().execute(request).await?;

        Ok(certificate.into_inner())
    }
}

#[derive(Debug)]
pub struct OrderBuilder {
    account: Account,
    identifiers: Vec<Identifier>,
}

impl OrderBuilder {
    pub(crate) fn new(account: Account) -> Self {
        Self {
            account,
            identifiers: Vec::new(),
        }
    }

    pub(crate) fn client(&self) -> &Client {
        self.account.client()
    }

    pub fn push(&mut self, identifier: Identifier) {
        self.identifiers.push(identifier);
    }

    pub fn dns<S: Into<String>>(&mut self, identifier: S) {
        self.identifiers.push(Identifier::dns(identifier.into()))
    }

    fn build(self) -> yacme_schema::orders::NewOrderRequest {
        todo!()
    }

    pub async fn create(self, certificate_key: Arc<SigningKey>) -> Result<Order, AcmeError> {
        let account = self.account.clone();
        let payload = self.build();

        let order: Response<yacme_schema::Order> = account
            .client()
            .execute(Request::post(
                payload,
                account.directory().new_order.clone(),
                account.key(),
            ))
            .await?;

        let order_url = order.location().expect("New order should have a location");

        let data = OrderData {
            info: ArcSwap::new(Arc::new(order.into_inner())),
            url: order_url,
        };

        Ok(Order {
            account,
            certificate_key,
            data: Arc::new(data),
        })
    }

    pub async fn find(&self) -> Result<Vec<Order>, AcmeError> {
        todo!()
    }
}
