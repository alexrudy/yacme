use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::account::Account;
use crate::client::Client;
use crate::identifier::Identifier;
use yacme_protocol::errors::AcmeError;
use yacme_protocol::errors::AcmeErrorDocument;
use yacme_protocol::Url;

#[derive(Debug, Deserialize)]
pub struct Orders {
    orders: Vec<Url>,
    #[serde(default)]
    next: Option<Url>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Order {
    status: OrderStatus,
    expires: Option<DateTime<Utc>>,
    identifiers: Vec<Identifier>,
    not_before: Option<DateTime<Utc>>,
    not_after: Option<DateTime<Utc>>,
    error: Option<AcmeErrorDocument>,
    authorizations: Vec<Url>,
    finalize: Url,
    certificate: Option<Url>,
}

impl Order {
    pub fn builder() -> OrderBuilder {
        OrderBuilder::new()
    }

    pub fn status(&self) -> &OrderStatus {
        &self.status
    }

    pub fn expires(&self) -> Option<DateTime<Utc>> {
        self.expires
    }

    pub fn identifiers(&self) -> &[Identifier] {
        self.identifiers.as_ref()
    }

    pub fn not_before(&self) -> Option<DateTime<Utc>> {
        self.not_before
    }

    pub fn not_after(&self) -> Option<DateTime<Utc>> {
        self.not_after
    }

    pub fn error(&self) -> Option<&AcmeErrorDocument> {
        self.error.as_ref()
    }

    pub fn authorizations(&self) -> &[Url] {
        self.authorizations.as_ref()
    }

    pub fn finalize(&self) -> &Url {
        &self.finalize
    }

    pub fn certificate(&self) -> Option<&Url> {
        self.certificate.as_ref()
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OrderStatus {
    Pending,
    Ready,
    Processing,
    Valid,
    Invalid,
}

#[derive(Debug, Serialize)]
struct NewOrderRequest {
    identifiers: Vec<Identifier>,
    not_before: Option<DateTime<Utc>>,
    not_after: Option<DateTime<Utc>>,
}

#[derive(Debug, Default)]
pub struct OrderBuilder {
    identifiers: Vec<Identifier>,
    not_before: Option<DateTime<Utc>>,
    not_after: Option<DateTime<Utc>>,
}

impl OrderBuilder {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn push(&mut self, identifier: Identifier) {
        self.identifiers.push(identifier);
    }

    pub fn dns<S: Into<String>>(&mut self, identifier: S) {
        self.identifiers.push(Identifier::dns(identifier.into()))
    }

    pub fn start(&mut self, when: DateTime<Utc>) {
        self.not_before = Some(when);
    }

    pub fn end(&mut self, when: DateTime<Utc>) {
        self.not_after = Some(when);
    }

    fn build(self) -> NewOrderRequest {
        NewOrderRequest {
            identifiers: self.identifiers,
            not_before: self.not_before,
            not_after: self.not_after,
        }
    }
}

impl Client {
    pub async fn orders(
        &mut self,
        account: &Account,
        limit: Option<usize>,
    ) -> Result<Vec<Url>, AcmeError> {
        let mut orders = Vec::new();
        let mut url = account.info().orders.clone();
        let mut page = 0;
        loop {
            tracing::debug!("Fetching orders, page {page}");
            let request = reqwest::Request::new(http::Method::POST, url.into());
            let response = self.account_get(account.key_identifier(), request).await?;
            let orders_page: Orders = response.json().await?;
            orders.extend(orders_page.orders.into_iter());

            if let Some(lim) = limit {
                if orders.len() >= lim {
                    return Ok(orders);
                }
            }

            match orders_page.next {
                Some(next_url) => url = next_url,
                None => return Ok(orders),
            }
            page += 1;
        }
    }

    pub async fn order(
        &mut self,
        account: &Account,
        order: OrderBuilder,
    ) -> Result<Order, AcmeError> {
        let request =
            reqwest::Request::new(http::Method::POST, self.directory.new_order.clone().into());
        let payload = order.build();
        let response = self
            .account_post(account.key_identifier(), request, &payload)
            .await?;

        Ok(response.json().await.expect("valid order JSON"))
    }

    #[allow(unused_variables)]
    pub async fn order_finalize(
        &mut self,
        account: &Account,
        order: Order,
    ) -> Result<Order, AcmeError> {
        todo!("Finalize order")
    }

    #[allow(unused_variables)]
    pub async fn download_certificate(
        &mut self,
        account: &Account,
        order: &Order,
    ) -> Result<Vec<()>, AcmeError> {
        todo!("Download the certificate as X509 data")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn orders_list() {
        let response = crate::response!("order-list.http");
        let orders: Orders = serde_json::from_str(response.body()).unwrap();
        assert_eq!(orders.orders.len(), 3);
        assert!(orders.next.is_none());
    }

    #[test]
    fn order() {
        let raw = crate::example!("order.json");
        let order: Order = serde_json::from_str(raw).unwrap();
        assert_eq!(
            order.certificate,
            Some("https://example.com/acme/cert/mAt3xBGaobw".parse().unwrap())
        )
    }
}
