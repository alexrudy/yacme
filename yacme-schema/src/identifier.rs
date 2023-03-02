use serde::{Deserialize, Serialize};
use yacme_key::cert::RequestedSubjectName;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase", tag = "type")]
pub enum Identifier {
    Dns {
        //TODO: Strongly type hostname with cortex-url
        value: String,
    },
}

impl Identifier {
    pub fn dns(hostname: String) -> Identifier {
        Self::Dns { value: hostname }
    }
}

impl From<Identifier> for RequestedSubjectName {
    fn from(value: Identifier) -> Self {
        match value {
            Identifier::Dns { value } => RequestedSubjectName::Dns(value),
        }
    }
}
