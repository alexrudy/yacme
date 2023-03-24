use serde::{Deserialize, Serialize};
use std::fmt;
use yacme_key::cert::RequestedSubjectName;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
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

impl fmt::Debug for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dns { value } => f.debug_tuple("Identifier::DNS").field(value).finish(),
        }
    }
}

impl fmt::Display for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Identifier::Dns { value } => f.write_str(value),
        }
    }
}
