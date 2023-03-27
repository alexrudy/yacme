//! # Identifiers
//!
//! Identifiers are used to identify the subject of a certificate. Only DNS identifiers are supported
//! by YACME.

use crate::key::cert::RequestedSubjectName;
use serde::{Deserialize, Serialize};
use std::fmt;

/// An identifier for a certificate subject.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase", tag = "type")]
pub enum Identifier {
    /// DNS identifiers for a certificate subject.
    Dns {
        /// The hostname being identified.
        value: String,
    },
}

impl Identifier {
    /// Create a new identifier for a DNS hostname.
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
