use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
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
