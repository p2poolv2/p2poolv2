// Copyright (C) 2024, 2025 P2Poolv2 Developers (see AUTHORS)
//
//  This file is part of P2Poolv2
//
// P2Poolv2 is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// P2Poolv2 is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// P2Poolv2. If not, see <https://www.gnu.org/licenses/>.

use std::vec;

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

/// JSON-RPC ID can be a number, string, or null.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Id {
    Number(i32),
    String(String),
    None(()),
}

impl From<()> for Id {
    fn from(_val: ()) -> Self {
        Id::None(())
    }
}

impl From<i64> for Id {
    fn from(val: i64) -> Self {
        Id::Number(val as i32)
    }
}

impl From<String> for Id {
    fn from(val: String) -> Self {
        Id::String(val)
    }
}

impl PartialEq for Id {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Id::Number(a), Id::Number(b)) => a == b,
            (Id::String(a), Id::String(b)) => a == b,
            (Id::None(_), Id::None(_)) => true,
            _ => false,
        }
    }
}

/// Params in JSON-RPC can be an array, object, or null.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Params {
    Array(Vec<Value>),
    Map(Map<String, Value>),
    None(()),
}

impl From<Value> for Params {
    fn from(val: Value) -> Self {
        match val {
            Value::Array(v) => Params::Array(v),
            Value::Object(v) => Params::Map(v),
            _ => Params::None(()),
        }
    }
}

impl From<Vec<Value>> for Params {
    fn from(val: Vec<Value>) -> Self {
        Params::Array(val)
    }
}

impl From<Map<String, Value>> for Params {
    fn from(val: Map<String, Value>) -> Self {
        Params::Map(val)
    }
}

impl Default for Params {
    fn default() -> Self {
        Params::None(())
    }
}

/// StratumError represents the error structure in Stratum responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Error {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// A generic stratum message structure as defined in the protocol specification
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StratumMessage {
    Request {
        #[serde(skip_serializing_if = "Option::is_none")]
        id: Option<Id>,
        method: String,
        #[serde(default)]
        params: Params,
    },
    Response {
        #[serde(skip_serializing_if = "Option::is_none")]
        id: Option<Id>, // Should match the id from the request
        #[serde(skip_serializing_if = "Option::is_none")]
        result: Option<Value>,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<Error>,
    },
    Notification {
        #[serde(skip_serializing_if = "Option::is_none")]
        id: Option<Id>, // Notifications have null id or no id field
        method: String,
        #[serde(default)]
        params: Params,
    },
}

impl StratumMessage {
    /// Creates a new subscribe message with an optional id and params
    /// If no params are provided, it defaults to an empty array
    /// If no id is provided, it defaults to None
    /// The user agent and version are concatenated with a slash
    pub fn new_subscribe(
        id: Option<i32>,
        user_agent: String,
        version: String,
        extra_nonce: Option<String>,
    ) -> Self {
        let user_agent_param = user_agent + "/" + &version;
        let mut params = vec![json!(user_agent_param)];
        if extra_nonce.is_some() {
            let extra_nonce = extra_nonce.unwrap();
            params.push(json!(extra_nonce));
        }
        StratumMessage::Request {
            id: id.map(Id::Number),
            method: "mining.subscribe".to_string(),
            params: Params::Array(params),
        }
    }

    /// Creates a new authorize message
    /// If no id is provided, it defaults to None
    /// The username and password are passed as parameters
    pub fn new_authorize(id: Option<i32>, username: String, password: Option<String>) -> Self {
        let mut params = vec![json!(username)];
        if let Some(password) = password {
            params.push(json!(password));
        }
        StratumMessage::Request {
            id: id.map(Id::Number),
            method: "mining.authorize".to_string(),
            params: Params::Array(params),
        }
    }

    /// Creates a new submit message
    /// The server never creates this message, but it is used by the client to submit work
    pub fn new_submit(
        id: Option<i32>,
        username: String,
        job_id: String,
        extra_nonce2: String,
        n_time: String,
        nonce: String,
    ) -> Self {
        let params = Params::Array(vec![
            json!(username),
            json!(job_id),
            json!(extra_nonce2),
            json!(n_time),
            json!(nonce),
        ]);
        StratumMessage::Request {
            id: id.map(Id::Number),
            method: "mining.submit".to_string(),
            params,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_new_subscribe() {
        let message =
            StratumMessage::new_subscribe(None, "agent".to_string(), "1.0".to_string(), None);
        let serialized_message = serde_json::to_string(&message).unwrap();
        assert_eq!(
            serialized_message,
            r#"{"method":"mining.subscribe","params":["agent/1.0"]}"#
        );

        let message =
            StratumMessage::new_subscribe(Some(42), "agent".to_string(), "1.0".to_string(), None);

        let serialized_message = serde_json::to_string(&message).unwrap();
        assert_eq!(
            serialized_message,
            r#"{"id":42,"method":"mining.subscribe","params":["agent/1.0"]}"#
        );
    }

    #[test]
    fn test_new_authorize() {
        let message = StratumMessage::new_authorize(
            None,
            "username".to_string(),
            Some("password".to_string()),
        );

        let serialized_message = serde_json::to_string(&message).unwrap();
        assert_eq!(
            serialized_message,
            r#"{"method":"mining.authorize","params":["username","password"]}"#
        );

        let message = StratumMessage::new_authorize(
            Some(1),
            "username".to_string(),
            Some("password".to_string()),
        );

        let serialized_message = serde_json::to_string(&message).unwrap();
        assert_eq!(
            serialized_message,
            r#"{"id":1,"method":"mining.authorize","params":["username","password"]}"#
        );
    }

    #[test]
    fn test_new_submit() {
        let message = StratumMessage::new_submit(
            None,
            "worker_name".to_string(),
            "job_id".to_string(),
            "extra_nonce2".to_string(),
            "ntime".to_string(),
            "nonce".to_string(),
        );
        let serialized_message = serde_json::to_string(&message).unwrap();
        assert_eq!(
            serialized_message,
            r#"{"method":"mining.submit","params":["worker_name","job_id","extra_nonce2","ntime","nonce"]}"#
        );

        let message = StratumMessage::new_submit(
            Some(5),
            "worker_name".to_string(),
            "job_id".to_string(),
            "extra_nonce2".to_string(),
            "ntime".to_string(),
            "nonce".to_string(),
        );
        let serialized_message = serde_json::to_string(&message).unwrap();
        assert_eq!(
            serialized_message,
            r#"{"id":5,"method":"mining.submit","params":["worker_name","job_id","extra_nonce2","ntime","nonce"]}"#
        );
    }
}
