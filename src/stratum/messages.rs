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
    Number(u64),
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
        Id::Number(val as u64)
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

/// NotifyParams represents the parameters for the mining.notify message
/// It includes job_id, prevhash, coinbase1, coinbase2, merkle_branches,
/// version, nbits, ntime, and clean_jobs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotifyParams {
    job_id: String,
    prevhash: String,
    coinbase1: String,
    coinbase2: String,
    merkle_branches: Vec<String>,
    version: String,
    nbits: String,
    ntime: String,
    clean_jobs: bool,
}

impl From<NotifyParams> for Params {
    fn from(params: NotifyParams) -> Self {
        Params::Array(vec![
            json!(params.job_id),
            json!(params.prevhash),
            json!(params.coinbase1),
            json!(params.coinbase2),
            json!(params.merkle_branches),
            json!(params.version),
            json!(params.nbits),
            json!(params.ntime),
            json!(params.clean_jobs),
        ])
    }
}

impl StratumMessage {
    /// Creates a new subscribe message with an optional id and params
    /// If no params are provided, it defaults to an empty array
    /// If no id is provided, it defaults to None
    /// The user agent and version are concatenated with a slash
    pub fn new_subscribe(
        id: Option<u64>,
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
    pub fn new_authorize(id: Option<u64>, username: String, password: Option<String>) -> Self {
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
        id: Option<u64>,
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

    pub fn new_notify(id: Option<u64>, params: NotifyParams) -> Self {
        StratumMessage::Notification {
            id: id.map(Id::Number),
            method: "mining.notify".to_string(),
            params: params.into(),
        }
    }

    pub fn new_set_difficulty(id: Option<u64>, difficulty: u64) -> Self {
        StratumMessage::Notification {
            id: id.map(Id::Number),
            method: "mining.set_difficulty".to_string(),
            params: Params::Array(vec![json!(difficulty)]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn test_new_notify() {
        let notify_params = NotifyParams {
            job_id: "job_id".to_string(),
            prevhash: "prevhash".to_string(),
            coinbase1: "coinbase1".to_string(),
            coinbase2: "coinbase2".to_string(),
            merkle_branches: vec!["branch1".to_string(), "branch2".to_string()],
            version: "version".to_string(),
            nbits: "nbits".to_string(),
            ntime: "ntime".to_string(),
            clean_jobs: true,
        };

        let message = StratumMessage::new_notify(Some(1), notify_params);
        let serialized_message = serde_json::to_string(&message).unwrap();
        assert_eq!(
            serialized_message,
            r#"{"id":1,"method":"mining.notify","params":["job_id","prevhash","coinbase1","coinbase2",["branch1","branch2"],"version","nbits","ntime",true]}"#
        );
    }

    fn test_new_set_difficulty() {
        let message = StratumMessage::new_set_difficulty(Some(1), 1000);
        let serialized_message = serde_json::to_string(&message).unwrap();
        assert_eq!(
            serialized_message,
            r#"{"id":1,"method":"mining.set_difficulty","params":[1000]}"#
        );
    }

    fn test_error_serialization() {
        let error = Error {
            code: -1,
            message: "An error occurred".to_string(),
            data: Some(json!("Additional error data")),
        };
        let serialized_error = serde_json::to_string(&error).unwrap();
        assert_eq!(
            serialized_error,
            r#"{"code":-1,"message":"An error occurred","data":"Additional error data"}"#
        );
    }

    fn test_id_serialization_handle_non_numbers() {
        let id_number = Id::Number(42);
        let serialized_id_number = serde_json::to_string(&id_number).unwrap();
        assert_eq!(serialized_id_number, "42");

        let id_string = Id::String("test".to_string());
        let serialized_id_string = serde_json::to_string(&id_string).unwrap();
        assert_eq!(serialized_id_string, r#""test""#);

        let id_none = Id::None(());
        let serialized_id_none = serde_json::to_string(&id_none).unwrap();
        assert_eq!(serialized_id_none, "null");
    }
}
