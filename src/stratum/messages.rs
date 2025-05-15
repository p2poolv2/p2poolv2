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

use std::borrow::Cow;
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

/// StratumError represents the error structure in Stratum responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Error<'a> {
    pub code: i32,
    #[serde(borrow)]
    pub message: Cow<'a, str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// Request represents a Stratum request message from client to the server
/// The params in this message are all strings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Id>,
    #[serde(borrow)]
    pub method: Cow<'a, str>,
    #[serde(borrow, default)]
    pub params: Cow<'a, Vec<String>>, // All params in stratum requests are strings
}

/// Response represents a Stratum response message from the server to the client
/// We use Value in result to allow for different types of responses.
/// TODO: Consider using various Response types to avoing using Value (which will result in memory allocations)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Id>, // Should match the id from the request
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none", borrow)]
    pub error: Option<Error<'a>>,
}

/// The mining.notify message is used to notify the client of new work
/// The params is an array of strings and one element is a nested array of strings (the merkle branches)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notify<'a> {
    #[serde(borrow)]
    pub method: Cow<'a, str>,
    #[serde(borrow)]
    pub params: Cow<'a, NotifyParams<'a>>,
}

/// mining.set_difficulty message is used to notify the client of a change in difficulty
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetDifficultyNotification<'a> {
    #[serde(borrow)]
    pub method: Cow<'a, str>,
    pub params: Vec<u64>,
}

/// NotifyParams represents the parameters for the mining.notify message
/// It includes job_id, prevhash, coinbase1, coinbase2, merkle_branches,
/// version, nbits, ntime, and clean_jobs
#[derive(Debug, Clone)]
pub struct NotifyParams<'a> {
    pub job_id: Cow<'a, str>,
    pub prevhash: Cow<'a, str>,
    pub coinbase1: Cow<'a, str>,
    pub coinbase2: Cow<'a, str>,
    pub merkle_branches: Vec<Cow<'a, str>>,
    pub version: Cow<'a, str>,
    pub nbits: Cow<'a, str>,
    pub ntime: Cow<'a, str>,
    pub clean_jobs: bool,
}

// Custom serializer to output an array format instead of keyed object
impl Serialize for NotifyParams<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeSeq;

        let mut seq = serializer.serialize_seq(Some(9))?;
        seq.serialize_element(&self.job_id)?;
        seq.serialize_element(&self.prevhash)?;
        seq.serialize_element(&self.coinbase1)?;
        seq.serialize_element(&self.coinbase2)?;
        seq.serialize_element(&self.merkle_branches)?;
        seq.serialize_element(&self.version)?;
        seq.serialize_element(&self.nbits)?;
        seq.serialize_element(&self.ntime)?;
        seq.serialize_element(&self.clean_jobs)?;
        seq.end()
    }
}

// Custom deserializer to parse the array format into NotifyParams
impl<'de> Deserialize<'de> for NotifyParams<'_> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let vec: Vec<Value> = Vec::deserialize(deserializer)?;
        if vec.len() != 9 {
            return Err(serde::de::Error::custom("Invalid number of fields"));
        }

        Ok(NotifyParams {
            job_id: Cow::Owned(vec[0].as_str().unwrap_or_default().to_string()),
            prevhash: Cow::Owned(vec[1].as_str().unwrap_or_default().to_string()),
            coinbase1: Cow::Owned(vec[2].as_str().unwrap_or_default().to_string()),
            coinbase2: Cow::Owned(vec[3].as_str().unwrap_or_default().to_string()),
            merkle_branches: vec
                .get(4)
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .map(|v| Cow::Owned(v.as_str().unwrap_or_default().to_string()))
                        .collect()
                })
                .unwrap_or_default(),
            version: Cow::Owned(vec[5].as_str().unwrap_or_default().to_string()),
            nbits: Cow::Owned(vec[6].as_str().unwrap_or_default().to_string()),
            ntime: Cow::Owned(vec[7].as_str().unwrap_or_default().to_string()),
            clean_jobs: vec[8].as_bool().unwrap_or(false),
        })
    }
}

/// Request represents a Stratum request message from client to the server
/// It includes the id, method, and params
/// The methods supported are mining.subscribe, mining.authorize, and mining.submit
impl Request<'_> {
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
        let mut params = vec![(user_agent_param)];
        if extra_nonce.is_some() {
            let extra_nonce = extra_nonce.unwrap();
            params.push(extra_nonce);
        }
        Request {
            id: id.map(Id::Number),
            method: Cow::Owned("mining.subscribe".to_string()),
            params: Cow::Owned(params),
        }
    }

    /// Creates a new authorize message
    /// If no id is provided, it defaults to None
    /// The username and password are passed as parameters
    pub fn new_authorize(id: Option<u64>, username: String, password: Option<String>) -> Self {
        let mut params = vec![(username)];
        if let Some(password) = password {
            params.push(password);
        }
        Request {
            id: id.map(Id::Number),
            method: Cow::Owned("mining.authorize".to_string()),
            params: Cow::Owned(params),
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
        let params = vec![username, job_id, extra_nonce2, n_time, nonce];
        Request {
            id: id.map(Id::Number),
            method: Cow::Owned("mining.submit".to_string()),
            params: Cow::Owned(params),
        }
    }
}

/// Response represents a Stratum response message from the server to the client
/// Supported resposes are set_difficulty (in response to subscribe), ok and error.
impl Response<'_> {
    pub fn new_set_difficulty_response(
        id: Option<Id>,
        difficulty: u64,
        extra_nonce: String,
        extra_nonce_size: u8,
    ) -> Self {
        let response_details = vec![
            json!("mining.set_difficulty"),
            json!(difficulty),
            json!(extra_nonce),
            json!(extra_nonce_size),
        ];
        Response {
            id,
            result: Some(Value::Array(response_details)),
            error: None,
        }
    }

    pub fn new_ok(id: Option<Id>, result: Value) -> Self {
        Response {
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn new_error(id: Option<Id>, code: i32, message: String) -> Self {
        Response {
            id,
            result: None,
            error: Some(Error {
                code,
                message: Cow::Owned(message),
                data: None,
            }),
        }
    }
}

/// Notify represents a Stratum notification message from the server to the client
/// It is used to notify the client of new work and changes in difficulty
impl<'a> Notify<'a> {
    /// Creates a new notify message with the given parameters
    pub fn new_notify(params: NotifyParams<'a>) -> Self {
        Notify {
            method: Cow::Owned("mining.notify".to_string()),
            params: Cow::Owned(params),
        }
    }

    /// Creates a new set_difficulty notification message
    pub fn new_set_difficulty_notification(difficulty: u64) -> SetDifficultyNotification<'a> {
        SetDifficultyNotification {
            method: Cow::Owned("mining.set_difficulty".to_string()),
            params: vec![difficulty],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_subscribe() {
        let message = Request::new_subscribe(None, "agent".to_string(), "1.0".to_string(), None);
        let serialized_message = serde_json::to_string(&message).unwrap();
        assert_eq!(
            serialized_message,
            r#"{"method":"mining.subscribe","params":["agent/1.0"]}"#
        );

        let message = Request::new_subscribe(
            Some(42),
            "agent".to_string(),
            "1.0".to_string(),
            Some("extra_nonce".to_string()),
        );

        let serialized_message = serde_json::to_string(&message).unwrap();
        assert_eq!(
            serialized_message,
            r#"{"id":42,"method":"mining.subscribe","params":["agent/1.0","extra_nonce"]}"#
        );
    }

    #[test]
    fn test_new_authorize() {
        let message =
            Request::new_authorize(None, "username".to_string(), Some("password".to_string()));

        let serialized_message = serde_json::to_string(&message).unwrap();
        assert_eq!(
            serialized_message,
            r#"{"method":"mining.authorize","params":["username","password"]}"#
        );

        let message = Request::new_authorize(
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
        let message = Request::new_submit(
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

        let message = Request::new_submit(
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

    #[test]
    fn test_new_notify() {
        let notify_params = NotifyParams {
            job_id: Cow::Borrowed("job_id"),
            prevhash: Cow::Borrowed("prevhash"),
            coinbase1: Cow::Borrowed("coinbase1"),
            coinbase2: Cow::Borrowed("coinbase2"),
            merkle_branches: vec![Cow::Borrowed("branch1"), Cow::Borrowed("branch2")],
            version: Cow::Borrowed("version"),
            nbits: Cow::Borrowed("nbits"),
            ntime: Cow::Borrowed("ntime"),
            clean_jobs: true,
        };

        let message = Notify::new_notify(notify_params);
        let serialized_message = serde_json::to_string(&message).unwrap();
        assert_eq!(
            serialized_message,
            r#"{"method":"mining.notify","params":["job_id","prevhash","coinbase1","coinbase2",["branch1","branch2"],"version","nbits","ntime",true]}"#
        );
    }

    #[test]
    fn test_new_set_difficulty_response() {
        // Test with numeric ID
        let response = Response::new_set_difficulty_response(
            Some(Id::Number(123)),
            500,
            "extranonce_value".to_string(),
            8,
        );
        let serialized = serde_json::to_string(&response).unwrap();
        assert!(serialized.contains(r#""id":123"#));
        assert!(serialized.contains(r#""mining.set_difficulty""#));
        assert!(serialized.contains("500"));
        assert!(serialized.contains(r#""extranonce_value""#));
        assert!(serialized.contains("8"));

        // Test with string ID
        let response = Response::new_set_difficulty_response(
            Some(Id::String("test-id".to_string())),
            1000,
            "nonce42".to_string(),
            4,
        );
        let serialized = serde_json::to_string(&response).unwrap();
        assert!(serialized.contains(r#""id":"test-id""#));
        assert!(serialized.contains("1000"));
        assert!(serialized.contains(r#""nonce42""#));
        assert!(serialized.contains("4"));
    }

    #[test]
    fn test_new_set_difficulty_notification() {
        let message = Notify::new_set_difficulty_notification(1000);
        let serialized_message = serde_json::to_string(&message).unwrap();
        assert_eq!(
            serialized_message,
            r#"{"method":"mining.set_difficulty","params":[1000]}"#
        );
    }

    #[test]
    fn test_error_serialization() {
        let error = Error {
            code: -1,
            message: Cow::Owned("An error occurred".to_string()),
            data: Some(json!("Additional error data")),
        };
        let serialized_error = serde_json::to_string(&error).unwrap();
        assert_eq!(
            serialized_error,
            r#"{"code":-1,"message":"An error occurred","data":"Additional error data"}"#
        );
    }

    #[test]
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

    #[test]
    fn test_id_variants() {
        // Test number ID
        let json = r#"{"id":123,"method":"test","params":[]}"#;
        let message: Request = serde_json::from_str(json).unwrap();
        match message {
            Request { id, .. } => {
                assert_eq!(id, Some(Id::Number(123)));
            }
            _ => panic!("Expected request message"),
        }

        // Test string ID
        let json = r#"{"id":"abc","method":"test","params":[]}"#;
        let message: Request = serde_json::from_str(json).unwrap();
        match message {
            Request { id, .. } => {
                assert_eq!(id, Some(Id::String("abc".to_string())));
            }
            _ => panic!("Expected request message"),
        }

        // Test null ID
        let json = r#"{"id":null,"method":"test","params":[]}"#;
        let message: Request = serde_json::from_str(json).unwrap();
        match message {
            Request { id, .. } => {
                assert_eq!(id, None);
            }
            _ => panic!("Expected request message"),
        }
    }

    #[test]
    fn test_id_conversions() {
        // From ()
        let id_none = Id::from(());
        assert!(matches!(id_none, Id::None(())));

        // From i64
        let id_number = Id::from(42i64);
        assert!(matches!(id_number, Id::Number(42)));

        // From String
        let id_string = Id::from("test".to_string());
        assert!(matches!(id_string, Id::String(ref s) if s == "test"));

        // PartialEq tests
        assert_eq!(Id::Number(42), Id::Number(42));
        assert_ne!(Id::Number(42), Id::Number(43));
        assert_eq!(
            Id::String("test".to_string()),
            Id::String("test".to_string())
        );
        assert_ne!(
            Id::String("test".to_string()),
            Id::String("other".to_string())
        );
        assert_eq!(Id::None(()), Id::None(()));
        assert_ne!(Id::Number(42), Id::String("42".to_string()));
        assert_ne!(Id::None(()), Id::Number(0));
    }

    #[test]
    fn test_response_creation() {
        // Test new_ok
        let response = Response::new_ok(Some(Id::Number(1)), json!("success"));
        assert_eq!(response.id, Some(Id::Number(1)));
        assert_eq!(response.result, Some(json!("success")));
        assert!(response.error.is_none());

        // Test new_error
        let response = Response::new_error(
            Some(Id::String("abc".to_string())),
            -32601,
            "Method not found".to_string(),
        );
        assert_eq!(response.id, Some(Id::String("abc".to_string())));
        assert!(response.result.is_none());
        assert!(response.error.is_some());
        assert_eq!(response.error.as_ref().unwrap().code, -32601);
        assert_eq!(response.error.as_ref().unwrap().message, "Method not found");

        // Test new_set_difficulty
        let response = Response::new_set_difficulty_response(
            Some(Id::Number(2)),
            500,
            "abc123".to_string(),
            4,
        );
        assert_eq!(response.id, Some(Id::Number(2)));
        assert!(response.result.is_some());
        assert!(response.error.is_none());

        if let Some(Value::Array(arr)) = response.result {
            assert_eq!(arr.len(), 4);
            assert_eq!(arr[0], json!("mining.set_difficulty"));
            assert_eq!(arr[1], json!(500));
            assert_eq!(arr[2], json!("abc123"));
            assert_eq!(arr[3], json!(4));
        } else {
            panic!("Expected array result");
        }
    }
}
