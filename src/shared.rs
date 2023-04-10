use core::fmt;
use reqwest::Error as ReqwestError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub enum ErrorKind {
    Request,
    Response,
}

#[derive(Debug, Clone)]
pub struct Error {
    pub kind: ErrorKind,
}

impl Error {
    pub fn new(kind: ErrorKind) -> Error {
        Error { kind }
    }
}

impl From<&ReqwestError> for Error {
    fn from(reqwest_error: &ReqwestError) -> Self {
        if reqwest_error.is_request() {
            Error::new(ErrorKind::Request)
        } else {
            Error::new(ErrorKind::Response)
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // TODO: write different msgs for different error types
        write!(f, "Error TODO")
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AccountResponse {
    pub account: AccountInfo,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AccountInfo {
    pub account_number: String,
    pub sequence: String,
}
