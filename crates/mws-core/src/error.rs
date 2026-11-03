use std::borrow::Cow;
use std::fmt;

/// Which side AWS blames for an error. Query protocols surface this as
/// `<Type>Sender</Type>` / `<Type>Receiver</Type>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorFault {
    Client,
    Server,
}

/// A protocol-neutral AWS error. Each protocol crate knows how to render it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceError {
    /// The wire error code, e.g. `NoSuchEntity` or `ValidationError`.
    pub code: Cow<'static, str>,
    pub message: String,
    pub status: u16,
    pub fault: ErrorFault,
    /// Extra modeled members of the error shape (beyond the message), in
    /// wire order.
    pub fields: Vec<ErrorField>,
}

/// An extra member of a modeled error, e.g. Route 53's
/// `InvalidChangeBatch.messages`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorField {
    /// Wire name of the member.
    pub name: String,
    pub value: ErrorValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorValue {
    String(String),
    /// A list of strings; `item` is the XML element name of each entry.
    List {
        item: String,
        values: Vec<String>,
    },
}

impl ServiceError {
    pub fn new(code: impl Into<Cow<'static, str>>, status: u16, fault: ErrorFault, message: impl Into<String>) -> Self {
        Self { code: code.into(), message: message.into(), status, fault, fields: Vec::new() }
    }

    /// Attach an extra modeled member.
    pub fn with_field(mut self, name: impl Into<String>, value: ErrorValue) -> Self {
        self.fields.push(ErrorField { name: name.into(), value });
        self
    }

    pub fn client(code: impl Into<Cow<'static, str>>, status: u16, message: impl Into<String>) -> Self {
        Self::new(code, status, ErrorFault::Client, message)
    }

    pub fn server(code: impl Into<Cow<'static, str>>, status: u16, message: impl Into<String>) -> Self {
        Self::new(code, status, ErrorFault::Server, message)
    }

    // ---- errors that every AWS service shares -------------------------------

    pub fn missing_authentication_token() -> Self {
        Self::client(
            "MissingAuthenticationToken",
            403,
            "Request must contain either a valid (registered) AWS access key ID or X.509 certificate.",
        )
    }

    pub fn incomplete_signature(message: impl Into<String>) -> Self {
        Self::client("IncompleteSignature", 400, message)
    }

    pub fn invalid_client_token_id() -> Self {
        Self::client("InvalidClientTokenId", 403, "The security token included in the request is invalid.")
    }

    pub fn expired_token() -> Self {
        Self::client("ExpiredToken", 403, "The security token included in the request is expired")
    }

    pub fn signature_does_not_match() -> Self {
        Self::client(
            "SignatureDoesNotMatch",
            403,
            "The request signature we calculated does not match the signature you provided. Check your AWS Secret Access Key and signing method. Consult the service documentation for details.",
        )
    }

    pub fn invalid_action(action: &str) -> Self {
        Self::client("InvalidAction", 400, format!("Could not find operation {action} for version"))
    }

    pub fn missing_action() -> Self {
        Self::client("MissingAction", 400, "Missing Action")
    }

    pub fn not_implemented(operation: &str) -> Self {
        Self::server("NotImplemented", 501, format!("MWS does not implement the {operation} operation yet."))
    }

    /// An operation name the service's model does not define.
    pub fn unknown_operation(operation: &str) -> Self {
        Self::client("UnknownOperation", 400, format!("The service has no operation named {operation}."))
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::server("InternalFailure", 500, message)
    }
}

impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({}): {}", self.code, self.status, self.message)
    }
}

impl std::error::Error for ServiceError {}
