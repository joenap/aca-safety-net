//! Output formatting and response generation.

mod redaction;
mod response;

pub use redaction::redact_secrets;
pub use response::format_response;
