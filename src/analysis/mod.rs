//! Tool analysis entry points.

mod bash;
mod edit;
mod read;
mod write;

pub use bash::analyze_bash;
pub use edit::analyze_edit;
pub use read::analyze_read;
pub use write::analyze_write;
