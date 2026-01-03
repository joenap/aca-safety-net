//! Tool analysis entry points.

mod bash;
mod read;

pub use bash::analyze_bash;
pub use read::analyze_read;
