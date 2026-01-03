//! Shell command parsing.

mod splitter;
mod tokenizer;
mod wrappers;

pub use splitter::{split_commands, CommandSegment, Operator};
pub use tokenizer::{tokenize, Token};
pub use wrappers::{strip_wrappers, extract_options};
