//! Rust port of [croc](https://github.com/schollz/croc), a tool for easily
//! and securely sending files between two computers.
//!
//! The module layout mirrors the Go source tree (`src/<pkg>` → `src/<pkg>.rs`)
//! so the two codebases can be compared side by side during the migration.
//! Wire formats are kept byte-compatible with croc v10 wherever a module is
//! marked as such — see MIGRATION.md for the compatibility matrix.

pub mod comm;
pub mod compress;
pub mod croc;
pub mod crypt;
pub mod discovery;
pub mod message;
pub mod mnemonicode;
pub mod models;
pub mod pake;
pub mod pakekey;
pub mod tcp;
pub mod utils;
