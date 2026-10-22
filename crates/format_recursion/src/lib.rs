//! Experimental compilation of the complete quotient verifier into the Boolean circuit format.
//! The child circuit and proof shapes are fixed; proof contents remain circuit inputs.

mod boolean_field;
pub mod hash_batch;
pub mod replay;
pub mod trace;
mod verifier;

pub use verifier::{Child, record};
