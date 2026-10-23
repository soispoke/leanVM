//! Experimental compilation of the complete quotient verifier into the Boolean circuit format.
//! The child circuit and proof shapes are fixed; proof contents remain circuit inputs.

mod boolean_field;
pub mod closed_recursion;
pub mod flock_trace;
pub mod hash_batch;
pub mod hometurf_application;
pub mod native_arithmetic;
pub mod native_hash;
pub mod native_recursion;
pub mod private_bridge;
pub mod private_recursion;
pub mod private_trace;
pub mod public_plan;
pub mod recursion_fast;
pub mod replay;
pub mod trace;
mod verifier;
pub mod xmss_application;

pub use verifier::{Child, record, record_bound};

pub mod native_verifier;

pub mod private_verifier;

pub mod lookup_reduction;
pub mod shielded_application;
pub mod shielded_lookup;
pub mod shielded_lookup_prototype;

pub mod application_lowering;
