//! Local ML primitives used by the grounded analysis layer.
//!
//! Only the isolation forest model is retained; it is fitted at runtime
//! on features extracted from the REAL process evidence of the open
//! case (see `analysis::ml`).

pub mod models;
