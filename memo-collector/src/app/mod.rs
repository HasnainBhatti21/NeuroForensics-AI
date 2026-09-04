//! Application layer: shared state and the acquisition engine.

pub mod engine;
pub mod state;

pub use engine::{run_acquisition, verify_case, AcquisitionParams};
pub use state::{AppState, Screen};
