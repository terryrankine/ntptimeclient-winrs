//! Sans-IO core of the NTP client. It takes events in and returns actions out.
//! It never touches the clock, the network or the file system.

pub mod discipline;
pub mod engine;
mod error;
pub mod filter;
mod ports;
pub mod select;
pub mod tier;
mod types;

pub use error::{ClockError, StoreError};
pub use ports::{Clock, DriftStore};
pub use types::{
    Delay, KodCode, Mono, Offset, Ppm, QueryFailure, Sample, SourceId, SourceSpec, Tier,
};

/// Crate name, used by the smoke test.
pub const CRATE_NAME: &str = "ntpc-core";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crate_name_matches_package() {
        assert_eq!(CRATE_NAME, env!("CARGO_PKG_NAME"));
    }
}
