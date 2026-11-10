//! Service wiring. Config and runtime arrive in later tasks.

pub mod cli;
pub mod config;
pub mod drift_store;
pub mod host;
pub mod logging;
pub mod proto;
pub mod resolver;
mod safe_open;
pub mod status;
pub mod transport;

/// Crate name, used by the smoke test.
pub const CRATE_NAME: &str = "ntpc-service";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crate_name_matches_package() {
        assert_eq!(CRATE_NAME, env!("CARGO_PKG_NAME"));
    }

    #[test]
    fn depends_on_platform_and_core() {
        assert_eq!(ntpc_platform::CRATE_NAME, "ntpc-platform");
        assert_eq!(ntpc_core::CRATE_NAME, "ntpc-core");
    }
}
