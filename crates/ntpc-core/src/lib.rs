//! Sans-IO core of the NTP client. It takes events in and returns actions out.
//! It never touches the clock, the network or the file system.

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
