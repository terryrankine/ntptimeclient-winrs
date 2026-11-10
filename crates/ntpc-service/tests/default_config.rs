//! The shipped `packaging/default-config.toml` must parse, validate and say
//! exactly what the code defaults say. If a default changes, this fails and
//! the file in the preview zip gets updated with it.

use ntpc_service::config::Config;

const SHIPPED: &str = include_str!("../../../packaging/default-config.toml");

#[test]
fn shipped_default_config_equals_the_code_defaults() {
    let parsed = Config::parse(SHIPPED).expect("shipped default config must parse and validate");
    assert_eq!(parsed, Config::default());
}

#[test]
fn shipped_default_config_is_not_an_empty_file() {
    // An empty file also equals the defaults. The shipped file must name
    // every key so a reader can see them.
    for key in [
        "servers",
        "dhcp",
        "pool",
        "step_threshold_ms",
        "panic_threshold_s",
        "allow_panic_step",
        "min_poll_s",
        "max_poll_s",
        "state_dir",
    ] {
        assert!(
            SHIPPED.lines().any(|l| l.starts_with(&format!("{key} = "))),
            "key {key} is not set in the shipped file"
        );
    }
}
