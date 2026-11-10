use std::time::Duration;

use super::*;

fn ok(text: &str) -> Config {
    Config::parse(text).unwrap_or_else(|e| panic!("should parse: {e}"))
}

fn err(text: &str) -> ConfigError {
    Config::parse(text).expect_err("should be rejected")
}

fn invalid_text(text: &str) -> String {
    match err(text) {
        ConfigError::Invalid(m) => m,
        other => panic!("expected Invalid, got {other:?}"),
    }
}

#[test]
fn defaults_match_the_spec() {
    let c = Config::default();
    assert!(c.servers.is_empty(), "no manual servers");
    assert!(c.dhcp, "DHCP on");
    assert_eq!(c.pool, "pool.ntp.org");
    assert_eq!(c.step_threshold_ms, 128);
    assert_eq!(c.panic_threshold_s, 1000);
    assert!(!c.allow_panic_step);
    assert_eq!(c.min_poll_s, 64);
    assert_eq!(c.max_poll_s, 1024);
    assert_eq!(
        c.state_dir,
        PathBuf::from(r"C:\ProgramData\ntptimeclient-winrs")
    );
    c.validate().expect("the default is valid");
}

#[test]
fn empty_file_gives_defaults() {
    assert_eq!(ok(""), Config::default());
    assert_eq!(ok("# only a comment\n\n"), Config::default());
}

#[test]
fn engine_defaults_equal_config_defaults_except_max_age() {
    // R59: max_age follows max_poll. Nothing else moves.
    let mut want = EngineConfig::default();
    want.selection.max_age = Duration::from_secs(2 * 1024 + 30);
    assert_eq!(Config::default().engine_config(), want);
}

#[test]
fn max_age_is_two_polls_and_30_seconds() {
    for (max_poll, want) in [(64, 158), (100, 230), (1024, 2078)] {
        let c = ok(&format!("max_poll_s = {max_poll}\n"));
        assert_eq!(
            c.engine_config().selection.max_age,
            Duration::from_secs(want)
        );
    }
    // The other selection fields keep the engine default.
    let d = EngineConfig::default().selection;
    let s = Config::default().engine_config().selection;
    assert_eq!(
        (s.min_survivors, s.max_stratum),
        (d.min_survivors, d.max_stratum)
    );
}

#[test]
fn cross_check_cap_is_unchanged_at_the_default_poll() {
    // The engine caps the cross-check window at min(max_age, reprobe_every).
    let e = Config::default().engine_config();
    assert_eq!(
        e.selection.max_age.min(e.tier.reprobe_every),
        EngineConfig::default()
            .selection
            .max_age
            .min(EngineConfig::default().tier.reprobe_every)
    );
}

#[test]
fn step_threshold_must_be_at_least_min_poll() {
    let cases = [
        (64, 63, false),
        (64, 64, true),
        (64, 65, true),
        (128, 127, false),
        (128, 128, true),
        (100, 99, false),
    ];
    for (min_poll, step, good) in cases {
        let r = Config::parse(&format!(
            "min_poll_s = {min_poll}\nstep_threshold_ms = {step}\n"
        ));
        assert_eq!(r.is_ok(), good, "min_poll {min_poll} step {step}: {r:?}");
    }
    let m = invalid_text("step_threshold_ms = 63\n");
    assert!(
        m.contains("step_threshold_ms") && m.contains("min_poll_s") && m.contains("cross-check"),
        "{m}"
    );
    // The default 128 ms still fits the largest allowed min_poll of 128 s.
    assert!(Config::parse("min_poll_s = 128\n").is_ok());
    Config::default().validate().expect("defaults are valid");
}

#[test]
fn bare_and_local_names_warn() {
    let c = ok(
        r#"servers = ["ntp", "pool.local", "Host.LOCAL.", "time.example.com", "192.0.2.1", "::1"]"#,
    );
    let w = c.warnings();
    assert_eq!(w.len(), 3, "{w:?}");
    assert!(w[0].contains("servers[0]") && w[0].contains("LLMNR"));
    assert!(w[1].contains("servers[1]"));
    assert!(w[2].contains("servers[2]"));
    assert_eq!(Config::default().warnings().len(), 0);
}

#[test]
fn a_bare_pool_name_warns() {
    let c = ok("pool = \"ntp\"\n");
    let w = c.warnings();
    assert_eq!(w.len(), 1);
    assert!(w[0].starts_with("pool "));
}

#[test]
fn full_file_parses() {
    let c = ok(r#"
        servers = ["time.example.com", "192.0.2.7", "2001:db8::1"]
        dhcp = false
        pool = "au.pool.ntp.org"
        step_threshold_ms = 200
        panic_threshold_s = 600
        allow_panic_step = true
        min_poll_s = 100
        max_poll_s = 512
        state_dir = 'D:\state'
    "#);
    assert_eq!(c.servers, ["time.example.com", "192.0.2.7", "2001:db8::1"]);
    assert!(!c.dhcp);
    assert_eq!(c.pool, "au.pool.ntp.org");
    assert_eq!(c.step_threshold_ms, 200);
    assert_eq!(c.panic_threshold_s, 600);
    assert!(c.allow_panic_step);
    assert_eq!(c.min_poll_s, 100);
    assert_eq!(c.max_poll_s, 512);
    assert_eq!(c.state_dir, PathBuf::from(r"D:\state"));
}

#[test]
fn partial_file_keeps_other_defaults() {
    let c = ok("dhcp = false\n");
    assert!(!c.dhcp);
    assert_eq!(Config { dhcp: true, ..c }, Config::default());
}

#[test]
fn rejects_unknown_keys() {
    let e = err("bogus = 1\n");
    assert!(matches!(e, ConfigError::Parse { .. }), "{e:?}");
    assert!(e.to_string().contains("bogus"), "{e}");
    assert!(matches!(err("Dhcp = true"), ConfigError::Parse { .. }));
    assert!(matches!(err("[section]\nx = 1"), ConfigError::Parse { .. }));
}

#[test]
fn rejects_min_poll_above_max_poll() {
    let m = invalid_text("min_poll_s = 128\nmax_poll_s = 100\n");
    assert!(m.contains("min_poll_s") && m.contains("max_poll_s"), "{m}");
}

#[test]
fn min_poll_bounds_are_64_to_128() {
    for (v, good) in [
        (63, false),
        (64, true),
        (65, true),
        (128, true),
        (129, false),
    ] {
        let r = Config::parse(&format!("min_poll_s = {v}\n"));
        assert_eq!(r.is_ok(), good, "min_poll_s = {v}: {r:?}");
    }
    assert!(Config::parse("min_poll_s = 0").is_err());
    assert!(Config::parse("min_poll_s = 256").is_err());
}

#[test]
fn min_poll_error_names_the_reason() {
    let m = invalid_text("min_poll_s = 129\n");
    assert!(
        m.contains("min_poll_s") && m.contains("64") && m.contains("128"),
        "{m}"
    );
    assert!(m.contains("cross-check"), "{m}");
}

#[test]
fn max_poll_bounds_are_up_to_1024() {
    for (v, good) in [(1023, true), (1024, true), (1025, false)] {
        let r = Config::parse(&format!("max_poll_s = {v}\n"));
        assert_eq!(r.is_ok(), good, "max_poll_s = {v}: {r:?}");
    }
    let m = invalid_text("max_poll_s = 2048\n");
    assert!(m.contains("max_poll_s") && m.contains("1024"), "{m}");
    assert!(m.contains("hold"), "{m}");
}

#[test]
fn max_poll_below_the_minimum_poll_is_rejected() {
    assert!(Config::parse("max_poll_s = 63").is_err());
    assert!(Config::parse("max_poll_s = 64").is_ok());
}

#[test]
fn equal_poll_limits_are_allowed() {
    let c = ok("min_poll_s = 100\nmax_poll_s = 100\n");
    assert_eq!((c.min_poll_s, c.max_poll_s), (100, 100));
}

#[test]
fn rejects_zero_step_threshold() {
    let m = invalid_text("step_threshold_ms = 0\n");
    assert!(m.contains("step_threshold_ms"), "{m}");
}

#[test]
fn panic_threshold_must_exceed_step_threshold() {
    // 1 s is 1000 ms, so a 1000 ms step threshold equals a 1 s panic threshold.
    assert!(Config::parse("step_threshold_ms = 1000\npanic_threshold_s = 1").is_err());
    assert!(Config::parse("step_threshold_ms = 999\npanic_threshold_s = 1").is_ok());
    assert!(Config::parse("step_threshold_ms = 5000\npanic_threshold_s = 1").is_err());
    assert!(Config::parse("panic_threshold_s = 0").is_err());
    // Large values must not overflow the millisecond comparison.
    assert!(
        Config::parse("step_threshold_ms = 4294967295\npanic_threshold_s = 4294967295").is_ok()
    );
    let m = invalid_text("panic_threshold_s = 0\n");
    assert!(
        m.contains("panic_threshold_s") && m.contains("step_threshold_ms"),
        "{m}"
    );
}

#[test]
fn engine_config_maps_units() {
    let c = ok(r"
        step_threshold_ms = 250
        panic_threshold_s = 900
        allow_panic_step = true
        min_poll_s = 70
        max_poll_s = 800
    ");
    let e = c.engine_config();
    assert_eq!(e.discipline.step_threshold, Duration::from_millis(250));
    assert_eq!(e.discipline.panic_threshold, Duration::from_secs(900));
    assert!(e.discipline.allow_panic_step);
    assert_eq!(e.min_poll, Duration::from_secs(70));
    assert_eq!(e.max_poll, Duration::from_secs(800));
    // Everything the file cannot set keeps the engine default.
    let d = EngineConfig::default();
    assert_eq!(e.selection.max_age, Duration::from_secs(2 * 800 + 30));
    assert_eq!(e.selection.min_survivors, d.selection.min_survivors);
    assert_eq!(e.selection.max_stratum, d.selection.max_stratum);
    assert_eq!(e.tier, d.tier);
    assert_eq!(e.discipline.max_slew, d.discipline.max_slew);
}

#[test]
fn malformed_inputs_are_rejected_without_panic() {
    let cases = [
        "step_threshold_ms = -1",
        "min_poll_s = -64",
        "step_threshold_ms = 4294967296",
        "panic_threshold_s = 99999999999999999999999",
        "step_threshold_ms = 1.5",
        "dhcp = \"yes\"",
        "dhcp = 1",
        "allow_panic_step = \"false\"",
        "pool = 5",
        "servers = \"a.example\"",
        "servers = [1, 2]",
        "servers = [[\"a\"]]",
        "state_dir = 7",
        "dhcp = true\ndhcp = false",
        "servers = [\"a\"\n",
        "= 1",
        "dhcp = tru",
        "pool = \"unterminated",
        "\u{0}",
        "dhcp = true # ok\n\u{1}",
        "min_poll_s = 64\nmin_poll_s = 64",
        "[servers]\na = 1",
    ];
    for text in cases {
        let r = Config::parse(text);
        assert!(r.is_err(), "should reject {text:?}, got {r:?}");
    }
}

#[test]
fn server_entries_are_checked() {
    assert!(Config::parse(r#"servers = [""]"#).is_err());
    assert!(Config::parse(r#"servers = ["a b"]"#).is_err());
    assert!(Config::parse("servers = [\"a\\tb\"]").is_err());
    assert!(Config::parse("servers = [\"a\\nb\"]").is_err());
    assert!(Config::parse(r#"servers = ["host:123"]"#).is_err());
    assert!(Config::parse(r#"servers = ["http://x"]"#).is_err());
    assert!(Config::parse(r#"servers = ["-bad.example"]"#).is_err());
    assert!(Config::parse(r#"servers = ["a/b"]"#).is_err());
    let name = |last: usize| {
        let l = "a".repeat(63);
        format!("{l}.{l}.{l}.{}", "a".repeat(last))
    };
    let long = name(62);
    assert_eq!(long.len(), 254);
    assert!(Config::parse(&format!("servers = [\"{long}\"]")).is_err());
    assert!(Config::parse(&format!("servers = [\"{}\"]", "a".repeat(64))).is_err());
    let ok_len = name(61);
    assert_eq!(ok_len.len(), 253);
    assert!(Config::parse(&format!("servers = [\"{ok_len}\"]")).is_ok());
    assert!(Config::parse(r#"servers = ["time.example.com", "192.0.2.1", "::1"]"#).is_ok());
    assert!(Config::parse(r#"servers = ["time-1.example.com", "ntp_2.lan"]"#).is_ok());
}

#[test]
fn server_list_length_is_capped() {
    let many = |n: usize| {
        let items: Vec<String> = (0..n).map(|i| format!("\"h{i}.example\"")).collect();
        format!("servers = [{}]", items.join(","))
    };
    assert!(Config::parse(&many(16)).is_ok());
    let m = invalid_text(&many(17));
    assert!(m.contains("servers"), "{m}");
}

#[test]
fn pool_must_be_a_name() {
    assert!(Config::parse(r#"pool = """#).is_err());
    assert!(Config::parse(r#"pool = "a b""#).is_err());
    assert!(Config::parse(r#"pool = "0.pool.ntp.org""#).is_ok());
}

#[test]
fn state_dir_must_not_be_empty() {
    assert!(Config::parse(r#"state_dir = """#).is_err());
    assert!(Config::parse("state_dir = \"C:\\\\x\\u0000y\"").is_err());
}

#[cfg(windows)]
#[test]
fn state_dir_must_be_absolute_on_windows() {
    assert!(Config::parse(r#"state_dir = "state""#).is_err());
    assert!(Config::parse(r"state_dir = '..\x'").is_err());
}

#[test]
fn parse_error_has_position_and_no_other_lines_of_the_file() {
    let secret = "SuperSecretValue123";
    let text = format!("dhcp = true\nservers = \"{secret}\"\n");
    let e = err(&text);
    let shown = format!("{e} {e:?}");
    assert!(shown.contains("line 2"), "{shown}");
    assert!(!shown.contains("dhcp = true"), "{shown}");
    assert!(!shown.contains("servers = "), "{shown}");
}

#[test]
fn oversize_text_is_rejected() {
    let big = format!("# {}\n", "x".repeat(MAX_CONFIG_BYTES));
    assert!(matches!(
        Config::parse(&big),
        Err(ConfigError::TooLarge { .. })
    ));
}

struct TempDir(PathBuf);
impl TempDir {
    fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!(
            "ntpc-cfg-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&p).expect("temp dir");
        Self(p)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn load_reads_a_file() {
    let d = TempDir::new("ok");
    let p = d.0.join("c.toml");
    std::fs::write(&p, "dhcp = false\n").expect("write");
    assert!(!Config::load(&p).expect("load").dhcp);
}

#[test]
fn load_missing_file_is_a_read_error_with_path() {
    let d = TempDir::new("missing");
    let p = d.0.join("nope.toml");
    let e = Config::load(&p).expect_err("missing");
    assert!(matches!(e, ConfigError::Read { .. }), "{e:?}");
    assert!(e.to_string().contains("nope.toml"), "{e}");
}

#[test]
fn load_bad_file_is_a_parse_error_not_a_read_error() {
    let d = TempDir::new("bad");
    let p = d.0.join("c.toml");
    std::fs::write(&p, "bogus = 1\n").expect("write");
    assert!(matches!(Config::load(&p), Err(ConfigError::Parse { .. })));
}

#[test]
fn load_rejects_a_huge_file_without_reading_it_all() {
    let d = TempDir::new("huge");
    let p = d.0.join("c.toml");
    std::fs::write(&p, vec![b'#'; MAX_CONFIG_BYTES + 10]).expect("write");
    assert!(matches!(
        Config::load(&p),
        Err(ConfigError::TooLarge { .. })
    ));
}

#[test]
fn load_rejects_non_utf8() {
    let d = TempDir::new("utf8");
    let p = d.0.join("c.toml");
    std::fs::write(&p, [0xff, 0xfe, 0x00]).expect("write");
    assert!(matches!(Config::load(&p), Err(ConfigError::NotUtf8 { .. })));
}

#[test]
fn load_directory_is_a_read_error() {
    let d = TempDir::new("dir");
    assert!(matches!(Config::load(&d.0), Err(ConfigError::Read { .. })));
}

#[cfg(windows)]
#[test]
fn a_symlinked_config_is_not_followed() {
    let d = TempDir::new("symcfg");
    let victim = d.0.join("victim.toml");
    std::fs::write(&victim, "dhcp = false\n").expect("victim");
    let link = d.0.join("c.toml");
    if let Err(e) = std::os::windows::fs::symlink_file(&victim, &link) {
        eprintln!("skipped: cannot create a symlink here: {e}");
        return;
    }
    assert!(
        matches!(Config::load(&link), Err(ConfigError::Read { .. })),
        "a link is refused: not read and not treated as an empty file"
    );
}
