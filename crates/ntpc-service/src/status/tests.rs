//! Unit tests for the status writer and reader.

use super::*;

fn sample() -> StatusReport {
    StatusReport {
        service_version: "0.0.0".into(),
        written_unix_s: 1_794_268_800,
        running: true,
        uptime_s: 3600,
        active_tier: Some(Tier::Pool),
        last_offset_s: Some(-0.000_123_4),
        drift_ppm: 12.5,
        last_good_age_s: Some(30),
        holdover: false,
        adjustment_allowed: true,
        adjustment_blocked: Blocked::None,
        last_step_unix_s: None,
        last_step_s: None,
        persistence: true,
        sources_config: 0,
        sources_dhcp: 1,
        sources_pool: 4,
        dhcp_differs: false,
        counters: Counters {
            queries: 7,
            log_suppressed: 2,
            ..Counters::default()
        },
    }
}

#[test]
fn round_trips() {
    let r = sample();
    assert_eq!(parse(&to_json(&r)).expect("parses"), r);
    let mut r2 = r;
    r2.active_tier = None;
    r2.last_offset_s = None;
    r2.last_good_age_s = None;
    r2.last_step_unix_s = Some(-5);
    r2.last_step_s = Some(1e-9);
    r2.adjustment_blocked = Blocked::ClockFailure;
    assert_eq!(parse(&to_json(&r2)).expect("parses"), r2);
}

#[test]
fn refuses_unknown_missing_and_repeated_keys() {
    let text = to_json(&sample());
    let extra = text.replacen("\"running\"", "\"extra\": 1,\n  \"running\"", 1);
    assert!(matches!(parse(&extra), Err(StatusError::Invalid(_))));
    let missing = text.replacen("  \"holdover\": false,\n", "", 1);
    assert!(matches!(parse(&missing), Err(StatusError::Invalid(_))));
    let repeated = text.replacen(
        "\"running\": true",
        "\"running\": true, \"running\": true",
        1,
    );
    assert!(matches!(parse(&repeated), Err(StatusError::Invalid(_))));
}

#[test]
fn refuses_wrong_types_escapes_arrays_and_depth() {
    let text = to_json(&sample());
    for (from, to) in [
        ("\"running\": true", "\"running\": 1"),
        ("\"uptime_s\": 3600", "\"uptime_s\": -1"),
        ("\"uptime_s\": 3600", "\"uptime_s\": 1.5"),
        (
            "\"service_version\": \"0.0.0\"",
            "\"service_version\": \"a\\nb\"",
        ),
        ("\"uptime_s\": 3600", "\"uptime_s\": [1]"),
        ("\"queries\": 7", "\"queries\": {\"a\": 1}"),
        ("\"drift_ppm\": 12.5", "\"drift_ppm\": 1e999"),
        ("\"drift_ppm\": 12.5", "\"drift_ppm\": 01"),
        ("\"active_tier\": \"pool\"", "\"active_tier\": \"moon\""),
    ] {
        let bad_text = text.replacen(from, to, 1);
        assert_ne!(bad_text, text, "{from}");
        assert!(parse(&bad_text).is_err(), "{to} accepted");
    }
    assert!(parse(&format!("{text}x")).is_err());
    assert!(parse("").is_err());
    assert!(parse("[]").is_err());
}

#[test]
fn refuses_other_version_and_format() {
    let text = to_json(&sample());
    let v2 = text.replacen("\"version\": 1", "\"version\": 2", 1);
    assert_eq!(parse(&v2), Err(StatusError::Version(2)));
    let other = text.replacen(FORMAT, "something-else", 1);
    assert!(matches!(parse(&other), Err(StatusError::Invalid(_))));
}

#[test]
fn refuses_oversize() {
    let big = format!("{}{}", to_json(&sample()), " ".repeat(5000));
    assert_eq!(parse(&big), Err(StatusError::TooLarge));
}

#[test]
fn garbage_never_panics() {
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    for _ in 0..2000 {
        let mut s = Vec::new();
        for _ in 0..(x % 64) {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            s.push(b"{}[]\":,0123456789-+.eEtrufalsn \\x"[(x % 33) as usize]);
        }
        let _ = parse(&String::from_utf8_lossy(&s));
    }
}

#[test]
fn version_string_cannot_break_the_file() {
    let mut r = sample();
    r.service_version = "1\"} evil\n".into();
    let parsed = parse(&to_json(&r)).expect("still valid");
    assert_eq!(parsed.service_version, "1_}_evil_");
}
#[test]
fn non_finite_numbers_never_make_an_unreadable_file() {
    let mut r = sample();
    r.last_offset_s = Some(f64::NAN);
    r.last_step_s = Some(f64::INFINITY);
    // Optional numbers are written as null and read back as none.
    let back = parse(&to_json(&r)).expect("still readable");
    assert_eq!(back.last_offset_s, None);
    assert_eq!(back.last_step_s, None);
    // R103: a NaN drift is written as null and reads back as NaN.
    r.drift_ppm = f64::NAN;
    assert!(check(&r).is_ok());
    let text = to_json(&r);
    assert!(text.contains("\"drift_ppm\": null"), "{text}");
    let back = parse(&text).expect("null drift accepted");
    assert!(back.drift_ppm.is_nan());
    assert!(format_status(&back).contains("drift:              unknown"));
    let dir = std::env::temp_dir().join(format!("ntpc-status-nan-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("dir");
    let w = FileStatusWriter::new(&dir);
    w.write(&r).expect("written");
    assert!(read_status(&w.path()).expect("reads").drift_ppm.is_nan());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn null_is_refused_for_every_other_required_number() {
    let text = to_json(&sample());
    for (from, to) in [
        ("\"uptime_s\": 3600", "\"uptime_s\": null"),
        ("\"version\": 1", "\"version\": null"),
        ("\"written_unix_s\": 1794268800", "\"written_unix_s\": null"),
        ("\"sources_pool\": 4", "\"sources_pool\": null"),
        ("\"queries\": 7", "\"queries\": null"),
    ] {
        let bad = text.replacen(from, to, 1);
        assert_ne!(bad, text, "{from}");
        assert!(parse(&bad).is_err(), "{to} accepted");
    }
}

#[test]
fn unknown_key_names_are_escaped_in_errors() {
    let text = to_json(&sample()).replacen(
        "\"running\"",
        // A raw control character is refused by the string rule, so the
        // hostile name uses a bidi override and a line separator.
        "\"evil\u{202e}x\u{2028}y\": 1,\n  \"running\"",
        1,
    );
    let Err(StatusError::Invalid(msg)) = parse(&text) else {
        panic!("refused");
    };
    assert!(
        !msg.contains('\u{202e}') && !msg.contains('\u{2028}'),
        "{msg:?}"
    );
    assert!(msg.contains("evil\\u{202E}x\\u{2028}y"), "{msg:?}");
}

#[test]
fn summary_escapes_the_version() {
    let mut r = sample();
    r.service_version = "1\u{1b}[31m".into();
    assert!(!format_status(&r).contains('\u{1b}'));
}
