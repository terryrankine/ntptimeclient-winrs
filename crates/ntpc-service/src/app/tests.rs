//! Command line parsing, config loading and `status`, with temp files. No
//! service, no SCM.

use std::collections::BTreeSet;

use super::*;
use crate::status::{Blocked, Counters, StatusReport, to_json};

fn args(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| (*s).to_owned()).collect()
}

fn run(a: &[&str]) -> (u8, String, String) {
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = main_entry(&args(a), &mut out, &mut err);
    (
        code,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

fn temp_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("ntpc-app-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

// ---- Parsing ----

#[test]
fn help_lists_every_subcommand_as_a_word() {
    for h in ["--help", "-h"] {
        let (code, out, err) = run(&[h]);
        assert_eq!(code, crate::cli::exit::OK);
        assert_eq!(err, "");
        // The Task 15 workflow gate matches whole words.
        for w in ["install", "uninstall", "status", "run", "service"] {
            let line_word = out.lines().any(|l| l.split_whitespace().next() == Some(w));
            assert!(line_word, "{w} missing as a command line: {out}");
        }
    }
}

#[test]
fn no_arguments_prints_usage_and_exits_2() {
    let (code, out, err) = run(&[]);
    assert_eq!(code, crate::cli::exit::USAGE);
    assert_eq!(out, "");
    assert_eq!(err.lines().count(), 1, "{err}");
    assert!(err.contains("usage:"), "{err}");
}

#[test]
fn unknown_commands_and_arguments_exit_2_with_one_line() {
    for a in [
        &["frobnicate"][..],
        &["--version"],
        &["--help", "x"],
        &["service", "--now"],
        &["status", "--config"],
        &["status", "--config", "--x"],
        &["status", "extra"],
        &["run", "--config", "a", "b"],
        &["INSTALL"],
    ] {
        let (code, out, err) = run(a);
        assert_eq!(code, crate::cli::exit::USAGE, "{a:?}");
        assert_eq!(out, "", "{a:?}");
        assert_eq!(err.lines().count(), 1, "{a:?}: {err}");
    }
}

#[test]
fn parse_gives_each_command() {
    assert_eq!(parse(&args(&["service"])), Ok(Command::Service));
    assert_eq!(
        parse(&args(&["install", "--silent"])),
        Ok(Command::Install(args(&["--silent"])))
    );
    assert_eq!(parse(&args(&["uninstall"])), Ok(Command::Uninstall(vec![])));
    assert_eq!(
        parse(&args(&["status", "--config", r"C:\x\c.toml"])),
        Ok(Command::Status {
            config: Some(PathBuf::from(r"C:\x\c.toml"))
        })
    );
    assert_eq!(parse(&args(&["run"])), Ok(Command::Run { config: None }));
}

#[test]
fn bad_install_and_uninstall_arguments_exit_2_before_any_real_call() {
    // Only invalid arguments: they stop at parsing inside cli, before any
    // registration or SCM call.
    assert_eq!(run(&["install", "--nope"]).0, crate::cli::exit::USAGE);
    assert_eq!(run(&["uninstall", "--nope"]).0, crate::cli::exit::USAGE);
}

#[test]
fn exit_codes_are_distinct_and_clear_of_the_wrapper_range() {
    let mut all: BTreeSet<u8> = crate::cli::exit::ALL.iter().copied().collect();
    for c in exit::ALL {
        assert!(all.insert(c), "duplicate {c}");
        assert!(!(40..=47).contains(&c), "{c} collides with the wrapper");
    }
    for c in crate::cli::exit::ALL {
        assert!(!(40..=47).contains(&c), "{c}");
    }
}

// ---- Config ----

#[test]
fn a_missing_config_file_gives_the_defaults() {
    let d = temp_dir("cfg-missing");
    assert_eq!(load_config(&default_config_path(&d)), Ok(Config::default()));
}

#[test]
fn a_valid_config_file_is_loaded() {
    let d = temp_dir("cfg-ok");
    let p = default_config_path(&d);
    std::fs::write(&p, "servers = [\"192.0.2.7\"]\nmin_poll_s = 128\n").unwrap();
    let c = load_config(&p).unwrap();
    assert_eq!(c.servers, vec!["192.0.2.7".to_owned()]);
    assert_eq!(c.min_poll_s, 128);
}

#[test]
fn a_bad_config_file_is_an_error_without_a_path() {
    let d = temp_dir("cfg-bad");
    let p = default_config_path(&d);
    for text in ["nope = 1\n", "min_poll_s = 1\n", "servers = [\n"] {
        std::fs::write(&p, text).unwrap();
        let e = load_config(&p).unwrap_err();
        assert!(!e.contains(d.to_str().unwrap()), "{e}");
    }
    std::fs::write(&p, [0xFFu8, 0xFE, 0x00]).unwrap();
    let e = load_config(&p).unwrap_err();
    assert!(e.contains("UTF-8"), "{e}");
    assert!(!e.contains('\\'), "{e}");
}

#[test]
fn an_oversized_config_file_is_refused() {
    let d = temp_dir("cfg-big");
    let p = default_config_path(&d);
    std::fs::write(&p, "#".repeat(70 * 1024)).unwrap();
    assert!(load_config(&p).is_err());
}

#[test]
fn config_folder_is_the_exe_folder() {
    assert_eq!(
        default_config_path(Path::new(r"C:\Program Files\ntptimeclient-winrs")),
        PathBuf::from(r"C:\Program Files\ntptimeclient-winrs\config.toml")
    );
}

// ---- status ----

fn report() -> StatusReport {
    StatusReport {
        service_version: "0.0.0".into(),
        written_unix_s: 1_794_268_800,
        running: true,
        uptime_s: 60,
        active_tier: None,
        last_offset_s: None,
        drift_ppm: 1.5,
        last_good_age_s: None,
        holdover: false,
        adjustment_allowed: false,
        adjustment_blocked: Blocked::Starting,
        last_step_unix_s: None,
        last_step_s: None,
        persistence: true,
        sources_config: 0,
        sources_dhcp: 0,
        sources_pool: 4,
        dhcp_differs: false,
        counters: Counters::default(),
    }
}

fn status_in(dir: &Path) -> (u8, String, String) {
    let cfg = Config {
        state_dir: dir.to_path_buf(),
        ..Config::default()
    };
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = status_command(&cfg, &mut out, &mut err);
    (
        code,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

#[test]
fn status_prints_a_valid_file() {
    let d = temp_dir("st-ok");
    std::fs::write(d.join("status.json"), to_json(&report())).unwrap();
    let (code, out, err) = status_in(&d);
    assert_eq!(code, crate::cli::exit::OK, "{err}");
    assert!(out.contains("ntptimeclient-winrs 0.0.0 (running)"), "{out}");
    assert!(out.contains("pool 4"), "{out}");
}

#[test]
fn status_without_a_file_or_directory_fails_cleanly() {
    let d = temp_dir("st-missing");
    let (code, out, err) = status_in(&d);
    assert_eq!(code, exit::STATUS_MISSING);
    assert_eq!(out, "");
    assert!(err.contains("No status file"), "{err}");
    let (code, _, _) = status_in(&d.join("no-such-dir"));
    assert_eq!(code, exit::STATUS_MISSING);
}

#[test]
fn status_with_a_tampered_file_fails_cleanly() {
    let d = temp_dir("st-bad");
    for bad in [
        b"{}".to_vec(),
        b"not json".to_vec(),
        vec![0xFF, 0xFE],
        to_json(&report())
            .replace("\"version\": 1,", "\"version\": 9,")
            .into_bytes(),
        vec![b' '; 5000],
    ] {
        std::fs::write(d.join("status.json"), &bad).unwrap();
        let (code, out, err) = status_in(&d);
        assert_eq!(code, exit::STATUS_INVALID, "{err}");
        assert_eq!(out, "");
        assert!(!err.contains(d.to_str().unwrap()), "{err}");
    }
}

#[test]
fn status_access_denied_says_elevated_with_its_own_code() {
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = report_status(
        Err(StatusError::Io(std::io::ErrorKind::PermissionDenied)),
        &mut out,
        &mut err,
    );
    assert_eq!(code, exit::STATUS_DENIED);
    assert!(String::from_utf8(err).unwrap().contains("elevated"));
    assert_eq!(out, Vec::<u8>::new());
}
