//! Assembly tests over fakes. Only files in fresh temp directories.

use std::fs;
use std::path::PathBuf;

use super::*;
use crate::logging::MemorySink;
use crate::transport::StdTimeSource;

/// A fresh directory under the system temp folder, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!("ntpc-winimpl-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir(&p).expect("temp dir");
        Self(p)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn time() -> Arc<dyn TimeSource> {
    Arc::new(StdTimeSource::new())
}

#[test]
fn a_secured_directory_gets_the_log_file_and_the_other_sinks() {
    let s = Scratch::new("logon");
    let mem = MemorySink::new();
    for outcome in [SecureOutcome::Ok, SecureOutcome::RestoreDropped] {
        let logger = build_logger(outcome, &s.0, vec![Box::new(mem.clone())], time());
        logger.log(Level::Info, "test", "hello");
    }
    let file = fs::read_to_string(s.0.join(LOG_FILE_NAME)).expect("log file");
    assert_eq!(file.lines().count(), 2);
    assert!(file.lines().all(|l| l.ends_with("hello")));
    assert_eq!(mem.lines().len(), 2, "other sinks still get every line");
}

#[test]
fn a_refused_directory_gets_no_log_file() {
    let s = Scratch::new("logoff");
    let mem = MemorySink::new();
    let logger = build_logger(
        SecureOutcome::Refused { reason: "x" },
        &s.0,
        vec![Box::new(mem.clone())],
        time(),
    );
    logger.log(Level::Warn, "test", "hello");
    assert_eq!(
        fs::read_dir(&s.0).expect("list").count(),
        0,
        "nothing written"
    );
    assert_eq!(mem.lines().len(), 1);
}

#[test]
fn the_log_names_are_known_state_children() {
    assert!(ntpc_platform::KNOWN_CHILDREN.contains(&LOG_FILE_NAME));
    let rotated = format!("{LOG_FILE_NAME}.1");
    assert!(ntpc_platform::KNOWN_CHILDREN.contains(&rotated.as_str()));
}

#[test]
fn the_file_sink_refuses_a_hard_linked_log() {
    let s = Scratch::new("loglink");
    let elsewhere = s.0.join("elsewhere.txt");
    fs::write(&elsewhere, b"keep\n").expect("write");
    let state = s.0.join("state");
    fs::create_dir(&state).expect("state dir");
    fs::hard_link(&elsewhere, state.join(LOG_FILE_NAME)).expect("hard link");
    let sink = FileSink::new(state.join(LOG_FILE_NAME), DEFAULT_MAX_FILE_BYTES);
    sink.write_line("must not land");
    assert_eq!(sink.write_errors(), 1);
    assert_eq!(fs::read(&elsewhere).expect("read"), b"keep\n");
}

#[test]
fn tee_writes_each_line_to_every_sink_in_order() {
    let (a, b) = (MemorySink::new(), MemorySink::new());
    let tee = TeeSink::new(vec![Box::new(a.clone()), Box::new(b.clone())]);
    tee.write_line("one");
    tee.write_line("two");
    assert_eq!(a.lines(), vec!["one", "two"]);
    assert_eq!(b.lines(), a.lines());
}

#[test]
fn deps_error_text_names_no_path() {
    let e = WinDepsError::Clock(ClockError::PermissionDenied);
    assert_eq!(
        e.to_string(),
        "the system clock could not be opened: permission denied"
    );
}
