//! The Event Log sink over a fake event API, and the source registration
//! over a fake registry.

use std::sync::Condvar;

use super::*;

#[derive(Clone, Default)]
struct FakeApi {
    events: Arc<Mutex<Vec<(u16, u32, String)>>>,
    fail: bool,
    gate: Option<Arc<Latch>>,
}

impl EventApi for FakeApi {
    fn report(&self, t: u16, id: u32, text: &str) -> Result<(), i32> {
        if let Some(g) = &self.gate {
            g.wait();
        }
        self.events.lock().unwrap().push((t, id, text.to_owned()));
        if self.fail { Err(1502) } else { Ok(()) }
    }
}

/// Closed until opened once, then open for ever.
#[derive(Default)]
struct Latch {
    open: Mutex<bool>,
    cv: Condvar,
}

impl Latch {
    fn wait(&self) {
        let mut o = self.open.lock().unwrap();
        while !*o {
            o = self.cv.wait(o).unwrap();
        }
    }
    fn open(&self) {
        *self.open.lock().unwrap() = true;
        self.cv.notify_all();
    }
}

const LINE_WARN: &str = "2026-11-10T12:34:56.789Z WARN  a source sent kiss-of-death RATE";

#[test]
fn levels_map_to_types_and_ids_and_debug_is_dropped() {
    assert_eq!(
        classify("2026-11-10T12:34:56.789Z ERROR clock command failed"),
        Some((TYPE_ERROR, ID_ERROR, "clock command failed"))
    );
    assert_eq!(
        classify(LINE_WARN),
        Some((TYPE_WARNING, ID_WARN, "a source sent kiss-of-death RATE"))
    );
    assert_eq!(
        classify("2026-11-10T12:34:56.789Z INFO  started"),
        Some((TYPE_INFORMATION, ID_INFO, "started"))
    );
    assert_eq!(classify("2026-11-10T12:34:56.789Z DEBUG detail"), None);
    assert_eq!(classify("garbage"), None);
    assert_eq!(classify(""), None);
}

#[test]
fn event_ids_are_in_the_message_file_range() {
    for id in [ID_INFO, ID_WARN, ID_ERROR, ID_SERVICE] {
        assert!((1..=1000).contains(&id), "{id}");
    }
}

#[test]
fn text_escapes_percent_and_control_characters() {
    let t = event_text("100% of %1 and a\nnew\u{1b}[31mline");
    assert!(!t.contains('%'), "{t}");
    assert!(!t.chars().any(char::is_control), "{t}");
    assert!(t.contains("\\u{25}1"), "{t}");
}

#[test]
fn text_is_capped() {
    let t = event_text(&"x".repeat(10_000));
    assert!(t.chars().count() <= MAX_EVENT_CHARS + 12);
    assert!(t.ends_with("[truncated]"));
    let t = event_text(&"%".repeat(10_000));
    assert!(t.chars().count() <= MAX_EVENT_CHARS + 12);
}

#[test]
fn sink_writes_through_the_api_on_its_thread() {
    let api = FakeApi::default();
    let events = api.events.clone();
    let sink = EventLogSink::start(Box::new(api)).unwrap();
    sink.write_line(LINE_WARN);
    sink.write_line("2026-11-10T12:34:56.789Z DEBUG nope");
    sink.event(TYPE_INFORMATION, ID_SERVICE, "service running");
    assert!(sink.drain(Duration::from_secs(5)));
    let e = events.lock().unwrap().clone();
    assert_eq!(
        e,
        vec![
            (
                TYPE_WARNING,
                ID_WARN,
                "a source sent kiss-of-death RATE".to_owned()
            ),
            (TYPE_INFORMATION, ID_SERVICE, "service running".to_owned()),
        ]
    );
    assert_eq!(sink.counts().written.load(Ordering::Relaxed), 2);
}

#[test]
fn a_blocked_event_log_never_blocks_the_logger() {
    // The writer blocks on its first event until the test opens the latch.
    let gate = Arc::new(Latch::default());
    let api = FakeApi {
        gate: Some(gate.clone()),
        ..FakeApi::default()
    };
    let sink = EventLogSink::start(Box::new(api)).unwrap();
    let t = std::time::Instant::now();
    for _ in 0..(QUEUE_LEN * 3) {
        sink.write_line(LINE_WARN);
    }
    assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
    let dropped = sink.counts().dropped.load(Ordering::Relaxed);
    assert!(dropped >= u64::try_from(QUEUE_LEN).unwrap(), "{dropped}");
    gate.open();
    assert!(sink.drain(Duration::from_secs(10)));
}

#[test]
fn failed_writes_are_counted_and_not_fatal() {
    let api = FakeApi {
        fail: true,
        ..FakeApi::default()
    };
    let sink = EventLogSink::start(Box::new(api)).unwrap();
    for _ in 0..5 {
        sink.write_line(LINE_WARN);
    }
    assert!(sink.drain(Duration::from_secs(5)));
    assert_eq!(sink.counts().failed.load(Ordering::Relaxed), 5);
}

// ---- Source registration over a fake registry ----

#[derive(Default)]
struct MemReg {
    present: bool,
    values: Option<(String, u32)>,
    write_error: Option<String>,
    delete_error: Option<String>,
    exists_error: Option<String>,
    deletes: u32,
}

impl EventSourceRegistry for MemReg {
    fn exists(&self, key: &str) -> Result<bool, String> {
        assert_eq!(key, EVENT_SOURCE_KEY);
        match &self.exists_error {
            Some(e) => Err(e.clone()),
            None => Ok(self.present),
        }
    }
    fn write(&mut self, key: &str, file: &str, types: u32) -> Result<(), String> {
        assert_eq!(key, EVENT_SOURCE_KEY);
        self.present = true;
        if let Some(e) = &self.write_error {
            return Err(e.clone());
        }
        self.values = Some((file.to_owned(), types));
        Ok(())
    }
    fn delete(&mut self, key: &str) -> Result<(), String> {
        assert_eq!(key, EVENT_SOURCE_KEY);
        self.deletes += 1;
        if let Some(e) = &self.delete_error {
            return Err(e.clone());
        }
        self.present = false;
        Ok(())
    }
}

#[test]
fn register_writes_the_message_file_and_types() {
    let mut r = MemReg::default();
    assert_eq!(register_source(&mut r), Ok(true));
    assert_eq!(
        r.values,
        Some((r"%SystemRoot%\System32\EventCreate.exe".to_owned(), 7))
    );
    // Again: overwritten, not created.
    assert_eq!(register_source(&mut r), Ok(false));
}

#[test]
fn a_failed_write_removes_only_a_key_it_created() {
    let mut r = MemReg {
        write_error: Some("denied".to_owned()),
        ..MemReg::default()
    };
    assert!(register_source(&mut r).is_err());
    assert!(!r.present);
    let mut r = MemReg {
        present: true,
        write_error: Some("denied".to_owned()),
        ..MemReg::default()
    };
    assert!(register_source(&mut r).is_err());
    assert!(r.present);
    assert_eq!(r.deletes, 0);
}

#[test]
fn a_failed_cleanup_reports_both() {
    let mut r = MemReg {
        write_error: Some("denied".to_owned()),
        delete_error: Some("busy".to_owned()),
        ..MemReg::default()
    };
    let e = register_source(&mut r).unwrap_err();
    assert!(e.contains("denied") && e.contains("busy"), "{e}");
}

#[test]
fn unregister_removes_only_what_is_there() {
    let mut r = MemReg::default();
    assert_eq!(unregister_source(&mut r), Ok(false));
    assert_eq!(r.deletes, 0);
    r.present = true;
    assert_eq!(unregister_source(&mut r), Ok(true));
    assert!(!r.present);
}

#[test]
fn a_registry_read_error_changes_nothing() {
    let mut r = MemReg {
        exists_error: Some("denied".to_owned()),
        ..MemReg::default()
    };
    assert!(register_source(&mut r).is_err());
    assert!(unregister_source(&mut r).is_err());
    assert!(!r.present);
    assert_eq!(r.deletes, 0);
}

#[test]
fn source_key_and_name_match() {
    assert!(EVENT_SOURCE_KEY.ends_with(EVENT_SOURCE));
    assert!(
        !EVENT_SOURCE.contains('\\'),
        "Learn: no backslash in a source"
    );
}
