//! The Windows Event Log: a [`LogSink`] and the source registration.
//!
//! The service writes its log lines to the Application log under the source
//! [`EVENT_SOURCE`]. Rules:
//! - Debug lines never go to the Event Log.
//! - Error, warning and information map to the Event Log types of the same
//!   name, with fixed event ids ([`ID_INFO`], [`ID_WARN`], [`ID_ERROR`]).
//! - The text is the logger's line without its time stamp (the Event Log
//!   stamps it), capped at [`MAX_EVENT_CHARS`]. The logger already escapes
//!   control characters. This sink escapes them again, as defence in depth,
//!   and writes `%` as `\u{25}` (Learn, `ReportEventW`: "%n" in a string is
//!   treated as an insertion string).
//! - The logger never waits on the Event Log. Lines go into a bounded
//!   queue that one writer thread drains. A full queue drops the line and
//!   counts it. A failed write is counted. Neither is ever fatal.
//!
//! Readable text without our own message DLL: the source names
//! `%SystemRoot%\System32\EventCreate.exe` as its message file. Measured on
//! the builder's machine (read only): its message table maps ids 1 to 1001
//! to `%1`, and sources made by `eventcreate` use that file with
//! `TypesSupported` 7. This is not documented by Microsoft. Learn only says
//! `eventcreate /id` takes 1 to 1000. If the trick stops working the Event
//! Viewer shows "description cannot be found" with our text still attached
//! as the insertion string.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use crate::logging::LogSink;
use crate::registration::SERVICE_NAME;

/// The Event Log source name.
pub const EVENT_SOURCE: &str = SERVICE_NAME;

/// The source key under `HKLM` (Learn, Event Sources).
pub const EVENT_SOURCE_KEY: &str =
    r"SYSTEM\CurrentControlSet\Services\EventLog\Application\ntptimeclient-winrs";

/// The message file named by the source. `REG_EXPAND_SZ`.
pub const MESSAGE_FILE: &str = r"%SystemRoot%\System32\EventCreate.exe";

/// `TypesSupported`: error, warning and information (1 | 2 | 4).
pub const TYPES_SUPPORTED: u32 = 7;

/// `EVENTLOG_ERROR_TYPE`.
pub const TYPE_ERROR: u16 = 1;
/// `EVENTLOG_WARNING_TYPE`.
pub const TYPE_WARNING: u16 = 2;
/// `EVENTLOG_INFORMATION_TYPE`.
pub const TYPE_INFORMATION: u16 = 4;

/// Event id of an information line.
pub const ID_INFO: u32 = 1;
/// Event id of a warning line.
pub const ID_WARN: u32 = 2;
/// Event id of an error line.
pub const ID_ERROR: u32 = 3;
/// Event id of the service wrapper's own start and stop lines.
pub const ID_SERVICE: u32 = 10;

/// Longest event text, in characters. Learn allows 31,839 per string. A
/// log line is at most about 530, so this only bounds a bug.
pub const MAX_EVENT_CHARS: usize = 2048;

/// Lines waiting for the writer. A burst at start is about 20.
pub const QUEUE_LEN: usize = 256;

/// Writes one event. The real one is `ntpc_platform::service_host::EventSource`.
pub trait EventApi: Send {
    /// Reports one event with one insertion string.
    ///
    /// # Errors
    /// The OS error code.
    fn report(&self, event_type: u16, id: u32, text: &str) -> Result<(), i32>;
}

/// The Event Log source key in the registry.
pub trait EventSourceRegistry {
    /// Whether the key exists. Read only.
    ///
    /// # Errors
    /// Why it could not be read.
    fn exists(&self, key: &str) -> Result<bool, String>;
    /// Creates the key if needed and writes both values.
    ///
    /// # Errors
    /// Why it failed.
    fn write(&mut self, key: &str, message_file: &str, types: u32) -> Result<(), String>;
    /// Deletes the key.
    ///
    /// # Errors
    /// Why it failed.
    fn delete(&mut self, key: &str) -> Result<(), String>;
}

/// Registers our source. Returns true if this call created the key.
///
/// # Errors
/// Why it failed. A key this call created is removed again first.
pub fn register_source(r: &mut dyn EventSourceRegistry) -> Result<bool, String> {
    let existed = r.exists(EVENT_SOURCE_KEY)?;
    if let Err(e) = r.write(EVENT_SOURCE_KEY, MESSAGE_FILE, TYPES_SUPPORTED) {
        if !existed && let Err(e2) = r.delete(EVENT_SOURCE_KEY) {
            return Err(format!(
                "{e}. Removing the half-written key also failed: {e2}"
            ));
        }
        return Err(e);
    }
    Ok(!existed)
}

/// Removes our source. Returns true if it was there.
///
/// # Errors
/// Why it failed.
pub fn unregister_source(r: &mut dyn EventSourceRegistry) -> Result<bool, String> {
    if !r.exists(EVENT_SOURCE_KEY)? {
        return Ok(false);
    }
    r.delete(EVENT_SOURCE_KEY)?;
    Ok(true)
}

/// The type and id for a logger line, from its level tag. `None` for debug
/// lines and anything unrecognised.
#[must_use]
pub fn classify(line: &str) -> Option<(u16, u32, &str)> {
    // "2026-11-10T12:34:56.789Z WARN  message": stamp, space, 5-char tag,
    // space, message.
    let rest = line.split_once(' ').map_or(line, |(_, r)| r);
    let (tag, msg) = (rest.get(..5)?, rest.get(6..).unwrap_or(""));
    match tag {
        "ERROR" => Some((TYPE_ERROR, ID_ERROR, msg)),
        "WARN " => Some((TYPE_WARNING, ID_WARN, msg)),
        "INFO " => Some((TYPE_INFORMATION, ID_INFO, msg)),
        _ => None,
    }
}

/// Makes `msg` safe for the Event Log: control characters and `%` escaped,
/// length capped.
#[must_use]
pub fn event_text(msg: &str) -> String {
    let mut out = String::with_capacity(msg.len().min(MAX_EVENT_CHARS));
    let mut n = 0usize;
    for c in msg.chars() {
        let piece: String = if c == '%' || c.is_control() {
            format!("\\u{{{:X}}}", u32::from(c))
        } else {
            c.to_string()
        };
        let len = piece.chars().count();
        if n + len > MAX_EVENT_CHARS {
            out.push_str(" [truncated]");
            return out;
        }
        n += len;
        out.push_str(&piece);
    }
    out
}

enum Item {
    Event(u16, u32, String),
    Flush(mpsc::Sender<()>),
}

/// Counts the sink keeps.
#[derive(Debug, Default)]
pub struct EventCounts {
    /// Lines dropped because the queue was full.
    pub dropped: AtomicU64,
    /// Writes the Event Log refused.
    pub failed: AtomicU64,
    /// Events written.
    pub written: AtomicU64,
}

/// A [`LogSink`] that hands lines to a writer thread.
pub struct EventLogSink {
    tx: Mutex<Option<SyncSender<Item>>>,
    counts: Arc<EventCounts>,
}

impl std::fmt::Debug for EventLogSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventLogSink").finish_non_exhaustive()
    }
}

fn writer(api: &dyn EventApi, rx: &Receiver<Item>, counts: &EventCounts) {
    while let Ok(item) = rx.recv() {
        match item {
            Item::Event(t, id, text) => {
                if api.report(t, id, &text).is_ok() {
                    counts.written.fetch_add(1, Ordering::Relaxed);
                } else {
                    counts.failed.fetch_add(1, Ordering::Relaxed);
                }
            }
            Item::Flush(done) => {
                let _ = done.send(());
            }
        }
    }
}

impl EventLogSink {
    /// A sink writing through `api` on its own thread.
    ///
    /// # Errors
    /// The thread could not be started.
    pub fn start(api: Box<dyn EventApi>) -> std::io::Result<Self> {
        let (tx, rx) = mpsc::sync_channel(QUEUE_LEN);
        let counts = Arc::new(EventCounts::default());
        let c = counts.clone();
        std::thread::Builder::new()
            .name("ntpc-eventlog".to_owned())
            .spawn(move || writer(api.as_ref(), &rx, &c))?;
        Ok(Self {
            tx: Mutex::new(Some(tx)),
            counts,
        })
    }

    /// The counts.
    #[must_use]
    pub fn counts(&self) -> Arc<EventCounts> {
        self.counts.clone()
    }

    /// Writes one event of the given type directly, skipping the level
    /// parse. Used by the service wrapper for its own start and stop lines.
    pub fn event(&self, event_type: u16, id: u32, text: &str) {
        self.enqueue(Item::Event(event_type, id, event_text(text)));
    }

    fn enqueue(&self, item: Item) -> bool {
        let guard = self.tx.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(tx) = guard.as_ref() else {
            return false;
        };
        match tx.try_send(item) {
            Ok(()) => true,
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                self.counts.dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    /// Waits until every line queued so far is written, at most `timeout`.
    /// True if it finished in time. Used once, before `SERVICE_STOPPED`.
    pub fn drain(&self, timeout: Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        let (done_tx, done_rx) = mpsc::channel();
        let mut item = Item::Flush(done_tx);
        // A full queue is normal here: keep offering the marker until the
        // writer makes room or the time is up. Only the stopping service
        // waits, never the logger.
        loop {
            let sent = {
                let guard = self.tx.lock().unwrap_or_else(PoisonError::into_inner);
                let Some(tx) = guard.as_ref() else {
                    return false;
                };
                match tx.try_send(item) {
                    Ok(()) => None,
                    Err(TrySendError::Full(back)) => Some(back),
                    Err(TrySendError::Disconnected(_)) => return false,
                }
            };
            match sent {
                None => break,
                Some(back) if std::time::Instant::now() < deadline => {
                    item = back;
                    std::thread::sleep(Duration::from_millis(5));
                }
                Some(_) => return false,
            }
        }
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        done_rx.recv_timeout(left).is_ok()
    }
}

impl LogSink for EventLogSink {
    fn write_line(&self, line: &str) {
        if let Some((t, id, msg)) = classify(line) {
            self.enqueue(Item::Event(t, id, event_text(msg)));
        }
    }
}

impl<T: LogSink + ?Sized> LogSink for Arc<T> {
    fn write_line(&self, line: &str) {
        (**self).write_line(line);
    }
}

/// Drops every line and counts it. Used when the Event Log source cannot
/// be opened, so the service still runs.
#[derive(Debug, Default)]
pub struct DiscardSink(pub AtomicU64);

impl LogSink for DiscardSink {
    fn write_line(&self, _line: &str) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------- real

/// The real Event Log, over `ntpc_platform::service_host::EventSource`.
#[cfg(windows)]
pub struct RealEventApi(ntpc_platform::service_host::EventSource);

#[cfg(windows)]
impl RealEventApi {
    /// Registers the event source handle for [`EVENT_SOURCE`].
    ///
    /// # Errors
    /// The OS error.
    pub fn open() -> std::io::Result<Self> {
        ntpc_platform::service_host::EventSource::register(EVENT_SOURCE).map(Self)
    }
}

#[cfg(windows)]
impl EventApi for RealEventApi {
    fn report(&self, event_type: u16, id: u32, text: &str) -> Result<(), i32> {
        self.0
            .report(event_type, id, text)
            .map_err(|e| e.raw_os_error().unwrap_or(-1))
    }
}

/// The real registry, over `ntpc_platform::service_host`.
#[cfg(windows)]
#[derive(Debug, Default, Clone, Copy)]
pub struct RealRegistry;

#[cfg(windows)]
impl EventSourceRegistry for RealRegistry {
    fn exists(&self, key: &str) -> Result<bool, String> {
        ntpc_platform::service_host::hklm_key_exists(key)
            .map_err(|e| format!("reading the registry failed: OS error {}", code(&e)))
    }

    fn write(&mut self, key: &str, message_file: &str, types: u32) -> Result<(), String> {
        ntpc_platform::service_host::write_event_source(key, message_file, types)
            .map_err(|e| format!("writing the registry failed: OS error {}", code(&e)))
    }

    fn delete(&mut self, key: &str) -> Result<(), String> {
        ntpc_platform::service_host::delete_hklm_key(key)
            .map_err(|e| format!("deleting the registry key failed: OS error {}", code(&e)))
    }
}

#[cfg(windows)]
fn code(e: &std::io::Error) -> i32 {
    e.raw_os_error().unwrap_or(-1)
}

#[cfg(test)]
mod tests;
