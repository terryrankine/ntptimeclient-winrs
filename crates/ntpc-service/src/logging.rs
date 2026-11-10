//! Log lines: one event per line, escaped, length capped and rate limited.
//!
//! Line format: `2026-11-10T12:34:56.789Z WARN  message`. Time is UTC.
//!
//! Rules:
//! - Every message is escaped before it reaches a sink. A host name, a
//!   kiss code or an OS error text can come from the network, and a raw
//!   newline or terminal escape in it could forge a log line or hide one.
//!   Backslash, every Unicode control character, the line and paragraph
//!   separators and the bidi and zero-width format characters are written
//!   as escapes.
//! - A line holds at most [`MAX_LINE_CHARS`] characters of message.
//! - Each message kind is written at most [`RATE_MAX`] times per
//!   [`RATE_WINDOW`]. The rest are counted and one summary line follows
//!   when the window ends. A hostile network cannot fill the disk through
//!   the log.
//! - Privacy: the host writes no path, no user or machine name and none of
//!   this machine's addresses. Sources appear by id and their configured
//!   label (a name from the config file, the pool name or a DHCP-offered
//!   server address).

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use ntpc_core::engine::{DisableReason, LogEvent};
use ntpc_core::{KodCode, Mono, SourceId, Tier};

use crate::transport::TimeSource;

/// Longest message kept on one line, in characters, after escaping.
pub const MAX_LINE_CHARS: usize = 512;

/// Rate limit window.
pub const RATE_WINDOW: Duration = Duration::from_secs(60);

/// Most lines of one kind per window. Ten covers a normal burst (a start,
/// a tier change with its probes) and caps a flood at 600 lines per hour
/// per kind.
pub const RATE_MAX: u32 = 10;

/// Default file size before the file sink rotates. Two files of this size
/// are the most the log uses on disk.
pub const DEFAULT_MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;

/// How serious a line is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// Something failed.
    Error,
    /// Something is wrong or unusual. The service goes on.
    Warn,
    /// Normal operation.
    Info,
    /// Detail for development.
    Debug,
}

impl Level {
    fn tag(self) -> &'static str {
        match self {
            Level::Error => "ERROR",
            Level::Warn => "WARN ",
            Level::Info => "INFO ",
            Level::Debug => "DEBUG",
        }
    }
}

/// Where finished lines go.
pub trait LogSink: Send + Sync {
    /// Writes one line. The line has no newline. The sink adds it.
    fn write_line(&self, line: &str);
}

/// The host's log.
pub trait Logger: Send + Sync {
    /// Logs one message. `kind` names the message for the rate limit, so
    /// messages with different text but the same cause share one budget.
    fn log(&self, level: Level, kind: &'static str, message: &str);

    /// Writes the summary lines of rate windows that have ended.
    fn flush(&self) {}

    /// Lines dropped by the rate limit so far.
    fn suppressed(&self) -> u64 {
        0
    }
}

/// True for characters that must not reach a log line raw.
fn needs_escape(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            // Arabic letter mark, zero-width space to right-to-left mark,
            // line and paragraph separators, bidi embeddings and overrides,
            // word joiner and invisible operators, bidi isolates, BOM.
            '\u{061C}'
                | '\u{200B}'..='\u{200F}'
                | '\u{2028}'..='\u{202E}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{2069}'
                | '\u{FEFF}'
        )
}

/// Escapes a string for one log line. Backslash becomes `\\`, so an escape
/// in the output always came from this function.
#[must_use]
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if needs_escape(c) => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{{{:04X}}}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out
}

/// Cuts an escaped message to [`MAX_LINE_CHARS`] characters and marks the
/// cut. It may end inside an escape sequence. The marker says so, and no
/// raw control character can appear, because the input is already escaped.
fn cap(escaped: String) -> String {
    if escaped.chars().count() <= MAX_LINE_CHARS {
        return escaped;
    }
    let mut out: String = escaped.chars().take(MAX_LINE_CHARS).collect();
    out.push_str(" [truncated]");
    out
}

/// Formats Unix nanoseconds as `YYYY-MM-DDTHH:MM:SS.mmmZ`.
#[must_use]
pub fn format_utc(unix_ns: i128) -> String {
    let ms_total = unix_ns.div_euclid(1_000_000);
    let ms = ms_total.rem_euclid(1000);
    let secs = ms_total.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{ms:03}Z",
        tod / 3600,
        (tod / 60) % 60,
        tod % 60
    )
}

/// Days since 1970-01-01 to a proleptic Gregorian date. H. Hinnant's
/// `civil_from_days`, in integers, valid for any i128 day count in range.
fn civil_from_days(z: i128) -> (i128, i128, i128) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[derive(Debug, Clone, Copy)]
struct Window {
    start: Mono,
    count: u32,
    suppressed: u64,
}

/// The default [`Logger`]: escapes, caps, rate limits, stamps and hands the
/// line to a sink.
pub struct LineLogger {
    sink: Box<dyn LogSink>,
    time: Arc<dyn TimeSource>,
    max_per_window: u32,
    windows: Mutex<BTreeMap<&'static str, Window>>,
    suppressed: AtomicU64,
}

impl std::fmt::Debug for LineLogger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LineLogger")
            .field("max_per_window", &self.max_per_window)
            .finish_non_exhaustive()
    }
}

impl LineLogger {
    /// A logger with the default rate limit.
    #[must_use]
    pub fn new(sink: Box<dyn LogSink>, time: Arc<dyn TimeSource>) -> Self {
        Self::with_limit(sink, time, RATE_MAX)
    }

    /// A logger that writes at most `max_per_window` lines of one kind per
    /// [`RATE_WINDOW`].
    #[must_use]
    pub fn with_limit(sink: Box<dyn LogSink>, time: Arc<dyn TimeSource>, max: u32) -> Self {
        Self {
            sink,
            time,
            max_per_window: max.max(1),
            windows: Mutex::new(BTreeMap::new()),
            suppressed: AtomicU64::new(0),
        }
    }

    fn emit(&self, level: Level, message: &str) {
        let line = format!(
            "{} {} {}",
            format_utc(self.time.wall_ns()),
            level.tag(),
            cap(escape(message))
        );
        self.sink.write_line(&line);
    }

    fn summary(&self, kind: &str, n: u64) {
        self.emit(
            Level::Warn,
            &format!("suppressed {n} similar messages of kind {kind}"),
        );
    }
}

impl Logger for LineLogger {
    fn log(&self, level: Level, kind: &'static str, message: &str) {
        let now = self.time.mono();
        // A summary is written outside the lock, after the window resets.
        let (write, summary) = {
            let mut map = self.windows.lock().unwrap_or_else(PoisonError::into_inner);
            let w = map.entry(kind).or_insert(Window {
                start: now,
                count: 0,
                suppressed: 0,
            });
            let mut summary = None;
            if now.saturating_duration_since(w.start) >= RATE_WINDOW {
                if w.suppressed > 0 {
                    summary = Some(w.suppressed);
                }
                *w = Window {
                    start: now,
                    count: 0,
                    suppressed: 0,
                };
            }
            w.count = w.count.saturating_add(1);
            let write = w.count <= self.max_per_window;
            if !write {
                w.suppressed += 1;
                self.suppressed.fetch_add(1, Ordering::Relaxed);
            }
            (write, summary)
        };
        if let Some(n) = summary {
            self.summary(kind, n);
        }
        if write {
            self.emit(level, message);
        }
    }

    fn flush(&self) {
        let now = self.time.mono();
        let ended: Vec<(&'static str, u64)> = {
            let mut map = self.windows.lock().unwrap_or_else(PoisonError::into_inner);
            let mut ended = Vec::new();
            for (kind, w) in map.iter_mut() {
                if w.suppressed > 0 && now.saturating_duration_since(w.start) >= RATE_WINDOW {
                    ended.push((*kind, w.suppressed));
                    *w = Window {
                        start: now,
                        count: 0,
                        suppressed: 0,
                    };
                }
            }
            ended
        };
        for (kind, n) in ended {
            self.summary(kind, n);
        }
    }

    fn suppressed(&self) -> u64 {
        self.suppressed.load(Ordering::Relaxed)
    }
}

/// Writes lines to standard error. For the console `run` mode.
#[derive(Debug, Default)]
pub struct ConsoleSink {
    errors: AtomicU64,
}

impl ConsoleSink {
    /// A sink on standard error.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Lines that could not be written.
    #[must_use]
    pub fn write_errors(&self) -> u64 {
        self.errors.load(Ordering::Relaxed)
    }
}

impl LogSink for ConsoleSink {
    fn write_line(&self, line: &str) {
        let mut err = io::stderr().lock();
        if writeln!(err, "{line}").is_err() {
            // Nowhere left to report it. Counted, not lost silently.
            self.errors.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Keeps lines in memory. For tests and for the status command's own use.
#[derive(Debug, Clone, Default)]
pub struct MemorySink {
    lines: Arc<Mutex<Vec<String>>>,
}

impl MemorySink {
    /// An empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Every line so far.
    #[must_use]
    pub fn lines(&self) -> Vec<String> {
        self.lines
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl LogSink for MemorySink {
    fn write_line(&self, line: &str) {
        self.lines
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(line.to_owned());
    }
}

/// Windows `FILE_FLAG_OPEN_REPARSE_POINT`, as in `safe_open`. A planted
/// link at the log path is opened as itself, not followed.
#[cfg(windows)]
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
/// Windows `SECURITY_IDENTIFICATION`, as in `safe_open`.
#[cfg(windows)]
const SECURITY_IDENTIFICATION: u32 = 0x0001_0000;

fn open_append(path: &Path) -> io::Result<File> {
    let mut o = OpenOptions::new();
    o.append(true).create(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        o.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .security_qos_flags(SECURITY_IDENTIFICATION);
    }
    let f = o.open(path)?;
    #[cfg(windows)]
    if f.metadata()?.file_type().is_symlink() {
        return Err(io::Error::other("log path is a symbolic link or junction"));
    }
    Ok(f)
}

struct FileState {
    file: Option<File>,
    size: u64,
    /// Rotation failed. Writing stops so a stuck file cannot grow without
    /// bound.
    stopped: bool,
}

/// Appends lines to a file. At `max_bytes` the file is renamed to
/// `<name>.1`, replacing an older one, and a new file starts. The folder
/// must be secured by the caller. Where the log lives is decided in 14c.
pub struct FileSink {
    path: PathBuf,
    rotated: PathBuf,
    max_bytes: u64,
    state: Mutex<FileState>,
    errors: AtomicU64,
}

impl std::fmt::Debug for FileSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileSink")
            .field("max_bytes", &self.max_bytes)
            .finish_non_exhaustive()
    }
}

impl FileSink {
    /// A sink appending to `path`. Opened on the first line.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>, max_bytes: u64) -> Self {
        let path = path.into();
        let mut rotated = path.clone().into_os_string();
        rotated.push(".1");
        Self {
            path,
            rotated: PathBuf::from(rotated),
            max_bytes: max_bytes.max(1024),
            state: Mutex::new(FileState {
                file: None,
                size: 0,
                stopped: false,
            }),
            errors: AtomicU64::new(0),
        }
    }

    /// Lines that could not be written.
    #[must_use]
    pub fn write_errors(&self) -> u64 {
        self.errors.load(Ordering::Relaxed)
    }

    fn write_locked(&self, st: &mut FileState, line: &str) -> io::Result<()> {
        if st.stopped {
            return Err(io::Error::other(
                "log writing stopped after a failed rotation",
            ));
        }
        if st.file.is_none() {
            let f = open_append(&self.path)?;
            st.size = f.metadata()?.len();
            st.file = Some(f);
        }
        let len = line.len() as u64 + 1;
        if st.size + len > self.max_bytes {
            st.file = None;
            if let Err(e) = std::fs::rename(&self.path, &self.rotated) {
                st.stopped = true;
                return Err(e);
            }
            let f = open_append(&self.path)?;
            st.size = 0;
            st.file = Some(f);
        }
        let Some(f) = st.file.as_mut() else {
            return Err(io::Error::other("log file not open"));
        };
        writeln!(f, "{line}")?;
        st.size += len;
        Ok(())
    }
}

impl LogSink for FileSink {
    fn write_line(&self, line: &str) {
        let mut st = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if self.write_locked(&mut st, line).is_err() {
            self.errors.fetch_add(1, Ordering::Relaxed);
            // Reopen on the next line, unless rotation stopped the sink.
            st.file = None;
        }
    }
}

/// The tier's name as `status.json` and the log write it.
#[must_use]
pub fn tier_label(t: Option<Tier>) -> &'static str {
    match t {
        Some(Tier::Config) => "config",
        Some(Tier::Dhcp) => "dhcp",
        Some(Tier::Pool) => "pool",
        None => "none",
    }
}

fn kod_name(c: KodCode) -> &'static str {
    match c {
        KodCode::Deny => "DENY",
        KodCode::Rstr => "RSTR",
        KodCode::Rate => "RATE",
        KodCode::Other => "other",
    }
}

fn ids(list: &[SourceId], label: &dyn Fn(SourceId) -> String) -> String {
    let parts: Vec<String> = list.iter().map(|&id| label(id)).collect();
    format!("[{}]", parts.join(", "))
}

/// Turns an engine log event into a level, a rate-limit kind and a message.
/// `label` names a source, for example `source 3 (pool.ntp.org)`.
#[must_use]
pub fn engine_event(
    ev: &LogEvent,
    label: &dyn Fn(SourceId) -> String,
) -> (Level, &'static str, String) {
    match ev {
        LogEvent::TierChanged { from, to } => (
            Level::Info,
            "tier_changed",
            format!(
                "active tier changed from {} to {}",
                tier_label(*from),
                tier_label(*to)
            ),
        ),
        LogEvent::SingleSourceTier { tier, source } => (
            Level::Warn,
            "single_source",
            format!(
                "the {} tier has a single source, {}. Only the pool cross-check guards it",
                tier_label(Some(*tier)),
                label(*source)
            ),
        ),
        LogEvent::DhcpDiffersFromConfig {
            dhcp_only,
            config_only,
        } => (
            Level::Info,
            "dhcp_differs",
            format!(
                "DHCP offers servers that differ from the config file. DHCP only {}, \
                 config only {}",
                ids(dhcp_only, label),
                ids(config_only, label)
            ),
        ),
        LogEvent::KissOfDeath { source, code, wait } => (
            Level::Warn,
            "kiss_of_death",
            format!(
                "{} sent kiss-of-death {}. Next query in {} s at the earliest",
                label(*source),
                kod_name(*code),
                wait.as_secs()
            ),
        ),
        LogEvent::StepTaken { offset } => (
            Level::Warn,
            "step_taken",
            format!("clock stepped by {:+.6} s", offset.as_secs()),
        ),
        LogEvent::StepRefused { offset } => (
            Level::Warn,
            "step_refused",
            format!(
                "a step of {:+.6} s was refused. The clock slews instead",
                offset.as_secs()
            ),
        ),
        LogEvent::AdjustmentDisabled { reason } => (
            Level::Warn,
            "adjustment_disabled",
            match reason {
                DisableReason::Host => {
                    "clock adjustment is off: another time service runs or the service is \
                     starting. Measuring only"
                        .to_owned()
                }
                DisableReason::ClockFailed => {
                    "clock adjustment is off after a failed clock command. Measuring only"
                        .to_owned()
                }
            },
        ),
        LogEvent::AdjustmentEnabled => (
            Level::Info,
            "adjustment_enabled",
            "clock adjustment is on".to_owned(),
        ),
        LogEvent::ClockCommandFailed { error } => (
            Level::Error,
            "clock_failed",
            format!("clock command failed: {error}"),
        ),
        LogEvent::HoldoverStarted { frequency } => (
            Level::Warn,
            "holdover",
            format!(
                "no fresh update in time. Holdover on the learned drift, {:+.3} ppm",
                frequency.value()
            ),
        ),
    }
}
