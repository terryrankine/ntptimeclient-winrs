//! `status.json`: what the service is doing, for the `status` subcommand.
//!
//! The host writes it every 30 s into the secured state directory. The
//! writer is atomic: a temp file is created with `create_new` and the
//! link no-follow flag, written, flushed and renamed over the old file.
//!
//! Format: one flat JSON object of fixed keys and one nested `counters`
//! object. A hand-written writer and strict reader, not `serde_json`: the
//! schema is fixed and small, and the reader must refuse anything else.
//! The reader refuses a file over [`MAX_STATUS_BYTES`], any unknown,
//! missing or repeated key, a wrong type, an array, a string escape, a
//! nesting deeper than `counters`, another `format` and another `version`.
//!
//! Privacy: no address, path, user or machine name. Sources are counted
//! per tier only. The state directory lets other local users read files,
//! so the file says no more than the log already does.

use std::fmt::Write as _;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use ntpc_core::Tier;
use thiserror::Error;

use crate::logging::{format_utc, tier_label};
use crate::safe_open;

/// Name of the status file in the state directory.
pub const FILE_NAME: &str = "status.json";
/// Temp name in the same directory, so the rename stays on one volume.
const TEMP_NAME: &str = "status.json.tmp";

/// Largest file the reader accepts. A real file is under 1.5 KiB.
pub const MAX_STATUS_BYTES: u64 = 4096;

/// Value of the `format` key.
pub const FORMAT: &str = "ntptimeclient-winrs-status";

/// Value of the `version` key. A reader refuses any other.
pub const VERSION: u64 = 1;

/// Why adjustment is off, as the host sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Blocked {
    /// Adjustment is on.
    None,
    /// The service has not checked `w32time` yet, or is stopping.
    Starting,
    /// `w32time` runs, or its state cannot be read.
    W32Time,
    /// A clock command failed. The host re-arms after a delay.
    ClockFailure,
}

impl Blocked {
    fn as_str(self) -> &'static str {
        match self {
            Blocked::None => "none",
            Blocked::Starting => "starting",
            Blocked::W32Time => "w32time",
            Blocked::ClockFailure => "clock_failure",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "none" => Blocked::None,
            "starting" => Blocked::Starting,
            "w32time" => Blocked::W32Time,
            "clock_failure" => Blocked::ClockFailure,
            _ => return None,
        })
    }
}

/// Counts since the service started.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counters {
    /// Queries started.
    pub queries: u64,
    /// Good replies.
    pub samples: u64,
    /// Queries with no reply in time.
    pub timeouts: u64,
    /// Kiss-of-death replies.
    pub kiss_of_death: u64,
    /// Queries that could not be sent or got only ICMP errors.
    pub unreachable: u64,
    /// Queries the transport ended as malformed. `UdpTransport` never does
    /// (R97), so this counts other transports only.
    pub malformed: u64,
    /// Engine queries skipped because one for the same source was in flight.
    pub duplicate_queries: u64,
    /// Frequency and step commands sent to the clock.
    pub clock_commands: u64,
    /// Clock commands that failed.
    pub clock_failures: u64,
    /// Steps applied.
    pub steps: u64,
    /// Drift values saved.
    pub drift_saves: u64,
    /// Drift saves that failed.
    pub drift_save_failures: u64,
    /// Status writes that failed.
    pub status_write_failures: u64,
    /// Requests sent without a random origin (R57).
    pub nonce_failures: u64,
    /// Datagrams discarded by the transport (R55).
    pub datagrams_discarded: u64,
    /// Log lines dropped by the rate limit.
    pub log_suppressed: u64,
    /// DHCP reads that failed.
    pub dhcp_read_failures: u64,
}

/// One snapshot. Field names are the JSON keys.
#[expect(
    clippy::struct_excessive_bools,
    reason = "each flag is one key of the fixed file format"
)]
#[derive(Debug, Clone, PartialEq)]
pub struct StatusReport {
    /// Version of the service that wrote the file.
    pub service_version: String,
    /// When the file was written, Unix seconds.
    pub written_unix_s: i64,
    /// False in the final write at stop.
    pub running: bool,
    /// Seconds since the service started, awake time.
    pub uptime_s: u64,
    /// The tier selection uses.
    pub active_tier: Option<Tier>,
    /// Latest selected offset, seconds, remote minus local.
    pub last_offset_s: Option<f64>,
    /// Learned drift.
    pub drift_ppm: f64,
    /// Seconds since the latest update from a fresh sample.
    pub last_good_age_s: Option<u64>,
    /// The clock runs on the drift alone.
    pub holdover: bool,
    /// The engine may move the clock.
    pub adjustment_allowed: bool,
    /// Why not, if not.
    pub adjustment_blocked: Blocked,
    /// When the clock was last stepped, Unix seconds after the step.
    pub last_step_unix_s: Option<i64>,
    /// Size of that step, seconds.
    pub last_step_s: Option<f64>,
    /// Drift and status files are written. False when the state directory
    /// could not be secured.
    pub persistence: bool,
    /// Sources listed per tier.
    pub sources_config: u64,
    /// Sources listed per tier.
    pub sources_dhcp: u64,
    /// Sources listed per tier.
    pub sources_pool: u64,
    /// DHCP offers servers that the config file does not list, or the
    /// other way round.
    pub dhcp_differs: bool,
    /// Counts since start.
    pub counters: Counters,
}

/// Why a status file could not be read.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StatusError {
    /// Opening or reading failed. The kind only, no path.
    #[error("cannot read the status file: {0}")]
    Io(io::ErrorKind),
    /// The file is larger than [`MAX_STATUS_BYTES`].
    #[error("the status file is larger than {MAX_STATUS_BYTES} bytes")]
    TooLarge,
    /// Not UTF-8.
    #[error("the status file is not UTF-8")]
    NotUtf8,
    /// Not the JSON this module writes.
    #[error("the status file is not valid: {0}")]
    Invalid(String),
    /// A `version` this reader does not know.
    #[error("the status file has version {0}, this reader knows version {VERSION}")]
    Version(u64),
}

// ---------------------------------------------------------------- writer

fn num(out: &mut String, v: f64) {
    // `{:?}` is the shortest text that reads back exactly and is valid
    // JSON for finite values. NaN and infinity are not JSON.
    if v.is_finite() {
        let _ = write!(out, "{v:?}");
    } else {
        out.push_str("null");
    }
}

fn opt_f(out: &mut String, v: Option<f64>) {
    match v {
        Some(v) => num(out, v),
        None => out.push_str("null"),
    }
}

fn opt_i(out: &mut String, v: Option<i64>) {
    match v {
        Some(v) => {
            let _ = write!(out, "{v}");
        }
        None => out.push_str("null"),
    }
}

fn opt_u(out: &mut String, v: Option<u64>) {
    match v {
        Some(v) => {
            let _ = write!(out, "{v}");
        }
        None => out.push_str("null"),
    }
}

/// A string token. Only characters the strict reader accepts, so a version
/// string with a quote cannot break the file.
fn token(out: &mut String, s: &str) {
    out.push('"');
    out.extend(s.chars().map(|c| {
        if c.is_ascii_graphic() && c != '"' && c != '\\' {
            c
        } else {
            '_'
        }
    }));
    out.push('"');
}

/// The counters, in the order the file holds them.
fn counter_fields(c: &Counters) -> [(&'static str, u64); 17] {
    [
        ("queries", c.queries),
        ("samples", c.samples),
        ("timeouts", c.timeouts),
        ("kiss_of_death", c.kiss_of_death),
        ("unreachable", c.unreachable),
        ("malformed", c.malformed),
        ("duplicate_queries", c.duplicate_queries),
        ("clock_commands", c.clock_commands),
        ("clock_failures", c.clock_failures),
        ("steps", c.steps),
        ("drift_saves", c.drift_saves),
        ("drift_save_failures", c.drift_save_failures),
        ("status_write_failures", c.status_write_failures),
        ("nonce_failures", c.nonce_failures),
        ("datagrams_discarded", c.datagrams_discarded),
        ("log_suppressed", c.log_suppressed),
        ("dhcp_read_failures", c.dhcp_read_failures),
    ]
}

/// The JSON text of a report.
#[must_use]
pub fn to_json(r: &StatusReport) -> String {
    let mut o = String::with_capacity(1536);
    o.push_str("{\n");
    let _ = write!(
        o,
        "  \"format\": \"{FORMAT}\",\n  \"version\": {VERSION},\n"
    );
    o.push_str("  \"service_version\": ");
    token(&mut o, &r.service_version);
    let _ = write!(
        o,
        ",\n  \"written_unix_s\": {},\n  \"running\": {},\n  \"uptime_s\": {},\n",
        r.written_unix_s, r.running, r.uptime_s
    );
    o.push_str("  \"active_tier\": ");
    match r.active_tier {
        Some(t) => token(&mut o, tier_label(Some(t))),
        None => o.push_str("null"),
    }
    o.push_str(",\n  \"last_offset_s\": ");
    opt_f(&mut o, r.last_offset_s);
    o.push_str(",\n  \"drift_ppm\": ");
    num(&mut o, r.drift_ppm);
    o.push_str(",\n  \"last_good_age_s\": ");
    opt_u(&mut o, r.last_good_age_s);
    let _ = write!(
        o,
        ",\n  \"holdover\": {},\n  \"adjustment_allowed\": {},\n  \"adjustment_blocked\": \"{}\"",
        r.holdover,
        r.adjustment_allowed,
        r.adjustment_blocked.as_str()
    );
    o.push_str(",\n  \"last_step_unix_s\": ");
    opt_i(&mut o, r.last_step_unix_s);
    o.push_str(",\n  \"last_step_s\": ");
    opt_f(&mut o, r.last_step_s);
    let _ = write!(
        o,
        ",\n  \"persistence\": {},\n  \"sources_config\": {},\n  \"sources_dhcp\": {},\n  \
         \"sources_pool\": {},\n  \"dhcp_differs\": {},\n  \"counters\": {{\n",
        r.persistence, r.sources_config, r.sources_dhcp, r.sources_pool, r.dhcp_differs
    );
    let fields = counter_fields(&r.counters);
    for (i, (k, v)) in fields.iter().enumerate() {
        let comma = if i + 1 < fields.len() { "," } else { "" };
        let _ = writeln!(o, "    \"{k}\": {v}{comma}");
    }
    o.push_str("  }\n}\n");
    o
}

/// Writes a report somewhere. The host writes through this so tests can
/// watch the writes.
pub trait StatusWriter {
    /// Writes one snapshot.
    ///
    /// # Errors
    /// A message without any path.
    fn write(&self, report: &StatusReport) -> Result<(), String>;
}

/// Writes `status.json` in a directory the caller has secured.
#[derive(Debug, Clone)]
pub struct FileStatusWriter {
    dir: PathBuf,
}

impl FileStatusWriter {
    /// A writer into `dir`.
    #[must_use]
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// The status file.
    #[must_use]
    pub fn path(&self) -> PathBuf {
        self.dir.join(FILE_NAME)
    }
}

impl StatusWriter for FileStatusWriter {
    fn write(&self, report: &StatusReport) -> Result<(), String> {
        let temp = self.dir.join(TEMP_NAME);
        let fail = |step: &str, e: &io::Error| format!("{step}: {e}");
        // A temp file left by a crash is ours to remove. A directory or a
        // locked file there is an error.
        match fs::remove_file(&temp) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(fail("remove old status temp file", &e)),
        }
        let mut f =
            safe_open::create_new(&temp).map_err(|e| fail("create status temp file", &e))?;
        let text = to_json(report);
        if let Err(e) = f.write_all(text.as_bytes()).and_then(|()| f.sync_all()) {
            drop(f);
            let _ = fs::remove_file(&temp);
            return Err(fail("write status temp file", &e));
        }
        drop(f);
        fs::rename(&temp, self.path()).map_err(|e| {
            let _ = fs::remove_file(&temp);
            fail("replace status file", &e)
        })
    }
}

// ---------------------------------------------------------------- reader

#[derive(Debug, Clone, PartialEq)]
enum Value {
    Null,
    Bool(bool),
    /// The literal text, checked against the JSON number grammar.
    Num(String),
    Str(String),
    Obj(Vec<(String, Value)>),
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

fn bad(why: &str) -> StatusError {
    StatusError::Invalid(why.to_owned())
}

impl Parser<'_> {
    fn ws(&mut self) {
        while self
            .s
            .get(self.i)
            .is_some_and(|b| matches!(b, b' ' | b'\n' | b'\r' | b'\t'))
        {
            self.i += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn eat(&mut self, b: u8) -> Result<(), StatusError> {
        self.ws();
        if self.peek() == Some(b) {
            self.i += 1;
            Ok(())
        } else {
            Err(bad("unexpected character"))
        }
    }

    fn literal(&mut self, word: &[u8]) -> Result<(), StatusError> {
        let end = self.i + word.len();
        if self.s.get(self.i..end) == Some(word) {
            self.i = end;
            Ok(())
        } else {
            Err(bad("unknown literal"))
        }
    }

    fn string(&mut self) -> Result<String, StatusError> {
        self.eat(b'"')?;
        let start = self.i;
        loop {
            match self.peek() {
                None => return Err(bad("unterminated string")),
                Some(b'"') => break,
                // The writer never escapes, so an escape is not ours.
                Some(b'\\') => return Err(bad("escape in string")),
                Some(b) if b < 0x20 => return Err(bad("control character in string")),
                Some(_) => self.i += 1,
            }
        }
        let text = std::str::from_utf8(self.s.get(start..self.i).unwrap_or(&[]))
            .map_err(|_| bad("string is not UTF-8"))?
            .to_owned();
        self.i += 1;
        Ok(text)
    }

    fn number(&mut self) -> Result<String, StatusError> {
        let start = self.i;
        let digits = |p: &mut Self| {
            let from = p.i;
            while p.peek().is_some_and(|b| b.is_ascii_digit()) {
                p.i += 1;
            }
            p.i > from
        };
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        if self.peek() == Some(b'0') {
            self.i += 1;
        } else if !digits(self) {
            return Err(bad("bad number"));
        }
        if self.peek() == Some(b'.') {
            self.i += 1;
            if !digits(self) {
                return Err(bad("bad number"));
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.i += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if !digits(self) {
                return Err(bad("bad number"));
            }
        }
        let text = std::str::from_utf8(self.s.get(start..self.i).unwrap_or(&[]))
            .map_err(|_| bad("bad number"))?;
        Ok(text.to_owned())
    }

    fn value(&mut self, depth: u8) -> Result<Value, StatusError> {
        self.ws();
        match self.peek() {
            Some(b'{') if depth < 2 => self.object(depth + 1).map(Value::Obj),
            Some(b'{') => Err(bad("nested too deep")),
            Some(b'"') => self.string().map(Value::Str),
            Some(b't') => self.literal(b"true").map(|()| Value::Bool(true)),
            Some(b'f') => self.literal(b"false").map(|()| Value::Bool(false)),
            Some(b'n') => self.literal(b"null").map(|()| Value::Null),
            Some(b'-' | b'0'..=b'9') => self.number().map(Value::Num),
            _ => Err(bad("unexpected value")),
        }
    }

    fn object(&mut self, depth: u8) -> Result<Vec<(String, Value)>, StatusError> {
        self.eat(b'{')?;
        let mut out: Vec<(String, Value)> = Vec::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(out);
        }
        loop {
            self.ws();
            let key = self.string()?;
            if out.iter().any(|(k, _)| *k == key) {
                return Err(StatusError::Invalid(format!("repeated key {key}")));
            }
            self.eat(b':')?;
            let v = self.value(depth)?;
            out.push((key, v));
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    return Ok(out);
                }
                _ => return Err(bad("expected , or }")),
            }
        }
    }
}

/// Takes keys out of an object one by one and refuses leftovers.
struct Fields(Vec<(String, Value)>);

impl Fields {
    fn take(&mut self, key: &str) -> Result<Value, StatusError> {
        let i = self
            .0
            .iter()
            .position(|(k, _)| k == key)
            .ok_or_else(|| StatusError::Invalid(format!("missing key {key}")))?;
        Ok(self.0.swap_remove(i).1)
    }

    fn done(self) -> Result<(), StatusError> {
        match self.0.first() {
            None => Ok(()),
            Some((k, _)) => Err(StatusError::Invalid(format!("unknown key {k}"))),
        }
    }

    fn u64(&mut self, key: &str) -> Result<u64, StatusError> {
        match self.take(key)? {
            Value::Num(n) => n
                .parse()
                .map_err(|_| StatusError::Invalid(format!("{key} is not a whole number"))),
            _ => Err(StatusError::Invalid(format!("{key} is not a number"))),
        }
    }

    fn opt_u64(&mut self, key: &str) -> Result<Option<u64>, StatusError> {
        match self.take(key)? {
            Value::Null => Ok(None),
            Value::Num(n) => n
                .parse()
                .map(Some)
                .map_err(|_| StatusError::Invalid(format!("{key} is not a whole number"))),
            _ => Err(StatusError::Invalid(format!("{key} is not a number"))),
        }
    }

    fn opt_i64(&mut self, key: &str) -> Result<Option<i64>, StatusError> {
        match self.take(key)? {
            Value::Null => Ok(None),
            Value::Num(n) => n
                .parse()
                .map(Some)
                .map_err(|_| StatusError::Invalid(format!("{key} is not a whole number"))),
            _ => Err(StatusError::Invalid(format!("{key} is not a number"))),
        }
    }

    fn i64(&mut self, key: &str) -> Result<i64, StatusError> {
        self.opt_i64(key)?
            .ok_or_else(|| StatusError::Invalid(format!("{key} is null")))
    }

    fn opt_f64(&mut self, key: &str) -> Result<Option<f64>, StatusError> {
        match self.take(key)? {
            Value::Null => Ok(None),
            Value::Num(n) => match n.parse::<f64>() {
                Ok(v) if v.is_finite() => Ok(Some(v)),
                _ => Err(StatusError::Invalid(format!("{key} is out of range"))),
            },
            _ => Err(StatusError::Invalid(format!("{key} is not a number"))),
        }
    }

    fn f64(&mut self, key: &str) -> Result<f64, StatusError> {
        self.opt_f64(key)?
            .ok_or_else(|| StatusError::Invalid(format!("{key} is null")))
    }

    fn bool(&mut self, key: &str) -> Result<bool, StatusError> {
        match self.take(key)? {
            Value::Bool(b) => Ok(b),
            _ => Err(StatusError::Invalid(format!("{key} is not true or false"))),
        }
    }

    fn opt_str(&mut self, key: &str) -> Result<Option<String>, StatusError> {
        match self.take(key)? {
            Value::Null => Ok(None),
            Value::Str(s) => Ok(Some(s)),
            _ => Err(StatusError::Invalid(format!("{key} is not a string"))),
        }
    }

    fn str(&mut self, key: &str) -> Result<String, StatusError> {
        self.opt_str(key)?
            .ok_or_else(|| StatusError::Invalid(format!("{key} is null")))
    }
}

fn parse_tier(s: &str) -> Option<Tier> {
    Some(match s {
        "config" => Tier::Config,
        "dhcp" => Tier::Dhcp,
        "pool" => Tier::Pool,
        _ => return None,
    })
}

/// Parses the text of a status file.
///
/// # Errors
/// [`StatusError::Invalid`] for anything this module does not write, or
/// [`StatusError::Version`] for another version.
pub fn parse(text: &str) -> Result<StatusReport, StatusError> {
    if text.len() as u64 > MAX_STATUS_BYTES {
        return Err(StatusError::TooLarge);
    }
    let mut p = Parser {
        s: text.as_bytes(),
        i: 0,
    };
    p.ws();
    if p.peek() != Some(b'{') {
        return Err(bad("not an object"));
    }
    let top = p.object(1)?;
    p.ws();
    if p.i != p.s.len() {
        return Err(bad("text after the object"));
    }
    let mut f = Fields(top);
    if f.str("format")? != FORMAT {
        return Err(bad("not a status file of this service"));
    }
    let version = f.u64("version")?;
    if version != VERSION {
        return Err(StatusError::Version(version));
    }
    let service_version = f.str("service_version")?;
    let written_unix_s = f.i64("written_unix_s")?;
    let running = f.bool("running")?;
    let uptime_s = f.u64("uptime_s")?;
    let active_tier = match f.opt_str("active_tier")? {
        None => None,
        Some(s) => Some(parse_tier(&s).ok_or_else(|| bad("unknown tier"))?),
    };
    let last_offset_s = f.opt_f64("last_offset_s")?;
    let drift_ppm = f.f64("drift_ppm")?;
    let last_good_age_s = f.opt_u64("last_good_age_s")?;
    let holdover = f.bool("holdover")?;
    let adjustment_allowed = f.bool("adjustment_allowed")?;
    let adjustment_blocked =
        Blocked::parse(&f.str("adjustment_blocked")?).ok_or_else(|| bad("unknown block"))?;
    let last_step_unix_s = f.opt_i64("last_step_unix_s")?;
    let last_step_s = f.opt_f64("last_step_s")?;
    let persistence = f.bool("persistence")?;
    let sources_config = f.u64("sources_config")?;
    let sources_dhcp = f.u64("sources_dhcp")?;
    let sources_pool = f.u64("sources_pool")?;
    let dhcp_differs = f.bool("dhcp_differs")?;
    let Value::Obj(cobj) = f.take("counters")? else {
        return Err(bad("counters is not an object"));
    };
    f.done()?;
    let mut c = Fields(cobj);
    let mut counters = Counters::default();
    {
        let slots: [(&str, &mut u64); 17] = [
            ("queries", &mut counters.queries),
            ("samples", &mut counters.samples),
            ("timeouts", &mut counters.timeouts),
            ("kiss_of_death", &mut counters.kiss_of_death),
            ("unreachable", &mut counters.unreachable),
            ("malformed", &mut counters.malformed),
            ("duplicate_queries", &mut counters.duplicate_queries),
            ("clock_commands", &mut counters.clock_commands),
            ("clock_failures", &mut counters.clock_failures),
            ("steps", &mut counters.steps),
            ("drift_saves", &mut counters.drift_saves),
            ("drift_save_failures", &mut counters.drift_save_failures),
            ("status_write_failures", &mut counters.status_write_failures),
            ("nonce_failures", &mut counters.nonce_failures),
            ("datagrams_discarded", &mut counters.datagrams_discarded),
            ("log_suppressed", &mut counters.log_suppressed),
            ("dhcp_read_failures", &mut counters.dhcp_read_failures),
        ];
        for (k, slot) in slots {
            *slot = c.u64(k)?;
        }
    }
    c.done()?;
    Ok(StatusReport {
        service_version,
        written_unix_s,
        running,
        uptime_s,
        active_tier,
        last_offset_s,
        drift_ppm,
        last_good_age_s,
        holdover,
        adjustment_allowed,
        adjustment_blocked,
        last_step_unix_s,
        last_step_s,
        persistence,
        sources_config,
        sources_dhcp,
        sources_pool,
        dhcp_differs,
        counters,
    })
}

/// Reads and checks a status file. At most [`MAX_STATUS_BYTES`] plus one
/// byte are read. Links are not followed.
///
/// # Errors
/// [`StatusError`].
pub fn read_status(path: &Path) -> Result<StatusReport, StatusError> {
    let file = safe_open::open_read(path).map_err(|e| StatusError::Io(e.kind()))?;
    let mut bytes = Vec::new();
    file.take(MAX_STATUS_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| StatusError::Io(e.kind()))?;
    if bytes.len() as u64 > MAX_STATUS_BYTES {
        return Err(StatusError::TooLarge);
    }
    let text = String::from_utf8(bytes).map_err(|_| StatusError::NotUtf8)?;
    parse(&text)
}

fn secs_text(v: Option<f64>) -> String {
    v.map_or_else(|| "none".to_owned(), |s| format!("{s:+.6} s"))
}

/// A short human summary for the `status` subcommand.
#[must_use]
pub fn format_status(r: &StatusReport) -> String {
    let mut o = String::new();
    let _ = writeln!(
        o,
        "ntptimeclient-winrs {} ({})",
        r.service_version,
        if r.running { "running" } else { "stopped" }
    );
    let _ = writeln!(
        o,
        "written:            {}",
        format_utc(i128::from(r.written_unix_s) * 1_000_000_000)
    );
    let _ = writeln!(o, "uptime:             {} s", r.uptime_s);
    let _ = writeln!(o, "active tier:        {}", tier_label(r.active_tier));
    let _ = writeln!(o, "last offset:        {}", secs_text(r.last_offset_s));
    let _ = writeln!(o, "drift:              {:+.3} ppm", r.drift_ppm);
    let _ = writeln!(
        o,
        "last good sample:   {}",
        r.last_good_age_s
            .map_or_else(|| "never".to_owned(), |a| format!("{a} s ago"))
    );
    let _ = writeln!(o, "holdover:           {}", yes_no(r.holdover));
    let _ = writeln!(
        o,
        "adjustment:         {}",
        if r.adjustment_allowed {
            "on".to_owned()
        } else {
            format!("off ({})", r.adjustment_blocked.as_str())
        }
    );
    let _ = writeln!(
        o,
        "last step:          {}",
        match (r.last_step_unix_s, r.last_step_s) {
            (Some(t), Some(s)) => format!(
                "{:+.6} s at {}",
                s,
                format_utc(i128::from(t) * 1_000_000_000)
            ),
            _ => "none".to_owned(),
        }
    );
    let _ = writeln!(
        o,
        "persistence:        {}",
        if r.persistence { "on" } else { "off" }
    );
    let _ = writeln!(
        o,
        "sources:            config {}, dhcp {}, pool {}",
        r.sources_config, r.sources_dhcp, r.sources_pool
    );
    let _ = writeln!(o, "dhcp differs:       {}", yes_no(r.dhcp_differs));
    o.push_str("counters:\n");
    for (k, v) in counter_fields(&r.counters) {
        let _ = writeln!(o, "  {k:<22}{v}");
    }
    o
}

fn yes_no(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
}

#[cfg(test)]
mod tests {
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
}
