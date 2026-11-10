//! The configuration file.
//!
//! The file is TOML. Every key is optional, and an empty file gives the
//! defaults. Unknown keys are an error, so a typo cannot silently leave a
//! safety setting at its default.
//!
//! ```toml
//! servers = ["time.example.com", "192.0.2.7"]
//! dhcp = true
//! pool = "pool.ntp.org"
//! step_threshold_ms = 128
//! panic_threshold_s = 1000
//! allow_panic_step = false
//! min_poll_s = 64
//! max_poll_s = 1024
//! state_dir = 'C:\ProgramData\ntptimeclient-winrs'
//! ```
//!
//! Error messages name the key and the rule. They never print the file.
//! A syntax error shows the line, the column and the parser's short
//! message. That message can quote the one offending value, capped in length.

use std::io::{self, Read};
use std::net::Ipv6Addr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ntpc_core::discipline::DisciplineConfig;
use ntpc_core::engine::EngineConfig;
use serde::Deserialize;
use thiserror::Error;

/// Largest config file read. A real file is a few hundred bytes. The cap
/// stops a wrong path (a log, a disk image) being read into memory.
pub const MAX_CONFIG_BYTES: usize = 64 * 1024;

/// Most entries in `servers`. The resolver keeps 8 addresses per tier, so
/// more than 16 names (each may give up to 4) can never all be used.
pub const MAX_SERVERS: usize = 16;

/// Longest host name, from RFC 1035.
const MAX_HOST_LEN: usize = 253;
/// Longest single label of a host name, from RFC 1035.
const MAX_LABEL_LEN: usize = 63;
/// Longest parser message kept in an error.
const MAX_MESSAGE_LEN: usize = 200;

/// Default state directory. A fixed path, so a service started with an odd
/// environment still lands in the one directory the installer secures.
const DEFAULT_STATE_DIR: &str = r"C:\ProgramData\ntptimeclient-winrs";

/// Why the configuration could not be used.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// The file could not be opened or read.
    #[error("cannot read config file {}: {kind}", path.display())]
    Read {
        /// The file the caller asked for.
        path: PathBuf,
        /// What the operating system said.
        kind: io::ErrorKind,
    },
    /// The file is not valid UTF-8.
    #[error("config file {} is not valid UTF-8", path.display())]
    NotUtf8 {
        /// The file the caller asked for.
        path: PathBuf,
    },
    /// The text is larger than [`MAX_CONFIG_BYTES`].
    #[error("config is larger than {limit} bytes")]
    TooLarge {
        /// The limit that was hit.
        limit: usize,
    },
    /// The text is not valid TOML, or a key or value type is wrong.
    #[error("config syntax error{}: {message}", position(*line, *column))]
    Parse {
        /// Line of the problem, counted from 1, if known.
        line: Option<usize>,
        /// Column of the problem, counted from 1, if known.
        column: Option<usize>,
        /// The parser's short message.
        message: String,
    },
    /// The text parsed but a value breaks a rule.
    #[error("invalid config: {0}")]
    Invalid(String),
}

fn position(line: Option<usize>, column: Option<usize>) -> String {
    match (line, column) {
        (Some(l), Some(c)) => format!(" at line {l}, column {c}"),
        (Some(l), None) => format!(" at line {l}"),
        _ => String::new(),
    }
}

/// All settings. Field names are the TOML keys.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// Host names or IP literals. The first tier. Default none.
    pub servers: Vec<String>,
    /// Use servers offered by DHCP, the second tier. Default true.
    pub dhcp: bool,
    /// Pool name, the last tier and the cross-check. Default `pool.ntp.org`.
    pub pool: String,
    /// Offsets above this may be stepped, in milliseconds. Default 128.
    pub step_threshold_ms: u32,
    /// Steps above this are refused unless `allow_panic_step`, in seconds.
    /// Default 1000.
    pub panic_threshold_s: u32,
    /// Allow a step above the panic threshold. Default false.
    pub allow_panic_step: bool,
    /// Shortest poll interval in seconds. 64 to 128. Default 64.
    pub min_poll_s: u32,
    /// Longest poll interval in seconds. At most 1024. Default 1024.
    pub max_poll_s: u32,
    /// Where the drift file lives. The platform crate secures it.
    pub state_dir: PathBuf,
}

impl Default for Config {
    fn default() -> Self {
        let d = EngineConfig::default();
        Self {
            servers: Vec::new(),
            dhcp: true,
            pool: "pool.ntp.org".to_owned(),
            step_threshold_ms: 128,
            panic_threshold_s: 1000,
            allow_panic_step: d.discipline.allow_panic_step,
            min_poll_s: 64,
            max_poll_s: 1024,
            state_dir: PathBuf::from(DEFAULT_STATE_DIR),
        }
    }
}

impl Config {
    /// Parses and validates TOML text. Empty text gives the defaults.
    ///
    /// # Errors
    /// [`ConfigError::TooLarge`], [`ConfigError::Parse`] or
    /// [`ConfigError::Invalid`].
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        if text.len() > MAX_CONFIG_BYTES {
            return Err(ConfigError::TooLarge {
                limit: MAX_CONFIG_BYTES,
            });
        }
        let config: Config = toml::from_str(text).map_err(|e| parse_error(text, &e))?;
        config.validate()?;
        Ok(config)
    }

    /// Reads, parses and validates a file.
    ///
    /// At most [`MAX_CONFIG_BYTES`] plus one byte are read.
    ///
    /// # Errors
    /// [`ConfigError::Read`] when the file cannot be read, then everything
    /// [`Config::parse`] returns. Read and parse failures are separate
    /// variants so the host can tell a missing file from a bad one.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let read_err = |e: &io::Error| ConfigError::Read {
            path: path.to_owned(),
            kind: e.kind(),
        };
        let file = std::fs::File::open(path).map_err(|e| read_err(&e))?;
        let mut bytes = Vec::new();
        file.take(MAX_CONFIG_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| read_err(&e))?;
        if bytes.len() > MAX_CONFIG_BYTES {
            return Err(ConfigError::TooLarge {
                limit: MAX_CONFIG_BYTES,
            });
        }
        let text = String::from_utf8(bytes).map_err(|_| ConfigError::NotUtf8 {
            path: path.to_owned(),
        })?;
        Self::parse(&text)
    }

    /// Checks every rule. [`Config::parse`] calls it. Call it again after
    /// building a `Config` by hand.
    ///
    /// # Errors
    /// [`ConfigError::Invalid`] naming the key and the rule.
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.check().map_err(ConfigError::Invalid)
    }

    fn check(&self) -> Result<(), String> {
        // The engine's cross-check slew-age margin is 500 ppm times min_poll
        // against the step threshold. The Task 7 review found it gone at
        // 256 s and ruled 128 s as the ceiling. Below 64 s the pool load
        // doubles while the cross-check refuses a step.
        if !(64..=128).contains(&self.min_poll_s) {
            return Err(format!(
                "min_poll_s is {} but must be 64 to 128 seconds. The pool cross-check \
                 slew-age margin and the pool load assume that range",
                self.min_poll_s
            ));
        }
        // The discipline holds a frequency for a bounded time and caps the
        // learning interval. Both assume a poll of at most 1024 s.
        if self.max_poll_s > 1024 {
            return Err(format!(
                "max_poll_s is {} but must be at most 1024 seconds. The discipline hold \
                 limit and learning cap assume it",
                self.max_poll_s
            ));
        }
        if self.min_poll_s > self.max_poll_s {
            return Err(format!(
                "min_poll_s ({}) must not exceed max_poll_s ({})",
                self.min_poll_s, self.max_poll_s
            ));
        }
        if self.step_threshold_ms == 0 {
            return Err("step_threshold_ms must be above 0".to_owned());
        }
        // Widen first. A u32 of seconds times 1000 overflows u32.
        if u64::from(self.panic_threshold_s) * 1000 <= u64::from(self.step_threshold_ms) {
            return Err(format!(
                "panic_threshold_s ({}) must be larger than step_threshold_ms ({} ms)",
                self.panic_threshold_s, self.step_threshold_ms
            ));
        }
        if self.servers.len() > MAX_SERVERS {
            return Err(format!(
                "servers has {} entries, at most {MAX_SERVERS} are allowed",
                self.servers.len()
            ));
        }
        for (i, s) in self.servers.iter().enumerate() {
            host_error(s).map_or(Ok(()), |why| Err(format!("servers[{i}] {why}")))?;
        }
        if let Some(why) = host_error(&self.pool) {
            return Err(format!("pool {why}"));
        }
        let dir = self.state_dir.to_string_lossy();
        if dir.is_empty() || dir.contains('\0') {
            return Err("state_dir is empty or holds a NUL character".to_owned());
        }
        // A relative path would land wherever the service manager starts us.
        if cfg!(windows) && !self.state_dir.is_absolute() {
            return Err("state_dir must be an absolute path".to_owned());
        }
        Ok(())
    }

    /// Builds the engine settings. Fields the file cannot set keep the
    /// engine defaults. Call it on a validated config.
    #[must_use]
    pub fn engine_config(&self) -> EngineConfig {
        let base = EngineConfig::default();
        EngineConfig {
            discipline: DisciplineConfig {
                step_threshold: Duration::from_millis(u64::from(self.step_threshold_ms)),
                panic_threshold: Duration::from_secs(u64::from(self.panic_threshold_s)),
                allow_panic_step: self.allow_panic_step,
                ..base.discipline
            },
            min_poll: Duration::from_secs(u64::from(self.min_poll_s)),
            max_poll: Duration::from_secs(u64::from(self.max_poll_s)),
            ..base
        }
    }
}

/// Why `host` is not a usable host name or IP literal, if it is not.
/// The text starts with a verb so the caller can prefix the key.
fn host_error(host: &str) -> Option<&'static str> {
    if host.is_empty() {
        return Some("is empty");
    }
    if host.len() > MAX_HOST_LEN {
        return Some("is longer than 253 characters");
    }
    if host.chars().any(char::is_whitespace) {
        return Some("contains whitespace");
    }
    if host.contains(':') {
        // A colon means an IPv6 literal. "host:123" would otherwise pass as a
        // name and fail later with a confusing lookup error.
        return host
            .parse::<Ipv6Addr>()
            .err()
            .map(|_| "has a colon but is not an IPv6 address. The port is always 123");
    }
    if !host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    {
        return Some("contains a character that is not a letter, digit, dot, dash or underscore");
    }
    // One trailing dot is a valid absolute name.
    let body = host.strip_suffix('.').unwrap_or(host);
    for label in body.split('.') {
        if label.is_empty() {
            return Some("has an empty label");
        }
        if label.len() > MAX_LABEL_LEN {
            return Some("has a label longer than 63 characters");
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Some("has a label that starts or ends with a dash");
        }
    }
    None
}

fn parse_error(text: &str, e: &toml::de::Error) -> ConfigError {
    let (line, column) = e.span().map_or((None, None), |span| {
        let before = text.get(..span.start).unwrap_or("");
        let line = before.matches('\n').count() + 1;
        let col = before.rsplit('\n').next().map_or(0, |l| l.chars().count()) + 1;
        (Some(line), Some(col))
    });
    // `message()` is the short text without the source excerpt that the
    // `Display` form adds.
    let mut message: String = e.message().chars().take(MAX_MESSAGE_LEN).collect();
    message.retain(|c| !c.is_control());
    ConfigError::Parse {
        line,
        column,
        message,
    }
}

#[cfg(test)]
mod tests;
