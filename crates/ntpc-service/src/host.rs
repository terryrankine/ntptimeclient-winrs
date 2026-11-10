//! The service host. It drives the engine and does its I/O.
//!
//! Ruling R90: no async runtime. One loop thread owns the [`Engine`](ntpc_core::engine::Engine) and
//! the clock. Everything that can block runs elsewhere and reports back
//! over one `std::sync::mpsc` channel:
//!
//! - Queries: one short worker thread each, through [`Spawn`]. The host
//!   keeps at most one query in flight per source (R15). A query the engine
//!   asks for while one is in flight is not sent again. The in-flight one
//!   answers it.
//! - Name lookups: one worker at a time runs [`Resolver::expand`]. The
//!   `std` lookup has no timeout, so the host never waits for it. After
//!   [`RESOLVE_GIVE_UP`] it builds a new resolver and ignores the old
//!   worker's result. Source ids may then repeat for other addresses, which
//!   the engine treats as a replaced source.
//! - DHCP: one dedicated reader thread for the whole run (R82). It reads
//!   only when the loop asks. The loop applies the settle delay, the
//!   minimum interval, the long re-read timer and the per-adapter negative
//!   cache, so the rules run on fake time in tests.
//! - Clock, drift file, status file, the `w32time` monitor and the network
//!   and power polls run on the loop. Each is a short local call.
//!
//! The loop sleeps in [`Waiter::wait`] until the earliest of: the engine's
//! next wake, the next `w32time` check, the next status write, the next DHCP
//! read, a query watchdog or a resolver give-up. A message wakes it early.
//!
//! On shutdown the loop stops starting work, resets the clock rate once
//! (R71), saves the drift once if it changed, writes a final status and
//! returns. It joins no worker. A worker blocked in the network or in a
//! lookup ends on its own, and its result goes nowhere.
//!
//! Engine host contract (see `ntpc_core::engine`): every query gets exactly
//! one answer, a `Tick` precedes any event without a time when time has
//! moved, clock results are fed in order, a batch's clock actions stop at
//! the first failure, the adjustment level is re-sent every
//! [`LEVEL_PERIOD`], and after a clock failure the host re-arms with
//! `AdjustmentAllowed(false)` then `(true)` (R39).

mod dhcp;
mod inflight;
mod startup;
mod state;

use std::collections::BTreeSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::Duration;

use ntpc_core::{
    Clock, ClockError, Mono, Ppm, QueryFailure, Sample, SourceId, SourceSpec, StoreError,
};
use thiserror::Error;

use crate::config::{Config, ConfigError};
use crate::drift_store::{FileDriftStore, LoadNote};
use crate::logging::Logger;
use crate::resolver::{NameLookup, OwnAddresses, ResolveNote, Resolver};
use crate::status::StatusWriter;
use crate::transport::{TimeSource, Transport};

pub use dhcp::{DHCP_MIN_INTERVAL, DHCP_REREAD, DHCP_SETTLE};

/// Timeout passed to the transport. The engine wants well under 30 s. An
/// internet round trip is under a second, so 5 s loses no real reply.
pub const QUERY_TIMEOUT: Duration = Duration::from_secs(5);

/// If a query worker has not answered after this, the host answers for it
/// with a timeout. A transport bug must not break the one-answer contract.
/// Still under the engine's 30 s round limit.
pub const QUERY_WATCHDOG: Duration = Duration::from_secs(15);

/// How often the host asks the `w32time` monitor and re-sends the
/// adjustment level. Task 12 polls every 30 s.
pub const LEVEL_PERIOD: Duration = Duration::from_secs(30);

/// How often `status.json` is written.
pub const STATUS_PERIOD: Duration = Duration::from_secs(30);

/// A lookup worker still running after this is given up. Windows lookups
/// time out on their own in well under a minute, so this only catches a
/// stuck resolver.
pub const RESOLVE_GIVE_UP: Duration = Duration::from_secs(300);

/// Ruling R66: while no tier is active, resolve at least this often, even
/// when the resolver's own back-off is longer.
pub const OFFLINE_RESOLVE_CAP: Duration = Duration::from_secs(900);

/// First wait before re-arming adjustment after a clock failure. It doubles
/// per failure in a row up to [`REARM_MAX`], so a clock that keeps failing
/// is retried rarely.
pub const REARM_FIRST: Duration = Duration::from_secs(60);

/// Longest wait before re-arming after a clock failure.
pub const REARM_MAX: Duration = Duration::from_secs(3600);

/// The clock plus what the host needs beyond the core port. The Windows
/// clock implements it in 14c.
pub trait ClockControl: Clock {
    /// Takes the clock rate at start: nominal, with the OS kept out (R71).
    ///
    /// # Errors
    /// [`ClockError`] if the OS refuses.
    fn take_rate_control(&mut self) -> Result<(), ClockError>;
}

/// The drift file as the host uses it.
pub trait DriftFile {
    /// The saved drift, or why there is none.
    ///
    /// # Errors
    /// A [`LoadNote`] for the log.
    fn load_checked(&self) -> Result<Ppm, LoadNote>;

    /// Saves the drift.
    ///
    /// # Errors
    /// [`StoreError`] for the log.
    fn save(&self, ppm: Ppm) -> Result<(), StoreError>;
}

impl DriftFile for FileDriftStore {
    fn load_checked(&self) -> Result<Ppm, LoadNote> {
        FileDriftStore::load_checked(self)
    }

    fn save(&self, ppm: Ppm) -> Result<(), StoreError> {
        ntpc_core::DriftStore::save(self, ppm)
    }
}

/// Whether `w32time` runs. Task 12's monitor implements it in 14c.
pub trait ServiceMonitor {
    /// True if it runs. True also when the state cannot be read, so an
    /// error never lets two services adjust the clock.
    fn is_running(&self) -> bool;
}

/// Network changes. The real watcher (address and DHCP lease change
/// notifications) implements it in 14c.
pub trait NetworkEvents {
    /// True if the network changed since the last call. The host calls it
    /// with a zero timeout on every loop turn, so a change is seen within
    /// [`LEVEL_PERIOD`] at worst.
    fn changed(&self, timeout: Duration) -> bool;
}

/// Resume from sleep. The service control handler implements it in 14c and
/// calls [`HostControl::wake`] so the loop sees it at once.
pub trait PowerEvents {
    /// True if the machine resumed since the last call.
    fn resumed(&self) -> bool;
}

/// One DHCP adapter lease: the adapter GUID plus the lease server. A new
/// lease gives a new key, which is how the negative cache forgets an
/// adapter when its lease changes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AdapterKey(pub String);

/// The outcome of one DHCP read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DhcpRead {
    /// Option 42 servers of every adapter read, merged.
    pub servers: Vec<Ipv4Addr>,
    /// Every leased adapter the reader saw, read or skipped.
    pub adapters: Vec<AdapterKey>,
    /// Adapters read now that offered no option 42. The host skips them
    /// until their lease changes or [`DHCP_REREAD`] passes.
    pub without_option: Vec<AdapterKey>,
}

/// A DHCP read failed. The text holds no path.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{0}")]
pub struct DhcpReadError(pub String);

/// Reads DHCP option 42. Blocking, may take minutes. Runs on the reader
/// thread only, one read at a time.
pub trait DhcpSource: Send + Sync {
    /// Reads every leased adapter except those in `skip`.
    ///
    /// # Errors
    /// [`DhcpReadError`] for the log.
    fn read(&self, skip: &BTreeSet<AdapterKey>) -> Result<DhcpRead, DhcpReadError>;
}

/// Result of securing the state directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureOutcome {
    /// Secured. Persistence is on.
    Ok,
    /// Secured, but the `w32time` restore record was not trusted and was
    /// dropped. Persistence is on.
    RestoreDropped,
    /// Not secured. Persistence is off. Timekeeping goes on.
    Refused {
        /// The reason class, without any path.
        reason: &'static str,
    },
}

/// The state directory. The real one calls `ntpc_platform::secure_state_dir`
/// in 14c.
pub trait StateDir {
    /// Secures the directory. Called once, before any file is read or
    /// written in it.
    fn secure(&self) -> SecureOutcome;
}

/// Domain join state, logged at every start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinClass {
    /// Not joined.
    Workgroup,
    /// Joined to a classic domain.
    Domain,
    /// Could not be read.
    Unknown,
}

/// The join state. Task 12's detection implements it in 14c.
pub trait JoinStateProvider {
    /// The join state now.
    fn join_state(&self) -> JoinClass;
}

/// Runs a job on another thread.
pub trait Spawn: Send + Sync {
    /// Starts `job`. False if it could not be started. The job is dropped
    /// then.
    fn spawn(&self, name: &'static str, job: Box<dyn FnOnce() + Send + 'static>) -> bool;
}

/// Spawns `std` threads that are never joined.
#[derive(Debug, Clone, Copy, Default)]
pub struct ThreadSpawn;

impl Spawn for ThreadSpawn {
    fn spawn(&self, name: &'static str, job: Box<dyn FnOnce() + Send + 'static>) -> bool {
        std::thread::Builder::new()
            .name(name.to_owned())
            .spawn(job)
            .is_ok()
    }
}

/// How the loop sleeps. Injected so tests run on fake time.
pub trait Waiter {
    /// Waits for a message until the monotonic `deadline`. `None` means the
    /// deadline came. `outstanding` is the number of worker jobs the host
    /// waits for, so a fake waiter can let them finish before it moves
    /// fake time on.
    fn wait(&mut self, inbox: &Inbox, deadline: Mono, outstanding: usize) -> Option<Msg>;
}

/// Sleeps in real time.
pub struct RealWaiter {
    time: Arc<dyn TimeSource>,
}

impl RealWaiter {
    /// A waiter on this time source.
    #[must_use]
    pub fn new(time: Arc<dyn TimeSource>) -> Self {
        Self { time }
    }
}

impl Waiter for RealWaiter {
    fn wait(&mut self, inbox: &Inbox, deadline: Mono, _outstanding: usize) -> Option<Msg> {
        let left = deadline.saturating_duration_since(self.time.mono());
        inbox.recv_timeout(left)
    }
}

pub(crate) type HostResolver = Resolver<SharedLookup, SharedOwn>;

/// What a worker or a controller tells the loop. Opaque outside the host.
pub struct Msg(pub(crate) Inner);

pub(crate) enum Inner {
    Shutdown,
    Wake,
    Query {
        source: SourceId,
        ticket: u64,
        result: Result<Sample, QueryFailure>,
    },
    Resolved {
        generation: u64,
        specs: Vec<SourceSpec>,
        notes: Vec<ResolveNote>,
    },
    Dhcp(Result<DhcpRead, DhcpReadError>),
}

impl Msg {
    /// Asks the loop to stop.
    #[must_use]
    pub fn shutdown() -> Self {
        Msg(Inner::Shutdown)
    }

    /// Wakes the loop, for example after a power event.
    #[must_use]
    pub fn wake() -> Self {
        Msg(Inner::Wake)
    }
}

/// The loop's end of the channel.
pub struct Inbox {
    rx: Receiver<Msg>,
    tx: Sender<Msg>,
}

impl Inbox {
    /// A message if one is waiting.
    #[must_use]
    pub fn try_recv(&self) -> Option<Msg> {
        self.rx.try_recv().ok()
    }

    /// A message within `timeout`, or `None`.
    #[must_use]
    pub fn recv_timeout(&self, timeout: Duration) -> Option<Msg> {
        self.rx.recv_timeout(timeout).ok()
    }

    pub(crate) fn sender(&self) -> Sender<Msg> {
        self.tx.clone()
    }
}

/// Controls a running host from another thread.
#[derive(Clone)]
pub struct HostControl {
    tx: Sender<Msg>,
}

impl HostControl {
    /// Asks the loop to stop. [`run`] returns soon after.
    pub fn shutdown(&self) {
        // The loop is gone already if this fails, which is the goal.
        let _ = self.tx.send(Msg::shutdown());
    }

    /// Wakes the loop so it polls the power and network events now.
    pub fn wake(&self) {
        let _ = self.tx.send(Msg::wake());
    }
}

/// A control and the inbox for [`run`].
#[must_use]
pub fn channel() -> (HostControl, Inbox) {
    let (tx, rx) = mpsc::channel();
    (HostControl { tx: tx.clone() }, Inbox { rx, tx })
}

/// A name lookup shared with the lookup worker.
#[derive(Clone)]
pub struct SharedLookup(pub Arc<dyn NameLookup + Send + Sync>);

impl NameLookup for SharedLookup {
    fn lookup(&self, name: &str) -> io::Result<Vec<IpAddr>> {
        self.0.lookup(name)
    }
}

/// This machine's addresses, shared with the lookup worker.
#[derive(Clone)]
pub struct SharedOwn(pub Arc<dyn OwnAddresses + Send + Sync>);

impl OwnAddresses for SharedOwn {
    fn own_addresses(&self) -> Vec<IpAddr> {
        self.0.own_addresses()
    }
}

/// Everything the host talks to.
pub struct HostDeps {
    /// The system clock.
    pub clock: Box<dyn ClockControl>,
    /// NTP queries.
    pub transport: Arc<dyn Transport>,
    /// The drift file.
    pub drift: Box<dyn DriftFile>,
    /// The status file.
    pub status: Box<dyn StatusWriter>,
    /// Name lookups for server and pool names.
    pub lookup: Arc<dyn NameLookup + Send + Sync>,
    /// This machine's addresses, dropped from every source list.
    pub own: Arc<dyn OwnAddresses + Send + Sync>,
    /// The `w32time` monitor.
    pub monitor: Box<dyn ServiceMonitor>,
    /// Network change notifications.
    pub network: Box<dyn NetworkEvents>,
    /// Resume notifications.
    pub power: Box<dyn PowerEvents>,
    /// DHCP option 42.
    pub dhcp: Arc<dyn DhcpSource>,
    /// The state directory.
    pub state_dir: Box<dyn StateDir>,
    /// Domain join state.
    pub join: Box<dyn JoinStateProvider>,
    /// The log.
    pub logger: Arc<dyn Logger>,
    /// Monotonic and wall time.
    pub time: Arc<dyn TimeSource>,
    /// Worker threads.
    pub spawn: Arc<dyn Spawn>,
    /// How the loop sleeps.
    pub waiter: Box<dyn Waiter>,
}

/// Why the host could not run.
#[derive(Debug, Error)]
pub enum HostError {
    /// The config breaks a rule.
    #[error(transparent)]
    Config(#[from] ConfigError),
}

/// Runs the host until [`HostControl::shutdown`].
///
/// Nothing at run time is fatal: clock, file, DHCP and network failures
/// are logged and counted, and timekeeping goes on as far as it can.
///
/// # Errors
/// [`HostError::Config`] if `cfg` breaks a rule. Nothing has run then.
pub fn run(cfg: Config, deps: HostDeps, inbox: Inbox) -> Result<(), HostError> {
    cfg.validate()?;
    let mut host = state::Host::start(cfg, deps, inbox);
    while host.turn() {}
    host.shutdown();
    Ok(())
}
