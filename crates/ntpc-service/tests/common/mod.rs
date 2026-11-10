//! Fakes for the host tests. Time is fake and moves only when the fake
//! waiter moves it, so a run of hours takes milliseconds and repeats
//! exactly. Nothing here touches the real clock, network, registry or
//! services.

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use ntpc_core::{
    Clock, ClockError, Delay, Mono, Offset, Ppm, QueryFailure, Sample, SourceId, StoreError,
};
use ntpc_service::config::Config;
use ntpc_service::drift_store::LoadNote;
use ntpc_service::host::{
    self, AdapterKey, ClockControl, DhcpRead, DhcpReadError, DhcpSource, DriftFile, HostDeps,
    Inbox, JoinClass, JoinStateProvider, Msg, NetworkEvents, PowerEvents, SecureOutcome,
    ServiceMonitor, Spawn, StateDir, ThreadSpawn, Waiter,
};
use ntpc_service::logging::{LineLogger, LogSink, MemorySink};
use ntpc_service::resolver::{NameLookup, OwnAddresses};
use ntpc_service::status::{StatusReport, StatusWriter};
use ntpc_service::transport::{TimeSource, Transport, TransportStats};

pub const SEC: u64 = 1_000_000_000;

/// DHCP reads seen: when, and the adapters skipped.
pub type Reads = Arc<Mutex<Vec<(Mono, BTreeSet<AdapterKey>)>>>;
pub const POOL: &str = "pool.test";

pub fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "test times are small, positive seconds"
)]
pub fn secs(s: f64) -> Mono {
    Mono::from_nanos((s * 1e9) as u64)
}

#[expect(
    clippy::cast_precision_loss,
    reason = "test times stay far below 2^52 ns"
)]
pub fn as_secs(m: Mono) -> f64 {
    m.as_nanos() as f64 / 1e9
}

/// Benchmark range 198.18.0.0/15, so no real host is named.
pub fn bench(n: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(198, 18, 0, n))
}

// ------------------------------------------------------------------ time

/// Fake monotonic time. With `step` above zero every read moves it on by
/// that many nanoseconds, as real time does between two reads.
#[derive(Debug, Clone, Default)]
pub struct FakeTime(Arc<AtomicU64>, Arc<AtomicU64>);

/// 2026-11-10T00:00:00Z.
const WALL_BASE: i128 = 1_794_268_800 * 1_000_000_000;

impl FakeTime {
    pub fn now(&self) -> Mono {
        let step = self.1.load(Ordering::SeqCst);
        Mono::from_nanos(self.0.fetch_add(step, Ordering::SeqCst) + step)
    }
    pub fn advance_per_read(&self, ns: u64) {
        self.1.store(ns, Ordering::SeqCst);
    }
    pub fn set(&self, t: Mono) {
        self.0.fetch_max(t.as_nanos(), Ordering::SeqCst);
    }
}

impl TimeSource for FakeTime {
    fn mono(&self) -> Mono {
        self.now()
    }
    fn wall_ns(&self) -> i128 {
        WALL_BASE + i128::from(self.0.load(Ordering::SeqCst))
    }
}

type Hook = Box<dyn FnMut()>;

/// Moves fake time to each deadline. Stops the host at `stop_at`.
pub struct FakeWaiter {
    pub time: FakeTime,
    pub stop_at: Mono,
    /// Real time to wait for outstanding worker jobs before moving on.
    /// Zero for inline jobs.
    pub patience: Duration,
    /// Run once when fake time first reaches the given time.
    pub hooks: Vec<(Mono, Hook)>,
    pub turns: Arc<AtomicU64>,
}

impl Waiter for FakeWaiter {
    fn wait(&mut self, inbox: &Inbox, deadline: Mono, outstanding: usize) -> Option<Msg> {
        self.turns.fetch_add(1, Ordering::SeqCst);
        if let Some(m) = inbox.try_recv() {
            return Some(m);
        }
        if outstanding > 0
            && !self.patience.is_zero()
            && let Some(m) = inbox.recv_timeout(self.patience)
        {
            return Some(m);
        }
        let target = deadline.min(self.stop_at);
        // Hooks due before the target run at their own time first.
        self.hooks.sort_by_key(|(t, _)| *t);
        if let Some(i) = self.hooks.iter().position(|(t, _)| *t <= target) {
            let (t, mut hook) = self.hooks.remove(i);
            self.time.set(t);
            hook();
            return None;
        }
        self.time.set(target);
        if target >= self.stop_at {
            return Some(Msg::shutdown());
        }
        None
    }
}

/// Refuses every query thread, as a system out of threads would. Other
/// jobs run inline.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoSpawn;

impl Spawn for NoSpawn {
    fn spawn(&self, name: &'static str, job: Box<dyn FnOnce() + Send + 'static>) -> bool {
        if name == "ntpc-query" {
            return false;
        }
        job();
        true
    }
}

/// Runs a job at once on the calling thread.
#[derive(Debug, Clone, Copy, Default)]
pub struct InlineSpawn;

impl Spawn for InlineSpawn {
    fn spawn(&self, _name: &'static str, job: Box<dyn FnOnce() + Send + 'static>) -> bool {
        job();
        true
    }
}

// ------------------------------------------------------------------ world

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Cmd {
    Freq(f64),
    Step(f64),
    Take,
    Reset,
}

/// The hidden true clock and what the clock was told.
#[derive(Debug)]
pub struct World {
    /// Local minus true, seconds.
    pub err: f64,
    pub at: Mono,
    pub applied: f64,
    pub need: f64,
    /// Commands (Freq or Step) counted from 1 that fail.
    pub fail_numbers: BTreeSet<u64>,
    pub commands: u64,
    /// The first `n` rate takes fail.
    pub fail_take: u32,
    /// The first `n` rate resets fail.
    pub fail_reset: u32,
    /// A failing command moves fake time on by this many seconds inside
    /// the call, as a slow failing system call would.
    pub fail_advance_s: u64,
    pub log: Vec<(Mono, Cmd, bool)>,
}

impl World {
    pub fn settle(&mut self, now: Mono) {
        let dt = now.saturating_duration_since(self.at).as_secs_f64();
        self.err += (self.applied - self.need) * 1e-6 * dt;
        self.at = self.at.max(now);
    }
    pub fn count(&self, f: impl Fn(&Cmd) -> bool) -> usize {
        self.log.iter().filter(|(_, c, _)| f(c)).count()
    }
}

pub type SharedWorld = Arc<Mutex<World>>;

pub fn world(err: f64, need: f64) -> SharedWorld {
    Arc::new(Mutex::new(World {
        err,
        at: Mono::from_nanos(0),
        applied: 0.0,
        need,
        fail_numbers: BTreeSet::new(),
        commands: 0,
        fail_take: 0,
        fail_reset: 0,
        fail_advance_s: 0,
        log: Vec::new(),
    }))
}

pub struct FakeClock {
    pub world: SharedWorld,
    pub time: FakeTime,
}

fn advance(time: &FakeTime, secs_on: u64) {
    if secs_on > 0 {
        let t = time.now();
        time.set(Mono::from_nanos(t.as_nanos() + secs_on * SEC));
    }
}

impl FakeClock {
    fn command(&self, cmd: Cmd) -> Result<(), ClockError> {
        let mut w = lock(&self.world);
        let now = self.time.now();
        w.settle(now);
        w.commands += 1;
        let n = w.commands;
        let ok = !w.fail_numbers.contains(&n);
        w.log.push((now, cmd, ok));
        if !ok {
            advance(&self.time, w.fail_advance_s);
            return Err(ClockError::Rejected("injected failure".into()));
        }
        match cmd {
            Cmd::Freq(f) => w.applied = f,
            Cmd::Step(s) => w.err += s,
            Cmd::Take | Cmd::Reset => w.applied = 0.0,
        }
        Ok(())
    }
}

impl Clock for FakeClock {
    fn mono(&self) -> Mono {
        self.time.now()
    }
    fn wall_ns(&self) -> i128 {
        self.time.wall_ns()
    }
    fn step(&mut self, by: Offset) -> Result<(), ClockError> {
        self.command(Cmd::Step(by.as_secs()))
    }
    fn set_frequency(&mut self, ppm: Ppm) -> Result<(), ClockError> {
        self.command(Cmd::Freq(ppm.value()))
    }
    fn reset_frequency(&mut self) -> Result<(), ClockError> {
        let mut w = lock(&self.world);
        let now = self.time.now();
        w.settle(now);
        let ok = w.fail_reset == 0;
        w.fail_reset = w.fail_reset.saturating_sub(1);
        w.log.push((now, Cmd::Reset, ok));
        if !ok {
            return Err(ClockError::Rejected("injected reset failure".into()));
        }
        w.applied = 0.0;
        Ok(())
    }
}

impl ClockControl for FakeClock {
    fn take_rate_control(&mut self) -> Result<(), ClockError> {
        let mut w = lock(&self.world);
        let now = self.time.now();
        let ok = w.fail_take == 0;
        w.fail_take = w.fail_take.saturating_sub(1);
        w.log.push((now, Cmd::Take, ok));
        if ok {
            Ok(())
        } else {
            Err(ClockError::PermissionDenied)
        }
    }
}

/// How a fake server answers.
#[derive(Debug, Clone, Copy)]
pub enum Reply {
    /// The server's error against true time, seconds.
    Good(f64),
    Fail(QueryFailure),
}

/// Answers from the world: offset is server error minus clock error.
pub struct FakeTransport {
    pub world: SharedWorld,
    pub time: FakeTime,
    pub replies: Mutex<BTreeMap<IpAddr, Reply>>,
    pub queries: Mutex<Vec<(Mono, SourceId)>>,
    /// Real delay per query, to let queries overlap on threads.
    pub real_delay: Duration,
    /// Block every query on this until the sender is dropped.
    pub block: Mutex<Option<Receiver<()>>>,
    pub active: Mutex<BTreeMap<SourceId, u32>>,
    pub max_active_per_source: AtomicU64,
}

impl FakeTransport {
    pub fn new(world: SharedWorld, time: FakeTime) -> Self {
        Self {
            world,
            time,
            replies: Mutex::new(BTreeMap::new()),
            queries: Mutex::new(Vec::new()),
            real_delay: Duration::ZERO,
            block: Mutex::new(None),
            active: Mutex::new(BTreeMap::new()),
            max_active_per_source: AtomicU64::new(0),
        }
    }
}

impl Transport for FakeTransport {
    fn query(
        &self,
        source: SourceId,
        dest: SocketAddr,
        _timeout: Duration,
    ) -> Result<Sample, QueryFailure> {
        let now = self.time.now();
        lock(&self.queries).push((now, source));
        {
            let mut a = lock(&self.active);
            let n = a.entry(source).or_default();
            *n += 1;
            self.max_active_per_source
                .fetch_max(u64::from(*n), Ordering::SeqCst);
        }
        if let Some(rx) = lock(&self.block).as_ref() {
            // Blocks until the test drops the sender. Never in practice.
            let _ = rx.recv();
        }
        if !self.real_delay.is_zero() {
            std::thread::sleep(self.real_delay);
        }
        let reply = lock(&self.replies)
            .get(&dest.ip())
            .copied()
            .unwrap_or(Reply::Good(0.0));
        if let Some(n) = lock(&self.active).get_mut(&source) {
            *n -= 1;
        }
        match reply {
            Reply::Fail(f) => Err(f),
            Reply::Good(server_err) => {
                let mut w = lock(&self.world);
                w.settle(now);
                Ok(Sample {
                    source,
                    offset: Offset::from_secs(server_err - w.err),
                    delay: Delay::from_secs(0.020),
                    stratum: 2,
                    unsynchronised: false,
                    leap_alarm: false,
                    at: now,
                })
            }
        }
    }

    fn stats(&self) -> TransportStats {
        TransportStats::default()
    }
}

// ------------------------------------------------------------------ files

#[derive(Debug, Default)]
pub struct DriftLog {
    pub loaded: Option<f64>,
    pub loads: u64,
    pub saves: Vec<(Mono, f64)>,
}

pub struct FakeDrift {
    pub log: Arc<Mutex<DriftLog>>,
    pub time: FakeTime,
}

impl DriftFile for FakeDrift {
    fn load_checked(&self) -> Result<Ppm, LoadNote> {
        let mut l = lock(&self.log);
        l.loads += 1;
        l.loaded.map(Ppm::new).ok_or(LoadNote::Missing)
    }
    fn save(&self, ppm: Ppm) -> Result<(), StoreError> {
        lock(&self.log).saves.push((self.time.now(), ppm.value()));
        Ok(())
    }
}

pub struct FakeStatus {
    pub reports: Arc<Mutex<Vec<(Mono, StatusReport)>>>,
    pub time: FakeTime,
}

impl StatusWriter for FakeStatus {
    fn write(&self, report: &StatusReport) -> Result<(), String> {
        lock(&self.reports).push((self.time.now(), report.clone()));
        Ok(())
    }
}

// ------------------------------------------------------------------ names

pub struct FakeLookup {
    pub names: BTreeMap<String, Vec<IpAddr>>,
    /// The first `n` lookups block on this.
    pub block_first: Mutex<u32>,
    pub gate: Mutex<Option<Receiver<()>>>,
    pub calls: AtomicU64,
    /// The first `n` lookups panic.
    pub panic_first: Mutex<u32>,
    /// Every lookup hangs while this is set.
    pub hang: Arc<std::sync::atomic::AtomicBool>,
}

impl FakeLookup {
    pub fn pool(n: u8) -> Self {
        Self {
            names: BTreeMap::from([(POOL.to_owned(), (1..=n).map(bench).collect())]),
            block_first: Mutex::new(0),
            gate: Mutex::new(None),
            calls: AtomicU64::new(0),
            panic_first: Mutex::new(0),
            hang: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }
}

impl NameLookup for FakeLookup {
    fn lookup(&self, name: &str) -> io::Result<Vec<IpAddr>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let boom = {
            let mut p = lock(&self.panic_first);
            let yes = *p > 0;
            *p = p.saturating_sub(1);
            yes
        };
        assert!(!boom, "injected lookup panic");
        while self.hang.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(5));
        }
        let block = {
            let mut b = lock(&self.block_first);
            let yes = *b > 0;
            *b = b.saturating_sub(1);
            yes
        };
        if block {
            // Take the gate so a second blocked call cannot share it.
            let gate = lock(&self.gate).take();
            if let Some(rx) = gate {
                let _ = rx.recv();
            }
        }
        self.names
            .get(name)
            .cloned()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
    }
}

pub struct NoOwn;

impl OwnAddresses for NoOwn {
    fn own_addresses(&self) -> Vec<IpAddr> {
        Vec::new()
    }
}

// ------------------------------------------------------------------ OS state

/// `w32time` runs during these fake time ranges, seconds.
pub struct FakeMonitor {
    pub running: Vec<(f64, f64)>,
    /// Panics on the first call at or after this time, seconds.
    pub panic_at: Option<f64>,
    /// On the first call that says running, move fake time on this many
    /// seconds inside the call.
    pub advance_when_running_s: u64,
    pub advanced: std::sync::atomic::AtomicBool,
    pub time: FakeTime,
    pub calls: Arc<Mutex<Vec<Mono>>>,
}

impl ServiceMonitor for FakeMonitor {
    fn is_running(&self) -> bool {
        let now = self.time.now();
        lock(&self.calls).push(now);
        let t = as_secs(now);
        let running = self.running.iter().any(|(a, b)| t >= *a && t < *b);
        if running && !self.advanced.swap(true, Ordering::SeqCst) {
            advance(&self.time, self.advance_when_running_s);
        }
        assert!(
            !self.panic_at.is_some_and(|p| t >= p),
            "injected monitor panic"
        );
        running
    }
}

/// Signals at fake times. One call takes every signal due by now.
pub struct FakeNetwork {
    pub at: Mutex<Vec<f64>>,
    pub time: FakeTime,
}

impl NetworkEvents for FakeNetwork {
    fn changed(&self, _timeout: Duration) -> bool {
        let t = as_secs(self.time.now());
        let mut at = lock(&self.at);
        let before = at.len();
        at.retain(|s| *s > t);
        at.len() != before
    }
}

/// Resumes at fake times. Each applies a clock jump to the world.
pub struct FakePower {
    pub at: Mutex<Vec<(f64, f64)>>,
    pub time: FakeTime,
    pub world: SharedWorld,
}

impl PowerEvents for FakePower {
    fn resumed(&self) -> bool {
        let t = as_secs(self.time.now());
        let mut at = lock(&self.at);
        if let Some(i) = at.iter().position(|(s, _)| *s <= t) {
            let (_, jump) = at.remove(i);
            let mut w = lock(&self.world);
            w.settle(self.time.now());
            w.err += jump;
            return true;
        }
        false
    }
}

pub struct FakeDhcp {
    pub time: FakeTime,
    pub results: Mutex<Vec<Result<DhcpRead, DhcpReadError>>>,
    pub reads: Reads,
    pub gate: Mutex<Option<Receiver<()>>>,
    pub panics: std::sync::atomic::AtomicBool,
}

impl DhcpSource for FakeDhcp {
    fn read(&self, skip: &BTreeSet<AdapterKey>) -> Result<DhcpRead, DhcpReadError> {
        lock(&self.reads).push((self.time.now(), skip.clone()));
        assert!(!self.panics.load(Ordering::SeqCst), "injected DHCP panic");
        let gate = lock(&self.gate).take();
        if let Some(rx) = gate {
            let _ = rx.recv();
        }
        let mut r = lock(&self.results);
        if r.len() > 1 {
            r.remove(0)
        } else {
            r.first()
                .cloned()
                .unwrap_or_else(|| Ok(DhcpRead::default()))
        }
    }
}

pub struct FakeStateDir(pub SecureOutcome);

impl StateDir for FakeStateDir {
    fn secure(&self) -> SecureOutcome {
        self.0
    }
}

pub struct FakeJoin(pub JoinClass);

impl JoinStateProvider for FakeJoin {
    fn join_state(&self) -> JoinClass {
        self.0
    }
}

/// A memory sink that panics on any line holding `needle`.
pub struct PanicSink {
    pub inner: MemorySink,
    pub needle: &'static str,
}

impl LogSink for PanicSink {
    fn write_line(&self, line: &str) {
        assert!(!line.contains(self.needle), "injected sink panic");
        self.inner.write_line(line);
    }
}

// ------------------------------------------------------------------ rig

/// One host run with fakes. Change the public fields, then call `run`.
pub struct Rig {
    pub cfg: Config,
    pub time: FakeTime,
    pub world: SharedWorld,
    pub transport: Arc<FakeTransport>,
    pub drift: Arc<Mutex<DriftLog>>,
    pub reports: Arc<Mutex<Vec<(Mono, StatusReport)>>>,
    pub lookup: Arc<FakeLookup>,
    pub monitor_running: Vec<(f64, f64)>,
    pub monitor_panic_at: Option<f64>,
    pub monitor_advance_s: u64,
    pub monitor_calls: Arc<Mutex<Vec<Mono>>>,
    pub network_at: Vec<f64>,
    pub power_at: Vec<(f64, f64)>,
    pub dhcp: Arc<FakeDhcp>,
    pub dhcp_reads: Reads,
    pub state: SecureOutcome,
    pub join: JoinClass,
    pub sink: MemorySink,
    /// The log sink panics on a line holding this text.
    pub sink_panic_on: Option<&'static str>,
    pub threads: bool,
    /// Every spawn fails.
    pub no_spawn: bool,
    pub patience: Duration,
    pub hooks: Vec<(Mono, Hook)>,
    pub status_writer: Option<Box<dyn StatusWriter>>,
    pub turns: Arc<AtomicU64>,
}

impl Rig {
    /// Pool only, four exact servers, clock `err` off, `need` ppm drift.
    pub fn new(err: f64, need: f64) -> Self {
        let time = FakeTime::default();
        let world = world(err, need);
        let cfg = Config {
            dhcp: false,
            pool: POOL.to_owned(),
            ..Config::default()
        };
        let dhcp_reads = Arc::new(Mutex::new(Vec::new()));
        Self {
            cfg,
            transport: Arc::new(FakeTransport::new(Arc::clone(&world), time.clone())),
            drift: Arc::new(Mutex::new(DriftLog::default())),
            reports: Arc::new(Mutex::new(Vec::new())),
            lookup: Arc::new(FakeLookup::pool(4)),
            monitor_running: Vec::new(),
            monitor_panic_at: None,
            monitor_advance_s: 0,
            monitor_calls: Arc::new(Mutex::new(Vec::new())),
            network_at: Vec::new(),
            power_at: Vec::new(),
            dhcp: Arc::new(FakeDhcp {
                time: time.clone(),
                results: Mutex::new(Vec::new()),
                reads: Arc::clone(&dhcp_reads),
                gate: Mutex::new(None),
                panics: std::sync::atomic::AtomicBool::new(false),
            }),
            dhcp_reads,
            state: SecureOutcome::Ok,
            join: JoinClass::Workgroup,
            sink: MemorySink::new(),
            sink_panic_on: None,
            threads: false,
            no_spawn: false,
            patience: Duration::ZERO,
            hooks: Vec::new(),
            status_writer: None,
            turns: Arc::new(AtomicU64::new(0)),
            time,
            world,
        }
    }

    /// Runs the host for `secs` of fake time and returns.
    pub fn run(&mut self, secs_total: u64) {
        self.try_run(secs_total).expect("host runs");
    }

    /// Runs the host and returns what `run` returned.
    pub fn try_run(&mut self, secs_total: u64) -> Result<(), host::HostError> {
        let time = self.time.clone();
        // The real watchers wake the loop through `HostControl::wake`. A
        // no-op hook at each event time does the same on fake time.
        for t in self
            .network_at
            .iter()
            .copied()
            .chain(self.power_at.iter().map(|p| p.0))
        {
            self.hooks.push((secs(t), Box::new(|| {})));
        }
        let sink: Box<dyn LogSink> = match self.sink_panic_on {
            Some(needle) => Box::new(PanicSink {
                inner: self.sink.clone(),
                needle,
            }),
            None => Box::new(self.sink.clone()),
        };
        let logger = Arc::new(LineLogger::new(sink, Arc::new(time.clone())));
        let status: Box<dyn StatusWriter> = self.status_writer.take().unwrap_or_else(|| {
            Box::new(FakeStatus {
                reports: Arc::clone(&self.reports),
                time: time.clone(),
            })
        });
        let spawn: Arc<dyn Spawn> = if self.no_spawn {
            Arc::new(NoSpawn)
        } else if self.threads {
            Arc::new(ThreadSpawn)
        } else {
            Arc::new(InlineSpawn)
        };
        let deps = HostDeps {
            clock: Box::new(FakeClock {
                world: Arc::clone(&self.world),
                time: time.clone(),
            }),
            transport: Arc::clone(&self.transport) as Arc<dyn Transport>,
            drift: Box::new(FakeDrift {
                log: Arc::clone(&self.drift),
                time: time.clone(),
            }),
            status,
            lookup: Arc::clone(&self.lookup) as Arc<dyn NameLookup + Send + Sync>,
            own: Arc::new(NoOwn),
            monitor: Box::new(FakeMonitor {
                running: self.monitor_running.clone(),
                panic_at: self.monitor_panic_at,
                advance_when_running_s: self.monitor_advance_s,
                advanced: std::sync::atomic::AtomicBool::new(false),
                time: time.clone(),
                calls: Arc::clone(&self.monitor_calls),
            }),
            network: Box::new(FakeNetwork {
                at: Mutex::new(self.network_at.clone()),
                time: time.clone(),
            }),
            power: Box::new(FakePower {
                at: Mutex::new(self.power_at.clone()),
                time: time.clone(),
                world: Arc::clone(&self.world),
            }),
            dhcp: Arc::clone(&self.dhcp) as Arc<dyn DhcpSource>,
            state_dir: Box::new(FakeStateDir(self.state)),
            join: Box::new(FakeJoin(self.join)),
            logger,
            time: Arc::new(time.clone()),
            spawn,
            waiter: Box::new(FakeWaiter {
                time: time.clone(),
                stop_at: Mono::from_nanos(time.now().as_nanos() + secs_total * SEC),
                patience: self.patience,
                hooks: std::mem::take(&mut self.hooks),
                turns: Arc::clone(&self.turns),
            }),
        };
        let (_control, inbox) = host::channel();
        host::run(self.cfg.clone(), deps, inbox)
    }

    pub fn lines(&self) -> Vec<String> {
        self.sink.lines()
    }

    pub fn log_has(&self, needle: &str) -> bool {
        self.lines().iter().any(|l| l.contains(needle))
    }

    pub fn commands(&self) -> Vec<(Mono, Cmd, bool)> {
        lock(&self.world).log.clone()
    }

    /// Gate for a blocking fake. Keep the sender alive to keep it blocked.
    pub fn gate() -> (Sender<()>, Receiver<()>) {
        mpsc::channel()
    }

    pub fn temp_dir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "ntpc-host-test-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("temp dir");
        p
    }
}
