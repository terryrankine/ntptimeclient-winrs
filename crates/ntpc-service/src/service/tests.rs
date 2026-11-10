//! The service state machine over a recording [`StatusApi`] and a fake
//! host. No SCM, no real host.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use super::*;
use crate::host::{Inner, Msg};
use crate::logging::{LineLogger, MemorySink};
use crate::transport::StdTimeSource;

#[derive(Default)]
struct RecordingApi {
    reports: Mutex<Vec<Report>>,
    fail: AtomicBool,
}

impl StatusApi for RecordingApi {
    fn set(&self, r: &Report) -> Result<(), i32> {
        self.reports.lock().unwrap().push(*r);
        if self.fail.load(Ordering::SeqCst) {
            Err(6)
        } else {
            Ok(())
        }
    }
}

impl RecordingApi {
    fn all(&self) -> Vec<Report> {
        self.reports.lock().unwrap().clone()
    }
    fn states(&self) -> Vec<State> {
        self.all().iter().map(|r| r.state).collect()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Behaviour {
    /// Runs until it reads a shutdown.
    UntilShutdown,
    /// Never looks at the inbox.
    IgnoresShutdown,
    /// Returns at once without being asked.
    EndsAtOnce,
    /// Panics outside the host's own guard.
    Panics,
    /// Returns a host panic error.
    HostPanicked,
    /// Fails to build its adapters.
    DepsFail,
}

struct FakeLauncher {
    ready: Result<(), String>,
    behaviour: Behaviour,
    wakes: Arc<AtomicU32>,
    resumes: Arc<AtomicU32>,
    /// Set when the host loop really ran (after `started` said yes).
    ran: Arc<AtomicBool>,
    /// Waits before handing over, so a test can send a stop first.
    hold: Option<Arc<AtomicBool>>,
}

impl FakeLauncher {
    fn new(behaviour: Behaviour) -> Self {
        Self {
            ready: Ok(()),
            behaviour,
            wakes: Arc::new(AtomicU32::new(0)),
            resumes: Arc::new(AtomicU32::new(0)),
            ran: Arc::new(AtomicBool::new(false)),
            hold: None,
        }
    }
}

/// Counts notifications and wakes the loop, as 14c-A's notifier does.
struct FakeResume {
    count: Arc<AtomicU32>,
    control: HostControl,
}

impl Resume for FakeResume {
    fn notify_resumed(&self) {
        self.count.fetch_add(1, Ordering::SeqCst);
        self.control.wake();
    }
}

impl Launcher for FakeLauncher {
    fn ready(&self) -> Result<(), String> {
        self.ready.clone()
    }

    fn run(
        &self,
        _cfg: Config,
        sinks: Vec<Arc<dyn LogSink>>,
        started: StartedFn<'_>,
    ) -> Result<(), JobError> {
        assert!(!sinks.is_empty(), "14c-A refuses an empty sink list");
        match self.behaviour {
            Behaviour::DepsFail => return Err(JobError::Deps("no clock".to_owned())),
            Behaviour::Panics => panic!("fake host panic"),
            _ => {}
        }
        if let Some(h) = &self.hold {
            while !h.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(2));
            }
        }
        let (control, inbox) = crate::host::channel();
        let resume = Arc::new(FakeResume {
            count: self.resumes.clone(),
            control: control.clone(),
        });
        if !started(Started { control, resume }) {
            return Ok(());
        }
        self.ran.store(true, Ordering::SeqCst);
        match self.behaviour {
            Behaviour::UntilShutdown => loop {
                match inbox.recv_timeout(Duration::from_secs(5)) {
                    Some(Msg(Inner::Shutdown)) | None => return Ok(()),
                    Some(Msg(Inner::Wake)) => {
                        self.wakes.fetch_add(1, Ordering::SeqCst);
                    }
                    Some(_) => {}
                }
            },
            Behaviour::IgnoresShutdown => {
                std::thread::sleep(Duration::from_secs(5));
                Ok(())
            }
            Behaviour::HostPanicked => Err(JobError::Host(HostError::Panicked("boom".to_owned()))),
            Behaviour::EndsAtOnce | Behaviour::DepsFail | Behaviour::Panics => Ok(()),
        }
    }
}

fn fast() -> Timing {
    Timing {
        start_hint: Duration::from_secs(30),
        stop_hint: Duration::from_millis(2_000),
        stop_budget: Duration::from_millis(300),
        poll: Duration::from_millis(20),
    }
}

struct Rig {
    api: Arc<RecordingApi>,
    sink: MemorySink,
    drained: Arc<AtomicBool>,
}

fn logger(sink: &MemorySink) -> Arc<dyn Logger> {
    Arc::new(LineLogger::new(
        Box::new(sink.clone()),
        Arc::new(StdTimeSource::new()),
    ))
}

/// Starts the service on a thread. Returns the rig, the controller and the
/// join handle giving the exit code.
fn start(
    launcher: FakeLauncher,
    config: Result<Config, String>,
) -> (Rig, Arc<Controller>, std::thread::JoinHandle<u32>) {
    let api = Arc::new(RecordingApi::default());
    let sink = MemorySink::new();
    let drained = Arc::new(AtomicBool::new(false));
    let core = new_core(api.clone(), fast());
    let controller = core.controller.clone();
    let d = drained.clone();
    let run = ServiceRun {
        config,
        launcher: Arc::new(launcher),
        logger: logger(&sink),
        sinks: vec![Arc::new(sink.clone())],
        drain: Box::new(move |_| d.store(true, Ordering::SeqCst)),
    };
    let h = std::thread::spawn(move || run_service(core, run));
    (Rig { api, sink, drained }, controller, h)
}

fn wait_for(api: &RecordingApi, s: State) {
    for _ in 0..500 {
        if api.states().contains(&s) {
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!("never reached {s:?}: {:?}", api.states());
}

fn assert_never_backwards(reports: &[Report]) {
    for w in reports.windows(2) {
        assert!(w[1].state >= w[0].state, "{reports:?}");
        if w[1].state == w[0].state {
            assert!(w[1].checkpoint > w[0].checkpoint, "{reports:?}");
        }
    }
    let stopped = reports.iter().filter(|r| r.state == State::Stopped).count();
    assert_eq!(stopped, 1, "{reports:?}");
    assert_eq!(reports.last().unwrap().state, State::Stopped);
}

#[test]
fn start_run_stop_reports_in_order_with_exit_zero() {
    let (rig, ctl, h) = start(
        FakeLauncher::new(Behaviour::UntilShutdown),
        Ok(Config::default()),
    );
    wait_for(&rig.api, State::Running);
    assert_eq!(ctl.handle(raw::CONTROL_STOP, 0), raw::NO_ERROR);
    assert_eq!(h.join().unwrap(), service_exit::OK);
    let r = rig.api.all();
    assert_never_backwards(&r);
    assert_eq!(r[0].state, State::StartPending);
    assert_eq!(r[0].accepts, 0, "no control is accepted while starting");
    assert_eq!(r[0].wait_hint_ms, 30_000);
    assert!(r[0].checkpoint >= 1);
    let running = r.iter().find(|x| x.state == State::Running).unwrap();
    assert_eq!(
        running.accepts,
        raw::ACCEPT_STOP | raw::ACCEPT_SHUTDOWN | raw::ACCEPT_POWEREVENT
    );
    assert_eq!(running.checkpoint, 0);
    assert_eq!(running.wait_hint_ms, 0);
    let pending = r.iter().find(|x| x.state == State::StopPending).unwrap();
    assert_eq!(pending.accepts, 0);
    assert_eq!(pending.wait_hint_ms, 2_000);
    let last = r.last().unwrap();
    assert_eq!(last.win32_exit, raw::NO_ERROR);
    assert_eq!(last.specific_exit, 0);
    assert_eq!(last.checkpoint, 0);
    assert!(
        rig.drained.load(Ordering::SeqCst),
        "event log drained before STOPPED"
    );
}

#[test]
fn shutdown_control_stops_like_stop() {
    let (rig, ctl, h) = start(
        FakeLauncher::new(Behaviour::UntilShutdown),
        Ok(Config::default()),
    );
    wait_for(&rig.api, State::Running);
    assert_eq!(ctl.handle(raw::CONTROL_SHUTDOWN, 0), raw::NO_ERROR);
    assert_eq!(h.join().unwrap(), service_exit::OK);
    assert_never_backwards(&rig.api.all());
    assert!(rig.api.states().contains(&State::StopPending));
}

#[test]
fn repeated_stop_reports_stop_pending_once() {
    let (rig, ctl, h) = start(
        FakeLauncher::new(Behaviour::UntilShutdown),
        Ok(Config::default()),
    );
    wait_for(&rig.api, State::Running);
    for _ in 0..3 {
        assert_eq!(ctl.handle(raw::CONTROL_STOP, 0), raw::NO_ERROR);
    }
    assert_eq!(h.join().unwrap(), service_exit::OK);
    let r = rig.api.all();
    assert_never_backwards(&r);
    // The handler reported STOP_PENDING with checkpoint 1 once. Any later
    // STOP_PENDING is a progress bump from the waiting thread.
    let firsts = r
        .iter()
        .filter(|x| x.state == State::StopPending && x.checkpoint == 1)
        .count();
    assert_eq!(firsts, 1, "{r:?}");
}

#[test]
fn a_control_after_stopped_changes_nothing() {
    let (rig, ctl, h) = start(
        FakeLauncher::new(Behaviour::UntilShutdown),
        Ok(Config::default()),
    );
    wait_for(&rig.api, State::Running);
    let _ = ctl.handle(raw::CONTROL_STOP, 0);
    h.join().unwrap();
    let before = rig.api.all().len();
    let _ = ctl.handle(raw::CONTROL_STOP, 0);
    let _ = ctl.handle(raw::CONTROL_POWEREVENT, raw::PBT_APMRESUMEAUTOMATIC);
    assert_eq!(rig.api.all().len(), before, "nothing after STOPPED");
}

#[test]
fn unknown_control_is_not_implemented_and_reports_nothing() {
    let (rig, ctl, h) = start(
        FakeLauncher::new(Behaviour::UntilShutdown),
        Ok(Config::default()),
    );
    wait_for(&rig.api, State::Running);
    let before = rig.api.all().len();
    for c in [2, 3, 6, 0x0B, 0x0E, 0x10, 0x20, 200] {
        assert_eq!(ctl.handle(c, 0), raw::ERROR_CALL_NOT_IMPLEMENTED, "{c}");
    }
    assert_eq!(ctl.handle(raw::CONTROL_INTERROGATE, 0), raw::NO_ERROR);
    assert_eq!(rig.api.all().len(), before);
    let _ = ctl.handle(raw::CONTROL_STOP, 0);
    h.join().unwrap();
}

#[test]
fn both_resume_events_notify_and_return_at_once() {
    let launcher = FakeLauncher::new(Behaviour::UntilShutdown);
    let wakes = launcher.wakes.clone();
    let resumes = launcher.resumes.clone();
    let (rig, ctl, h) = start(launcher, Ok(Config::default()));
    wait_for(&rig.api, State::Running);
    let before = rig.api.all().len();
    for e in [
        raw::PBT_APMSUSPEND,
        raw::PBT_APMRESUMEAUTOMATIC,
        raw::PBT_APMRESUMESUSPEND,
        10,
        0x8013,
    ] {
        assert_eq!(ctl.handle(raw::CONTROL_POWEREVENT, e), raw::NO_ERROR, "{e}");
    }
    // R107: both resume events notify. The notifier debounces them.
    assert_eq!(resumes.load(Ordering::SeqCst), 2);
    for _ in 0..200 {
        if wakes.load(Ordering::SeqCst) == 2 {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(wakes.load(Ordering::SeqCst), 2);
    assert_eq!(rig.api.all().len(), before, "power events report nothing");
    let _ = ctl.handle(raw::CONTROL_STOP, 0);
    assert_eq!(h.join().unwrap(), service_exit::OK);
}

#[test]
fn a_resume_before_the_host_is_built_is_ignored() {
    let api = Arc::new(RecordingApi::default());
    let core = new_core(api, fast());
    assert_eq!(
        core.controller
            .handle(raw::CONTROL_POWEREVENT, raw::PBT_APMRESUMEAUTOMATIC),
        raw::NO_ERROR
    );
}

#[test]
fn running_is_reported_only_after_the_host_handed_over() {
    let mut l = FakeLauncher::new(Behaviour::UntilShutdown);
    let hold = Arc::new(AtomicBool::new(false));
    l.hold = Some(hold.clone());
    let (rig, ctl, h) = start(l, Ok(Config::default()));
    wait_for(&rig.api, State::StartPending);
    std::thread::sleep(Duration::from_millis(50));
    assert!(!rig.api.states().contains(&State::Running));
    hold.store(true, Ordering::SeqCst);
    wait_for(&rig.api, State::Running);
    let _ = ctl.handle(raw::CONTROL_STOP, 0);
    assert_eq!(h.join().unwrap(), service_exit::OK);
}

#[test]
fn a_stop_before_the_handover_means_the_host_never_runs() {
    let mut l = FakeLauncher::new(Behaviour::UntilShutdown);
    let hold = Arc::new(AtomicBool::new(false));
    l.hold = Some(hold.clone());
    let ran = l.ran.clone();
    let (rig, ctl, h) = start(l, Ok(Config::default()));
    wait_for(&rig.api, State::StartPending);
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(ctl.handle(raw::CONTROL_STOP, 0), raw::NO_ERROR);
    hold.store(true, Ordering::SeqCst);
    assert_eq!(h.join().unwrap(), service_exit::OK);
    assert!(!ran.load(Ordering::SeqCst), "the host loop must not run");
    let r = rig.api.all();
    assert_never_backwards(&r);
    assert!(!r.iter().any(|x| x.state == State::Running), "{r:?}");
}

#[test]
fn bad_config_stops_from_start_pending_with_its_code() {
    let (rig, _ctl, h) = start(
        FakeLauncher::new(Behaviour::UntilShutdown),
        Err("config syntax error at line 3".to_owned()),
    );
    assert_eq!(h.join().unwrap(), service_exit::CONFIG);
    let r = rig.api.all();
    assert_never_backwards(&r);
    assert!(!r.iter().any(|x| x.state == State::Running));
    let last = r.last().unwrap();
    assert_eq!(last.win32_exit, raw::ERROR_SERVICE_SPECIFIC_ERROR);
    assert_eq!(last.specific_exit, service_exit::CONFIG);
    assert!(
        rig.sink.lines().iter().any(|l| l.contains("line 3")),
        "{:?}",
        rig.sink.lines()
    );
}

#[test]
fn a_config_that_breaks_a_rule_is_a_config_stop() {
    let cfg = Config {
        min_poll_s: 1,
        ..Config::default()
    };
    let (_rig, _ctl, h) = start(FakeLauncher::new(Behaviour::UntilShutdown), Ok(cfg));
    assert_eq!(h.join().unwrap(), service_exit::CONFIG);
}

#[test]
fn host_not_built_stops_before_running() {
    let mut l = FakeLauncher::new(Behaviour::UntilShutdown);
    l.ready = Err("platform adapters are not built".to_owned());
    let (rig, _ctl, h) = start(l, Ok(Config::default()));
    assert_eq!(h.join().unwrap(), service_exit::HOST_NOT_BUILT);
    assert!(!rig.api.states().contains(&State::Running));
}

#[test]
fn host_error_and_panic_map_to_codes() {
    for (b, code) in [
        (Behaviour::HostPanicked, service_exit::PANICKED),
        (Behaviour::Panics, service_exit::PANICKED),
        (Behaviour::EndsAtOnce, service_exit::ENDED_UNASKED),
        (Behaviour::DepsFail, service_exit::DEPS_FAILED),
    ] {
        let (rig, _ctl, h) = start(FakeLauncher::new(b), Ok(Config::default()));
        assert_eq!(h.join().unwrap(), code, "{b:?}");
        let r = rig.api.all();
        assert_never_backwards(&r);
        assert_eq!(r.last().unwrap().specific_exit, code, "{b:?}");
        assert!(
            rig.sink.lines().iter().any(|l| l.contains("ERROR")),
            "{b:?} logs an error"
        );
    }
}

#[test]
fn a_host_that_ignores_stop_is_given_up_within_the_wait_hint() {
    let (rig, ctl, h) = start(
        FakeLauncher::new(Behaviour::IgnoresShutdown),
        Ok(Config::default()),
    );
    wait_for(&rig.api, State::Running);
    let t = Instant::now();
    let _ = ctl.handle(raw::CONTROL_STOP, 0);
    assert_eq!(h.join().unwrap(), service_exit::STOP_TIMEOUT);
    let took = t.elapsed();
    assert!(took < fast().stop_hint, "{took:?}");
    let r = rig.api.all();
    assert_never_backwards(&r);
    // Checkpoints counted up while waiting.
    let bumps = r
        .iter()
        .filter(|x| x.state == State::StopPending)
        .map(|x| x.checkpoint)
        .collect::<Vec<_>>();
    assert!(bumps.len() >= 3, "{bumps:?}");
    assert!(bumps.windows(2).all(|w| w[1] == w[0] + 1), "{bumps:?}");
}

#[test]
fn stop_during_start_never_reports_running() {
    // A stop arrives after START_PENDING and before the host thread starts.
    let api = Arc::new(RecordingApi::default());
    let core = new_core(api.clone(), fast());
    core.reporter.start_pending();
    assert_eq!(core.controller.handle(raw::CONTROL_STOP, 0), raw::NO_ERROR);
    let sink = MemorySink::new();
    let l = FakeLauncher::new(Behaviour::UntilShutdown);
    let ran = l.ran.clone();
    let run = ServiceRun {
        config: Ok(Config::default()),
        launcher: Arc::new(l),
        logger: logger(&sink),
        sinks: vec![Arc::new(sink.clone())],
        drain: Box::new(|_| {}),
    };
    assert_eq!(run_service(core, run), service_exit::OK);
    let r = api.all();
    assert_never_backwards(&r);
    assert!(!r.iter().any(|x| x.state == State::Running), "{r:?}");
    assert!(!ran.load(Ordering::SeqCst));
}

#[test]
fn running_after_a_stop_request_reports_stop_pending_instead() {
    let api = Arc::new(RecordingApi::default());
    let rep = Reporter::new(api.clone(), fast());
    rep.start_pending();
    assert!(rep.request_stop());
    assert!(!rep.request_stop(), "second request is not new");
    rep.running();
    assert_eq!(api.states(), vec![State::StartPending, State::StopPending]);
}

#[test]
fn reports_never_go_backwards_and_stopped_is_sent_once() {
    let api = Arc::new(RecordingApi::default());
    let rep = Reporter::new(api.clone(), fast());
    rep.start_pending();
    rep.start_pending();
    rep.running();
    rep.running();
    rep.start_pending();
    rep.stopped(service_exit::OK);
    rep.stopped(service_exit::PANICKED);
    rep.running();
    rep.stop_progress();
    let r = api.all();
    assert_eq!(
        r.iter()
            .map(|x| (x.state, x.checkpoint))
            .collect::<Vec<_>>(),
        vec![
            (State::StartPending, 1),
            (State::StartPending, 2),
            (State::Running, 0),
            (State::Stopped, 0),
        ]
    );
    assert_eq!(r[3].specific_exit, 0);
}

#[test]
fn a_refused_report_is_counted_and_not_fatal() {
    let api = Arc::new(RecordingApi::default());
    api.fail.store(true, Ordering::SeqCst);
    let rep = Reporter::new(api.clone(), fast());
    rep.start_pending();
    rep.running();
    rep.stopped(0);
    assert_eq!(rep.failures(), 3);
    assert_eq!(api.all().len(), 3);
}

#[test]
fn stop_progress_outside_stop_pending_sends_nothing() {
    let api = Arc::new(RecordingApi::default());
    let rep = Reporter::new(api.clone(), fast());
    rep.stop_progress();
    rep.start_pending();
    rep.stop_progress();
    assert_eq!(api.states(), vec![State::StartPending]);
}

#[test]
fn default_timing_fits_inside_the_shutdown_window() {
    let t = Timing::default();
    // Learn: about 20 s at system shutdown. The budget plus one poll must
    // fit inside the stop hint, and the hint inside that window.
    assert!(t.stop_budget + t.poll < t.stop_hint);
    assert!(t.stop_hint <= Duration::from_secs(20));
}

#[test]
fn the_controller_handler_never_panics_on_any_input() {
    let api = Arc::new(RecordingApi::default());
    let core = new_core(api, fast());
    for c in 0..300u32 {
        for e in [0, 4, 7, 10, 18, 0x8013, u32::MAX] {
            let _ = core.controller.handle(c, e);
        }
    }
}
