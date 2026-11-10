//! Admin tests that CHANGE THE SYSTEM CLOCK AND ITS RATE.
//!
//! Every test is `#[ignore]`. Run them only in an elevated shell on a
//! throwaway VM with hypervisor time sync off and `w32time` stopped:
//!
//! ```text
//! set NTPC_ALLOW_CLOCK_TESTS=1
//! cargo test -p ntpc-platform --test clock_windows -- --ignored --test-threads=1 --nocapture
//! ```
//!
//! Each test refuses (panics with the reason) unless
//! `NTPC_ALLOW_CLOCK_TESTS=1` is set and `w32time` is not running (R72).
//! Guards undo what a test did, also when an assert fails: steps are
//! stepped back by exactly what was applied, the rate is reset, and a child
//! process is killed and waited for.

#![cfg(windows)]

use std::process::{Child, Command};
use std::time::{Duration, Instant};

use ntpc_core::{Clock, Offset, Ppm};
use ntpc_platform::WindowsClock;
use ntpc_platform::clock::{read_adjustment, wall_now_ns};
use ntpc_platform::ppm_to_adjustment;

/// Why the admin tests may not run here, or `Ok` if they may. Read only:
/// the service state comes from `sc.exe query`, which changes nothing.
fn allowed() -> Result<(), String> {
    if std::env::var("NTPC_ALLOW_CLOCK_TESTS").as_deref() != Ok("1") {
        return Err("NTPC_ALLOW_CLOCK_TESTS=1 is not set".into());
    }
    let out = Command::new("sc.exe")
        .args(["query", "w32time"])
        .output()
        .map_err(|e| format!("cannot query w32time: {e}"))?;
    let text = String::from_utf8_lossy(&out.stdout);
    if text.contains("RUNNING") || text.contains("PENDING") {
        return Err("w32time is running or changing state: stop it first".into());
    }
    // 1060: the service does not exist, which is fine.
    if !text.contains("STOPPED") && !text.contains("1060") {
        return Err(format!("w32time state unknown: {}", text.trim()));
    }
    Ok(())
}

fn require_allowed() {
    if let Err(why) = allowed() {
        panic!("refusing to change the clock: {why}");
    }
}

/// Owns the clock for one test. On drop it steps back by exactly the sum it
/// stepped and resets the rate.
struct ClockGuard {
    clock: WindowsClock,
    stepped_secs: f64,
}

impl ClockGuard {
    fn new() -> Self {
        require_allowed();
        Self {
            clock: WindowsClock::new().expect("needs an elevated shell"),
            stepped_secs: 0.0,
        }
    }

    fn step(&mut self, secs: f64) {
        self.clock.step(Offset::from_secs(secs)).unwrap();
        self.stepped_secs += secs;
    }
}

impl Drop for ClockGuard {
    fn drop(&mut self) {
        if self.stepped_secs != 0.0 {
            let back = -self.stepped_secs;
            match self.clock.step(Offset::from_secs(back)) {
                Ok(()) => eprintln!("guard: stepped back {back} s"),
                Err(e) => eprintln!("GUARD STEP BACK FAILED, fix the clock by hand: {e}"),
            }
        }
        if let Err(e) = self.clock.reset_frequency() {
            eprintln!("GUARD RESET FAILED, fix the rate by hand: {e}");
        }
    }
}

/// Kills and waits for the child on drop, then resets the rate it set.
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        match self.0.wait() {
            Ok(status) => eprintln!("guard: child ended: {status}"),
            Err(e) => eprintln!("GUARD WAIT FAILED, check for a stray test process: {e}"),
        }
        match WindowsClock::new().and_then(|mut c| c.reset_frequency()) {
            Ok(()) => eprintln!("guard: rate reset after child"),
            Err(e) => eprintln!("GUARD RESET FAILED, fix the rate by hand: {e}"),
        }
    }
}

#[test]
#[ignore = "changes the system clock: elevated, throwaway VM only"]
fn step_forward_then_back() {
    let mut g = ClockGuard::new();
    let before = wall_now_ns();
    g.step(1.0);
    let moved = wall_now_ns() - before;
    eprintln!("moved by {moved} ns after +1 s");
    assert!((moved - 1_000_000_000).abs() < 50_000_000, "{moved}");
    g.step(-1.0);
    let back = wall_now_ns() - before;
    eprintln!("net after -1 s: {back} ns");
    assert!(back.abs() < 100_000_000, "{back}");
}

#[test]
#[ignore = "changes the system clock and its rate: elevated, throwaway VM only"]
fn step_then_set_frequency_on_the_same_clock() {
    // SetSystemTime disables the privilege before it returns (Learn). The
    // rate call after it must still succeed on the same WindowsClock.
    let mut g = ClockGuard::new();
    g.step(1.0);
    let after_step = read_adjustment().unwrap();
    eprintln!("adjustment after SetSystemTime: {after_step:?}");
    g.clock.set_frequency(Ppm::new(100.0)).unwrap();
    let s = read_adjustment().unwrap();
    eprintln!("after 100 ppm: {s:?} ({:?} ppm)", s.ppm());
    assert_eq!(
        s.adjustment,
        ppm_to_adjustment(Ppm::new(100.0), g.clock.nominal())
    );
    g.step(-1.0);
}

#[test]
#[ignore = "changes the system clock rate: elevated, throwaway VM only"]
fn set_100_ppm_then_reset() {
    let mut g = ClockGuard::new();
    eprintln!("initial state: {:?}", g.clock.initial_state());
    g.clock.set_frequency(Ppm::new(100.0)).unwrap();
    let s = read_adjustment().unwrap();
    eprintln!("after 100 ppm: {s:?} ({:?} ppm)", s.ppm());
    assert!(!s.disabled);
    assert_eq!(
        s.adjustment,
        ppm_to_adjustment(Ppm::new(100.0), g.clock.nominal())
    );
    g.clock.reset_frequency().unwrap();
    let s = read_adjustment().unwrap();
    eprintln!("after reset: {s:?}");
    assert!(s.disabled, "reset should hand control back to the OS");
    assert!(s.is_nominal());
}

/// Child half of the kill test. Does nothing unless the parent set the
/// variable. It sets 100 ppm and then waits to be killed.
#[test]
#[ignore = "helper for rate_after_kill_is_read_and_reset"]
fn kill_child_helper() {
    if std::env::var_os("NTPC_KILL_CHILD").is_none() {
        return;
    }
    require_allowed();
    let mut c = WindowsClock::new().unwrap();
    c.set_frequency(Ppm::new(100.0)).unwrap();
    eprintln!("child: 100 ppm set, waiting to be killed");
    // No reset guard here on purpose: the parent kills this process. The
    // parent's ChildGuard resets the rate afterwards.
    loop {
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn spawn_child() -> ChildGuard {
    ChildGuard(
        Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", "kill_child_helper", "--nocapture"])
            .env("NTPC_KILL_CHILD", "1")
            .spawn()
            .unwrap(),
    )
}

/// Review Focus 7. A process sets a rate and is killed. The next start must
/// read the rate and reset it. Prints whether the rate survived the kill,
/// which the Win32 docs do not say.
#[test]
#[ignore = "changes the system clock rate and kills a process: elevated, throwaway VM only"]
fn rate_after_kill_is_read_and_reset() {
    // Start from a known nominal state.
    ClockGuard::new().clock.reset_frequency().unwrap();
    let mut child = spawn_child();
    let deadline = Instant::now() + Duration::from_secs(30);
    let set = loop {
        let s = read_adjustment().unwrap();
        if !s.disabled && !s.is_nominal() {
            break s;
        }
        assert!(Instant::now() < deadline, "child never set the rate");
        std::thread::sleep(Duration::from_millis(100));
    };
    eprintln!("child set: {set:?} ({:?} ppm)", set.ppm());
    child.0.kill().unwrap();
    let _ = child.0.wait();
    std::thread::sleep(Duration::from_secs(1));
    let after_kill = read_adjustment().unwrap();
    let persisted = !after_kill.is_nominal();
    eprintln!("after kill: {after_kill:?} ({:?} ppm)", after_kill.ppm());
    eprintln!("RATE PERSISTED AFTER KILL: {persisted}");

    // The next start: read, then reset.
    let mut g = ClockGuard::new();
    assert_eq!(g.clock.initial_state(), after_kill);
    assert_eq!(g.clock.initial_state().is_nominal(), !persisted);
    g.clock.reset_frequency().unwrap();
    let s = read_adjustment().unwrap();
    eprintln!("after reset: {s:?}");
    assert!(s.is_nominal());
    drop(g);
    drop(child);
}
