//! Admin tests that CHANGE THE SYSTEM CLOCK AND ITS RATE.
//!
//! Every test is `#[ignore]`. Run them only in an elevated shell on a
//! throwaway VM with hypervisor time sync off and `w32time` stopped:
//!
//! ```text
//! cargo test -p ntpc-platform --test clock_windows -- --ignored --test-threads=1 --nocapture
//! ```
//!
//! Never run them on a machine whose clock matters. Each test resets the
//! rate when it ends, also on panic. A step test steps back what it stepped.

#![cfg(windows)]

use std::process::{Child, Command};
use std::time::{Duration, Instant};

use ntpc_core::{Clock, Offset, Ppm};
use ntpc_platform::WindowsClock;
use ntpc_platform::clock::{read_adjustment, wall_now_ns};
use ntpc_platform::ppm_to_adjustment;

/// Resets the rate on drop, so a failed assert does not leave it set.
struct ResetOnDrop(WindowsClock);

impl Drop for ResetOnDrop {
    fn drop(&mut self) {
        if let Err(e) = self.0.reset_frequency() {
            eprintln!("RESET FAILED, fix the rate by hand: {e}");
        }
    }
}

fn clock() -> ResetOnDrop {
    ResetOnDrop(WindowsClock::new().expect("needs an elevated shell"))
}

#[test]
#[ignore = "changes the system clock: elevated, throwaway VM only"]
fn step_forward_then_back() {
    let mut c = clock();
    let before = wall_now_ns();
    c.0.step(Offset::from_secs(1.0)).unwrap();
    let after = wall_now_ns();
    let moved = after - before;
    eprintln!("moved by {moved} ns after +1 s");
    assert!((moved - 1_000_000_000).abs() < 50_000_000, "{moved}");
    c.0.step(Offset::from_secs(-1.0)).unwrap();
    let back = wall_now_ns() - before;
    eprintln!("net after -1 s: {back} ns");
    assert!(back.abs() < 100_000_000, "{back}");
}

#[test]
#[ignore = "changes the system clock rate: elevated, throwaway VM only"]
fn set_100_ppm_then_reset() {
    let mut c = clock();
    eprintln!("initial state: {:?}", c.0.initial_state());
    c.0.set_frequency(Ppm::new(100.0)).unwrap();
    let s = read_adjustment().unwrap();
    eprintln!("after 100 ppm: {s:?} ({:?} ppm)", s.ppm());
    assert!(!s.disabled);
    assert_eq!(
        s.adjustment,
        ppm_to_adjustment(Ppm::new(100.0), c.0.nominal())
    );
    c.0.reset_frequency().unwrap();
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
    let mut c = WindowsClock::new().unwrap();
    c.set_frequency(Ppm::new(100.0)).unwrap();
    eprintln!("child: 100 ppm set, waiting to be killed");
    // No reset guard here on purpose: the parent kills this process.
    loop {
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn spawn_child() -> Child {
    Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "kill_child_helper", "--nocapture"])
        .env("NTPC_KILL_CHILD", "1")
        .spawn()
        .unwrap()
}

/// Review Focus 7. A process sets a rate and is killed. The next start must
/// read the rate and reset it. Prints whether the rate survived the kill,
/// which the Win32 docs do not say.
#[test]
#[ignore = "changes the system clock rate and kills a process: elevated, throwaway VM only"]
fn rate_after_kill_is_read_and_reset() {
    // Start from a known nominal state.
    clock().0.reset_frequency().unwrap();
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
    child.kill().unwrap();
    let _ = child.wait();
    std::thread::sleep(Duration::from_secs(1));
    let after_kill = read_adjustment().unwrap();
    let persisted = !after_kill.is_nominal();
    eprintln!("after kill: {after_kill:?} ({:?} ppm)", after_kill.ppm());
    eprintln!("RATE PERSISTED AFTER KILL: {persisted}");

    // The next start: read, then reset.
    let mut c = clock();
    assert_eq!(c.0.initial_state(), after_kill);
    assert_eq!(c.0.initial_state().is_nominal(), !persisted);
    c.0.reset_frequency().unwrap();
    let s = read_adjustment().unwrap();
    eprintln!("after reset: {s:?}");
    assert!(s.is_nominal());
}
