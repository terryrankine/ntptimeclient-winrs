//! A deterministic simulated world for whole-engine scenarios.
//!
//! The world plays the host. It turns the engine's actions into simulated
//! queries and clock commands and feeds events back, following the host
//! contract in [`crate::engine`]. Time is virtual, so a week runs in well
//! under a second.
//!
//! The world keeps the true time to itself. The engine sees only what a
//! real host could report: monotonic readings and query results built from
//! four NTP timestamps on a simulated path. [`SimReport`] measures the
//! error against the hidden true clock.
//!
//! Model, and where it is a choice:
//! - The local clock has a true drift. Each applied frequency is rounded to
//!   a whole number of `tick_granularity_ppm`, as Windows applies it.
//! - Each path leg takes half the base delay, plus or minus half the
//!   asymmetry, plus queuing drawn uniformly from `[0, jitter]`.
//! - Monotonic time runs at the true rate and stands still in sleep.
//! - A started `w32time` takes the clock and runs it at the nominal rate.
//!   Its own discipline is not modelled.
//! - The simulated clock never fails a command.
//!
//! Built only with the `sim` feature.

mod world;

pub use world::SimWorld;

use std::collections::BTreeMap;

use crate::engine::LogEvent;
use crate::{Mono, Offset, Ppm, Tier};

/// One simulated NTP server and the path to it. Times are in seconds.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ServerSpec {
    /// The tier the host lists the server under.
    pub tier: Tier,
    /// The server's clock minus true time. Zero for a good server.
    pub offset: f64,
    /// Base round trip, both legs together.
    pub delay: f64,
    /// Largest extra queuing on each leg. Drawn per leg and per query.
    pub jitter: f64,
    /// Outbound leg minus return leg. NTP reads half of it as offset and
    /// cannot tell.
    pub asymmetry: f64,
    /// Chance that a query gets no reply, from 0 to 1.
    pub loss_rate: f64,
    /// A fault the server shows on every query.
    pub fault: Fault,
}

impl Default for ServerSpec {
    /// An exact pool server on a 30 ms path with up to 2 ms queuing per leg.
    fn default() -> Self {
        Self {
            tier: Tier::Pool,
            offset: 0.0,
            delay: 0.030,
            jitter: 0.002,
            asymmetry: 0.0,
            loss_rate: 0.0,
            fault: Fault::None,
        }
    }
}

/// What is wrong with a server.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Fault {
    /// Nothing.
    None,
    /// Every reply is a kiss-of-death `DENY`.
    KodDeny,
    /// Every reply is a kiss-of-death `RATE`.
    KodRate,
    /// The server is this far wrong on top of `offset`. Kept apart from
    /// `offset` so a scenario reads as intent.
    Falseticker(Offset),
    /// No reply ever. The host's query times out.
    Unreachable,
}

/// Something that happens to the world at a scheduled time.
#[derive(Debug, Clone, PartialEq)]
pub enum SimEvent {
    /// The machine wakes from sleep. The wall clock comes back this far off
    /// from where it was, as the real-time clock restores it. Positive is
    /// ahead. Replies in flight are lost.
    Resume(Offset),
    /// The host lists exactly these servers, by label. A server must be
    /// added to the world first.
    SourcesChanged(Vec<String>),
    /// No route. Every query fails at once. Replies in flight are lost.
    NetworkDown,
    /// The route is back.
    NetworkUp,
    /// Another program moves the wall clock by this much.
    ExternalStep(Offset),
    /// `w32time` starts and takes the clock. The host turns adjustment off.
    W32TimeStarted,
    /// `w32time` stops. The host turns adjustment back on.
    W32TimeStopped,
    /// The clock's true drift changes, as on a machine that warms up.
    SetDrift(Ppm),
}

/// What happened during one [`SimWorld::run`].
///
/// Errors are the local clock minus true time, in seconds. Positive means
/// the local clock is ahead. They come from the hidden true clock.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SimReport {
    /// Largest error size seen. The error is linear between events, so
    /// checking at each event is exact.
    pub max_abs_error: f64,
    /// Error at the end of the run.
    pub final_error: f64,
    /// Every step the host applied, with its time.
    pub steps: Vec<(Mono, Offset)>,
    /// Every log line, with its time.
    pub logs: Vec<(Mono, LogEvent)>,
    /// Queries sent, per server label.
    pub queries: BTreeMap<String, u32>,
    /// Clock commands the host performed.
    pub clock_commands: u32,
    /// Clock commands the engine sent while the host had adjustment off.
    /// Always zero for a correct engine.
    pub commands_while_disabled: u32,
    /// Largest applied frequency size, in ppm, after quantisation.
    pub max_abs_frequency: f64,
    /// The last drift the engine asked to save.
    pub saved_drift: Option<Ppm>,
}

/// splitmix64. Small, fast and good enough for path noise. A fixed seed
/// replays a run exactly.
#[derive(Debug, Clone)]
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in `[0, 1)`.
    fn unit(&mut self) -> f64 {
        // 53 bits fill the mantissa exactly, so the casts lose nothing.
        #[allow(clippy::cast_precision_loss)]
        let u = (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64;
        u
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rng_is_seeded_and_in_range() {
        let (mut a, mut b, mut c) = (Rng(1), Rng(1), Rng(2));
        for _ in 0..1000 {
            let x = a.unit();
            assert!((0.0..1.0).contains(&x));
            assert!((x - b.unit()).abs() < f64::EPSILON);
        }
        assert_ne!(a.next_u64(), c.next_u64());
    }

    #[test]
    fn rng_mean_is_near_one_half() {
        let mut r = Rng(42);
        let n = 100_000;
        let mean = (0..n).map(|_| r.unit()).sum::<f64>() / f64::from(n);
        assert!((mean - 0.5).abs() < 0.01, "{mean}");
    }
}
