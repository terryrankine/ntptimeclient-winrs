//! Plain data types shared by the engine, the host and the simulation.
//!
//! Newtypes keep their field private so a value in seconds cannot be
//! mixed up with a value in parts per million.

use std::net::SocketAddr;
use std::time::Duration;

/// Clock offset in seconds. Positive means the remote clock is ahead.
///
/// The field is private. Build a value with [`Offset::from_secs`] or
/// [`Offset::between`].
///
/// ```compile_fail
/// use ntpc_core::Offset;
/// let _ = Offset(1.0);
/// ```
///
/// ```compile_fail
/// use ntpc_core::Offset;
/// let o = Offset::from_secs(1.0);
/// let _ = o.0;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct Offset(f64);

impl Offset {
    /// Wraps a value in seconds.
    #[must_use]
    pub fn from_secs(secs: f64) -> Self {
        Self(secs)
    }

    /// The offset in seconds.
    #[must_use]
    pub fn as_secs(self) -> f64 {
        self.0
    }

    /// Remote time minus local time, both in seconds.
    #[must_use]
    pub fn between(remote_secs: f64, local_secs: f64) -> Self {
        Self(remote_secs - local_secs)
    }
}

/// Round-trip delay in seconds.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct Delay(f64);

impl Delay {
    /// Wraps a value in seconds.
    #[must_use]
    pub fn from_secs(secs: f64) -> Self {
        Self(secs)
    }

    /// The delay in seconds.
    #[must_use]
    pub fn as_secs(self) -> f64 {
        self.0
    }
}

/// Frequency error in parts per million.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct Ppm(f64);

impl Ppm {
    const PER_UNIT: f64 = 1e-6;

    /// Wraps a value in parts per million.
    #[must_use]
    pub fn new(ppm: f64) -> Self {
        Self(ppm)
    }

    /// The value in parts per million.
    #[must_use]
    pub fn value(self) -> f64 {
        self.0
    }

    /// The value as a plain ratio, so 1 ppm is `1e-6`.
    #[must_use]
    pub fn as_fraction(self) -> f64 {
        self.0 * Self::PER_UNIT
    }

    /// Builds a value from a plain ratio.
    #[must_use]
    pub fn from_fraction(fraction: f64) -> Self {
        Self(fraction / Self::PER_UNIT)
    }
}

/// A point on the monotonic clock, in nanoseconds.
///
/// It counts awake time only. Suspend does not advance it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Mono(u64);

impl Mono {
    /// Wraps nanoseconds since an arbitrary fixed start.
    #[must_use]
    pub fn from_nanos(nanos: u64) -> Self {
        Self(nanos)
    }

    /// Nanoseconds since the start of the monotonic clock.
    #[must_use]
    pub fn as_nanos(self) -> u64 {
        self.0
    }

    /// Adds a duration. Returns `None` if the result does not fit.
    #[must_use]
    pub fn checked_add(self, by: Duration) -> Option<Self> {
        let nanos = u64::try_from(by.as_nanos()).ok()?;
        self.0.checked_add(nanos).map(Self)
    }

    /// Time since `earlier`, or zero if `earlier` is not earlier.
    #[must_use]
    pub fn saturating_duration_since(self, earlier: Mono) -> Duration {
        Duration::from_nanos(self.0.saturating_sub(earlier.0))
    }
}

/// Stable identity of one configured source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceId(u32);

impl SourceId {
    /// Wraps a numeric id.
    #[must_use]
    pub fn new(id: u32) -> Self {
        Self(id)
    }

    /// The numeric id.
    #[must_use]
    pub fn get(self) -> u32 {
        self.0
    }
}

/// Where a source came from. The declaration order is the priority order.
///
/// `Config < Dhcp < Pool`. `Config` has the highest priority and sorts first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Tier {
    /// Set by the operator in the configuration file.
    Config,
    /// Offered by the network through DHCP.
    Dhcp,
    /// Found by resolving a public pool name.
    Pool,
}

/// One server the engine may query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceSpec {
    /// Identity used in samples and events.
    pub id: SourceId,
    /// Where the source came from.
    pub tier: Tier,
    /// Resolved address and port.
    pub addr: SocketAddr,
    /// Name for logs.
    pub label: String,
}

/// One accepted reply from a source.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Sample {
    /// The source that answered.
    pub source: SourceId,
    /// Remote minus local.
    pub offset: Offset,
    /// Round-trip delay.
    pub delay: Delay,
    /// Stratum the server reported.
    pub stratum: u8,
    /// The server said its clock is not synchronised.
    pub unsynchronised: bool,
    /// The server raised the leap indicator alarm.
    pub leap_alarm: bool,
    /// Local monotonic time when the reply arrived.
    pub at: Mono,
}

/// Why a query gave no sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryFailure {
    /// No reply in time.
    Timeout,
    /// The server sent a kiss-of-death packet.
    KissOfDeath(KodCode),
    /// The address could not be reached.
    Unreachable,
    /// The reply failed validation.
    Malformed,
}

/// Kiss-of-death code from the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KodCode {
    /// `DENY`.
    Deny,
    /// `RSTR`.
    Rstr,
    /// `RATE`.
    Rate,
    /// Any other code.
    Other,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_sorts_config_first() {
        let mut tiers = [Tier::Pool, Tier::Config, Tier::Dhcp];
        tiers.sort();
        assert_eq!(tiers, [Tier::Config, Tier::Dhcp, Tier::Pool]);
        assert!(Tier::Config < Tier::Dhcp && Tier::Dhcp < Tier::Pool);
    }

    #[test]
    fn offset_is_remote_minus_local() {
        let o = Offset::between(100.5, 100.0);
        assert!((o.as_secs() - 0.5).abs() < 1e-12);
        let o = Offset::between(99.0, 100.0);
        assert!((o.as_secs() + 1.0).abs() < 1e-12);
    }

    #[test]
    fn ppm_to_fraction_round_trips() {
        let p = Ppm::new(12.5);
        assert!((p.as_fraction() - 12.5e-6).abs() < 1e-18);
        let back = Ppm::from_fraction(p.as_fraction());
        assert!((back.value() - 12.5).abs() < 1e-9);
    }

    #[test]
    fn mono_saturating_duration_since_clamps_at_zero() {
        let a = Mono::from_nanos(5_000);
        let b = Mono::from_nanos(2_000);
        assert_eq!(a.saturating_duration_since(b), Duration::from_nanos(3_000));
        assert_eq!(b.saturating_duration_since(a), Duration::ZERO);
    }

    #[test]
    fn mono_checked_add_overflow_is_none() {
        let m = Mono::from_nanos(u64::MAX - 1);
        assert_eq!(
            m.checked_add(Duration::from_nanos(1)),
            Some(Mono::from_nanos(u64::MAX))
        );
        assert_eq!(m.checked_add(Duration::from_nanos(2)), None);
        assert_eq!(m.checked_add(Duration::MAX), None);
    }

    #[test]
    fn source_id_round_trips() {
        assert_eq!(SourceId::new(7).get(), 7);
    }
}
