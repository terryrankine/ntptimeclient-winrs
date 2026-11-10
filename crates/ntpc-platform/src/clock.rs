//! The Windows clock adapter and the pure rate arithmetic behind it.
//!
//! The arithmetic builds on every host. The adapter itself is Windows only.
//! Facts and sources: `docs/architecture.md`, "Platform".

use ntpc_core::{ClockError, Offset, Ppm};

#[cfg(windows)]
use crate::win32;
#[cfg(windows)]
use ntpc_core::{Clock, Mono};

/// Largest rate offset `ppm_to_adjustment` will produce, in ppm.
///
/// The Win32 docs give no valid range. The Learn sample for
/// `SetSystemTimeAdjustmentPrecise` refuses more than 1000 ppm, so we stay
/// inside that. The discipline caps at 500 ppm.
pub const MAX_ADJUSTMENT_PPM: f64 = 1000.0;

/// `ppm` is held as an integer count of this many parts per unit of ppm.
/// A nano-ppm is far below the 0.1 ppm the OS can apply.
const PPM_SCALE: f64 = 1e9;

/// `nominal * ppm_scaled / DENOM` is the adjustment delta in counts.
/// It is 1e6 (ppm) times `PPM_SCALE`.
const DENOM: i128 = 1_000_000_000_000_000;

/// Maps a rate offset to the value for `SetSystemTimeAdjustmentPrecise`.
///
/// `nominal` is the increment the OS reports. The result is
/// `nominal + round(nominal * ppm / 1e6)`. Positive `ppm` gives a value above
/// nominal, which the OS runs fast.
///
/// - `ppm` is clamped to plus or minus [`MAX_ADJUSTMENT_PPM`]. NaN maps to
///   nominal.
/// - `ppm` is fixed to whole nano-ppm, then the rest is integer arithmetic.
///   No precision is lost for any `nominal` up to `u64::MAX`.
/// - Rounding is to the nearest count, ties away from zero, so plus and
///   minus the same ppm sit the same distance from nominal.
/// - The result is monotonic in `ppm` and never overflows.
#[must_use]
pub fn ppm_to_adjustment(ppm: Ppm, nominal: u64) -> u64 {
    let v = ppm.value();
    if v.is_nan() {
        return nominal;
    }
    let clamped = v.clamp(-MAX_ADJUSTMENT_PPM, MAX_ADJUSTMENT_PPM);
    // The clamp bounds the product to plus or minus 1e12, far inside i128.
    #[allow(clippy::cast_possible_truncation)]
    let scaled = (clamped * PPM_SCALE).round() as i128;
    // u64::MAX * 1e12 is about 1.8e31. i128 holds 1.7e38.
    let product = i128::from(nominal) * scaled;
    let delta = div_round_half_away(product, DENOM);
    let result = i128::from(nominal) + delta;
    // |delta| is at most nominal / 1000, so the result is never negative.
    // It can pass u64::MAX only when nominal is near u64::MAX.
    u64::try_from(result).unwrap_or(u64::MAX)
}

/// `n / d` rounded to the nearest integer, ties away from zero. `d > 0`.
fn div_round_half_away(n: i128, d: i128) -> i128 {
    let q = (n.abs() + d / 2) / d;
    if n < 0 { -q } else { q }
}

/// Rounds `ppm` to a whole number of `granularity_ppm` steps.
///
/// Ties round away from zero. A granularity that is zero, negative or not
/// finite leaves `ppm` unchanged. So does a result that would not be finite.
/// This mirrors what the OS does to a rate, so the host can report the rate
/// it really applied.
#[must_use]
pub fn quantise(ppm: Ppm, granularity_ppm: f64) -> Ppm {
    if !(granularity_ppm.is_finite() && granularity_ppm > 0.0) {
        return ppm;
    }
    let q = (ppm.value() / granularity_ppm).round() * granularity_ppm;
    if q.is_finite() { Ppm::new(q) } else { ppm }
}

/// The clock rate state the OS reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdjustmentState {
    /// Counts added per update period.
    pub adjustment: u64,
    /// Counts per update period at the nominal rate.
    pub increment: u64,
    /// The OS keeps time itself and runs at the normal rate.
    pub disabled: bool,
}

impl AdjustmentState {
    /// The rate offset in ppm that is in force. Zero when disabled, because
    /// the docs say the clock then advances at the normal rate. `None` when
    /// the increment is zero and no rate can be worked out.
    #[must_use]
    pub fn ppm(&self) -> Option<f64> {
        if self.disabled {
            return Some(0.0);
        }
        if self.increment == 0 {
            return None;
        }
        // Counts are far below 2^53 on any real system, so f64 is exact.
        #[allow(clippy::cast_precision_loss)]
        let (a, i) = (self.adjustment as f64, self.increment as f64);
        Some((a - i) / i * 1e6)
    }

    /// One count of `adjustment` in ppm. `None` for a zero increment.
    #[must_use]
    pub fn granularity_ppm(&self) -> Option<f64> {
        // As above, the increment is exact in f64.
        #[allow(clippy::cast_precision_loss)]
        (self.increment != 0).then(|| 1e6 / self.increment as f64)
    }

    /// True when the clock runs at the nominal rate. A start that finds this
    /// false met a rate left by a crashed run or another time service.
    #[must_use]
    pub fn is_nominal(&self) -> bool {
        self.disabled || self.adjustment == self.increment
    }
}

/// 1601-01-01 to 1970-01-01 in `FILETIME` units of 100 ns.
const UNIX_EPOCH_AS_FILETIME: i128 = 116_444_736_000_000_000;

/// Steps may not land at or after 2106-02-07T06:28:16Z, the end of 32-bit
/// Unix seconds. Our bound, well inside `SYSTEMTIME`. It covers NTP era 1.
const STEP_LIMIT_NS: i128 = (1_i128 << 32) * 1_000_000_000;

const NANOS_PER_MILLI: i128 = 1_000_000;

/// The `FILETIME` value a step by `by` from `now_ns` sets.
///
/// `now_ns` is Unix nanoseconds. The target is rounded to the nearest
/// millisecond, ties away from zero, because `SetSystemTime` takes
/// milliseconds. The error is at most 0.5 ms. The engine slews the rest.
///
/// # Errors
/// [`ClockError::Rejected`] if the offset is not finite or the target falls
/// before 1970 or at or after 2106-02-07T06:28:16Z.
pub fn step_target_filetime(now_ns: i128, by: Offset) -> Result<u64, ClockError> {
    let secs = by.as_secs();
    // 2^32 s bounds any target we accept, so a larger offset is refused
    // before the cast and nothing can overflow.
    if !secs.is_finite() || secs.abs() > 4_294_967_296.0 {
        return Err(ClockError::Rejected("step offset out of range".into()));
    }
    // |secs * 1e9| is at most about 4.3e18, inside i128.
    #[allow(clippy::cast_possible_truncation)]
    let off_ns = (secs * 1e9).round() as i128;
    let target = now_ns + off_ns;
    let target = div_round_half_away(target, NANOS_PER_MILLI) * NANOS_PER_MILLI;
    if !(0..STEP_LIMIT_NS).contains(&target) {
        return Err(ClockError::Rejected(
            "step target outside 1970 to 2106".into(),
        ));
    }
    let ft = target / 100 + UNIX_EPOCH_AS_FILETIME;
    u64::try_from(ft).map_err(|_| ClockError::Rejected("step target out of range".into()))
}

/// Maps an OS error to the port error. The text names the operation and the
/// OS message only, never a path, per the engine host contract.
#[cfg(windows)]
fn clock_error(op: &str, e: &std::io::Error) -> ClockError {
    /// `ERROR_ACCESS_DENIED`.
    const ACCESS_DENIED: i32 = 5;
    /// `ERROR_NOT_ALL_ASSIGNED`: the token lacks the privilege.
    const NOT_ALL_ASSIGNED: i32 = 1300;
    /// `ERROR_PRIVILEGE_NOT_HELD`.
    const PRIVILEGE_NOT_HELD: i32 = 1314;
    match e.raw_os_error() {
        Some(ACCESS_DENIED | NOT_ALL_ASSIGNED | PRIVILEGE_NOT_HELD) => ClockError::PermissionDenied,
        _ => ClockError::Rejected(format!("{op}: {e}")),
    }
}

/// Reads the rate state. Read only, no privilege needed.
///
/// # Errors
/// [`ClockError::Rejected`] if the OS call fails.
#[cfg(windows)]
pub fn read_adjustment() -> Result<AdjustmentState, ClockError> {
    let raw =
        win32::time_adjustment_precise().map_err(|e| clock_error("read clock adjustment", &e))?;
    Ok(AdjustmentState {
        adjustment: raw.adjustment,
        increment: raw.increment,
        disabled: raw.disabled,
    })
}

/// Wall time in Unix nanoseconds from `GetSystemTimePreciseAsFileTime`.
#[cfg(windows)]
#[must_use]
pub fn wall_now_ns() -> i128 {
    (i128::from(win32::system_time_precise()) - UNIX_EPOCH_AS_FILETIME) * 100
}

/// Awake time from `QueryUnbiasedInterruptTimePrecise`. Sleep does not count
/// and clock steps do not move it.
#[cfg(windows)]
#[must_use]
pub fn mono_now() -> Mono {
    // 100 ns units. u64 nanoseconds last 584 years of uptime.
    Mono::from_nanos(win32::unbiased_interrupt_time_precise().saturating_mul(100))
}

/// The Windows system clock.
///
/// Rates go through `SetSystemTimeAdjustmentPrecise` and steps through
/// `SetSystemTime`. The rate setting is system wide. Whether it outlives
/// this process is not documented, so the host calls
/// [`Clock::reset_frequency`] at start and at stop.
#[cfg(windows)]
#[derive(Debug)]
pub struct WindowsClock {
    nominal: u64,
    initial: AdjustmentState,
}

#[cfg(windows)]
impl WindowsClock {
    /// Reads the rate state and enables `SeSystemtimePrivilege`. It does
    /// not change the clock or its rate.
    ///
    /// # Errors
    /// [`ClockError::PermissionDenied`] if the token lacks the privilege.
    /// [`ClockError::Rejected`] if the state cannot be read or the OS
    /// reports a zero increment.
    pub fn new() -> Result<Self, ClockError> {
        let initial = read_adjustment()?;
        if initial.increment == 0 {
            return Err(ClockError::Rejected(
                "OS reports a zero clock increment".into(),
            ));
        }
        win32::enable_systemtime_privilege().map_err(|e| clock_error("enable privilege", &e))?;
        Ok(Self {
            nominal: initial.increment,
            initial,
        })
    }

    /// The rate state found at start. A non-nominal state means a rate left
    /// by a crashed run or by another time service. The host logs it and
    /// calls [`Clock::reset_frequency`].
    #[must_use]
    pub fn initial_state(&self) -> AdjustmentState {
        self.initial
    }

    /// The nominal increment, the base of every adjustment.
    #[must_use]
    pub fn nominal(&self) -> u64 {
        self.nominal
    }

    /// The smallest rate change the OS can apply, in ppm.
    #[must_use]
    pub fn granularity_ppm(&self) -> f64 {
        // The increment is non-zero (checked in `new`) and exact in f64.
        #[allow(clippy::cast_precision_loss)]
        let n = self.nominal as f64;
        1e6 / n
    }
}

#[cfg(windows)]
impl Clock for WindowsClock {
    fn mono(&self) -> Mono {
        mono_now()
    }

    fn wall_ns(&self) -> i128 {
        wall_now_ns()
    }

    fn step(&mut self, by: Offset) -> Result<(), ClockError> {
        let ft = step_target_filetime(wall_now_ns(), by)?;
        win32::set_system_time(ft).map_err(|e| clock_error("set system time", &e))
    }

    fn set_frequency(&mut self, ppm: Ppm) -> Result<(), ClockError> {
        let adjustment = ppm_to_adjustment(ppm, self.nominal);
        win32::set_time_adjustment_precise(adjustment, false)
            .map_err(|e| clock_error("set clock rate", &e))
    }

    fn reset_frequency(&mut self) -> Result<(), ClockError> {
        // TRUE hands timekeeping back to the OS at the normal rate. The
        // value is ignored in that mode.
        win32::set_time_adjustment_precise(0, true).map_err(|e| clock_error("reset clock rate", &e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The increment measured on Windows 11 with the precise API.
    const NOMINAL: u64 = 10_000_000;

    #[test]
    fn adjustment_zero_ppm_is_nominal() {
        assert_eq!(ppm_to_adjustment(Ppm::new(0.0), NOMINAL), NOMINAL);
        assert_eq!(ppm_to_adjustment(Ppm::new(-0.0), NOMINAL), NOMINAL);
        assert_eq!(ppm_to_adjustment(Ppm::new(0.0), 156_250), 156_250);
    }

    #[test]
    fn adjustment_is_monotonic() {
        let mut last = 0;
        for i in -12_000..=12_000 {
            let ppm = f64::from(i) * 0.1;
            let a = ppm_to_adjustment(Ppm::new(ppm), NOMINAL);
            assert!(a >= last, "not monotonic at {ppm} ppm");
            last = a;
        }
    }

    #[test]
    fn adjustment_clamps_to_valid_range() {
        let hi = ppm_to_adjustment(Ppm::new(MAX_ADJUSTMENT_PPM), NOMINAL);
        let lo = ppm_to_adjustment(Ppm::new(-MAX_ADJUSTMENT_PPM), NOMINAL);
        assert_eq!(hi, 10_010_000);
        assert_eq!(lo, 9_990_000);
        assert_eq!(ppm_to_adjustment(Ppm::new(1e9), NOMINAL), hi);
        assert_eq!(ppm_to_adjustment(Ppm::new(-1e9), NOMINAL), lo);
        assert_eq!(ppm_to_adjustment(Ppm::new(f64::MAX), NOMINAL), hi);
        assert_eq!(ppm_to_adjustment(Ppm::new(f64::MIN), NOMINAL), lo);
    }

    #[test]
    fn quantise_rounds_to_granularity() {
        assert!((quantise(Ppm::new(20.0), 6.4).value() - 19.2).abs() < 1e-9);
        assert!((quantise(Ppm::new(23.0), 6.4).value() - 25.6).abs() < 1e-9);
        assert!((quantise(Ppm::new(12.34), 0.1).value() - 12.3).abs() < 1e-9);
    }

    #[test]
    fn adjustment_at_plus_and_minus_500_ppm_is_exact() {
        // 500 ppm of 10 000 000 is 5000 counts.
        assert_eq!(ppm_to_adjustment(Ppm::new(500.0), NOMINAL), 10_005_000);
        assert_eq!(ppm_to_adjustment(Ppm::new(-500.0), NOMINAL), 9_995_000);
        // Legacy increment: 500 ppm of 156 250 is 78.125, rounds to 78.
        assert_eq!(ppm_to_adjustment(Ppm::new(500.0), 156_250), 156_328);
        assert_eq!(ppm_to_adjustment(Ppm::new(-500.0), 156_250), 156_172);
    }

    #[test]
    fn adjustment_rounds_half_away_from_zero() {
        // 0.05 ppm of 10 000 000 is exactly half a count.
        assert_eq!(ppm_to_adjustment(Ppm::new(0.05), NOMINAL), 10_000_001);
        assert_eq!(ppm_to_adjustment(Ppm::new(-0.05), NOMINAL), 9_999_999);
        assert_eq!(ppm_to_adjustment(Ppm::new(0.049), NOMINAL), NOMINAL);
        assert_eq!(ppm_to_adjustment(Ppm::new(-0.049), NOMINAL), NOMINAL);
        assert_eq!(ppm_to_adjustment(Ppm::new(0.15), NOMINAL), 10_000_002);
    }

    #[test]
    fn adjustment_of_zero_nominal_is_zero() {
        assert_eq!(ppm_to_adjustment(Ppm::new(500.0), 0), 0);
        assert_eq!(ppm_to_adjustment(Ppm::new(-500.0), 0), 0);
    }

    #[test]
    fn adjustment_at_u64_extremes_does_not_overflow() {
        let max = u64::MAX;
        assert_eq!(ppm_to_adjustment(Ppm::new(0.0), max), max);
        assert_eq!(ppm_to_adjustment(Ppm::new(1000.0), max), max);
        assert!(ppm_to_adjustment(Ppm::new(-1000.0), max) < max);
        assert_eq!(ppm_to_adjustment(Ppm::new(-1000.0), 1), 1);
        assert_eq!(ppm_to_adjustment(Ppm::new(1000.0), 1), 1);
    }

    #[test]
    fn adjustment_of_nan_is_nominal() {
        // Ppm::new asserts finite in debug builds. A release build can still
        // carry NaN, and the mapping must stay safe then.
        if !cfg!(debug_assertions) {
            assert_eq!(ppm_to_adjustment(Ppm::new(f64::NAN), NOMINAL), NOMINAL);
        }
    }

    #[test]
    fn quantise_with_zero_or_bad_granularity_is_identity() {
        assert!((quantise(Ppm::new(12.34), 0.0).value() - 12.34).abs() < 1e-12);
        assert!((quantise(Ppm::new(12.34), -1.0).value() - 12.34).abs() < 1e-12);
        assert!((quantise(Ppm::new(12.34), f64::NAN).value() - 12.34).abs() < 1e-12);
        let inf = quantise(Ppm::new(12.34), f64::INFINITY).value();
        assert!((inf - 12.34).abs() < 1e-12);
    }

    #[test]
    fn quantise_negative_ppm_is_symmetric() {
        assert!((quantise(Ppm::new(-20.0), 6.4).value() + 19.2).abs() < 1e-9);
        assert!((quantise(Ppm::new(-23.0), 6.4).value() + 25.6).abs() < 1e-9);
    }

    #[test]
    fn quantise_ties_round_away_from_zero() {
        assert!((quantise(Ppm::new(3.2), 6.4).value() - 6.4).abs() < 1e-9);
        assert!((quantise(Ppm::new(-3.2), 6.4).value() + 6.4).abs() < 1e-9);
    }

    #[test]
    fn quantise_granularity_larger_than_value_gives_zero() {
        assert!(quantise(Ppm::new(3.0), 6.4).value().abs() < 1e-12);
        assert!(quantise(Ppm::new(-3.0), 6.4).value().abs() < 1e-12);
    }

    #[test]
    fn quantise_never_returns_a_non_finite_value() {
        let q = quantise(Ppm::new(f64::MAX), 1e-300);
        assert!(q.value().is_finite());
    }

    /// 2026-01-01T00:00:00Z in Unix nanoseconds.
    const NOW_NS: i128 = 1_767_225_600 * 1_000_000_000;

    fn filetime_of(unix_ns: i128) -> u64 {
        u64::try_from(unix_ns / 100 + UNIX_EPOCH_AS_FILETIME).unwrap()
    }

    #[test]
    fn step_adds_the_offset() {
        let ft = step_target_filetime(NOW_NS, Offset::from_secs(1.0)).unwrap();
        assert_eq!(ft, filetime_of(NOW_NS + 1_000_000_000));
        let ft = step_target_filetime(NOW_NS, Offset::from_secs(-1.0)).unwrap();
        assert_eq!(ft, filetime_of(NOW_NS - 1_000_000_000));
    }

    #[test]
    fn step_rounds_to_the_nearest_millisecond() {
        let ft = step_target_filetime(NOW_NS, Offset::from_secs(0.200_499)).unwrap();
        assert_eq!(ft, filetime_of(NOW_NS + 200_000_000));
        let ft = step_target_filetime(NOW_NS, Offset::from_secs(0.200_5)).unwrap();
        assert_eq!(ft, filetime_of(NOW_NS + 201_000_000));
        let ft = step_target_filetime(NOW_NS + 999_999, Offset::from_secs(0.0)).unwrap();
        assert_eq!(ft, filetime_of(NOW_NS + 1_000_000));
    }

    #[test]
    fn step_refuses_a_target_before_1970() {
        let r = step_target_filetime(NOW_NS, Offset::from_secs(-2_000_000_000.0));
        assert!(matches!(r, Err(ClockError::Rejected(_))));
    }

    #[test]
    fn step_refuses_a_target_from_2106() {
        let r = step_target_filetime(NOW_NS, Offset::from_secs(3_000_000_000.0));
        assert!(matches!(r, Err(ClockError::Rejected(_))));
        let last_ok = STEP_LIMIT_NS - NANOS_PER_MILLI;
        assert!(step_target_filetime(last_ok, Offset::from_secs(0.0)).is_ok());
        assert!(step_target_filetime(STEP_LIMIT_NS, Offset::from_secs(0.0)).is_err());
    }

    #[test]
    fn step_refuses_huge_and_non_finite_offsets_without_panic() {
        for s in [1e30, -1e30, f64::MAX, f64::MIN] {
            let r = step_target_filetime(NOW_NS, Offset::from_secs(s));
            assert!(matches!(r, Err(ClockError::Rejected(_))));
        }
        if !cfg!(debug_assertions) {
            for s in [f64::NAN, f64::INFINITY] {
                assert!(step_target_filetime(NOW_NS, Offset::from_secs(s)).is_err());
            }
        }
    }

    #[test]
    fn step_error_text_has_no_path() {
        let e = step_target_filetime(NOW_NS, Offset::from_secs(1e30)).unwrap_err();
        let s = e.to_string();
        assert!(!s.contains('\\') && !s.contains('/'), "{s}");
    }

    #[test]
    fn adjustment_state_reports_ppm_and_granularity() {
        let s = AdjustmentState {
            adjustment: 9_999_919,
            increment: 10_000_000,
            disabled: false,
        };
        assert!((s.ppm().unwrap() + 8.1).abs() < 1e-9);
        assert!((s.granularity_ppm().unwrap() - 0.1).abs() < 1e-12);
        assert!(!s.is_nominal());
        let off = AdjustmentState {
            disabled: true,
            ..s
        };
        assert_eq!(off.ppm(), Some(0.0));
        assert!(off.is_nominal());
        let zero = AdjustmentState {
            adjustment: 0,
            increment: 0,
            disabled: false,
        };
        assert_eq!(zero.ppm(), None);
        assert_eq!(zero.granularity_ppm(), None);
    }

    #[test]
    fn mapping_round_trips_through_the_reported_ppm() {
        for ppm in [-500.0, -8.1, 0.0, 0.1, 37.3, 500.0] {
            let adjustment = ppm_to_adjustment(Ppm::new(ppm), NOMINAL);
            let s = AdjustmentState {
                adjustment,
                increment: NOMINAL,
                disabled: false,
            };
            assert!((s.ppm().unwrap() - ppm).abs() < 0.05 + 1e-9, "{ppm}");
        }
    }
}

/// Read-only checks against the real OS. Nothing here changes the clock,
/// its rate or the token. The tests that do live in
/// `tests/clock_windows.rs` and are ignored.
#[cfg(all(test, windows))]
mod os_tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn precise_adjustment_reads_a_sane_state() {
        let s = read_adjustment().unwrap();
        eprintln!(
            "precise: adjustment {} increment {} disabled {} ppm {:?} granularity {:?}",
            s.adjustment,
            s.increment,
            s.disabled,
            s.ppm(),
            s.granularity_ppm()
        );
        assert!(s.increment > 0, "zero increment");
        // Another time service (w32time) may hold a non-nominal rate, so
        // "nominal or disabled" cannot be asserted on a live machine. A rate
        // beyond 1 % would be broken whoever set it.
        if !s.disabled {
            let ppm = s.ppm().unwrap();
            assert!(ppm.abs() < 10_000.0, "rate {ppm} ppm");
        }
    }

    #[test]
    fn legacy_adjustment_reads_for_comparison() {
        let l = win32::time_adjustment_legacy().unwrap();
        eprintln!(
            "legacy: adjustment {} increment {} disabled {}",
            l.adjustment, l.increment, l.disabled
        );
        assert!(l.increment > 0);
    }

    #[test]
    fn mono_never_goes_backwards() {
        let mut last = mono_now();
        for _ in 0..100_000 {
            let now = mono_now();
            assert!(now >= last, "mono went back");
            last = now;
        }
    }

    #[test]
    fn mono_advances_with_real_time() {
        let a = mono_now();
        std::thread::sleep(std::time::Duration::from_millis(50));
        let b = mono_now();
        let d = b.as_nanos() - a.as_nanos();
        assert!((40_000_000..5_000_000_000).contains(&d), "advanced {d} ns");
    }

    #[test]
    fn wall_is_close_to_std_system_time() {
        let std_ns = i128::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        )
        .unwrap();
        let ours = wall_now_ns();
        assert!((ours - std_ns).abs() < 2_000_000_000, "{ours} vs {std_ns}");
    }

    #[test]
    fn privilege_without_the_right_fails_cleanly() {
        // Only run where the token does not hold the privilege. Then the
        // enable call changes nothing. Where it is held, enabling it would
        // be a change to this process, so the test skips.
        if win32::token_has_systemtime_privilege().unwrap() {
            eprintln!("skip: token holds SeSystemtimePrivilege");
            return;
        }
        let e = win32::enable_systemtime_privilege().unwrap_err();
        assert_eq!(e.raw_os_error(), Some(1300), "{e}");
        assert_eq!(
            WindowsClock::new().unwrap_err(),
            ClockError::PermissionDenied
        );
    }

    #[test]
    fn clock_error_maps_privilege_codes_and_names_no_path() {
        let e = std::io::Error::from_raw_os_error(1314);
        assert_eq!(clock_error("set", &e), ClockError::PermissionDenied);
        let e = std::io::Error::from_raw_os_error(87);
        let s = clock_error("set clock rate", &e).to_string();
        assert!(s.contains("set clock rate") && !s.contains('\\'), "{s}");
    }

    #[test]
    fn elevation_reads() {
        eprintln!("elevated: {}", win32::token_is_elevated().unwrap());
    }
}
