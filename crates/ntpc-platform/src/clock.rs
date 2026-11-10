//! The Windows clock adapter and the pure rate arithmetic behind it.
//!
//! The arithmetic builds on every host. The adapter itself is Windows only.
//! Facts and sources: `docs/architecture.md`, "Platform".

use ntpc_core::Ppm;

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
}
