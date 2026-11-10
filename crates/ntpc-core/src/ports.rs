//! Ports. Adapters implement them. The host and the simulation use them.
//! The engine itself does not call them.

use crate::error::{ClockError, StoreError};
use crate::types::{Mono, Offset, Ppm};

/// The local clock.
pub trait Clock {
    /// Monotonic time. It counts awake time only.
    fn mono(&self) -> Mono;

    /// Wall time in nanoseconds since the Unix epoch (UTC).
    fn wall_ns(&self) -> i128;

    /// Moves the wall clock by `by`.
    ///
    /// # Errors
    /// Returns [`ClockError`] if the clock cannot be changed.
    fn step(&mut self, by: Offset) -> Result<(), ClockError>;

    /// Sets the clock frequency. The value is absolute from nominal, not
    /// relative to the previous setting.
    ///
    /// # Errors
    /// Returns [`ClockError`] if the frequency cannot be set.
    fn set_frequency(&mut self, ppm: Ppm) -> Result<(), ClockError>;

    /// Returns the clock to its nominal frequency.
    ///
    /// # Errors
    /// Returns [`ClockError`] if the frequency cannot be reset.
    fn reset_frequency(&mut self) -> Result<(), ClockError>;
}

/// Persistent storage for the learned frequency.
pub trait DriftStore {
    /// The saved value, or `None` if there is none or it is unreadable.
    fn load(&self) -> Option<Ppm>;

    /// Saves the value.
    ///
    /// # Errors
    /// Returns [`StoreError`] if the value cannot be written.
    fn save(&self, ppm: Ppm) -> Result<(), StoreError>;
}
