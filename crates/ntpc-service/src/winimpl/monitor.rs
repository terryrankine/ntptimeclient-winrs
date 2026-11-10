//! The `w32time` monitor and the domain join state.

use ntpc_platform::w32time::{ServiceControl, is_running};
use ntpc_platform::{JoinState, ScmControl};

use crate::host::{JoinClass, JoinStateProvider, ServiceMonitor};

/// Whether `w32time` runs, through the service control manager.
///
/// Read only: [`ScmControl`] opens `w32time` with query rights only.
/// True for every state but stopped, and true when the state cannot be
/// read, including a missing service (R85). When we cannot tell, the
/// engine must not adjust.
#[derive(Debug, Default)]
pub struct W32TimeMonitor<C: ServiceControl = ScmControl> {
    ctl: C,
}

impl W32TimeMonitor {
    /// The real monitor.
    #[must_use]
    pub fn new() -> Self {
        Self { ctl: ScmControl }
    }
}

impl<C: ServiceControl> W32TimeMonitor<C> {
    /// A monitor over another service control. For tests.
    pub fn with(ctl: C) -> Self {
        Self { ctl }
    }

    /// The service control.
    pub fn control(&self) -> &C {
        &self.ctl
    }
}

impl<C: ServiceControl> ServiceMonitor for W32TimeMonitor<C> {
    fn is_running(&self) -> bool {
        is_running(&self.ctl)
    }
}

/// The host's join class of a platform join state.
#[must_use]
pub fn join_class(s: JoinState) -> JoinClass {
    match s {
        JoinState::Workgroup => JoinClass::Workgroup,
        JoinState::Domain => JoinClass::Domain,
        JoinState::Unknown => JoinClass::Unknown,
    }
}

/// The join state from `NetGetJoinInformation`. Read only. The domain or
/// workgroup name is freed unread by the platform crate.
#[derive(Debug, Clone, Copy, Default)]
pub struct WinJoinState;

impl JoinStateProvider for WinJoinState {
    fn join_state(&self) -> JoinClass {
        join_class(ntpc_platform::join_state())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ntpc_platform::w32time::fake::{Call, FakeScm, Script};
    use ntpc_platform::w32time::{RunState, StartType, SvcError};

    fn monitor(script: Script) -> W32TimeMonitor<FakeScm> {
        W32TimeMonitor::with(FakeScm::new(script))
    }

    #[test]
    fn only_stopped_counts_as_not_running() {
        let stopped = monitor(Script::with(RunState::Stopped, StartType::Disabled));
        assert!(!stopped.is_running());
        for run in [
            RunState::Running,
            RunState::StartPending,
            RunState::StopPending,
            RunState::Paused,
        ] {
            assert!(
                monitor(Script::with(run, StartType::Manual)).is_running(),
                "{run:?}"
            );
        }
    }

    #[test]
    fn errors_and_a_missing_service_count_as_running() {
        assert!(monitor(Script::missing()).is_running());
        let mut s = Script::with(RunState::Stopped, StartType::Manual);
        s.query_error = Some(SvcError::AccessDenied);
        assert!(monitor(s).is_running());
        let mut s = Script::with(RunState::Stopped, StartType::Manual);
        s.query_error = Some(SvcError::Os {
            op: "open",
            code: 1,
        });
        assert!(monitor(s).is_running());
    }

    #[test]
    fn it_only_queries_w32time() {
        let m = monitor(Script::with(RunState::Stopped, StartType::Manual));
        let _ = m.is_running();
        let _ = m.is_running();
        assert!(!m.control().mutated());
        assert_eq!(
            m.control().calls(),
            vec![Call::Query("w32time".into()), Call::Query("w32time".into())]
        );
    }

    #[test]
    fn join_states_map_one_to_one() {
        assert_eq!(join_class(JoinState::Workgroup), JoinClass::Workgroup);
        assert_eq!(join_class(JoinState::Domain), JoinClass::Domain);
        assert_eq!(join_class(JoinState::Unknown), JoinClass::Unknown);
    }

    /// Read only: `QueryServiceStatusEx` and `QueryServiceConfigW` with
    /// query rights. Prints nothing.
    #[test]
    fn live_monitor_returns_a_bool() {
        let _running: bool = W32TimeMonitor::new().is_running();
    }

    /// Read only: `NetGetJoinInformation`. Prints nothing.
    #[test]
    fn live_join_state_is_one_of_three() {
        assert!(matches!(
            WinJoinState.join_state(),
            JoinClass::Workgroup | JoinClass::Domain | JoinClass::Unknown
        ));
    }
}
