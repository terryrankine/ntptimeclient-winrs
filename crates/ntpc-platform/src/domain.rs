//! Classic domain join detection.
//!
//! Only the join class leaves this module. The domain or workgroup name that
//! `NetGetJoinInformation` returns is freed unread, so it can never reach a
//! log. Entra ID and hybrid join are out of scope for version one. See
//! `docs/architecture.md`, "Platform: `w32time` takeover and domain join".

/// How the machine is joined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinState {
    /// Not joined to a domain: a workgroup or not joined at all.
    Workgroup,
    /// Joined to a classic Active Directory domain.
    Domain,
    /// The OS could not say. Callers treat it like `Domain`, the safe
    /// direction for the silent install rule.
    Unknown,
}

impl JoinState {
    /// Short text for the log. Holds no name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Workgroup => "workgroup",
            Self::Domain => "domain",
            Self::Unknown => "unknown",
        }
    }

    /// Whether the install rule must treat the machine as domain-joined.
    /// `Unknown` counts, because aborting a silent install is the safe side.
    #[must_use]
    pub const fn counts_as_domain(self) -> bool {
        !matches!(self, Self::Workgroup)
    }
}

/// Maps a raw `NETSETUP_JOIN_STATUS` value. Values from Learn:
/// `NetSetupUnknownStatus = 0`, `NetSetupUnjoined = 1`,
/// `NetSetupWorkgroupName = 2`, `NetSetupDomainName = 3`.
#[must_use]
pub const fn map_join_status(raw: i32) -> JoinState {
    match raw {
        1 | 2 => JoinState::Workgroup,
        3 => JoinState::Domain,
        _ => JoinState::Unknown,
    }
}

/// The local machine's join state. `Unknown` on any error. Read only.
#[cfg(windows)]
#[must_use]
pub fn join_state() -> JoinState {
    match crate::win32::scm::join_status() {
        Ok(raw) => map_join_status(raw),
        Err(_) => JoinState::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_every_documented_value() {
        assert_eq!(map_join_status(0), JoinState::Unknown);
        assert_eq!(map_join_status(1), JoinState::Workgroup);
        assert_eq!(map_join_status(2), JoinState::Workgroup);
        assert_eq!(map_join_status(3), JoinState::Domain);
    }

    #[test]
    fn maps_undocumented_values_to_unknown() {
        for raw in [-1, 4, 5, 100, i32::MIN, i32::MAX] {
            assert_eq!(map_join_status(raw), JoinState::Unknown, "{raw}");
        }
    }

    #[test]
    fn unknown_counts_as_domain() {
        assert!(JoinState::Domain.counts_as_domain());
        assert!(JoinState::Unknown.counts_as_domain());
        assert!(!JoinState::Workgroup.counts_as_domain());
    }

    /// Read only. Prints nothing, so no domain or workgroup name can leak
    /// into the test log.
    #[cfg(windows)]
    #[test]
    fn live_join_state_is_one_of_three() {
        let s = join_state();
        assert!(matches!(
            s,
            JoinState::Workgroup | JoinState::Domain | JoinState::Unknown
        ));
    }
}
