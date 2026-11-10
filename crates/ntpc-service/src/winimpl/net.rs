//! Own addresses, DHCP option 42 per adapter and the query thread priority.

use std::collections::{BTreeSet, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};

use ntpc_platform::dhcp::{
    self, AdapterLease, DhcpError, LeaseOptions, merged_servers, read_lease_servers_per_adapter,
};
use ntpc_platform::net::{NetError, own_addresses};
use ntpc_platform::thread::{Priority, set_current_thread_priority};

use crate::host::{AdapterKey, DhcpRead, DhcpReadError, DhcpSource};
use crate::logging::{Level, Logger};
use crate::resolver::OwnAddresses;
use crate::transport::ThreadTuning;

/// Raises each query worker to above normal priority before it builds the
/// request (spec: a timing path that survives CPU load). The worker thread
/// ends after its one query, so the level is kept for its life. Only the
/// calling thread is touched.
pub struct WinThreadTuning {
    logger: Arc<dyn Logger>,
}

impl WinThreadTuning {
    /// Logs a failure to raise the priority through `logger`.
    #[must_use]
    pub fn new(logger: Arc<dyn Logger>) -> Self {
        Self { logger }
    }
}

impl ThreadTuning for WinThreadTuning {
    fn raise_priority(&self) {
        match set_current_thread_priority(Priority::AboveNormal) {
            Ok(guard) => guard.keep(),
            Err(e) => self.logger.log(
                Level::Warn,
                "thread_priority",
                &format!("could not raise a query thread's priority: {e}"),
            ),
        }
    }
}

type ReadOwn = fn() -> Result<Vec<IpAddr>, NetError>;

/// This machine's unicast addresses for the resolver. Read fresh on every
/// call. A failed read keeps the last good list and is logged without any
/// address.
pub struct WinOwnAddresses {
    logger: Arc<dyn Logger>,
    read: ReadOwn,
    last: Mutex<Vec<IpAddr>>,
}

impl WinOwnAddresses {
    /// The real list, `ntpc_platform::net::own_addresses`.
    #[must_use]
    pub fn new(logger: Arc<dyn Logger>) -> Self {
        Self::with_reader(logger, own_addresses)
    }

    /// Over another reader. For tests.
    #[must_use]
    pub fn with_reader(logger: Arc<dyn Logger>, read: ReadOwn) -> Self {
        Self {
            logger,
            read,
            last: Mutex::new(Vec::new()),
        }
    }
}

impl OwnAddresses for WinOwnAddresses {
    fn own_addresses(&self) -> Vec<IpAddr> {
        let mut last = self.last.lock().unwrap_or_else(PoisonError::into_inner);
        match (self.read)() {
            Ok(fresh) => last.clone_from(&fresh),
            Err(e) => self.logger.log(
                Level::Warn,
                "own_addresses",
                &format!("{e}. The last list is used"),
            ),
        }
        last.clone()
    }
}

type ReadDhcp = fn(&HashSet<dhcp::AdapterKey>) -> Result<Vec<AdapterLease>, DhcpError>;

/// The host's DHCP read over the platform's per-adapter read (R82).
/// Blocking, may send a DHCPINFORM per adapter asked. The host runs it on
/// its reader thread only.
pub struct WinDhcpSource {
    read: ReadDhcp,
}

impl WinDhcpSource {
    /// The real reader.
    #[must_use]
    pub fn new() -> Self {
        Self::with_reader(read_lease_servers_per_adapter)
    }

    /// Over another reader. For tests.
    #[must_use]
    pub fn with_reader(read: ReadDhcp) -> Self {
        Self { read }
    }
}

impl Default for WinDhcpSource {
    fn default() -> Self {
        Self::new()
    }
}

/// Maps the per-adapter result to the host's read. `adapters` holds every
/// leased adapter, read or skipped. `without_option` holds those that were
/// read now and gave no option 42. A failed adapter is in neither list's
/// negative side, so the host asks it again next time.
#[must_use]
pub fn dhcp_read(leases: &[AdapterLease]) -> DhcpRead {
    DhcpRead {
        servers: merged_servers(leases),
        adapters: leases.iter().map(|l| AdapterKey(l.key.0.clone())).collect(),
        without_option: leases
            .iter()
            .filter(|l| l.options == LeaseOptions::NoOption42)
            .map(|l| AdapterKey(l.key.0.clone()))
            .collect(),
    }
}

impl DhcpSource for WinDhcpSource {
    fn read(&self, skip: &BTreeSet<AdapterKey>) -> Result<DhcpRead, DhcpReadError> {
        // Same key text on both sides: `<GUID>/<lease server>`.
        let skip: HashSet<dhcp::AdapterKey> =
            skip.iter().map(|k| dhcp::AdapterKey(k.0.clone())).collect();
        (self.read)(&skip)
            .map(|leases| dhcp_read(&leases))
            .map_err(|e| DhcpReadError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::{LineLogger, MemorySink};
    use crate::transport::StdTimeSource;
    use std::net::Ipv4Addr;

    const S1: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 67);
    const N1: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 1);
    const N2: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 2);

    fn memory_logger() -> (Arc<dyn Logger>, MemorySink) {
        let sink = MemorySink::new();
        let logger: Arc<dyn Logger> = Arc::new(LineLogger::new(
            Box::new(sink.clone()),
            Arc::new(StdTimeSource::new()),
        ));
        (logger, sink)
    }

    fn lease(guid: &str, options: LeaseOptions) -> AdapterLease {
        AdapterLease {
            key: dhcp::AdapterKey::new(guid, S1),
            options,
        }
    }

    #[test]
    fn dhcp_read_maps_every_outcome() {
        let got = dhcp_read(&[
            lease("{A}", LeaseOptions::Servers(vec![N1, N2])),
            lease("{B}", LeaseOptions::NoOption42),
            lease("{C}", LeaseOptions::Skipped),
            lease("{D}", LeaseOptions::Failed(1460)),
            lease("{E}", LeaseOptions::Servers(vec![N2])),
        ]);
        assert_eq!(got.servers, vec![N1, N2]);
        let k = |g: &str| AdapterKey(format!("{g}/192.0.2.67"));
        assert_eq!(
            got.adapters,
            vec![k("{A}"), k("{B}"), k("{C}"), k("{D}"), k("{E}")]
        );
        assert_eq!(
            got.without_option,
            vec![k("{B}")],
            "only a real 'no 42' is cached"
        );
    }

    #[test]
    fn the_host_skip_set_reaches_the_platform_read() {
        // The reader type returns a Result, so the fake does too.
        #[allow(clippy::unnecessary_wraps)]
        fn read(skip: &HashSet<dhcp::AdapterKey>) -> Result<Vec<AdapterLease>, DhcpError> {
            let mut keys: Vec<String> = skip.iter().map(|k| k.0.clone()).collect();
            keys.sort();
            assert_eq!(keys, vec!["{A}/192.0.2.67".to_owned()]);
            Ok(vec![AdapterLease {
                key: dhcp::AdapterKey::new("{A}", S1),
                options: LeaseOptions::Skipped,
            }])
        }
        let src = WinDhcpSource::with_reader(read);
        let skip = BTreeSet::from([AdapterKey("{A}/192.0.2.67".into())]);
        let got = src.read(&skip).expect("read");
        assert!(got.servers.is_empty() && got.without_option.is_empty());
        assert_eq!(got.adapters, vec![AdapterKey("{A}/192.0.2.67".into())]);
    }

    #[test]
    fn a_dhcp_error_keeps_its_text_and_no_address() {
        fn read(_: &HashSet<dhcp::AdapterKey>) -> Result<Vec<AdapterLease>, DhcpError> {
            Err(DhcpError::Request(1460))
        }
        let e = WinDhcpSource::with_reader(read)
            .read(&BTreeSet::new())
            .expect_err("error");
        assert!(e.0.contains("1460"), "{}", e.0);
        assert!(e.0.matches('.').count() < 3 && !e.0.contains('{'));
    }

    #[test]
    fn own_addresses_returns_the_fresh_list_and_keeps_it_on_failure() {
        use std::sync::atomic::{AtomicBool, Ordering};
        static FAIL: AtomicBool = AtomicBool::new(false);
        fn read() -> Result<Vec<IpAddr>, NetError> {
            if FAIL.load(Ordering::SeqCst) {
                Err(NetError::AdapterList(8))
            } else {
                Ok(vec![IpAddr::V4(N1)])
            }
        }
        let (logger, sink) = memory_logger();
        let own = WinOwnAddresses::with_reader(logger, read);
        assert_eq!(own.own_addresses(), vec![IpAddr::V4(N1)]);
        FAIL.store(true, Ordering::SeqCst);
        assert_eq!(own.own_addresses(), vec![IpAddr::V4(N1)], "last good list");
        let lines = sink.lines();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("os error 8"), "{}", lines[0]);
        assert!(!lines[0].contains("203.0.113"), "no address in the log");
    }

    #[test]
    fn own_addresses_with_no_good_read_yet_is_empty() {
        fn read() -> Result<Vec<IpAddr>, NetError> {
            Err(NetError::AdapterList(8))
        }
        let (logger, _sink) = memory_logger();
        assert_eq!(
            WinOwnAddresses::with_reader(logger, read).own_addresses(),
            Vec::<IpAddr>::new()
        );
    }

    /// Read only: one `GetAdaptersAddresses` call. Prints nothing.
    #[test]
    fn live_own_addresses_does_not_panic() {
        let (logger, sink) = memory_logger();
        let list = WinOwnAddresses::new(logger).own_addresses();
        assert!(list.len() <= ntpc_platform::net::MAX_OWN_ADDRESSES);
        // Any log line would be the error text, which holds no address.
        assert!(sink.lines().iter().all(|l| l.matches('.').count() < 6));
    }

    /// Touches only a fresh thread of this test.
    #[test]
    fn tuning_raises_the_calling_thread_to_above_normal() {
        let (logger, sink) = memory_logger();
        std::thread::spawn(move || {
            WinThreadTuning::new(logger).raise_priority();
            assert_eq!(
                ntpc_platform::thread::current_thread_priority().expect("read"),
                Priority::AboveNormal.to_raw()
            );
        })
        .join()
        .expect("tuning thread");
        assert!(sink.lines().is_empty(), "no failure logged");
    }
}
