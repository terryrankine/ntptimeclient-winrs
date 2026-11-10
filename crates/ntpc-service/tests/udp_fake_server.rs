//! `UdpTransport` against a fake NTP server on loopback.
//!
//! The server and the transport bind loopback only, on ports the OS picks.
//! No packet leaves the machine and the real clock is only read, never set.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ntpc_core::{KodCode, QueryFailure, SourceId};
use ntpc_service::logging::{LineLogger, MemorySink};
use ntpc_service::proto::NtpTime;
use ntpc_service::proto::codec::{self, Header, MODE_SERVER};
use ntpc_service::transport::{NoTuning, StdTimeSource, Transport, UdpTransport};

/// What the server does for one request.
#[derive(Debug, Clone)]
enum Act {
    /// A good reply with the server clock this far ahead, seconds.
    Good(f64),
    /// A kiss-of-death with this code.
    Kod([u8; 4]),
    /// Wait, then a good reply.
    Late(Duration),
    /// A 20 byte datagram, then a good reply.
    Truncated,
    /// A good reply from another port, then a good one from the right port.
    WrongPort,
    /// A reply with the wrong origin, then the real one.
    Spoof,
    /// The previous good reply again, then a new good one.
    Replay,
    /// This many garbage datagrams, then a good reply.
    Garbage(u32),
    /// Garbage without pause for this long, and no reply.
    Flood(Duration),
    /// No reply.
    Silent,
}

fn wall_ns() -> i128 {
    i128::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("after 1970")
            .as_nanos(),
    )
    .expect("fits")
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "offsets in this test are at most 1000 s"
)]
fn reply(request: &[u8], ahead: f64) -> [u8; 48] {
    let req = codec::decode(request).expect("a 48 byte request");
    let t = NtpTime::from_unix_nanos(wall_ns() + (ahead * 1e9) as i128).to_bits();
    codec::encode(&Header {
        leap: 0,
        version: 4,
        mode: MODE_SERVER,
        stratum: 2,
        poll: 6,
        precision: -20,
        root_delay: 0,
        root_dispersion: 0,
        reference_id: *b"TEST",
        reference_time: t,
        origin_time: req.transmit_time,
        receive_time: t,
        transmit_time: t,
    })
}

fn kod(request: &[u8], code: [u8; 4]) -> [u8; 48] {
    let req = codec::decode(request).expect("a 48 byte request");
    codec::encode(&Header {
        leap: 3,
        version: 4,
        mode: MODE_SERVER,
        stratum: 0,
        poll: 6,
        precision: -20,
        root_delay: 0,
        root_dispersion: 0,
        reference_id: code,
        reference_time: 0,
        origin_time: req.transmit_time,
        receive_time: 0,
        transmit_time: 0,
    })
}

/// Serves one request per act, in order, then ends.
fn serve(local: IpAddr, acts: Vec<Act>) -> (SocketAddr, JoinHandle<()>) {
    let sock = UdpSocket::bind(SocketAddr::new(local, 0)).expect("bind loopback");
    let other = UdpSocket::bind(SocketAddr::new(local, 0)).expect("bind second port");
    let addr = sock.local_addr().expect("addr");
    let h = std::thread::spawn(move || {
        sock.set_read_timeout(Some(Duration::from_secs(10)))
            .expect("timeout");
        let mut buf = [0u8; 512];
        let mut last: Option<[u8; 48]> = None;
        for act in acts {
            // Windows reports an ICMP error from an earlier send (to a
            // query socket that has closed) on the next receive. Skip it.
            let (n, from) = loop {
                match sock.recv_from(&mut buf) {
                    Ok(got) => break got,
                    Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
                    Err(_) => return,
                }
            };
            let req = buf[..n].to_vec();
            let good = |ahead| reply(&req, ahead);
            match act {
                Act::Good(ahead) => {
                    let r = good(ahead);
                    sock.send_to(&r, from).expect("send");
                    // A duplicate right after. The query has returned and
                    // closed its socket, so it must count for nothing.
                    let _ = sock.send_to(&r, from);
                    last = Some(r);
                }
                Act::Kod(code) => {
                    sock.send_to(&kod(&req, code), from).expect("send");
                }
                Act::Late(d) => {
                    std::thread::sleep(d);
                    let _ = sock.send_to(&good(0.0), from);
                }
                Act::Truncated => {
                    sock.send_to(&good(0.0)[..20], from).expect("send");
                    sock.send_to(&good(0.0), from).expect("send");
                }
                Act::WrongPort => {
                    other.send_to(&good(0.0), from).expect("send");
                    std::thread::sleep(Duration::from_millis(20));
                    sock.send_to(&good(0.0), from).expect("send");
                }
                Act::Spoof => {
                    let mut r = good(0.0);
                    r[31] ^= 0x01;
                    sock.send_to(&r, from).expect("send");
                    sock.send_to(&good(0.0), from).expect("send");
                }
                Act::Replay => {
                    let old = last.expect("a reply to replay");
                    sock.send_to(&old, from).expect("send");
                    sock.send_to(&good(0.0), from).expect("send");
                }
                Act::Garbage(k) => {
                    for i in 0..k {
                        let junk = [u8::try_from(i % 251).expect("byte"); 48];
                        sock.send_to(&junk, from).expect("send");
                    }
                    std::thread::sleep(Duration::from_millis(20));
                    let _ = sock.send_to(&good(0.0), from);
                }
                Act::Flood(d) => {
                    let end = Instant::now() + d;
                    let mut i = 0u8;
                    while Instant::now() < end {
                        let _ = sock.send_to(&[i; 48], from);
                        i = i.wrapping_add(1);
                    }
                }
                Act::Silent => {}
            }
        }
    });
    (addr, h)
}

fn transport() -> (UdpTransport, MemorySink) {
    let sink = MemorySink::new();
    let time = Arc::new(StdTimeSource::new());
    let logger = Arc::new(LineLogger::new(Box::new(sink.clone()), time.clone()));
    let t = UdpTransport::new(time, Arc::new(NoTuning), logger)
        .bind_to(Ipv4Addr::LOCALHOST, Ipv6Addr::LOCALHOST);
    (t, sink)
}

#[test]
fn udp_transport_handles_fake_server_faults() {
    let acts = vec![
        Act::Good(0.0),
        Act::Good(1000.0),
        Act::Kod(*b"DENY"),
        Act::Kod(*b"RATE"),
        Act::Late(Duration::from_millis(900)),
        Act::Truncated,
        Act::WrongPort,
        Act::Spoof,
        Act::Good(0.0),
        Act::Replay,
        Act::Garbage(1000),
        Act::Flood(Duration::from_millis(600)),
        Act::Silent,
    ];
    let (server, handle) = serve(IpAddr::V4(Ipv4Addr::LOCALHOST), acts);
    let (t, sink) = transport();
    let id = SourceId::new(7);
    let q = |timeout_ms| t.query(id, server, Duration::from_millis(timeout_ms));

    // A plain good reply. Same clock on both ends, so near zero.
    let s = q(1000).expect("good reply");
    assert_eq!(s.source, id);
    assert!(s.offset.as_secs().abs() < 0.05, "{:?}", s.offset);
    assert!(s.delay.as_secs() >= 0.0 && s.delay.as_secs() < 0.05);

    // Wrong time: returned as measured. The engine decides.
    let s = q(1000).expect("plausible reply with a big offset");
    assert!((s.offset.as_secs() - 1000.0).abs() < 0.05, "{:?}", s.offset);

    assert_eq!(q(1000), Err(QueryFailure::KissOfDeath(KodCode::Deny)));
    assert_eq!(q(1000), Err(QueryFailure::KissOfDeath(KodCode::Rate)));

    // Longer than the timeout.
    let started = Instant::now();
    assert_eq!(q(300), Err(QueryFailure::Timeout));
    assert!(started.elapsed() < Duration::from_millis(800));
    // Let the late reply land on the closed socket before the next query.
    std::thread::sleep(Duration::from_millis(700));

    // R55: a bad datagram is discarded and the real reply still counts.
    let before = t.stats().discarded;
    q(1000).expect("truncated then good");
    q(1000).expect("wrong port then good");
    q(1000).expect("spoofed origin then good");
    assert_eq!(t.stats().discarded - before, 3);

    // A replayed earlier reply has the old origin and is not taken again.
    q(1000).expect("good");
    let before = t.stats().discarded;
    q(1000).expect("replay then good");
    assert_eq!(t.stats().discarded - before, 1);

    // R97: no count of bad datagrams ends a query.
    let before = t.stats().discarded;
    q(3000).expect("1000 garbage then good");
    assert!(
        t.stats().discarded - before >= 900,
        "most of the garbage arrived"
    );
    // A flood for the whole timeout ends at the deadline, not before and
    // not much after. Each loop turn waits in the socket for a datagram.
    let started = Instant::now();
    assert_eq!(q(300), Err(QueryFailure::Timeout));
    let took = started.elapsed();
    assert!(
        took >= Duration::from_millis(300) && took < Duration::from_millis(800),
        "{took:?}"
    );
    // Let the rest of the flood land on the closed socket.
    std::thread::sleep(Duration::from_millis(400));

    assert_eq!(q(200), Err(QueryFailure::Timeout));
    handle.join().expect("server thread");
    assert_eq!(t.stats().nonce_failures, 0);
    assert!(sink.lines().is_empty(), "{:?}", sink.lines());
}

#[test]
fn udp_transport_works_on_ipv6_loopback() {
    if UdpSocket::bind("[::1]:0").is_err() {
        eprintln!("skipped: no IPv6 loopback on this machine");
        return;
    }
    let (server, handle) = serve(
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        vec![Act::Good(0.0), Act::Spoof],
    );
    let (t, _) = transport();
    let s = t
        .query(SourceId::new(1), server, Duration::from_secs(1))
        .expect("good over IPv6");
    assert!(s.offset.as_secs().abs() < 0.05);
    t.query(SourceId::new(1), server, Duration::from_secs(1))
        .expect("spoof then good over IPv6");
    handle.join().expect("server thread");
}

#[test]
fn udp_transport_unreachable_never_panics() {
    let (t, _) = transport();
    // A loopback port nobody listens on. Windows may report an ICMP reset,
    // which is ignored like a bad datagram, so this ends in time.
    let free = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let addr = free.local_addr().expect("addr");
    drop(free);
    let started = Instant::now();
    let r = t.query(SourceId::new(2), addr, Duration::from_millis(300));
    assert!(
        matches!(r, Err(QueryFailure::Timeout | QueryFailure::Unreachable)),
        "{r:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(2));
}
