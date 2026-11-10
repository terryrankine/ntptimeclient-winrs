//! THROWAWAY spike. Never sets the clock.
//! Modes: `probe live <host:port> <fixture>` | `probe file <fixture>` | `probe kalman`
use ntp_proto::{
    AlgorithmConfig, KalmanClockController, Measurement, NoCipher, NtpClock, NtpDuration,
    NtpInstant, NtpLeapIndicator, NtpPacket, NtpTimestamp, PollInterval, SourceConfig,
    SourceController, SynchronizationConfig, TimeSyncController,
};
use std::io::Cursor;
use std::net::UdpSocket;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const NTP_UNIX_OFFSET: u64 = 2_208_988_800;

fn now_ts() -> NtpTimestamp {
    let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    NtpTimestamp::from_seconds_nanos_since_ntp_era(
        ((d.as_secs() + NTP_UNIX_OFFSET) & 0xffff_ffff) as u32,
        d.subsec_nanos(),
    )
}

fn print_packet(p: &NtpPacket) {
    println!("version   {:?}", p.version());
    println!("leap      {:?} synchronized={}", p.leap(), p.leap().is_synchronized());
    println!("mode      {:?}", p.mode());
    println!("stratum   {}", p.stratum());
    println!("poll      {:?}", p.poll());
    println!("precision {}", p.precision());
    println!("root_delay {:.6}s", p.root_delay().to_seconds());
    println!("root_disp  {:.6}s", p.root_dispersion().to_seconds());
    println!("refid     {:?}", p.reference_id());
    println!("rx_ts     {:?}", p.receive_timestamp());
    println!("tx_ts     {:?}", p.transmit_timestamp());
    println!("is_kiss={} deny={} rstr={} ntsn={}", p.is_kiss(), p.is_kiss_deny(), p.is_kiss_rstr(), p.is_kiss_ntsn());
}

fn live(addr: &str, fixture: &str) {
    let (req, id) = NtpPacket::poll_message(PollInterval::from_byte(6));
    let mut buf = [0u8; 1024];
    let mut cur = Cursor::new(&mut buf[..]);
    req.serialize(&mut cur, &NoCipher, None).expect("serialize");
    let n = cur.position() as usize;
    println!("request {} bytes", n);
    let sock = UdpSocket::bind("0.0.0.0:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    sock.connect(addr).unwrap();
    let t1 = now_ts();
    sock.send(&buf[..n]).unwrap();
    let mut rbuf = [0u8; 1024];
    let m = sock.recv(&mut rbuf).expect("recv");
    let t4 = now_ts();
    println!("reply {} bytes from {}", m, addr);
    std::fs::write(fixture, &rbuf[..m]).unwrap();
    let (reply, _cookie) = NtpPacket::deserialize(&rbuf[..m], &NoCipher).expect("parse");
    println!("valid_server_response = {}", reply.valid_server_response(id, false));
    print_packet(&reply);
    let t2 = reply.receive_timestamp();
    let t3 = reply.transmit_timestamp();
    let offset: NtpDuration = ((t2 - t1) + (t3 - t4)) / 2;
    let delay: NtpDuration = (t4 - t1) - (t3 - t2);
    println!("offset {:+.6}s delay {:.6}s", offset.to_seconds(), delay.to_seconds());
}

fn file(path: &str) {
    let data = std::fs::read(path).unwrap();
    match NtpPacket::deserialize(&data, &NoCipher) {
        Ok((p, _)) => print_packet(&p),
        Err(e) => println!("parse error {:?}", e),
    }
    // negative test: truncated
    println!("truncated: {:?}", NtpPacket::deserialize(&data[..20], &NoCipher).map(|_| ()).map_err(|e| format!("{e:?}")));
}

#[derive(Clone)]
struct MockClock;
#[derive(Debug)]
struct MockErr;
impl std::fmt::Display for MockErr { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "mock") } }
impl std::error::Error for MockErr {}
impl NtpClock for MockClock {
    type Error = MockErr;
    fn now(&self) -> Result<NtpTimestamp, MockErr> { Ok(now_ts()) }
    fn set_frequency(&self, _f: f64) -> Result<NtpTimestamp, MockErr> { Ok(now_ts()) }
    fn get_frequency(&self) -> Result<f64, MockErr> { Ok(0.0) }
    fn step_clock(&self, o: NtpDuration) -> Result<NtpTimestamp, MockErr> { println!("  (mock) step {:+.6}s", o.to_seconds()); Ok(now_ts()) }
    fn disable_ntp_algorithm(&self) -> Result<(), MockErr> { Ok(()) }
    fn error_estimate_update(&self, _e: NtpDuration, _m: NtpDuration) -> Result<(), MockErr> { Ok(()) }
    fn status_update(&self, _l: NtpLeapIndicator) -> Result<(), MockErr> { Ok(()) }
}

fn kalman() {
    let mut c = KalmanClockController::<MockClock, u32>::new(
        MockClock, SynchronizationConfig::default(), AlgorithmConfig::default()).unwrap();
    let mut src = c.add_source(1, SourceConfig::default());
    c.source_update(1, true);
    let start = now_ts();
    for i in 0..8u32 {
        let m = Measurement {
            delay: NtpDuration::from_seconds(0.02),
            offset: NtpDuration::from_seconds(0.0123),
            localtime: start + NtpDuration::from_seconds(i as f64 * 16.0),
            monotime: NtpInstant::now(),
            stratum: 2,
            root_delay: NtpDuration::from_seconds(0.001),
            root_dispersion: NtpDuration::from_seconds(0.001),
            leap: NtpLeapIndicator::NoWarning,
            precision: -20,
        };
        if let Some(msg) = src.handle_measurement(m) {
            let upd = c.source_message(1, msg);
            println!("i={} snapshot={:?} used={:?}", i, upd.time_snapshot.is_some(), upd.used_sources);
        } else { println!("i={} no message", i); }
    }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("live") => live(&a[2], &a[3]),
        Some("file") => file(&a[2]),
        Some("kalman") => kalman(),
        _ => eprintln!("usage"),
    }
}
