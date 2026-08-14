//! C6 — Boundary hardening for the hand-rolled HTTP server in src/server.rs.
//!
//! Before C6 the accept loop had no per-connection socket read/write
//! timeout, the header-parsing loop had no cap on line length or header
//! count, and every accepted connection spawned a handler thread
//! unconditionally. A slow/silent client could hold a handler thread
//! forever, an unterminated or oversized header line could grow server
//! memory without bound, and there was no limit on simultaneous
//! connections. These are black-box tests over real loopback TCP sockets
//! against `serve()` (the same accept loop `main()` runs) — the only
//! faithful way to prove socket-level behavior.

#[path = "../src/server.rs"]
#[allow(dead_code)]
mod server;

use governance_spine::GovernancePipeline;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

const SERVICE_TOKEN: &str = "boundary-hardening-test-service-token-9f86d081884c7d659a2fe";

fn start_server(max_connections: usize, socket_timeout: Duration) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local_addr");
    let pipeline = Arc::new(GovernancePipeline::default_pipeline().expect("pipeline init"));
    let token = Arc::new(SERVICE_TOKEN.to_string());
    std::thread::spawn(move || {
        server::serve(listener, pipeline, token, max_connections, socket_timeout);
    });
    // Give the accept loop a moment to actually start listening/accepting.
    std::thread::sleep(Duration::from_millis(50));
    addr
}

fn read_all_available(stream: &mut TcpStream, timeout: Duration) -> String {
    stream.set_read_timeout(Some(timeout)).unwrap();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => break, // timeout or reset — return what we have
        }
    }
    String::from_utf8_lossy(&buf).to_string()
}

#[test]
fn normal_health_request_succeeds() {
    let addr = start_server(64, Duration::from_secs(10));
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream.write_all(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    let resp = read_all_available(&mut stream, Duration::from_secs(5));
    assert!(resp.starts_with("HTTP/1.1 200"), "expected 200, got: {resp}");
    assert!(resp.contains("\"ok\":true"), "expected ok:true body, got: {resp}");
}

#[test]
fn oversized_header_line_rejected_431() {
    let addr = start_server(64, Duration::from_secs(10));
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream.write_all(b"GET /health HTTP/1.1\r\n").unwrap();
    // One header line far exceeding MAX_HEADER_LINE_BYTES (8192).
    let huge_value = "A".repeat(20_000);
    stream.write_all(format!("X-Huge: {huge_value}\r\n").as_bytes()).unwrap();
    stream.write_all(b"\r\n").unwrap();
    let resp = read_all_available(&mut stream, Duration::from_secs(5));
    assert!(resp.starts_with("HTTP/1.1 431"), "expected 431, got: {resp}");
}

#[test]
fn too_many_headers_rejected_431() {
    let addr = start_server(64, Duration::from_secs(10));
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream.write_all(b"GET /health HTTP/1.1\r\n").unwrap();
    // MAX_HEADER_COUNT is 100 — send 101 short, well-formed header lines.
    for i in 0..101 {
        stream.write_all(format!("X-Filler-{i}: v\r\n").as_bytes()).unwrap();
    }
    stream.write_all(b"\r\n").unwrap();
    let resp = read_all_available(&mut stream, Duration::from_secs(5));
    assert!(resp.starts_with("HTTP/1.1 431"), "expected 431, got: {resp}");
}

#[test]
fn silent_client_is_dropped_by_socket_timeout_not_held_forever() {
    // A short server-side timeout; the client sends nothing at all.
    let addr = start_server(64, Duration::from_millis(300));
    let mut stream = TcpStream::connect(addr).expect("connect");
    let start = Instant::now();
    // Bound our own read so a regression (server hangs forever) fails this
    // test with a clear timeout instead of hanging the test suite.
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut buf = [0u8; 16];
    let result = stream.read(&mut buf);
    let elapsed = start.elapsed();
    // Either the server closed the connection (Ok(0) = EOF) or the OS
    // surfaced the reset/timeout as an error — both prove the server did
    // not hold the connection open indefinitely.
    // Err(_) case (connection reset/aborted by server-side timeout) is also
    // acceptable and intentionally not asserted on here.
    if let Ok(n) = result {
        assert_eq!(n, 0, "expected EOF (server closed idle connection), got {n} bytes");
    }
    assert!(
        elapsed < Duration::from_secs(4),
        "server did not enforce its socket timeout — client waited {elapsed:?}"
    );
}

#[test]
fn connection_over_capacity_rejected_503() {
    let addr = start_server(1, Duration::from_secs(10));

    // Connection A: open and hold (send request line only, no terminating
    // blank line yet) so the server's handler thread stays blocked reading
    // headers, keeping the connection counted as in-flight.
    let mut a = TcpStream::connect(addr).expect("connect A");
    a.write_all(b"GET /health HTTP/1.1\r\n").unwrap();

    // Let the single-threaded accept loop actually accept + count A before B connects.
    std::thread::sleep(Duration::from_millis(150));

    // Connection B: max_connections=1 is already occupied by A.
    let mut b = TcpStream::connect(addr).expect("connect B");
    let resp = read_all_available(&mut b, Duration::from_secs(5));
    assert!(resp.starts_with("HTTP/1.1 503"), "expected 503, got: {resp}");

    // Let A finish so the server thread doesn't outlive the test noisily.
    let _ = a.write_all(b"\r\n");
}
