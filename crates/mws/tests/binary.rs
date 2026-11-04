//! The `mws` binary starts, listens on `MWS_LISTEN` and answers its health
//! check. Having an integration test here also makes `cargo test` build
//! `target/debug/mws`, which the boto3 tests run.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn binary_serves_health_check() {
    let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let mut child = Command::new(env!("CARGO_BIN_EXE_mws"))
        .env("MWS_LISTEN", format!("127.0.0.1:{port}"))
        .env("RUST_LOG", "warn")
        .stdout(Stdio::null())
        .spawn()
        .expect("start mws");

    let deadline = Instant::now() + Duration::from_secs(30);
    let response = loop {
        if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) {
            stream.write_all(b"GET /_mws/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).unwrap();
            break response;
        }
        assert!(Instant::now() < deadline, "mws did not start listening");
        std::thread::sleep(Duration::from_millis(50));
    };
    child.kill().unwrap();
    child.wait().unwrap();

    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
}
