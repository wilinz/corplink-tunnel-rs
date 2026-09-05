//! Manual test: bring up the tunnel from a WgConf JSON, connect to <ip> <port> through it,
//! run a TLS handshake with SNI <sni> and issue an HTTP/1.1 GET, print the response status line.
//!
//!   test-conn <wgconf.json> <ip> <port> <sni> [path]
use anyhow::Result;
use std::net::Ipv4Addr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().init();
    let mut args = std::env::args().skip(1);
    let conf_path = args.next().expect("wgconf.json");
    let ip: Ipv4Addr = args.next().expect("ip").parse()?;
    let port: u16 = args.next().expect("port").parse()?;
    let sni = args.next().expect("sni");
    let path = args.next().unwrap_or_else(|| "/".into());

    let conf: corplink_tunnel::WgConf = serde_json::from_slice(&std::fs::read(conf_path)?)?;
    let tun = corplink_tunnel::Tunnel::start(conf).await?;
    eprintln!("tunnel up; connecting {ip}:{port} ...");

    let stream = tun.connect(ip, port).await?;
    eprintln!("tcp connected through tunnel; TLS handshake ...");

    let cx = tokio_native_tls::TlsConnector::from(native_tls::TlsConnector::builder().build()?);
    let mut tls = cx.connect(&sni, stream).await?;
    eprintln!("TLS ok; sending request ...");

    let req = format!("GET {path} HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\n\r\n");
    tls.write_all(req.as_bytes()).await?;
    let mut buf = vec![0u8; 4096];
    let n = tls.read(&mut buf).await?;
    let head = String::from_utf8_lossy(&buf[..n]);
    println!("response: {}", head.lines().next().unwrap_or(""));
    Ok(())
}
