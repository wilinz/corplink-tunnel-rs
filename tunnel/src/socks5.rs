//! Minimal SOCKS5 server (no auth) that bridges CONNECT requests to the WireGuard tunnel.
use crate::Tunnel;
use anyhow::{bail, Result};
use std::net::Ipv4Addr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Serve SOCKS5 on `listen` (e.g. "127.0.0.1:1080"), forwarding through `tun`.
pub async fn serve(tun: Tunnel, listen: &str) -> Result<()> {
    let l = TcpListener::bind(listen).await?;
    tracing::info!("socks5 listening on {listen}");
    loop {
        let (cli, _) = l.accept().await?;
        let tun = tun.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(cli, tun).await { tracing::debug!("socks5 conn: {e}"); }
        });
    }
}

async fn handle(mut cli: TcpStream, tun: Tunnel) -> Result<()> {
    // greeting
    let mut h = [0u8; 2];
    cli.read_exact(&mut h).await?;
    if h[0] != 5 { bail!("not socks5"); }
    let nm = h[1] as usize;
    let mut methods = vec![0u8; nm];
    cli.read_exact(&mut methods).await?;
    cli.write_all(&[5, 0]).await?; // no auth

    // request
    let mut r = [0u8; 4];
    cli.read_exact(&mut r).await?;
    if r[1] != 1 { cli.write_all(&[5, 7, 0, 1, 0,0,0,0, 0,0]).await?; bail!("only CONNECT"); }
    let (host, is_ip): (String, Option<Ipv4Addr>) = match r[3] {
        1 => { let mut a=[0u8;4]; cli.read_exact(&mut a).await?; let ip=Ipv4Addr::from(a); (ip.to_string(), Some(ip)) }
        3 => { let mut l=[0u8;1]; cli.read_exact(&mut l).await?; let mut d=vec![0u8;l[0] as usize]; cli.read_exact(&mut d).await?; (String::from_utf8_lossy(&d).to_string(), None) }
        _ => { cli.write_all(&[5, 8, 0, 1, 0,0,0,0, 0,0]).await?; bail!("bad atyp"); }
    };
    let mut p = [0u8; 2]; cli.read_exact(&mut p).await?;
    let port = u16::from_be_bytes(p);

    let upstream = match is_ip {
        Some(ip) => tun.connect(ip, port).await,
        None => tun.connect_host(&host, port).await,
    };
    let upstream = match upstream {
        Ok(s) => s,
        Err(e) => { cli.write_all(&[5, 4, 0, 1, 0,0,0,0, 0,0]).await?; return Err(e); }
    };
    cli.write_all(&[5, 0, 0, 1, 0,0,0,0, 0,0]).await?; // success

    let (mut cr, mut cw) = tokio::io::split(cli);
    let (mut ur, mut uw) = tokio::io::split(upstream);
    let a = tokio::io::copy(&mut cr, &mut uw);
    let b = tokio::io::copy(&mut ur, &mut cw);
    let _ = tokio::try_join!(a, b);
    Ok(())
}
