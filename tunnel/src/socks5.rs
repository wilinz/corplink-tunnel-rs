//! Minimal SOCKS5 server (no auth) that bridges CONNECT requests to the WireGuard tunnel.
use crate::Tunnel;
use anyhow::{bail, Result};
use std::net::Ipv4Addr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Serve SOCKS5 on `listen` (e.g. "127.0.0.1:1080"), forwarding through `tun`.
/// No authentication.
pub async fn serve(tun: Tunnel, listen: &str) -> Result<()> {
    serve_auth(tun, listen, None).await
}

/// Serve SOCKS5 with optional username/password authentication (RFC 1929).
pub async fn serve_auth(tun: Tunnel, listen: &str, auth: Option<(String, String)>) -> Result<()> {
    let l = TcpListener::bind(listen).await?;
    tracing::info!("socks5 listening on {listen}");
    serve_on(tun, l, auth).await
}

/// Bind a SOCKS5 listener without serving yet (lets the caller read `local_addr()`,
/// e.g. when binding an ephemeral port with "127.0.0.1:0").
pub async fn bind(listen: &str) -> Result<TcpListener> {
    Ok(TcpListener::bind(listen).await?)
}

/// Serve SOCKS5 on a pre-bound listener with optional auth.
pub async fn serve_on(tun: Tunnel, l: TcpListener, auth: Option<(String, String)>) -> Result<()> {
    loop {
        let (cli, _) = l.accept().await?;
        let tun = tun.clone();
        let auth = auth.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(cli, tun, auth).await { tracing::debug!("socks5 conn: {e}"); }
        });
    }
}

async fn handle(mut cli: TcpStream, tun: Tunnel, auth: Option<(String, String)>) -> Result<()> {
    // greeting
    let mut h = [0u8; 2];
    cli.read_exact(&mut h).await?;
    if h[0] != 5 { bail!("not socks5"); }
    let nm = h[1] as usize;
    let mut methods = vec![0u8; nm];
    cli.read_exact(&mut methods).await?;
    if let Some((want_u, want_p)) = &auth {
        // require username/password (method 0x02)
        if !methods.contains(&0x02) { cli.write_all(&[5, 0xff]).await?; bail!("no acceptable auth"); }
        cli.write_all(&[5, 0x02]).await?;
        let mut v = [0u8; 1]; cli.read_exact(&mut v).await?; // version 1
        let mut ul = [0u8; 1]; cli.read_exact(&mut ul).await?;
        let mut u = vec![0u8; ul[0] as usize]; cli.read_exact(&mut u).await?;
        let mut pl = [0u8; 1]; cli.read_exact(&mut pl).await?;
        let mut pw = vec![0u8; pl[0] as usize]; cli.read_exact(&mut pw).await?;
        let ok = u == want_u.as_bytes() && pw == want_p.as_bytes();
        cli.write_all(&[1, if ok { 0 } else { 1 }]).await?;
        if !ok { bail!("bad socks5 credentials"); }
    } else {
        cli.write_all(&[5, 0]).await?; // no auth
    }

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
