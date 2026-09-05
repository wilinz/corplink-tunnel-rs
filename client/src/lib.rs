//! Self-contained pure-Rust CorpLink/feilian client, as a library.
//!
//! [`connect`] performs the login (company lookup, feilian_v1 password/2FA,
//! `connect_vpn`), brings up the userspace WireGuard-over-TCP [`Tunnel`], and
//! returns a [`Session`] that keeps the server-side session alive in the
//! background and, on [`Session::close`] / drop, disconnects and logs out.
pub mod api;
pub mod client;
pub mod config;
pub mod qrcode;
pub mod resp;
pub mod state;
pub mod template;
pub mod totp;
pub mod utils;

pub use config::{Config, WgConf};
pub use corplink_tunnel::{Tunnel, TunnelStream};

use anyhow::{Context, Result};
use std::time::Duration;
use tokio::sync::oneshot;

fn to_tunnel_conf(wg: &WgConf) -> corplink_tunnel::WgConf {
    corplink_tunnel::WgConf {
        address: wg.address.clone(),
        peer_address: wg.peer_address.clone(),
        mtu: wg.mtu,
        private_key: wg.private_key.clone(),
        peer_key: wg.peer_key.clone(),
        dns: wg.dns.clone(),
        protocol: wg.protocol,
        allowed_ips: wg.allowed_ips.clone(),
    }
}

/// A live tunnel session. Clone the [`Tunnel`] via [`Session::tunnel`] to open
/// connections; keepalive runs in the background until [`Session::close`] or drop.
pub struct Session {
    tunnel: Tunnel,
    shutdown: Option<oneshot::Sender<()>>,
    join: Option<tokio::task::JoinHandle<()>>,
}

impl Session {
    /// A clonable handle to the tunnel for opening connections.
    pub fn tunnel(&self) -> Tunnel {
        self.tunnel.clone()
    }
    /// Gracefully disconnect the VPN and log out the terminal.
    pub async fn close(mut self) {
        if let Some(s) = self.shutdown.take() {
            let _ = s.send(());
        }
        if let Some(j) = self.join.take() {
            let _ = j.await;
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Some(s) = self.shutdown.take() {
            let _ = s.send(()); // best-effort background cleanup
        }
    }
}

/// Log in with `config` and bring up the tunnel. `config` may be in-memory
/// (no file); credentials come from its fields.
pub async fn connect(mut config: Config) -> Result<Session> {
    config.prepare()?;
    if config.server.is_none() {
        let resp = client::get_company_url(&config.company_name)
            .await
            .with_context(|| format!("company lookup failed for {}", config.company_name))?;
        config.server = Some(resp.domain);
    }
    let platform = config.platform.clone();
    let mut c = client::Client::new(config).context("failed to init client")?;
    if c.need_login() {
        c.login().await.context("login failed")?;
    }
    let wg = c.connect_vpn().await.context("connect_vpn failed")?;
    let tunnel = Tunnel::start(to_tunnel_conf(&wg)).await.context("failed to start tunnel")?;

    let (sd_tx, sd_rx) = oneshot::channel();
    let join = tokio::spawn(session_task(c, wg, platform, sd_rx));
    Ok(Session { tunnel, shutdown: Some(sd_tx), join: Some(join) })
}

async fn session_task(mut c: client::Client, wg: WgConf, platform: Option<String>, mut sd_rx: oneshot::Receiver<()>) {
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    tick.tick().await; // consume immediate
    loop {
        tokio::select! {
            _ = tick.tick() => { let _ = c.report_vpn_status(&wg).await; }
            _ = &mut sd_rx => break,
        }
    }
    let _ = c.disconnect_vpn(&wg).await;
    if platform.as_deref() == Some(config::PLATFORM_CORPLINK_V1) {
        let _ = c.logout().await;
    }
}
