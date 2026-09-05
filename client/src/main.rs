//! Self-contained CorpLink/feilian client: login (pure Rust) + userspace
//! WireGuard-over-TCP tunnel (corplink-tunnel) exposed as a local SOCKS5 proxy.
//! No Go, no libwg, no CGO, no TUN device, no root.
mod api;
mod client;
mod config;
mod qrcode;
mod resp;
mod state;
mod template;
mod totp;
mod utils;

use anyhow::{Context, Result};
use client::Client;
use config::{Config, WgConf, PLATFORM_CORPLINK_V1};
use std::time::Duration;

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

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let conf_file = std::env::args().nth(1).unwrap_or_else(|| "config.json".into());
    let mut conf = Config::from_file(&conf_file).await.context("failed to load config")?;

    let socks5_listen = conf
        .socks5_listen
        .clone()
        .context("`socks5_listen` is required (this client runs in userspace SOCKS5 mode only)")?;
    let socks5_auth = match conf.socks5_username.clone().unwrap_or_default() {
        u if u.is_empty() => None,
        u => Some((u, conf.socks5_password.clone().unwrap_or_default())),
    };

    // resolve company server from company name if not cached
    if conf.server.is_none() {
        let resp = client::get_company_url(conf.company_name.as_str())
            .await
            .with_context(|| format!("failed to fetch company server for {}", conf.company_name))?;
        log::info!("company {}(zh)/{}(en) server {}", resp.zh_name, resp.en_name, resp.domain);
        conf.server = Some(resp.domain);
        conf.save().await.context("failed to persist company server")?;
    }

    let platform = conf.platform.clone();
    let mut c = Client::new(conf).context("failed to initialize client")?;

    // login + connect with in-process exponential backoff
    const BACKOFF_MIN: u64 = 5;
    const BACKOFF_MAX: u64 = 300;
    let mut backoff = BACKOFF_MIN;
    let mut logout_retry = true;

    let wg_conf = loop {
        if c.need_login() {
            log::info!("not login yet, try to login");
            match c.login().await {
                Ok(_) => { log::info!("login success"); backoff = BACKOFF_MIN; }
                Err(e) => {
                    log::warn!("login failed: {:#}; retrying in {}s", e, backoff);
                    tokio::time::sleep(Duration::from_secs(backoff)).await;
                    backoff = (backoff * 2).min(BACKOFF_MAX);
                    continue;
                }
            }
        }
        log::info!("try to connect");
        match c.connect_vpn().await {
            Ok(conf) => break conf,
            Err(e) => {
                if logout_retry && e.to_string().contains("logout") {
                    log::warn!("{}", e);
                    logout_retry = false;
                    continue;
                }
                log::warn!("failed to connect: {:#}; retrying in {}s", e, backoff);
                tokio::time::sleep(Duration::from_secs(backoff)).await;
                backoff = (backoff * 2).min(BACKOFF_MAX);
                continue;
            }
        }
    };

    // bring up the pure-Rust tunnel and expose SOCKS5
    let tun = corplink_tunnel::Tunnel::start(to_tunnel_conf(&wg_conf))
        .await
        .context("failed to start userspace tunnel")?;
    match &socks5_auth {
        Some(_) => log::info!("socks5 proxy ready at {socks5_listen} (username/password auth required)"),
        None => log::info!("socks5 proxy ready at {socks5_listen} (no auth)"),
    }
    let listen = socks5_listen.clone();
    let tun2 = tun.clone();
    tokio::spawn(async move {
        if let Err(e) = corplink_tunnel::socks5::serve_auth(tun2, &listen, socks5_auth).await {
            log::error!("socks5 server exited: {e:#}");
        }
    });

    // keep the server-side session alive; exit on Ctrl-C / SIGTERM
    tokio::select! {
        _ = c.keep_alive_vpn(&wg_conf, 60) => {}
        _ = wait_for_shutdown_signal() => { log::info!("shutting down"); }
    }

    // graceful shutdown: free the server-side session/terminal slot
    log::info!("disconnecting vpn...");
    if let Err(e) = c.disconnect_vpn(&wg_conf).await { log::warn!("disconnect failed: {e}"); }
    if platform.as_deref() == Some(PLATFORM_CORPLINK_V1) {
        log::info!("logging out current terminal...");
        if let Err(e) = c.logout().await { log::warn!("logout failed: {e}"); }
    }
    Ok(())
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    { let _ = tokio::signal::ctrl_c().await; }
}
