//! Thin CLI over the corplink-client library: login + userspace tunnel + SOCKS5.
use anyhow::{Context, Result};
use corplink_client::{connect, Config};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let conf_file = std::env::args().nth(1).unwrap_or_else(|| "config.json".into());
    let config = Config::from_file(&conf_file).await.context("failed to load config")?;

    let socks5_listen = config
        .socks5_listen
        .clone()
        .context("`socks5_listen` is required (userspace SOCKS5 mode only)")?;
    let auth = match config.socks5_username.clone().unwrap_or_default() {
        u if u.is_empty() => None,
        u => Some((u, config.socks5_password.clone().unwrap_or_default())),
    };

    // login + bring up tunnel, with in-process exponential backoff
    let mut backoff = 5u64;
    let session = loop {
        match connect(config.clone()).await {
            Ok(s) => break s,
            Err(e) => {
                log::warn!("connect failed: {e:#}; retrying in {backoff}s");
                tokio::time::sleep(Duration::from_secs(backoff)).await;
                backoff = (backoff * 2).min(300);
            }
        }
    };
    match &auth {
        Some(_) => log::info!("socks5 proxy ready at {socks5_listen} (username/password auth required)"),
        None => log::info!("socks5 proxy ready at {socks5_listen} (no auth)"),
    }

    let tun = session.tunnel();
    let listen = socks5_listen.clone();
    tokio::spawn(async move {
        if let Err(e) = corplink_tunnel::socks5::serve_auth(tun, &listen, auth).await {
            log::error!("socks5 server exited: {e:#}");
        }
    });

    wait_for_shutdown_signal().await;
    log::info!("shutting down");
    session.close().await;
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
