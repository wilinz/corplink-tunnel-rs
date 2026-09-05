use anyhow::Result;
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().init();
    let path = std::env::args().nth(1).expect("wgconf.json");
    let listen = std::env::args().nth(2).unwrap_or_else(|| "127.0.0.1:1080".into());
    let conf: corplink_tunnel::WgConf = serde_json::from_slice(&std::fs::read(path)?)?;
    let tun = corplink_tunnel::Tunnel::start(conf).await?;
    eprintln!("✅ 纯 Rust 隧道已建立, socks5 -> {listen}");
    corplink_tunnel::socks5::serve(tun, &listen).await
}
