//! Log out a saved session (frees its server-side terminal slot).
//! Usage: cargo run -p corplink-client --example logout -- <config.json>
use anyhow::{Context, Result};
use corplink_client::{client, Config};

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let f = std::env::args().nth(1).context("usage: logout <config.json>")?;
    let mut conf = Config::from_file(&f).await?;
    if conf.server.is_none() {
        conf.server = Some(client::get_company_url(&conf.company_name).await?.domain);
    }
    let mut c = client::Client::new(conf)?;
    c.logout().await?;
    println!("logged out {f}");
    Ok(())
}
