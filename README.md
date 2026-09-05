# corplink-tunnel-rs

A **pure-Rust, userspace** WireGuard-over-TCP tunnel for the **CorpLink / feilian**
WireGuard variant. No Go, no `libwg`, no CGO, no TUN device, no root — a single
`cargo build`.

It brings up a WireGuard session over the CorpLink TCP transport using
[boringtun](https://github.com/cloudflare/boringtun) for the crypto and
[smoltcp](https://github.com/smoltcp-rs/smoltcp) for a userspace TCP/IP stack,
then lets you either:

- open connections programmatically — `Tunnel::connect(ip, port) -> TunnelStream`
  (an `AsyncRead + AsyncWrite` stream), or
- expose a local **SOCKS5** proxy that forwards through the tunnel.

## How it works

```
your app / SOCKS5  ──▶  smoltcp (userspace TCP/IP, holds the tunnel IP)
                          │  IP packets
                          ▼
                        boringtun  (WireGuard encrypt/decrypt)
                          │  WG packets
                          ▼
                        CorpLink TCP transport  (u32-LE length-prefixed frames)
                          │
                          ▼
                        TCP  ──▶  WireGuard endpoint
```

Two protocol details make CorpLink differ from stock WireGuard, both handled here:

1. **Transport**: WireGuard runs over TCP with a 4-byte little-endian length
   prefix per packet (instead of UDP).
2. **Handshake identifier**: the Noise `IDENTIFIER` constant is
   `"CorpLink v1 vpn@feilian-----------"` instead of the stock WireGuard one.
   The vendored boringtun in `vendor/boringtun` recomputes `INITIAL_CHAIN_HASH`
   accordingly (see `vendor/boringtun/MODIFICATIONS.md`).

## Usage

You supply a `WgConf` (private/peer keys, endpoint, tunnel address, DNS, MTU),
typically obtained from a CorpLink login handshake:

```rust
use corplink_tunnel::{Tunnel, WgConf};

let conf: WgConf = serde_json::from_slice(&std::fs::read("wgconf.json")?)?;
let tun = Tunnel::start(conf).await?;

// direct stream
let mut s = tun.connect_host("example.internal", 443).await?; // resolves via tunnel DNS
// ... use s as an AsyncRead + AsyncWrite ...

// or a SOCKS5 proxy
corplink_tunnel::socks5::serve(tun, "127.0.0.1:1080").await?;
```

### WgConf JSON

```json
{
  "address": "10.0.0.2/24",
  "peer_address": "192.0.2.1:443",
  "mtu": 1400,
  "private_key": "<base64>",
  "peer_key": "<base64>",
  "dns": "10.0.0.1",
  "protocol": 1
}
```

## Binaries (manual testing)

```bash
# SOCKS5 proxy on 127.0.0.1:1080
cargo run --release --bin socks5d -- wgconf.json 127.0.0.1:1080

# one-shot: connect + TLS + HTTP GET through the tunnel
cargo run --release --bin test-conn -- wgconf.json <ip> <port> <sni> [path]
```

## License

MIT (this crate). The vendored `boringtun` is BSD-3-Clause, © Cloudflare, Inc.;
see `vendor/boringtun/LICENSE` and `vendor/boringtun/MODIFICATIONS.md`.
