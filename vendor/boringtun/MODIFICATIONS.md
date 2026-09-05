# Modifications

This directory is a vendored copy of [boringtun](https://github.com/cloudflare/boringtun)
v0.7.1 (BSD-3-Clause, © Cloudflare, Inc.), with a single change:

- `src/noise/handshake.rs`: the WireGuard `IDENTIFIER` constant baked into
  `INITIAL_CHAIN_HASH` is changed from the stock `"WireGuard v1 zx2c4 Jason@zx2c4.com"`
  to `"CorpLink v1 vpn@feilian-----------"`, so the handshake interoperates with the
  CorpLink WireGuard variant. `INITIAL_CHAIN_HASH` was recomputed as
  `BLAKE2s-256(INITIAL_CHAIN_KEY || IDENTIFIER)`.

Everything else is unmodified upstream boringtun.
