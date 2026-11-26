# PrimeBoost VPN

PrimeBoost VPN for Astra.

## Features

- Sign in with Google or Telegram; a new account is created automatically.
- One-click connect: all servers are pinged in parallel within 3 s, the fastest is used, and the next one is tried if traffic does not pass within 4 s.
- VLESS over TCP/RAW, WebSocket (early data), gRPC (gun/multi), HTTP/2, HTTPUpgrade and XHTTP with TLS or Reality.
- Smart routing (local sites direct) or all traffic through the VPN.
- Proxy mode by default; TUN mode and split tunneling for other apps.
- Plans and payment inside the tab, free trial for new users.
- Assistant tools and command steps to turn the VPN on and off.
- Russian and English interface.

## Build

Requirements: Rust (stable), `astra-plugin` CLI.

1. The VPN cores (sing-box, and Xray for XHTTP, gRPC multi, Reality over RAW/TCP/gRPC and TLS certificate pins), `wintun.dll` and rule sets live in `core/` and are embedded into the plugin binary; on first connect they are unpacked into `data/core/`. `scripts/sync-core.ps1 -Source <path>` refreshes them from a desktop build.
2. Server addresses are stored sealed in `endpoints.dat`. To change them, copy `endpoints.example.json` to `endpoints.local.json` (ignored by git), fill it in and run `python scripts/seal-endpoints.py`.
3. Build and check:

```
cargo build --release
astra-plugin check . --strict
astra-plugin test .
```

## Layout

| Path | Purpose |
|------|---------|
| `src/api.rs` | Account, subscription and key API |
| `src/auth.rs` | Google and Telegram sign-in |
| `src/trial.rs`, `src/device.rs` | Free trial bound to the device |
| `src/billing.rs`, `src/billing_api.rs` | Plans and payment |
| `src/commands.rs` | Assistant tools and command steps |
| `src/vpn.rs` | Server selection, connection, monitoring |
| `src/singbox_config.rs`, `src/split.rs` | sing-box configuration and split tunneling |
| `src/xray.rs` | Local Xray SOCKS bridge |
| `src/runner.rs` | Elevated core launcher (Windows TUN), started as `prime_vpn --prime-runner` |
| `src/core_assets.rs`, `core/` | Embedded VPN core and rule sets |
| `src/endpoints.rs`, `endpoints.dat` | Sealed server addresses |
| `ui/` | Astra tab |

## Third-party

The VPN core is sing-box (GPL-3.0, https://github.com/SagerNet/sing-box). Windows TUN uses Wintun (https://www.wintun.net/). Their licences are in `core/`.

## License

MIT
