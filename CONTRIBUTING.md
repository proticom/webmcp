# Contributing

Thanks for looking. This is the open-source half of webmcp.fast: the daemon and
CLI that run on your machine. The hosted gateway is not in this repository.

## Build and test

```
cargo build
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

Tests never touch your real config, key file, launchd or systemd; they use temp
directories and in-process mock gateways. Please keep it that way.

## Changes

- Open an issue first for anything that changes the wire protocol
  (`docs/PROTOCOL.md`) or what the gateway is allowed to ask the daemon to do.
  The rule that the gateway can only narrow what a device exposes is not up for
  negotiation.
- Conventional commit prefixes (`feat:`, `fix:`, `docs:`, `chore:`).
- No secrets, tokens or personal absolute paths in code, tests, docs or fixtures.
- Security problems: see `SECURITY.md`, not a public issue.

By contributing you agree your contribution is licensed under Apache-2.0.
