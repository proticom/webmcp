## What and why

## Checklist
- [ ] `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test` pass
- [ ] No secrets, tokens, or personal absolute paths (`/Users/…`, `/home/…`) in code, tests, docs or fixtures
- [ ] Wire protocol unchanged, or `docs/PROTOCOL.md` updated and an issue linked
- [ ] Nothing here lets the gateway make a device expose more than its owner configured
