# Security

`webmcp` runs on your machine and can start the MCP servers you attach to it, so
we treat reports seriously and want them privately.

## Reporting

- Preferred: a private report through GitHub, **Security → Report a vulnerability**
  on this repository.
- Or email **support@webmcp.fast** with "SECURITY" in the subject.

Please do not open a public issue for a vulnerability. Include the version
(`webmcp --version`), your platform, and the smallest reproduction you can. We
aim to acknowledge within 3 business days.

## Scope

In scope: this daemon and CLI, the wire protocol in `docs/PROTOCOL.md`, the
installer script, and the release artifacts. The hosted gateway at webmcp.fast is
closed source; report issues with it the same way.

## What the project does to protect you

- Releases are built by GitHub Actions from a tag. The npm packages
  (`@proticom/webmcp` and its platform packages) are published through OIDC
  trusted publishing with provenance attestations, so `npm audit signatures`
  can tie what you installed to the release workflow and commit; no long-lived
  npm token exists. The GitHub release tarballs and Windows zip ship with SHA-256 checksums
  (`SHA256SUMS`).
  Binaries are not code-signed or notarized on any platform.
- CI runs `cargo audit` against the RustSec advisory database on every change.
- Dependabot watches Cargo and GitHub Actions dependencies.
- Third-party GitHub Actions are pinned to full commit SHAs.

See `THREAT_MODEL.md` for what the daemon can and cannot be made to do.
