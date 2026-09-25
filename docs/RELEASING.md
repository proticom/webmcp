# Releasing

**One-time setup:** run `scripts/npm-bootstrap.sh` while logged in to npm. It publishes the six placeholder names and adds the GitHub Actions trusted publisher to each with `npm trust github`, so the manual steps below are only a fallback.

A release is one git tag. Pushing `vX.Y.Z` runs `.github/workflows/release.yml`,
which builds five binaries, creates the GitHub release (tarballs, a Windows
zip, `SHA256SUMS`, `install.sh`) and publishes six npm packages:

| npm package                       | contents                        |
|-----------------------------------|---------------------------------|
| `@proticom/webmcp`                | launcher `bin/webmcp.js`, no deps |
| `@proticom/webmcp-darwin-arm64`   | `webmcp` (aarch64-apple-darwin) |
| `@proticom/webmcp-darwin-x64`     | `webmcp` (x86_64-apple-darwin)  |
| `@proticom/webmcp-linux-x64`      | `webmcp` (x86_64-unknown-linux-gnu) |
| `@proticom/webmcp-linux-arm64`    | `webmcp` (aarch64-unknown-linux-gnu) |
| `@proticom/webmcp-win32-x64`      | `webmcp.exe` (x86_64-pc-windows-msvc) |

The main package lists the five platform packages as `optionalDependencies`
at the exact same version; npm installs only the one whose `os`/`cpu` match.
There is no npm token anywhere: publishing uses npm trusted publishing (OIDC
from GitHub Actions), which also attaches a provenance attestation to every
package (`npm audit signatures`). Nothing is code-signed or notarized.

## One-time setup: npm trusted publishers

Do this once per package name, six times in total. npm's documentation is
https://docs.npmjs.com/trusted-publishers (checked 2026-09-21).

### The first-publish caveat

Trusted publishing is configured on **the package's settings page on
npmjs.com**: the docs say "Navigate to your package settings on npmjs.com and
find the 'Trusted Publisher' section." A package that has never been
published has no settings page, so the very first version of each name
cannot go out through the workflow. The docs do not describe a bootstrap
path for a brand-new name, so use the standard workaround:

1. From your own machine, logged in as the `proticom` org owner with 2FA
   (`npm login`), publish a placeholder `0.0.0` of each of the six names.
   The placeholder needs only a `package.json` (name, version, license,
   `"private": false`) and a one-line README; for the platform packages keep
   the `os`/`cpu` fields so the placeholder is never installed by mistake.
   Publish with `npm publish --access public` (scoped packages are private by
   default). Do **not** publish a real version this way: the real versions
   must carry provenance from the workflow.
2. On npmjs.com, for each package: Settings, then "Trusted Publisher",
   choose GitHub Actions and fill in:
   - Organization or user: `proticom`
   - Repository: `webmcp`
   - Workflow filename: `release.yml`
   - Environment name: `release`
3. Still in each package's settings, under "Publishing access", select
   "Require two-factor authentication and disallow tokens". The docs
   "strongly recommend restricting traditional token-based publishing access"
   once a trusted publisher exists; after this, only the workflow can publish.
4. Optionally `npm deprecate @proticom/webmcp@0.0.0 "placeholder; install a real version"`
   for each name so the placeholder never shows up as installable.

If npm has by then added a way to register a trusted publisher for a name
that does not exist yet, use it instead of the placeholder and skip step 1.

### Requirements the workflow already meets

- npm CLI 11.5.1 or newer and Node 22.14 or newer on the runner: the job
  uses Node 24 (`actions/setup-node`, SHA-pinned) and checks `npm --version`.
- `permissions: id-token: write` on the publishing job, `contents: read`
  everywhere else.
- No `registry-url` on `setup-node` and no `NODE_AUTH_TOKEN`: with OIDC the
  CLI exchanges the job's identity token for a short-lived credential on its
  own. npm's own example shows `registry-url`; it is not needed and leaving
  it out avoids an `.npmrc` that expects a token.
- `npm publish --provenance --access public`. Provenance is automatic under
  trusted publishing; the flag makes the intent explicit and fails loudly if
  OIDC is somehow unavailable.
- The GitHub `release` environment exists and is restricted to `v*` tags.

## Release procedure

1. On `master`, bump `version` in `Cargo.toml`, then sync the npm manifests:

       node scripts/sync-versions.mjs
       cargo build --locked            # refreshes Cargo.lock's own entry
       node scripts/sync-versions.mjs --check

2. Commit (`chore: release vX.Y.Z`) and get it onto `master` through the usual
   PR; CI runs the sync check and the npm smoke test on every push.
3. Tag as a repository admin (the tag ruleset restricts who may create `v*`):

       git tag -a vX.Y.Z -m "vX.Y.Z"
       git push origin vX.Y.Z

4. Watch `Actions` → `release`. Job by job:
   - `build` (5 targets): asserts the tag equals `Cargo.toml` and every
     `package.json`; `cargo build --release --locked`; packages a tarball
     (zip on Windows) plus `.sha256`; uploads both the archive and the bare
     binary as artifacts.
   - `publish`: creates the GitHub release with the archives, `SHA256SUMS`
     and `install.sh`.
   - `publish-npm`: Node 24, npm version check, sync check against the tag,
     downloads the five binaries into `npm/platforms/<name>/`, runs the Linux
     one for `--version`, publishes the five platform packages, then
     `@proticom/webmcp` last so the launcher never resolves to a version whose
     binaries are missing.
5. Verify from a clean machine:

       npx -y @proticom/webmcp@X.Y.Z --version
       npm i -g @proticom/webmcp@X.Y.Z && npm audit signatures -g

If `publish-npm` fails part-way, fix the cause and re-run only that job:
npm rejects re-publishing a version that already exists, so the packages that
went out stay, and the job is safe to repeat once the remaining names are
free. Never delete the tag or the GitHub release to "retry"; bump the patch
version instead.
