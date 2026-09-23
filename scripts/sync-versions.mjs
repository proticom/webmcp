#!/usr/bin/env node
// Keep every npm package.json at the version in Cargo.toml.
//
//   node scripts/sync-versions.mjs            write the version everywhere
//   node scripts/sync-versions.mjs --check    fail if anything differs (CI)
//   node scripts/sync-versions.mjs --check --tag v1.2.3
//                                             also fail if the tag does not match
//
// The main package's optionalDependencies pin the platform packages to the
// exact same version, so one release always resolves to one binary build.

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const args = process.argv.slice(2);
const check = args.includes("--check");
const tagIdx = args.indexOf("--tag");
const tag = tagIdx >= 0 ? args[tagIdx + 1] : process.env.GITHUB_REF_NAME;

const PLATFORMS = ["darwin-arm64", "darwin-x64", "linux-x64", "linux-arm64", "win32-x64"];
const MAIN = join(root, "npm/webmcp/package.json");
const platformPath = (p) => join(root, "npm/platforms", p, "package.json");

const cargo = readFileSync(join(root, "Cargo.toml"), "utf8");
const m = /^version\s*=\s*"([^"]+)"/m.exec(cargo);
if (!m) throw new Error("no version in Cargo.toml");
const version = m[1];

if (tag && tag.startsWith("v") && tag !== `v${version}`) {
  console.error(`sync-versions: tag ${tag} does not match Cargo.toml version ${version}`);
  process.exit(1);
}

const problems = [];
function sync(file, edit) {
  const before = readFileSync(file, "utf8");
  const pkg = JSON.parse(before);
  edit(pkg);
  const after = JSON.stringify(pkg, null, 2) + "\n";
  if (after === before) return;
  if (check) problems.push(file.slice(root.length + 1));
  else writeFileSync(file, after);
}

sync(MAIN, (pkg) => {
  pkg.version = version;
  const deps = {};
  for (const p of PLATFORMS) deps[`@proticom/webmcp-${p}`] = version;
  pkg.optionalDependencies = deps;
});
for (const p of PLATFORMS) {
  sync(platformPath(p), (pkg) => {
    if (pkg.name !== `@proticom/webmcp-${p}`) throw new Error(`${p}: unexpected name ${pkg.name}`);
    pkg.version = version;
  });
}

if (problems.length) {
  console.error(`sync-versions: out of date with Cargo.toml (${version}):`);
  for (const f of problems) console.error(`  ${f}`);
  console.error("run: node scripts/sync-versions.mjs");
  process.exit(1);
}
console.log(`sync-versions: all npm packages at ${version}${check ? " (ok)" : ""}`);
