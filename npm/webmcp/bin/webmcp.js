#!/usr/bin/env node
"use strict";
// Thin launcher for the prebuilt `webmcp` binary. The binary itself lives in a
// platform package (@proticom/webmcp-<os>-<cpu>) that npm selects through this
// package's optionalDependencies and the platform packages' os/cpu fields.
// No postinstall, no download, no network: if the platform package is not
// installed, we say so and stop.

const { spawnSync } = require("child_process");
const path = require("path");

const PLATFORMS = {
  "darwin-arm64": "@proticom/webmcp-darwin-arm64",
  "darwin-x64": "@proticom/webmcp-darwin-x64",
  "linux-x64": "@proticom/webmcp-linux-x64",
  "linux-arm64": "@proticom/webmcp-linux-arm64",
  "win32-x64": "@proticom/webmcp-win32-x64",
};

function binaryPath() {
  const key = `${process.platform}-${process.arch}`;
  const pkg = PLATFORMS[key];
  const file = process.platform === "win32" ? "webmcp.exe" : "webmcp";
  if (!pkg) {
    fail(
      `webmcp has no prebuilt binary for ${key}.`,
      "Build from source: cargo install --git https://github.com/proticom/webmcp --locked",
    );
  }
  try {
    return require.resolve(`${pkg}/${file}`);
  } catch (_) {
    fail(
      `The platform package ${pkg} is not installed (this is ${key}).`,
      "It is an optional dependency of @proticom/webmcp; npm may have skipped it because",
      "of --no-optional / --omit=optional, a lockfile made on another platform, or a",
      "package manager setting. Try again with: npm i -g @proticom/webmcp",
      "Other ways to get webmcp: https://github.com/proticom/webmcp/releases",
      "or: cargo install --git https://github.com/proticom/webmcp --locked",
    );
  }
}

function fail(...lines) {
  for (const line of lines) process.stderr.write(`webmcp: ${line}\n`);
  process.exit(1);
}

const bin = binaryPath();
const result = spawnSync(bin, process.argv.slice(2), {
  stdio: "inherit",
  windowsHide: true,
});

if (result.error) {
  fail(`could not run ${path.basename(bin)}: ${result.error.message}`);
}
if (result.signal) {
  // The daemon died from a signal (e.g. SIGTERM from a supervisor, SIGINT
  // from Ctrl-C). Die the same way so the parent sees the same status.
  process.kill(process.pid, result.signal);
  // If the signal is ignored or not deliverable, fall back to the shell's
  // convention for signal deaths.
  process.exit(128 + (require("os").constants.signals[result.signal] || 1));
}
process.exit(result.status === null ? 1 : result.status);
