# @proticom/webmcp

The [webmcp.fast](https://webmcp.fast) daemon: any local MCP server, reachable
by any agent harness through one outbound connection. This package installs a
prebuilt binary for your platform (macOS arm64/x64, Linux x64/arm64, Windows
x64); it has no runtime dependencies and no install script.

    npm i -g @proticom/webmcp
    webmcp up

or, without installing:

    npx @proticom/webmcp up

`webmcp up` pairs this machine, offers the MCP servers your other tools already
use, offers to install the background service (macOS, Linux), and prints each
server's URL.

Packages are published from GitHub Actions with provenance attestations;
verify with `npm audit signatures`. Full documentation, protocol, threat model
and source: https://github.com/proticom/webmcp
