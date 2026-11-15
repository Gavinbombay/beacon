# Security and dependency checks

Beacon is pre-1.0 software. Keep administration local or behind an encrypted, trusted ingress and enable authentication before remote administration. Public TLS does not encrypt the separate administrative listener. Protect static roots from concurrent untrusted modification.

Use the repository Security tab to report a vulnerability privately when private reporting is enabled. If that option is unavailable, request a private reporting channel without sharing vulnerability details in a public issue. Do not include credentials in reports.

## Offline release audit environment

This release review uses a staged RustSec advisory database at commit 4ef2df8e806a65e2f1ecc14f56f51249062b23d6. The review runs without network access. The snapshot contains advisories, but no crates.io index entries. Consequently cargo audit and cargo deny cannot determine whether locked versions were yanked. This is an environment limitation, not evidence that all versions are unyanked. The final independent audit is a separate step.

A maintainer with network access should refresh advisory and registry metadata and run both tools before publishing:

```sh
cargo audit
cargo deny check advisories bans licenses sources
cargo deny --features game_forward check advisories bans licenses sources
```

Run these from the repository with installed cargo-audit and cargo-deny, a configured dependency/license policy, and a writable Cargo home. Allow the tools to fetch the advisory database and crates.io index; do not pass offline or no-fetch options. Check that the tool output actually completes the yanked check and investigate any missing-index diagnostics. An advisory database alone does not supply yanked metadata.

## Trust at the edge

Default forwarding discards incoming identity headers and records the actual transport peer. Preserving a chain requires both an explicit flag and an allowlisted transport peer. Admin trust is configured independently. Consult the root README section Deploying behind a proxy for complete examples. A trusted front proxy must overwrite or append the client address it actually observed; merely trusting arbitrary incoming headers defeats this boundary.

WebSocket upgrades may carry cookies across origins. Configure each site's allowed-Origin list when browser cookies authorize actions. Without that list the upstream must enforce Origin. Origin filtering supplements upstream authentication; it does not authenticate a non-browser client.
