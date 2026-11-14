# Beacon

Beacon is a Rust edge proxy with host and path routing, static content, redirects, TLS and an administrative API backed by PostgreSQL. When you add a site, Beacon creates the DNS record, obtains a certificate and starts routing, through a **provider-agnostic DNS adapter**: DNS hosts are plugins behind one trait and one registry, and Porkbun is simply the first implemented provider.

Status: early open-source release (v0.2). APIs and configuration may change; review the Security section before exposing it to untrusted networks.

## How the DNS adapter works

- `beacon-dns` defines the `DnsProvider` trait: `ensure_record_with_change` (idempotent create or update, returning what changed), `rollback_change` (undo that exact change) and `wait_for_propagation`.
- `beacon-core/src/provider.rs` holds the provider registry (`ProviderSpec`). Each entry names the provider, says whether it is implemented, picks its record adapter, and maps configured values (`dns.api_key`, `dns.secret_key`) to the environment variables the ACME client (lego) expects for DNS-01 challenges.
- `beacon_dns::provider()` turns `dns.provider` from the config into a concrete adapter. The certificate lifecycle reads the same registry entry, so there is no provider-specific branch anywhere else. Unknown names fail loudly, and skeleton providers return a typed error instead of silently falling back.

Today: `porkbun` is implemented; `cloudflare` is a registered skeleton you can use as the starting point for a contribution.

## Build

Use Rust and Cargo 1.98.1 with rustfmt. The lockfile pins the dependency graph. With those exact tools on PATH and the dependency cache already populated, run:

```sh
sh ./check-toolchain.sh
cargo fmt --all -- --check
cargo test --locked --offline --workspace --all-targets
cargo build --locked --offline --release
cargo test --locked --offline --workspace --all-targets --features game_forward
cargo build --locked --offline --release --features game_forward
```

Offline builds require an independently provisioned Cargo cache; dependencies are not included in this repository. The optional game forwarding feature is off by default.

For a mock-only quickstart, run the two test commands above and `node tests/ui.test.cjs` from a disposable copy. They use in-process fixtures and create no listeners. Node is needed only for the DOM helper check. Forwarding's internal tests can also be run from that copy with `cargo test --offline --manifest-path crates/beacon-forward/Cargo.toml`; this excluded optional crate creates its own local lockfile. Default workspace tests exclude it. Enabling the feature builds its runtime and enables different UI, persistence and binary tests.

On Windows with Git Bash, invoke the toolchain check using the Git installation's `sh.exe`. When the pinned toolchain is unavailable offline, explicitly select an installed toolchain through `RUSTUP_TOOLCHAIN`, record its exact version, and expect the check script to fail until the pin is installed. Do not change the pin to hide that mismatch.

## Configuration

Set `BEACON_CONFIG_JSON` to a JSON object containing `server`, `brain`, `dns`, and `store`. `server` can be an empty object to use the port defaults. `brain` requires `api_key`, `api_base`, and `model`; `dns` requires `default_ip`, and optionally `provider`, `api_key`, and `secret_key`; `store` requires `database_url`. Values must be supplied by the operator. The process fails with a configuration error if the database URL, API key, API base, model, or DNS IP is missing or invalid. Optional `auth`, `tls`, `proxy`, `sites`, and `domains` are defined in `crates/beacon-core/src/config.rs`. A minimal configuration shape follows (replace each placeholder with an operator-supplied value):

```json
{"server": {}, "brain": {"api_key": "<TOKEN>", "api_base": "<LLM_URL>", "model": "<MODEL>"}, "dns": {"provider": "porkbun", "default_ip": "<PUBLIC_IP>"}, "store": {"database_url": "<DATABASE_URL>"}}
```

Run `target/release/beacon` after configuring a reachable database. Startup runs database migrations.

The administrative UI is served on the configured admin port. Set `BEACON_TOKEN_KEY` and `BEACON_TOKEN_HEADER` to override its browser storage key and request header. Set `BEACON_METRICS` to `true` to expose `/metrics` on the public router. DNS provider `porkbun` is supported for record management; `cloudflare` is a non-production skeleton that returns a typed error. DNS and the lego adapter share the capability registry in `beacon-core/src/provider.rs`; unsupported selectors fail explicitly. Lego must be installed separately. The Cloudflare skeleton does not issue certificates.

Management uses HTTP independently of public TLS. Place the management listener behind a trusted encrypted tunnel or HTTPS ingress, protecting every backend hop from untrusted peers. Public TLS does not encrypt management traffic. Authentication is optional by design: omitting `auth` enables anonymous administration for trusted isolated attachments. Enable `auth` with a nonempty username and operator-supplied password for authenticated administration. Do not expose anonymous management to untrusted networks. The management page denies framing; API text is rendered as text, including model responses and provider diagnostics.

Route refresh errors withdraw the entire cached public snapshot until the next successful refresh. This deliberately favors withdrawal over availability. Forward deletion or replacement stops and joins admitted workers before reconciliation returns. UDP sessions have a fixed admission cap; reaching it rejects new sessions while preserving existing owners. Reply pumps accept only the selected responder. Desired-state reads and applies share a reconciliation lock; new callers must use `reconcile_from` rather than loading a snapshot before `apply`.

Static roots must be trusted and protected from concurrent modification by untrusted users. Missing files use a root-local `404.html` when present. Review `NOTICE` and dependency licenses before distribution.

## Architecture and capabilities

The public HTTP router serves static files, proxies requests and redirects; the admin API coordinates PostgreSQL persistence, DNS and TLS. The brain adapter connects to an operator-selected model endpoint. Game forwarding is an optional feature.

| Capability | Status |
| --- | --- |
| Static `404.html` | implemented per spec; live parity unverified |
| Configurable UI storage key and header | implemented per spec; live parity unverified |
| Opt-in `/metrics` | implemented per spec; live parity unverified |
| Porkbun DNS | implemented |
| Cloudflare DNS | non-production skeleton |
| Game forwarding | opt-in build feature |

## Configuration reference

| Setting | Purpose |
| --- | --- |
| `BEACON_CONFIG_JSON` | Required JSON configuration described above |
| `BEACON_TOKEN_KEY` | Browser storage key override |
| `BEACON_TOKEN_HEADER` | Administrative request header override |
| `BEACON_METRICS` | Enable metrics when true |

| JSON field | Validation |
| --- | --- |
| `server` | Required object; ports default when omitted within it |
| `brain.api_key` | Required nonempty string, supplied at runtime |
| `brain.api_base` | Required absolute HTTP or HTTPS URL with a host |
| `brain.model` | Required nonempty operator-supplied identifier; no default |
| `dns.default_ip` | Required IPv4 or IPv6 address |
| `dns.provider` | Optional; empty selects Porkbun; unknown names fail provider construction |
| `dns.api_key`, `dns.secret_key` | Optional for config parsing; required by the supported lego adapter |
| `store.database_url` | Required absolute postgres or postgresql URL with a host |
| `auth` | Optional; enabled mode requires nonempty username/password and positive session TTL |

Malformed JSON, wrong field types, missing required sections or fields, empty required strings, invalid URL schemes/hosts and malformed addresses fail startup validation. Errors identify fields without echoing configured values. Debug formatting redacts sensitive configuration structs. API values and model identifiers belong in runtime configuration, never in source fixtures.

## Adding a DNS provider

1. In `crates/beacon-core/src/provider.rs`, add a `RecordAdapter` variant and a `ProviderSpec` entry: `name` (the `dns.provider` value), `implemented`, `adapter`, `lego_name` (lego's provider selector) and `lego_env` (lego environment variable names mapped to `DnsValue::ApiKey` / `DnsValue::SecretKey`).
2. In `crates/beacon-dns/src/lib.rs`, implement `DnsProvider` for your adapter (create/update must be idempotent and return a `DnsChange` that `rollback_change` can undo), then add its arm to `provider()`.
3. Add fixture tests as described below. Never call a real provider API from tests.
4. Document the provider in the capability table.

Implement `DnsProvider` in `beacon-dns`, including idempotent record creation and rollback. Add a record adapter kind and registry entry in `beacon-core/src/provider.rs`, then wire that adapter in the DNS factory. The entry declares lego's provider selector and mappings from configured values to environment key names. Lego's command builder consumes that data without a provider-specific branch in the certificate lifecycle. Mark incomplete adapters as skeletons. Cover create, update, no-op, update failure restoration, cleanup, propagation timeout, API errors, ACME failure/fallback, required email/domains and renewal with injected in-process transport, resolver and clock fixtures. Production endpoints remain in transport construction; fixtures inject their own endpoint. Do not call a real provider from tests.

## Troubleshooting

Check required configuration fields and JSON syntax on startup errors. Offline builds require the pinned toolchain and an already populated Cargo cache. For certificate issues, check the configured domains and email and the separately installed ACME client; self-signed fallback depends on configuration.

## Security reporting

Please report vulnerabilities privately through GitHub's private vulnerability reporting (the repository's **Security** tab, then **Report a vulnerability**), not through public issues.

Known limitations: this is pre-1.0 software. A pre-release review flagged several unconfirmed edge cases that still need validation, around concurrent site updates in the admin API, forward reconciliation under concurrent removal, and login lockout behaviour under repeated failures. Run the management API only on trusted networks until these are resolved.
