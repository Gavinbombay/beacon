# Design notes

Routing matches the requested host and dispatches proxy, static, redirect, or composite handlers. Game forwarding is optional at compile time and defaults off. DNS record changes use a provider interface; the Cloudflare implementation is a non-production skeleton. The ACME lifecycle validates and installs artifacts returned by an injected transport. The lego adapter uses Porkbun DNS challenges; other adapters can implement the transport interface independently.

The UI storage key defaults to `beacon_token` and is configurable using `BEACON_TOKEN_KEY`; the authentication header defaults to `X-Beacon-Token` and is configurable using `BEACON_TOKEN_HEADER`. The optional public `/metrics` endpoint counts requests handled by the proxy router. Both features are implemented per spec; live parity unverified.


Administrator login admission uses transport connection information by default. Explicit auth.trusted_proxies CIDRs permit a single valid X-Forwarded-For chain, parsed from the trusted end. Each effective client gets five attempts per fixed minute across all usernames; at most 1024 sources are held with earliest-expiry eviction. No trusted proxy means clients sharing a peer share the allowance. Two concurrent verification permits remain independent of rejection delays; bcrypt runs on blocking workers.

Public proxy forwarding uses an independent trusted-proxy list and a default-off preservation flag. Default HTTP and WebSocket requests replace identity headers with transport peer, Host and actual TLS state. A preserved trusted chain appends the observed peer. Missing connection metadata never authorizes preservation. Each site's optional websocket_allowed_origins list is checked before handler dispatch and upstream contact; invalid or empty lists refuse all upgrades.

Legacy imported @ and _ alias rows are unsupported in this first release. Startup rejects them before route publication, without altering those rows. The docs site is local static HTML/CSS, prepared for branch-based Pages from main /docs only after publication approval.

WebSocket connection and handshake setup is bounded by the proxy request timeout. Timeout returns a generic 504, closes the pending socket and records a circuit failure. Established sessions retain their normal streaming lifetime. Database regressions require the disposable Unix-socket PostgreSQL fixture and fail if its URL is absent.

## FF3 validation and cleanup

Behavioral regressions cover actual upstream headers on both transports, trusted shared-proxy login budgets, refusal before upstream contact and the real startup error with legacy database rows. The release's offline RustSec snapshot cannot establish yanked status; docs/SECURITY.md records how maintainers complete that check with network access.

CLEANUP: no service is deployed or replaced. Disposable database data and sockets, build output, caches and validation copies are removed after evidence capture. Keep source, documentation, captures and release evidence. HOW-IT-WORKS is the final builder document and remains pending owner review.
