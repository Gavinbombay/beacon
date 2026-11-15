# Design notes

Routing matches the requested host and dispatches proxy, static, redirect, or composite handlers. Game forwarding is optional at compile time and defaults off. DNS record changes use a provider interface; the Cloudflare implementation is a non-production skeleton. The ACME lifecycle validates and installs artifacts returned by an injected transport. The lego adapter uses Porkbun DNS challenges; other adapters can implement the transport interface independently.

The UI storage key defaults to `beacon_token` and is configurable using `BEACON_TOKEN_KEY`; the authentication header defaults to `X-Beacon-Token` and is configurable using `BEACON_TOKEN_HEADER`. The optional public `/metrics` endpoint counts requests handled by the proxy router. Both features are implemented per spec; live parity unverified.


Administrator login admission uses the TCP peer IP supplied by Axum connection information, never an HTTP forwarding header or caller-supplied username. Each source gets five attempts in a fixed one-minute window. The map expires entries and holds at most 1024 sources; it evicts the earliest-expiring entry on capacity. A shared proxy or address shares this budget. Two concurrent verification permits remain independent of rejection delays; bcrypt runs on blocking workers.

WebSocket connection and handshake setup is bounded by the proxy request timeout. Timeout returns a generic 504, closes the pending socket and records a circuit failure. Established sessions retain their normal streaming lifetime. Database regressions require the disposable Unix-socket PostgreSQL fixture and fail if its URL is absent.
