# Design notes

Routing matches the requested host and dispatches proxy, static, redirect, or composite handlers. Game forwarding is optional at compile time and defaults off. DNS record changes use a provider interface; the Cloudflare implementation is a non-production skeleton. The ACME lifecycle validates and installs artifacts returned by an injected transport. The lego adapter uses Porkbun DNS challenges; other adapters can implement the transport interface independently.

The UI storage key defaults to `beacon_token` and is configurable using `BEACON_TOKEN_KEY`; the authentication header defaults to `X-Beacon-Token` and is configurable using `BEACON_TOKEN_HEADER`. The optional public `/metrics` endpoint counts requests handled by the proxy router. Both features are implemented per spec; live parity unverified.
