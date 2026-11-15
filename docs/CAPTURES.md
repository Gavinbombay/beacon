# Terminal capture provenance

The images in captures/ are renderings of actual output from sandboxed Cargo tests of the FF3 implementation. They show terminal results, not an administrative user interface. No browser was installed or used. Raw command output was reduced by selecting verbatim lines beginning with running, test or test result; no test names, results, counts or timing were edited.

Commands that produced these captures (with a disposable PostgreSQL fixture and a separately built Beacon binary for startup tests):

```sh
cargo build --locked --offline
cargo test --locked --offline -p beacon-http ff3_ -- --nocapture
cargo test --locked --offline -p beacon-admin ff3_ -- --nocapture
python3 -B docs/tools/render-captures.py
```

Set BEACON_TEST_DATABASE_URL for a disposable PostgreSQL cluster, and BEACON_TEST_BINARY to the freshly built Beacon executable before the admin test. Both are necessary; missing fixture settings fail tests. These captures include real proxy upstream handshakes and real database migrations/startup tests. Assertions check refusals before upstream contact and isolation of login budgets behind a trusted proxy.

- `captures/http-policy.txt` SHA-256 `29de3ac2f0c14e13676983fa7e73f74e09d5b9cb6d4a611d86039863c2e0a702`.
- `captures/admin-policy.txt` SHA-256 `cfdb04a0cd7e9d16d326dc9779510175e282b8d8426ecc0db3470d21a18b6284`.

The generator uses only the Python standard library, reads committed text and writes deterministic SVG. Re-running it without modifying captures must reproduce the image bytes. To refresh captures after a code change, run the recorded commands and select their actual result lines again. The job's retained test evidence records the full tests and pre-fix replay separately.

The hero and mark are Quill web illustrations supplied for Beacon. They are not screenshots or evidence of a deployed service. Their original staged files were not modified.
