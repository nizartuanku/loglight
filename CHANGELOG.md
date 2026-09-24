# Changelog

## 0.2.1 — 2026-09-24

- **The tier table and the binary now agree on two rows, and the binary was right about one of them.** Syslog is a free alert channel, alongside webhook. Kill-chain correlation runs on every tier — it was documented as a paid feature it had never actually been gated behind.
- **Verification identifiers renamed to Hexward.** The HTTP header, DNS TXT label and well-known file used to prove ownership now read `X-Hexward-Token`, `_hexward-verify.<domain>` and `/.well-known/hexward-verify.txt`. A challenge is satisfied by either the old or the new identifier and the webhook sends both headers, so nothing already installed breaks. The old names are removed on **1 March 2027**.
- **The product page is reachable from inside the product.** The messages that report a free-edition limit, and the dashboard Licence panel and footer, now say where the paid editions are — a product URL, not a plan id.
- **`scripts/first-run.sh` — one command from a clean machine to a working dashboard.** It resolves the latest release at run time rather than pinning a tag, verifies the download against `SHA256SUMS` with no `--ignore-missing`, extracts, starts the binary and polls the dashboard until it answers. If the port is already taken it says so instead of letting the binary exit a second later and read like a broken product (`FIRST_RUN_PORT` overrides). When the unauthenticated GitHub API budget of 60 calls per hour is spent, the script names the rate limit and when it resets, instead of reporting "cannot reach".
- **`docs/CONCEPTS.md`** — what bounded correlation is, what it will and will not join, and why the tier table matches the binary.
- The documentation says seven detections, which is how many there are.
- The README states the pricing rule plainly: Whop sells paid licences only; the free build is downloaded here. The install block runs `docker build` before `docker run`, and the example commands no longer carry pre-rename product names.
- Packaging: the `LICENSE` / `license` collision is fixed and the real licence text ships with the source; one copyright holder is named.
- CI runs `gofmt`, `go vet` and `go test` on every push.

## 0.2.0 — 2026-08-24

Loglight sees the network, not just the logs. NetFlow v5/v9 and IPFIX ingest (flow metadata only — no agent, no packet capture), a live rotatable 3D network map that runs fully offline with a vendored renderer, and two new detections: beaconing (regular-interval calls to one external endpoint) and new service (a host starts accepting connections on a never-seen port).

## 0.1.0 — 2026-08-21

First public release. Self-hosted SIEM-lite: syslog (UDP/TCP, RFC 3164/5424), file tail, journald and docker ingest; curated detections (brute force, credential stuffing, port scan, exfiltration volume, new admin) plus cross-source kill-chain correlation that folds scan → brute force → success into one incident. Free edition: 1 source, 3-day retention.
