# Changelog

## 0.2.4 — 2026-10-28

- **Wazuh alerts in, as first-class events.** A Wazuh manager's `syslog_output` (`<format>json</format>`) can now point at a Loglight syslog source. Loglight reads the alert's own fields (source address, user, originating host, rule id and level, authentication outcome) instead of guessing from the text, so Wazuh-relayed failed logins feed the brute-force detector and a Decoy trip from the same address raises one critical incident across both systems. Wazuh's aggregate brute-force rules are not counted as extra failures, and Hexward's own Wazuh rules (100500–100599) are ignored so nothing is counted twice. Tested end to end with Wazuh 4.14.9.
- **Hexward Finding Schema JSON accepted.** Findings sent with `-syslog-format json` from any Hexward tool are understood exactly like the original key=value lines.

## 0.2.3 — 2026-10-28

- **Send findings to your SIEM, in every edition.** Findings now leave Loglight as [Hexward Finding Schema](https://github.com/nizartuanku/hexward-core/blob/main/SCHEMA.md) events (`hexward.finding/1`), the shape every Hexward tool shares. New outputs: an NDJSON file (`-export-file`) for a Wazuh agent, Splunk Universal Forwarder or Elastic Agent; Splunk HTTP Event Collector (`-hec-url`, `-hec-token-file`); syslog as HFS JSON or CEF (`-syslog-format json|cef`), RFC 5424 by default or 3164, over udp, tcp or tls with verified certificates; and webhook v2 (`-webhook-format v2`). Ready-made content: [hexward-wazuh](https://github.com/nizartuanku/hexward-wazuh) and [TA-hexward](https://github.com/nizartuanku/TA-hexward).
- **New `GET /api/findings/export`** returns the current findings as HFS `snapshot` events (NDJSON), so a SIEM can load existing state before it follows changes.
- **Evidence leaves redacted.** Secret-like evidence keys (password, token, secret, session, …) are dropped at every level before any export; `-export-evidence none` sends no evidence at all.
- **Fix: the webhook secret is now actually sent.** `-webhook-secret-file` sets the `X-Hexward-Token` header for webhook v1 and v2; before, the command line had no way to set it.
- Defaults are unchanged: `-syslog` still sends the original key=value lines (`-syslog-format kv`) and `-webhook` the original digest (`-webhook-format v1`), so Loglight and existing receivers keep working untouched.
- Docs: added `docs/samples/` — a real run of the README's headline scenario (port scan → brute force → successful login, one syslog source), findings exported exactly as the API returned them.
- Docs: English is the supported AI Assist language in this release. Bahasa Indonesia
  (`-ai-assist-lang id`) is an unsupported preview; more languages will be added based on demand.

## 0.2.2 — 2026-09-24

- **AI Assist (optional): an ✨ Explain button on every finding.** When Loglight is started
  with `-ai-assist-url`, a local [hexward-ai](https://github.com/nizartuanku/hexward-ai) sidecar
  explains a finding in plain language and lists what to verify. The engine remains the only
  source of findings and severity. Only one sanitised finding is sent (secret-like evidence keys
  are dropped). Any AI failure shows a quiet note and changes nothing. Free edition: a sidecar on
  the same host. Pro/Team: also a dedicated AI host or your own endpoint
  (`-ai-assist-key-file`). English or Bahasa Indonesia (`-ai-assist-lang`). New endpoints
  `GET /api/ai` and `POST /api/findings/explain`, covered by tests for: AI off, bad config,
  sanitising, tier gating, sidecar down, and bad requests.

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
