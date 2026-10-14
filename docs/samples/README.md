# Sample run

This is real Loglight output, not a mockup. One syslog source received ten
distinct port-scan hits, eight failed SSH logins, then one that worked — all
from the same address, in that order — and Loglight's own detection and
correlation engine turned that into three open findings and one escalated
critical incident, exported exactly as the API returned them. Nothing in
[`sample-findings.json`](sample-findings.json),
[`sample-incidents.json`](sample-incidents.json) or
[`sample-summary.json`](sample-summary.json) was hand-edited.

**Source:** a lab instance of Loglight 0.2.2, free edition (1 source,
3-day retention), with AI Assist turned off so this sample shows the
detection/correlation engine on its own, not a model's narration. The one
ingest source is a `syslog` listener (`sample-syslog`, UDP) — free tier's
exact limit. `GET /api/loglight/sources` in
[`sample-sources.json`](sample-sources.json) shows `"targets":1,"max_targets":1`.

## What was sent

The free edition's own README demo (`docs/demo.gif`) describes this exact
scenario — a port sweep, then failed logins, then one that works, all from
one address — so this sample reproduces it for real rather than just citing
the GIF. Real RFC 5424 syslog datagrams were sent to the listener with the
standard Linux `logger` utility (`logger -n <host> -P <port> -d`, which
frames and timestamps the message for real — only the tag and body text
were authored here), shaped exactly like what a Linux firewall and an
OpenSSH server actually emit:

| Stage | What was sent | Count |
|---|---|---|
| Port scan | `kernel`-tagged `[UFW BLOCK] ... SRC=203.0.113.77 ... DPT=<port>` lines, 10 distinct destination ports | 10 |
| Brute force | `sshd`-tagged `Failed password for invalid user ops-admin from 203.0.113.77 port <n> ssh2` | 8 |
| Success | `sshd`-tagged `Accepted password for ops-admin from 203.0.113.77 port 50099 ssh2` | 1 |

`203.0.113.77` is from `203.0.113.0/24`, the block IANA/RFC 5737 reserves for
documentation examples — not a real attacker, so nobody's actual address is
named here. This is generated traffic against a lab instance, not a capture
of a real intrusion or a change to DevNet's live firewall/syslog routing:
the host's own firewall and syslog configuration were left untouched, and
the listener only accepted datagrams a test script sent it directly on a
test port — the same network path a router or appliance uses when pointed
at Loglight in production.

## What Loglight found

**3 open findings: 1 critical, 1 high, 1 medium** — the exact counts in
`sample-summary.json`.

| Check | Severity | Count | Title |
|---|---|---|---|
| `detect.scan` | medium | 10 | Port scan: 203.0.113.77 hit 10 distinct ports |
| `detect.brute_force` | high | 8 | Brute force: 8 failed logins from 203.0.113.77 |
| `incident.killchain` | **critical** | 3 | Likely intrusion from 203.0.113.77: scan → brute force → successful login |

The scan and brute-force findings fired at exactly the thresholds that
trigger them (`ScanPorts`=10 within 30s, `BruteFailures`=8 within 60s —
both untouched defaults). The killchain incident is the correlator doing
its one job: it exists only because the same actor (`203.0.113.77`) crossed
both thresholds and then authenticated successfully inside the 10-minute
correlation window — its `evidence` in `sample-findings.json` lists the
three member stages with their real timestamps, not a summary written for
this document.

## Reading the evidence honestly

Every finding's `evidence` field in `sample-findings.json` carries the raw
syslog lines Loglight actually parsed — full RFC 5424 framing, including the
`timeQuality` structured-data block `logger` adds on its own — nothing is
reformatted or summarized away.

This sample does not show file tail, journald, Docker log, or NetFlow/IPFIX
ingest (the other five source types — see `BuildSourceWith` in
`loglight/sources.go`), the auth-failure spike detector (needs failures from
≥3 distinct sources; this sample uses one source on purpose to keep the kill
chain readable), exfiltration, beaconing or new-service detection (all
flow-based, needing NetFlow/IPFIX input), the 3D network map, or AI Assist
narration — those exist and are covered by the engine's own unit tests
(`detect/detect_test.go`, `detect/traffic_test.go`,
`correlate/correlate_test.go`); this sample is one real run of the headline
scenario the product's own demo already describes, not a tour of every
feature.
