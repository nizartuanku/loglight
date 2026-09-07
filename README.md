# Loglight

**Self-hosted threat detection from your logs and network flows — brute force, scans, exfiltration, beaconing, and correlated kill-chains, with a 3D map of your network.**

![Loglight merging a port scan, a brute force and a successful login from one source into a single critical incident](docs/demo.gif)

*Real run: a port sweep, then failed logins, then one that works — all from the same address, 30
seconds end to end. Three separate detections become one CRITICAL incident with the kill chain
attached, instead of three alerts you have to correlate yourself.*

You have logs. `auth.log`, your firewall's syslog, a few Windows boxes, some
containers. Nobody reads them — so if you're being brute-forced or something is
beaconing out, you find out a week too late. A full SIEM (Splunk, Elastic) is a
project you don't have time for. Loglight is the **SIEM-lite** for that gap.

Point your logs at it and Loglight runs curated, high-signal detections and shows
a short, ranked list of *what looks like an attack*:

- **Brute force / credential stuffing** — failed-login bursts per IP, or distributed across many.
- **Port & host scans** — one source touching many distinct ports fast.
- **Abnormal egress** — outbound volume far above a host's baseline (possible exfiltration).
- **New privileged accounts** — `useradd`, sudoers/group changes, Windows 4720/4728 — the classic persistence step.
- **Beaconing** *(v0.2, from flows)* — an internal host calling one external endpoint at a metronome-regular interval: the C2 heartbeat.
- **New services** *(v0.2, from flows)* — a host starts accepting connections on a port never seen for it before.

> The SIEM part: it **correlates**. A scan, then a brute force, then a successful
> login from the same source isn't three blips — it's one **CRITICAL kill-chain
> incident**, escalated above its parts, with the full timeline.

Every finding shows the numbers behind it and the fix — it ranks and explains, it
doesn't hand you a black box. Under the hood: bounded-state streaming detectors +
a per-actor correlation state machine — turning an unbounded log firehose into a
small, explained, ranked set of incidents without a query language.

## Ingest sources

syslog (UDP/TCP, RFC3164 & RFC5424), tailed files (rotation-safe), systemd
journald, Docker containers, Windows Event Log (via a syslog forwarder), and —
new in v0.2 — **NetFlow v5 / v9 / IPFIX** flow export from the router or
firewall you already own (MikroTik, pfSense, FortiGate, Cisco, Ubiquiti). All
normalize to one event model, so every detector works across every source.

## 3D Network Map (v0.2)

Feed Loglight a NetFlow/IPFIX source and it draws your network as a live,
rotatable **3D map** — every host a node sized by traffic, every conversation a
link, and any host with an active detection glowing by severity. Rendered fully
offline with a vendored WebGL engine: no CDN, no external requests, true to the
self-hosted promise. External endpoints auto-group per /24 when the internet
side gets busy, so the picture stays readable. Flow records are **metadata
only** (who talked to whom, which port, how many bytes) — never packet
contents.

## Self-hosted by design

Runs as a single binary or container on your infrastructure. **Your logs never
leave the machine** — no telemetry, no shipping to us, only the alert channels you
configure reach out. Offline license validation — no phone-home, ever. Safe to
run on an isolated management host.

## Quick start

```bash
# Docker — build the image from this repo first; there is no published loglight image
# (map any syslog listener ports you configure)
docker build -t loglight .
docker run -d -p 127.0.0.1:8427:8427 -p 5514:5514/udp -v loglight-data:/data loglight

# Or the bare binary
./loglight
```

Open `http://127.0.0.1:8427`, add a log source (start with a syslog listener or
tail `/var/log/auth.log`), point your hosts at it, and watch the findings — worst
first. For the 3D map, add a **NetFlow / IPFIX** source (e.g. UDP `0.0.0.0:2055`),
point your router's flow export at it, and open **Network Map** in the header.

## Free vs paid

This repository is the **free edition**: **1 source**, all seven detections,
webhook notifications, 3-day retention, self-hosted, no telemetry. It runs the
same detection engine as the paid edition.

The paid edition ([Loglight on Whop](https://whop.com/nizar-tuanku/loglight?utm_source=github)) lifts the caps
and adds the correlation layer and team features:

| | Free | Pro | Team |
|---|---|---|---|
| Sources | 1 | 10 | unlimited |
| Detections (brute, scan, exfil, new-admin, spike, beaconing, new-service) | ✓ | ✓ | ✓ |
| Kill-chain correlation | ✓ — full chain needs ≥2 sources | ✓ | ✓ |
| Custom thresholds · scan-now | — | ✓ | ✓ |
| Notifications | webhook, syslog | + email/Slack/Telegram | + PagerDuty/MS Teams |
| Retention | 3 days | 30 days | unlimited (disk-bound) |
| Multi-user | — | — | ✓ |
| Support | community | email | priority |

**Whop sells paid licences only.** Free: github.com/nizartuanku/loglight — this repository is the free edition, Apache-2.0, no time limit; nothing on Whop is free, so try it here first.

Licensing is offline: an expired or absent key simply returns to free limits.

## Build from source

```bash
git clone https://github.com/nizartuanku/loglight
cd loglight
CGO_ENABLED=1 go build -o loglight ./cmd/loglight
go test ./...
```

Requires Go 1.24+. CGO is on for the SQLite driver.

## Working with the other Hexward tools

Loglight is the collector end of the line. Every other Hexward tool can emit
its findings as syslog, so point them here:

```bash
decoy      -syslog loglight.internal:5514        # udp by default
certlight  -syslog loglight.internal:5514 -syslog-network tcp
```

then add a matching source in Loglight:

```bash
curl -X POST localhost:8427/api/loglight/source \
  -H 'Content-Type: application/json' \
  -d '{"name":"hexward-bus","type":"syslog","params":{"udp":"0.0.0.0:5514"}}'
```

Their findings then sit next to Loglight's own detections, and high or critical
ones carrying a source address join that actor's timeline. A Decoy trip from an
address Loglight already saw port-scanning is raised as one critical incident
with the whole chain attached, rather than two alerts you have to join up
yourself.

A finding on its own stays quiet: the tool that raised it already alerted, and
repeating it here would be the duplicate-alert problem this exists to remove.
Findings with no attacker — an expiring certificate, a shadowed firewall rule —
are ignored for correlation and belong on their own product's dashboard.

Loglight can emit its own incidents the same way, so it can forward to a
collector upstream. There is nothing Hexward-specific about the format: any
syslog receiver reads it.

Available on every tier, free included.

## Honest limits

Loglight is a **detection** tool, not a forensics platform or a searchable log
archive — it keeps bounded recent events for context, not a long-term store.
Detections are curated, tuned rules (not ML/UEBA); correlation is time- and
entity-bounded heuristics, and every incident shows its member events so you can
judge. Windows ingest is via a syslog forwarder (not a native agent). Flow
telemetry is sampled/aggregated metadata, not packet capture — egress baselines
need a day or two to settle, and the beacon/new-service learning state is
in-memory, so a restart re-learns (a persisting pattern simply re-opens the same
finding). Your exporter must support NetFlow/IPFIX (most business routers do;
some ISP boxes don't — pfSense or MikroTik in front solves it). It's the
high-signal self-hosted layer for teams that have no SIEM — not a replacement for
a full SOC at scale.

## License

Apache-2.0. See [LICENSE.txt](LICENSE.txt).

Part of the **Hexward** line of self-hosted security tools.
