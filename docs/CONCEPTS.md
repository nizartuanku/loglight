# Loglight — Concepts

What this product is, what problem it solves, and why it works the way it does — written for
someone meeting the problem for the first time. The command reference is in the README; this
is the reasoning behind it.

*Hexward Labs · Nizar Tuanku — Cybersecurity. · last reviewed 12 September 2026*

---

## Logs are kept by everyone and read by no one

Every server writes an authentication log. Every firewall can send syslog. Every container runtime
has a log driver. In practice the whole lot is written to disk, rotated, and read exactly once — a
week after something happened, by someone trying to work out how.

The recommended fix is a SIEM: collect everything centrally, then write queries against it. That
advice is sound for an organisation with people whose job is to write those queries. For a team of
three that also handles the printers, a SIEM is a project with an indexing cluster at the end of
it, and the honest outcome is that it never starts.

What that team actually needs is much narrower. Not "search all logs", but "tell me if I am being
attacked right now, in a list short enough to read".

## Detections, not queries

Loglight ships a fixed set of detectors and runs them continuously as events stream in. Nobody
writes a rule. Each one exists because it corresponds to a step an intruder actually takes:

failed-login bursts from one address, or spread thinly across many, which is credential stuffing;
one source touching many distinct ports quickly, which is a scan; outbound volume far above a
host's own baseline, which is what exfiltration looks like from outside the file; a new privileged
account — `useradd`, a sudoers edit, Windows 4720 or 4728 — which is the classic persistence step;
an internal host calling one external endpoint at metronome-regular intervals, which is a command
and control heartbeat; and a host that starts accepting connections on a port it has never served
before.

Each finding shows the numbers it was computed from and what to do about it. There is no score
without an explanation behind it, because an unexplained score is something an operator learns to
click past.

## The part that makes it a SIEM rather than a rule set

Three of those detections firing separately is three notifications, and three notifications about
one intruder is how real intrusions get missed — each looks minor on its own.

Loglight keeps a small state machine per actor. A scan, then a brute force, then a login that
succeeds, all from one address within the linking window, is not three blips: it is one incident,
raised to Critical, above the severity of any of its parts, with the timeline of member events
attached.

The window is bounded on purpose — ten minutes between stages by default, with a cooldown so one
persistent actor does not produce the same incident every minute — and the state kept per actor is
bounded too. Correlation that is not bounded in time and entity stops being correlation and becomes
a machine for inventing connections. Every incident carries its members precisely so that a person
can disagree with it.

## What the tier table says, and what it does not

The correlation layer runs on every edition, free included. What a single-source free installation
cannot do is span *sources* — a chain that starts in your firewall's syslog and ends in a server's
auth log needs both of them connected, and the free edition holds one source at a time. So the
tier table reads *"✓ — full chain needs ≥2 sources"* rather than putting correlation behind the
paywall, because putting it there would not be true of the code.

This is worth saying out loud because the opposite is common: a feature listed as paid, present in
the free build, and quietly working. A tier table that does not match the binary is a small lie
that costs a customer's trust the first time they notice.

## Flows tell you what logs cannot

A log records what a machine chose to write down. A network flow record — NetFlow, IPFIX, sFlow
from the router or firewall already in the rack — records that a conversation happened at all: who
talked to whom, on which port, how many bytes. Malware does not have to write a log line; it does
have to make a connection.

That is where beaconing and new-service detection come from, and it is what the network map draws:
every host a node sized by its traffic, every conversation a link, anything with an active
detection glowing by severity, rendered offline with no external requests. External endpoints are
grouped per /24 once the internet side gets busy, so the picture stays readable rather than
becoming a hairball.

Flow records are metadata only. There is no packet content in them, which is both a privacy
property and a limitation worth knowing.

## Nothing leaves the machine

Loglight is a single binary or container on your own infrastructure. Your logs stay on it: no
telemetry, no shipping anything to us, and only the alert channels you configure make an outbound
connection. Licence validation is offline cryptography, so even a paid installation never phones
home, and the whole thing runs on an isolated management host.

Given that the product's input is a complete record of who logged in where and which host talked to
which endpoint, any other design would be asking for a lot of trust in exchange for very little.

## Where it stops

Loglight is a detection tool, not a forensics platform and not a searchable archive. It keeps
bounded recent events for context; if your requirement is "find every mention of this address
across two years", that is a different product and probably a real SIEM.

The detections are curated rules, not machine learning — which means they are explainable and
predictable, and also that they will not surprise you with something nobody thought of. Egress
baselines need a day or two to settle. The beaconing and new-service learning state lives in memory,
so a restart re-learns; a pattern that is still happening simply re-opens the same finding. Windows
events arrive through a syslog forwarder rather than a native agent, and your router has to be able
to export NetFlow or IPFIX — most business routers can, some ISP-supplied boxes cannot.

## The rest of the line reports here

Every other Hexward tool can emit its findings as syslog, which makes Loglight the collector end of
the line:

```
decoy      -syslog loglight.internal:5514
certlight  -syslog loglight.internal:5514 -syslog-network tcp
```

A canary token tripped by an address Loglight already watched port-scanning becomes one critical
incident with the whole chain attached, instead of two alerts somebody has to join up by hand. A
finding arriving on its own stays quiet — the tool that raised it has already alerted, and repeating
it here would recreate the duplicate-alert problem this exists to remove. Findings with no attacker
behind them, such as an expiring certificate, are ignored for correlation and belong on their own
product's dashboard. Available on every tier, free included, and there is nothing proprietary about
the format: any syslog receiver reads it.

## Try it on one source

```
curl -LO https://github.com/nizartuanku/loglight/releases/latest/download/loglight-free-0.2.0-linux-amd64.tar.gz
curl -LO https://github.com/nizartuanku/loglight/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS
tar xzf loglight-free-0.2.0-linux-amd64.tar.gz && cd loglight-0.2.0
./loglight
```

The dashboard is on `http://127.0.0.1:8427`. Add one source — a syslog listener, or a tail of
`/var/log/auth.log` — point a host at it, and the findings appear worst first. For the network map,
add a NetFlow/IPFIX source on UDP `0.0.0.0:2055` and aim your router's flow export at it.

The free Apache-2.0 edition runs one source with every detector and three days of retention, no
time limit. Pro and Team are paid licences on Whop —
[whop.com/nizar-tuanku/loglight](https://whop.com/nizar-tuanku/loglight?utm_source=github); nothing
on Whop is free, so try it here first.

Nizar Tuanku — Cybersecurity. · github.com/nizartuanku/loglight

## Terms used above

- Syslog — the long-standing standard for a machine to send a log line to a collector over the network.
- NetFlow / IPFIX — a router's summary of the conversations passing through it: addresses, ports, byte counts. No packet contents.
- Beaconing — malware checking in with its operator at a regular interval, which is easier to see in flow timing than in any log line.
- Kill chain — the ordered steps of an intrusion: look around, get in, stay in. Seeing the order is what turns separate alerts into one incident.
- Actor — the address or account a set of events is attributed to, and the key the correlator keeps its bounded state under.
