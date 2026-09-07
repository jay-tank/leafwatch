# leafwatch

**Report TLS/X.509 certificate expiry and health so a renewal never surprises you — offline, from your cert files.**

> 📖 Read the write-up: [leafwatch](https://jaytank.hashnode.dev/leafwatch-tls-cert-expiry-monitor)

`leafwatch` parses the certificates you point it at — PEM or DER files, a
directory of them, a bundle / fullchain, or globs — and prints one clear report:
for each cert, its **subject and SANs, issuer, validity window, days remaining**,
key type/size, signature algorithm, and a set of **health flags**. Entries are
sorted by **soonest expiry first**, so the thing about to break is at the top.

It reads certificates with the Go standard library and, in file mode, makes
**no network calls** and is fully deterministic. An **opt-in** `--connect`
mode fetches the certificate a live host serves so you can inspect production
without copying files around.

```
leafwatch  TLS/X.509 certificate report  (warn < 30d)

● legacy.example.com
    source   examples/expired.pem
    issuer   Example Test Root CA
    key/sig  RSA-2048, SHA256-RSA
    valid    2022-01-01  →  2023-06-01   (EXPIRED 1193 day(s) ago)
    sans     legacy.example.com
    flags    EXPIRED

● internal.example.local
    source   examples/weak-selfsigned.pem
    issuer   internal.example.local
    key/sig  RSA-1024, SHA1-RSA
    valid    2025-01-01  →  2035-01-01   (3038 days left)
    sans     internal.example.local
    flags    SELF_SIGNED  WEAK_KEY  WEAK_SIG

summary 2 cert(s): 0 ok, 1 expired, 1 weak-key, 1 weak-sig, 1 self-signed
```

## Why

An expired TLS certificate is one of the most **preventable** production
incidents there is — the fix is a calendar reminder, yet outages from a lapsed
cert keep happening because the expiry lives in a file nobody looks at until the
pager goes off. `leafwatch` turns that invisible date into something you can put
in front of your eyes, pipe into CI, or run over a directory of certs in a single
command — with no agent, no dashboard, and nothing leaving the machine.

## Install

```bash
go install github.com/jay-tank/leafwatch@latest
```

Or build from source:

```bash
git clone https://github.com/jay-tank/leafwatch
cd leafwatch
go build -o leafwatch .
```

## Usage

```bash
# A single certificate
leafwatch server.crt

# A whole directory of certs (walks .pem/.crt/.cer/.cert/.der/.ca/.chain)
leafwatch /etc/ssl/certs/

# A bundle / fullchain — every certificate in it is reported
leafwatch fullchain.pem

# Warn earlier (60 days) and emit JSON for a dashboard
leafwatch --warn 60 --json /etc/ssl/certs/

# CI gate: fail the build if anything is already expired
leafwatch --fail-on expired /etc/ssl/certs/

# Opt-in live check of what a host actually serves (network)
leafwatch --connect example.com:443,api.example.com:443
```

### What it reports

Per certificate:

| Field | Meaning |
| :--- | :--- |
| subject / SANs | Common name and the DNS/IP/URI/email subject-alternative names. |
| issuer | Who signed it. |
| notBefore / notAfter | The validity window. |
| **days remaining** | Whole days until `notAfter` (negative once expired). |
| key / sig | Key type and size (e.g. `RSA-2048`, `ECDSA-256`) and signature algorithm. |
| flags | The health findings below. |

### Health flags

| Flag | Fires when |
| :--- | :--- |
| `EXPIRED` | `notAfter` is in the past. |
| `EXPIRING` | Still valid but fewer than `--warn` days remain (default 30). |
| `NOT_YET_VALID` | `notBefore` is in the future (clock skew or premature deploy). |
| `SELF_SIGNED` | The certificate is its own issuer (verified by signature, not just DN). |
| `WEAK_KEY` | RSA/DSA key smaller than 2048 bits. |
| `WEAK_SIG` | Signed with SHA-1 or MD5 (collision-broken). |
| `SAN_COVERAGE_ENDING` | Context flag on an expiring cert that carries SANs — those names lose coverage with it. |

### Flags

| Flag | Meaning |
| :--- | :--- |
| `--warn N` | Days-remaining threshold for `EXPIRING` (default `30`). |
| `--fail-on WHICH` | Exit `1` when the report contains `expired` (also not-yet-valid) or `expiring` (expired + expiring). Default: always exit `0`. |
| `--connect LIST` | Comma-separated `host:port` to fetch live over TLS (opt-in network). |
| `--timeout N` | Per-host dial timeout in seconds (default `8`). |
| `--json` | Machine-readable JSON report. |
| `--no-color` | Disable ANSI colors. |
| `--version`, `-h/--help` | Version / help. |

### Exit codes

- `0` — a report was produced (and no `--fail-on` threshold was met).
- `1` — a `--fail-on` threshold was met (use this to gate CI).
- `2` — usage or bad input (unreadable file, no certificate found, connect failure).

## Live mode is opt-in

Everything except `--connect` is **offline**. `--connect host:443` is the only
code path that touches the network: it opens a TLS connection and reads the
certificate the server presents **without verifying the chain** — on purpose, so
an already-expired or self-signed cert is still inspected and reported rather than
rejected at the handshake. `leafwatch` never trusts these certs for anything; it
only describes them (the same posture as `openssl s_client -showcerts`).

## Distinct from

`leafwatch` reports on **actual X.509 certificates** — their real expiry and
health. It is deliberately not a source-code linter: it does not grep your code
for `InsecureSkipVerify`/`verify=False` (that is a different kind of tool), and it
is not a secret-rotation checker. It is the **producer** that answers one
question — *"which of my certs is about to expire, and which are unhealthy?"* —
and prints the answer.

## License

MIT © Jay Tank
