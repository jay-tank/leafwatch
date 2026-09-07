# USAGE

`leafwatch` turns certificate files (or a live TLS endpoint) into a sorted expiry
& health report. This guide covers inputs, the health model, and the CI gate.

## 1. Inputs

### File mode (offline, deterministic — the default)

Point `leafwatch` at any of:

- a **single file** — PEM or DER (`server.crt`, `cert.der`);
- a **bundle / fullchain** — one PEM file with several `CERTIFICATE` blocks;
  each is reported separately (labelled `path#1`, `path#2`, …);
- a **directory** — walked recursively; files ending in
  `.pem`/`.crt`/`.cer`/`.cert`/`.der`/`.ca`/`.chain` are read;
- **globs** — e.g. `leafwatch 'certs/*.pem'`.

PEM blocks that are not certificates (private keys, CSRs, DH params) are skipped,
so a combined key+cert file is fine. A file with no certificate, or an
unparseable file, exits `2`.

### Live mode (opt-in, network)

```bash
leafwatch --connect example.com:443
leafwatch --connect example.com:443,api.example.com:443 --timeout 5
```

`--connect` opens a TLS connection to each host and reports the certificate (and
any intermediates) it serves. The chain is **not verified** — the point is to
inspect whatever is served, including an expired or self-signed cert. If a host
cannot be reached, `leafwatch` exits `2`. This is the only feature that uses the
network; without `--connect` nothing leaves the machine.

You can mix modes — files and `--connect` in the same run are merged into one
report.

## 2. The health model

For each certificate, as of the current time:

| Flag | Condition |
| :--- | :--- |
| `EXPIRED` | now is after `notAfter`. |
| `NOT_YET_VALID` | now is before `notBefore`. |
| `EXPIRING` | valid, but `days_remaining < --warn` (default 30). |
| `SELF_SIGNED` | issuer DN equals subject DN **and** the signature verifies against the cert's own key (a DN-only match to a real CA is not counted). |
| `WEAK_KEY` | RSA or DSA key below 2048 bits. |
| `WEAK_SIG` | signature algorithm is MD2/MD5/SHA-1 based. |
| `SAN_COVERAGE_ENDING` | an expiring cert that carries SANs — a reminder those names lose coverage with it. |

`days_remaining` is whole 24-hour periods until `notAfter` and goes negative once
the cert is expired. Entries are sorted by `notAfter` ascending, so the soonest
expiry is always first.

Severity per cert: `crit` (expired / not-yet-valid), `warn` (expiring / weak /
self-signed), or `ok`.

## 3. Output

Default is a colored text report ending in a one-line summary. Use:

- `--no-color` for logs / non-TTY output;
- `--json` for the full machine-readable report — `generated_at`, `warn_days`,
  an `entries` array (each with `days_remaining`, `flags`, `severity`, …), and a
  `summary` roll-up. Feed it to `jq`, a dashboard, or an alerting rule.

```bash
leafwatch --json /etc/ssl/certs/ | jq '.summary'
```

## 4. Gating CI

By default `leafwatch` always exits `0` — it is a report. Turn it into a gate
with `--fail-on`:

```bash
# Fail only once something has actually lapsed (or a clock-skewed not-yet-valid).
leafwatch --fail-on expired /etc/ssl/certs/

# Fail earlier — anything within the warn window trips the build.
leafwatch --warn 45 --fail-on expiring /etc/ssl/certs/
```

| `--fail-on` | Exit 1 when the report contains |
| :--- | :--- |
| `expired` | any `EXPIRED` or `NOT_YET_VALID` cert |
| `expiring` | any `EXPIRED`, `NOT_YET_VALID`, or `EXPIRING` cert |

## 5. Exit codes

| Code | Meaning |
| :--- | :--- |
| `0` | Report produced; no `--fail-on` threshold met. |
| `1` | `--fail-on` threshold met. |
| `2` | Usage / bad input (no cert found, unreadable file, connect failure). |
