# examples

Sample certificates for trying `leafwatch`. They are throwaway certs for
demonstration only — **not** trusted by anything and safe to commit.

| File | What it shows |
| :--- | :--- |
| `healthy.pem` | A long-lived, CA-issued EC leaf — clean, no flags. |
| `expired.pem` | A certificate whose validity ended in 2023 → `EXPIRED`. |
| `weak-selfsigned.pem` | A 1024-bit RSA, SHA-1, self-signed cert → `SELF_SIGNED` + `WEAK_KEY` + `WEAK_SIG`. |
| `fullchain.pem` | A leaf followed by its issuing CA (a bundle) — parsed as two entries. |

Run the whole folder:

```bash
leafwatch examples/
```

Gate a build on anything already expired:

```bash
leafwatch --fail-on expired examples/   # exit 1
```

Machine-readable:

```bash
leafwatch --json examples/healthy.pem
```

Regenerating these fixtures is not required, but they were produced with the Go
standard library (`crypto/x509`) so no external tooling (OpenSSL, etc.) is
needed to reproduce equivalents.
