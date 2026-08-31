package cert

import (
	"bytes"
	"crypto/dsa" //nolint:staticcheck // only used to read key size for a weak-key check
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"net"
	"sort"
	"strings"
	"time"
)

// weak signature algorithms (SHA-1 / MD5 based) — collision-broken, must go.
var weakSigAlgos = map[x509.SignatureAlgorithm]bool{
	x509.MD2WithRSA:    true,
	x509.MD5WithRSA:    true,
	x509.SHA1WithRSA:   true,
	x509.DSAWithSHA1:   true,
	x509.ECDSAWithSHA1: true,
}

// Analyze turns parsed certificates into a full Report as of the instant now,
// flagging health issues and sorting entries by soonest expiry first.
func Analyze(parsed []Parsed, now time.Time, warnDays int) Report {
	rep := Report{
		GeneratedAt: now,
		WarnDays:    warnDays,
		Entries:     make([]Entry, 0, len(parsed)),
	}
	for _, p := range parsed {
		rep.Entries = append(rep.Entries, analyzeOne(p, now, warnDays))
	}

	// Sort by soonest expiry (notAfter ascending); tie-break on source for
	// deterministic output.
	sort.SliceStable(rep.Entries, func(i, j int) bool {
		if !rep.Entries[i].NotAfter.Equal(rep.Entries[j].NotAfter) {
			return rep.Entries[i].NotAfter.Before(rep.Entries[j].NotAfter)
		}
		return rep.Entries[i].Source < rep.Entries[j].Source
	})

	for _, e := range rep.Entries {
		rep.Summary.Total++
		switch {
		case e.has(FlagExpired):
			rep.Summary.Expired++
		case e.has(FlagExpiring):
			rep.Summary.Expiring++
		}
		if e.has(FlagNotYetValid) {
			rep.Summary.NotYetValid++
		}
		if e.has(FlagWeakKey) {
			rep.Summary.WeakKey++
		}
		if e.has(FlagWeakSig) {
			rep.Summary.WeakSig++
		}
		if e.has(FlagSelfSigned) {
			rep.Summary.SelfSigned++
		}
		if e.Severity == SevOK {
			rep.Summary.OK++
		}
	}
	return rep
}

func analyzeOne(p Parsed, now time.Time, warnDays int) Entry {
	c := p.Cert
	e := Entry{
		Source:     p.Source,
		Subject:    nameOf(c.Subject.String(), c.Subject.CommonName),
		Issuer:     nameOf(c.Issuer.String(), c.Issuer.CommonName),
		SANs:       sans(c),
		NotBefore:  c.NotBefore.UTC(),
		NotAfter:   c.NotAfter.UTC(),
		SigAlgo:    c.SignatureAlgorithm.String(),
		IsCA:       c.IsCA,
		SelfSigned: isSelfSigned(c),
	}
	e.KeyType, e.KeyBits = keyInfo(c)

	// Days remaining: whole 24h periods until notAfter (negative once expired).
	e.DaysRemaining = int(c.NotAfter.UTC().Sub(now).Hours() / 24)

	var flags []Flag
	switch {
	case now.After(c.NotAfter):
		flags = append(flags, FlagExpired)
	case now.Before(c.NotBefore):
		flags = append(flags, FlagNotYetValid)
	case e.DaysRemaining < warnDays:
		flags = append(flags, FlagExpiring)
		if len(e.SANs) > 0 {
			flags = append(flags, FlagSANExpiring)
		}
	}
	if e.SelfSigned {
		flags = append(flags, FlagSelfSigned)
	}
	if isWeakKey(e.KeyType, e.KeyBits) {
		flags = append(flags, FlagWeakKey)
	}
	if weakSigAlgos[c.SignatureAlgorithm] {
		flags = append(flags, FlagWeakSig)
	}
	e.Flags = flags
	e.Severity = severity(flags)
	return e
}

func severity(flags []Flag) Severity {
	sev := SevOK
	for _, f := range flags {
		switch f {
		case FlagExpired, FlagNotYetValid:
			return SevCrit
		case FlagExpiring, FlagWeakKey, FlagWeakSig, FlagSelfSigned:
			sev = SevWarn
		}
	}
	return sev
}

// isSelfSigned reports whether the certificate is signed by its own key. It
// verifies the signature directly (rather than via CheckSignatureFrom, which
// additionally requires the signer to be a CA) so a self-signed *leaf* — the
// common "self-signed server cert" — is still detected, while a cert that only
// copies a real CA's DN is not mistaken for self-signed.
func isSelfSigned(c *x509.Certificate) bool {
	if !strings.EqualFold(c.Issuer.String(), c.Subject.String()) {
		return false
	}
	err := c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature)
	if err == nil {
		return true
	}
	// CheckSignature refuses to verify SHA-1/MD5 (returns InsecureAlgorithmError)
	// rather than reporting a mismatch. A weak-signed cert is exactly the kind we
	// still want to flag, so fall back to the key-identifier / DN evidence.
	var insecure x509.InsecureAlgorithmError
	if errors.As(err, &insecure) {
		if len(c.SubjectKeyId) > 0 && len(c.AuthorityKeyId) > 0 {
			return bytes.Equal(c.SubjectKeyId, c.AuthorityKeyId)
		}
		return true // issuer == subject and no contradicting key IDs
	}
	return false
}

func keyInfo(c *x509.Certificate) (string, int) {
	switch pub := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", pub.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", pub.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "Ed25519", 0
	case *dsa.PublicKey:
		if pub.P != nil {
			return "DSA", pub.P.BitLen()
		}
		return "DSA", 0
	default:
		return "unknown", 0
	}
}

// isWeakKey flags RSA/DSA keys below 2048 bits. EC and Ed25519 keys of any
// standard curve are considered strong.
func isWeakKey(keyType string, bits int) bool {
	switch keyType {
	case "RSA", "DSA":
		return bits < 2048
	default:
		return false
	}
}

func sans(c *x509.Certificate) []string {
	var out []string
	out = append(out, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		out = append(out, ip.String())
	}
	for _, u := range c.URIs {
		out = append(out, u.String())
	}
	out = append(out, c.EmailAddresses...)
	return out
}

// nameOf prefers the common name for readability, falling back to the full DN.
func nameOf(dn, cn string) string {
	if cn != "" {
		return cn
	}
	if dn != "" {
		return dn
	}
	return "(no subject)"
}

// hostMatchesSAN is a small helper reused by the connect path for reporting.
func hostMatchesSAN(host string, sans []string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if ip := net.ParseIP(host); ip != nil {
		for _, s := range sans {
			if strings.EqualFold(s, host) {
				return true
			}
		}
		return false
	}
	for _, s := range sans {
		s = strings.ToLower(s)
		if s == host {
			return true
		}
		if strings.HasPrefix(s, "*.") && strings.HasSuffix(host, s[1:]) {
			// wildcard matches exactly one left-most label
			left := strings.TrimSuffix(host, s[1:])
			if left != "" && !strings.Contains(strings.TrimSuffix(left, "."), ".") {
				return true
			}
		}
	}
	return false
}
