package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fixedNow is the reference instant every test analyses "as of".
var fixedNow = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

type genOpts struct {
	cn        string
	dns       []string
	notBefore time.Time
	notAfter  time.Time
	rsaBits   int                     // if >0, use an RSA key of this size
	ec        elliptic.Curve          // else an EC key on this curve
	sigAlgo   x509.SignatureAlgorithm // zero = default for the key
	selfCA    *caPair                 // explicit signer
	self      bool                    // force a self-signed cert (its own issuer)
}

type caPair struct {
	cert *x509.Certificate
	key  interface{}
}

// sharedCA is a lazily-built issuer so leaves are NOT self-signed by default.
var sharedCAPair *caPair

func sharedCA(t *testing.T) *caPair {
	t.Helper()
	if sharedCAPair == nil {
		ca := makeCert(t, genOpts{cn: "leafwatch Test CA", notBefore: day(-30),
			notAfter: day(3650), rsaBits: 2048, self: true})
		sharedCAPair = &caPair{cert: ca, key: keyByCert[ca]}
	}
	return sharedCAPair
}

// makeCert builds a certificate per opts and returns its parsed form.
func makeCert(t *testing.T, o genOpts) *x509.Certificate {
	t.Helper()

	var pub, priv interface{}
	if o.rsaBits > 0 {
		k, err := rsa.GenerateKey(rand.Reader, o.rsaBits)
		if err != nil {
			t.Fatalf("rsa keygen: %v", err)
		}
		pub, priv = &k.PublicKey, k
	} else {
		curve := o.ec
		if curve == nil {
			curve = elliptic.P256()
		}
		k, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatalf("ec keygen: %v", err)
		}
		pub, priv = &k.PublicKey, k
	}

	// Decide the signer: an explicit CA, self-signed on request, else the
	// shared test CA (so ordinary leaves are not flagged self-signed).
	ca := o.selfCA
	if ca == nil && !o.self {
		ca = sharedCA(t)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: o.cn},
		DNSNames:              o.dns,
		NotBefore:             o.notBefore,
		NotAfter:              o.notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  ca == nil,
	}
	if o.sigAlgo != 0 {
		tmpl.SignatureAlgorithm = o.sigAlgo
	}

	signerCert := tmpl
	signerKey := priv
	if ca != nil {
		signerCert = ca.cert
		signerKey = ca.key
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, pub, signerKey)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	// stash the private key on the returned cert via a side table when used as CA
	keyByCert[c] = priv
	return c
}

var keyByCert = map[*x509.Certificate]interface{}{}

func day(n int) time.Time { return fixedNow.Add(time.Duration(n) * 24 * time.Hour) }

func TestDaysRemainingAndExpiryFlags(t *testing.T) {
	cases := []struct {
		name      string
		notAfter  time.Time
		wantDays  int
		wantFlags []Flag
	}{
		{"healthy", day(400), 400, nil},
		{"expiring", day(10), 10, []Flag{FlagExpiring}},
		{"boundary_29", day(29), 29, []Flag{FlagExpiring}},
		{"boundary_30_ok", day(30), 30, nil},
		{"expired", day(-5), -5, []Flag{FlagExpired}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := makeCert(t, genOpts{cn: "example.com", dns: []string{"example.com"},
				notBefore: day(-1), notAfter: tc.notAfter, rsaBits: 2048})
			rep := Analyze([]Parsed{{Source: "t", Cert: c}}, fixedNow, 30)
			e := rep.Entries[0]
			if e.DaysRemaining != tc.wantDays {
				t.Errorf("days = %d, want %d", e.DaysRemaining, tc.wantDays)
			}
			for _, want := range tc.wantFlags {
				if !e.has(want) {
					t.Errorf("missing flag %s in %v", want, e.Flags)
				}
			}
			if len(tc.wantFlags) == 0 && e.Severity != SevOK {
				t.Errorf("expected ok severity, got %s (flags %v)", e.Severity, e.Flags)
			}
		})
	}
}

func TestNotYetValid(t *testing.T) {
	c := makeCert(t, genOpts{cn: "future.com", notBefore: day(5), notAfter: day(400), rsaBits: 2048})
	e := Analyze([]Parsed{{Source: "t", Cert: c}}, fixedNow, 30).Entries[0]
	if !e.has(FlagNotYetValid) {
		t.Fatalf("expected NOT_YET_VALID, got %v", e.Flags)
	}
	if e.Severity != SevCrit {
		t.Errorf("severity = %s, want crit", e.Severity)
	}
}

func TestWeakKey(t *testing.T) {
	weak := makeCert(t, genOpts{cn: "weak", notBefore: day(-1), notAfter: day(400), rsaBits: 1024})
	strong := makeCert(t, genOpts{cn: "strong", notBefore: day(-1), notAfter: day(400), rsaBits: 2048})

	we := Analyze([]Parsed{{Source: "w", Cert: weak}}, fixedNow, 30).Entries[0]
	if !we.has(FlagWeakKey) || we.KeyBits != 1024 {
		t.Errorf("expected WEAK_KEY at 1024, got flags=%v bits=%d", we.Flags, we.KeyBits)
	}
	se := Analyze([]Parsed{{Source: "s", Cert: strong}}, fixedNow, 30).Entries[0]
	if se.has(FlagWeakKey) {
		t.Errorf("2048-bit RSA should not be weak: %v", se.Flags)
	}
}

func TestECKeyNotWeak(t *testing.T) {
	c := makeCert(t, genOpts{cn: "ec", notBefore: day(-1), notAfter: day(400), ec: elliptic.P256()})
	e := Analyze([]Parsed{{Source: "e", Cert: c}}, fixedNow, 30).Entries[0]
	if e.KeyType != "ECDSA" || e.has(FlagWeakKey) {
		t.Errorf("EC P-256 should be strong: type=%s flags=%v", e.KeyType, e.Flags)
	}
}

func TestWeakSig(t *testing.T) {
	c := makeCert(t, genOpts{cn: "sha1", notBefore: day(-1), notAfter: day(400),
		rsaBits: 2048, sigAlgo: x509.SHA1WithRSA})
	e := Analyze([]Parsed{{Source: "t", Cert: c}}, fixedNow, 30).Entries[0]
	if !e.has(FlagWeakSig) {
		t.Fatalf("expected WEAK_SIG for SHA1WithRSA, got %v (%s)", e.Flags, e.SigAlgo)
	}
}

func TestSelfSigned(t *testing.T) {
	self := makeCert(t, genOpts{cn: "self", notBefore: day(-1), notAfter: day(400), rsaBits: 2048, self: true})
	e := Analyze([]Parsed{{Source: "t", Cert: self}}, fixedNow, 30).Entries[0]
	if !e.SelfSigned || !e.has(FlagSelfSigned) {
		t.Fatalf("expected self-signed, got %v", e.Flags)
	}

	// CA-signed leaf must NOT be self-signed.
	ca := makeCert(t, genOpts{cn: "My CA", notBefore: day(-2), notAfter: day(800), rsaBits: 2048})
	leaf := makeCert(t, genOpts{cn: "leaf.com", notBefore: day(-1), notAfter: day(400),
		rsaBits: 2048, selfCA: &caPair{cert: ca, key: keyByCert[ca]}})
	le := Analyze([]Parsed{{Source: "t", Cert: leaf}}, fixedNow, 30).Entries[0]
	if le.SelfSigned || le.has(FlagSelfSigned) {
		t.Errorf("CA-signed leaf wrongly flagged self-signed: %v", le.Flags)
	}
}

func TestSelfSignedWeakSigLeaf(t *testing.T) {
	// A self-signed, non-CA leaf with a SHA-1 signature: must still be flagged
	// self-signed even though CheckSignature refuses SHA-1.
	c := makeCert(t, genOpts{cn: "internal.local", notBefore: day(-1), notAfter: day(400),
		rsaBits: 2048, sigAlgo: x509.SHA1WithRSA, self: true})
	e := Analyze([]Parsed{{Source: "t", Cert: c}}, fixedNow, 30).Entries[0]
	if !e.SelfSigned || !e.has(FlagSelfSigned) {
		t.Errorf("self-signed SHA-1 leaf not flagged self-signed: %v", e.Flags)
	}
	if !e.has(FlagWeakSig) {
		t.Errorf("expected WEAK_SIG too: %v", e.Flags)
	}
}

func TestSortBySoonestExpiry(t *testing.T) {
	late := makeCert(t, genOpts{cn: "late", notBefore: day(-1), notAfter: day(300), rsaBits: 2048})
	soon := makeCert(t, genOpts{cn: "soon", notBefore: day(-1), notAfter: day(10), rsaBits: 2048})
	mid := makeCert(t, genOpts{cn: "mid", notBefore: day(-1), notAfter: day(100), rsaBits: 2048})

	rep := Analyze([]Parsed{
		{Source: "late", Cert: late},
		{Source: "soon", Cert: soon},
		{Source: "mid", Cert: mid},
	}, fixedNow, 30)

	got := []string{rep.Entries[0].Subject, rep.Entries[1].Subject, rep.Entries[2].Subject}
	want := []string{"soon", "mid", "late"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("sort order = %v, want %v", got, want)
		}
	}
}

func TestSummaryCounts(t *testing.T) {
	expired := makeCert(t, genOpts{cn: "e", notBefore: day(-10), notAfter: day(-1), rsaBits: 2048})
	expiring := makeCert(t, genOpts{cn: "x", notBefore: day(-1), notAfter: day(5), rsaBits: 2048})
	ok := makeCert(t, genOpts{cn: "o", notBefore: day(-1), notAfter: day(400), rsaBits: 2048})

	rep := Analyze([]Parsed{
		{Source: "e", Cert: expired},
		{Source: "x", Cert: expiring},
		{Source: "o", Cert: ok},
	}, fixedNow, 30)

	s := rep.Summary
	if s.Total != 3 || s.Expired != 1 || s.Expiring != 1 || s.OK < 1 {
		t.Fatalf("summary = %+v", s)
	}
}

func TestParseBundleAndSkipKey(t *testing.T) {
	dir := t.TempDir()
	c1 := makeCert(t, genOpts{cn: "one.com", notBefore: day(-1), notAfter: day(100), rsaBits: 2048})
	c2 := makeCert(t, genOpts{cn: "two.com", notBefore: day(-1), notAfter: day(200), rsaBits: 2048})

	// Bundle: a private-key PEM block (must be skipped) + two certs.
	var buf []byte
	buf = append(buf, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not-a-real-key")})...)
	buf = append(buf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c1.Raw})...)
	buf = append(buf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c2.Raw})...)

	path := filepath.Join(dir, "fullchain.pem")
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseFile(path)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if len(parsed) != 2 {
		t.Fatalf("expected 2 certs from bundle, got %d", len(parsed))
	}
	if parsed[0].Source == parsed[1].Source {
		t.Errorf("bundle sources should be distinct: %s", parsed[0].Source)
	}
}

func TestParseDER(t *testing.T) {
	dir := t.TempDir()
	c := makeCert(t, genOpts{cn: "der.com", notBefore: day(-1), notAfter: day(100), rsaBits: 2048})
	path := filepath.Join(dir, "cert.der")
	if err := os.WriteFile(path, c.Raw, 0o600); err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseFile(path)
	if err != nil || len(parsed) != 1 {
		t.Fatalf("DER parse: err=%v n=%d", err, len(parsed))
	}
	if parsed[0].Cert.Subject.CommonName != "der.com" {
		t.Errorf("wrong subject: %s", parsed[0].Cert.Subject.CommonName)
	}
}

func TestParseBadInput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "garbage.pem")
	if err := os.WriteFile(path, []byte("this is not a certificate at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseFile(path); err == nil {
		t.Fatal("expected error on garbage input")
	}
}

func TestHostMatchesSAN(t *testing.T) {
	sans := []string{"example.com", "*.example.com"}
	cases := map[string]bool{
		"example.com":     true,
		"api.example.com": true,
		"a.b.example.com": false, // wildcard is single-label
		"other.com":       false,
	}
	for host, want := range cases {
		if got := hostMatchesSAN(host, sans); got != want {
			t.Errorf("hostMatchesSAN(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestJSONShape(t *testing.T) {
	c := makeCert(t, genOpts{cn: "j.com", notBefore: day(-1), notAfter: day(5), rsaBits: 2048})
	rep := Analyze([]Parsed{{Source: "j", Cert: c}}, fixedNow, 30)
	js := ToJSON(rep)
	if !contains(js, "days_remaining") || !contains(js, "EXPIRING") {
		t.Errorf("json missing expected fields:\n%s", js)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
