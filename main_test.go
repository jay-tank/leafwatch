package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeCert generates a self-signed RSA cert valid until notAfter and writes it
// as PEM, returning the path. Times are relative to real now so CLI exit codes
// (which use time.Now) are exercised end-to-end.
func writeCert(t *testing.T, dir, name string, notAfter time.Time) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		DNSNames:              []string{name},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name+".pem")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatal(err)
	}
	return path
}

func runCLI(args ...string) (int, string, string) {
	var out, errBuf bytes.Buffer
	code := run(args, &out, &errBuf)
	return code, out.String(), errBuf.String()
}

func TestCLIReportExitZero(t *testing.T) {
	dir := t.TempDir()
	p := writeCert(t, dir, "healthy.example", time.Now().Add(365*24*time.Hour))
	code, out, _ := runCLI(p)
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if !strings.Contains(out, "healthy.example") || !strings.Contains(out, "days left") {
		t.Errorf("unexpected output:\n%s", out)
	}
}

func TestCLIFailOnExpired(t *testing.T) {
	dir := t.TempDir()
	expired := writeCert(t, dir, "dead.example", time.Now().Add(-24*time.Hour))

	// Without --fail-on: still exit 0 (report only).
	if code, _, _ := runCLI(expired); code != 0 {
		t.Errorf("no fail-on: exit = %d, want 0", code)
	}
	// With --fail-on expired: exit 1.
	if code, _, _ := runCLI("--fail-on", "expired", expired); code != 1 {
		t.Errorf("fail-on expired: exit = %d, want 1", code)
	}
}

func TestCLIFailOnExpiring(t *testing.T) {
	dir := t.TempDir()
	soon := writeCert(t, dir, "soon.example", time.Now().Add(10*24*time.Hour))

	if code, _, _ := runCLI("--fail-on", "expired", soon); code != 0 {
		t.Errorf("fail-on expired should not trip on merely-expiring: got %d", code)
	}
	if code, _, _ := runCLI("--fail-on", "expiring", soon); code != 1 {
		t.Errorf("fail-on expiring: exit = %d, want 1", code)
	}
}

func TestCLIWarnWindow(t *testing.T) {
	dir := t.TempDir()
	c := writeCert(t, dir, "warncase.example", time.Now().Add(20*24*time.Hour))
	// 20 days out: not expiring under default-ish --warn 7, expiring under --warn 30.
	if code, _, _ := runCLI("--warn", "7", "--fail-on", "expiring", c); code != 0 {
		t.Errorf("warn 7: exit = %d, want 0", code)
	}
	if code, _, _ := runCLI("--warn", "30", "--fail-on", "expiring", c); code != 1 {
		t.Errorf("warn 30: exit = %d, want 1", code)
	}
}

func TestCLIJSON(t *testing.T) {
	dir := t.TempDir()
	c := writeCert(t, dir, "json.example", time.Now().Add(100*24*time.Hour))
	code, out, _ := runCLI("--json", c)
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(out, "\"days_remaining\"") || !strings.Contains(out, "\"summary\"") {
		t.Errorf("json output missing fields:\n%s", out)
	}
}

func TestCLIBadInputExitTwo(t *testing.T) {
	// Nonexistent path.
	if code, _, errOut := runCLI("/no/such/cert.pem"); code != 2 {
		t.Errorf("missing file: exit = %d, want 2 (%s)", code, errOut)
	}
	// Garbage file.
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(bad, []byte("nonsense"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := runCLI(bad); code != 2 {
		t.Errorf("garbage file: exit = %d, want 2", code)
	}
	// No args at all.
	if code, _, _ := runCLI(); code != 2 {
		t.Errorf("no args: exit = %d, want 2", code)
	}
	// Unknown flag.
	if code, _, _ := runCLI("--bogus"); code != 2 {
		t.Errorf("unknown flag: exit = %d, want 2", code)
	}
}

func TestCLIDirectoryWalk(t *testing.T) {
	dir := t.TempDir()
	writeCert(t, dir, "a.example", time.Now().Add(30*24*time.Hour))
	writeCert(t, dir, "b.example", time.Now().Add(60*24*time.Hour))
	code, out, _ := runCLI(dir)
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(out, "a.example") || !strings.Contains(out, "b.example") {
		t.Errorf("directory walk missed a cert:\n%s", out)
	}
	if !strings.Contains(out, "2 cert(s)") {
		t.Errorf("expected 2 certs in summary:\n%s", out)
	}
}

func TestCLIHelpAndVersion(t *testing.T) {
	if code, out, _ := runCLI("--help"); code != 0 || !strings.Contains(out, "USAGE") {
		t.Errorf("help: code=%d", code)
	}
	if code, out, _ := runCLI("--version"); code != 0 || !strings.Contains(out, "leafwatch "+version) {
		t.Errorf("version: code=%d out=%s", code, out)
	}
}
