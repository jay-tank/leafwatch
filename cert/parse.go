package cert

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// Parsed pairs a decoded certificate with the source label it came from.
type Parsed struct {
	Source string
	Cert   *x509.Certificate
}

// ParseFile reads a single file that may hold one or more certificates in PEM
// form (including a bundle / fullchain) or a single DER-encoded certificate.
// Non-certificate PEM blocks (keys, etc.) are skipped. Sources are labelled
// "path" for a lone cert or "path#N" when a file yields several.
func ParseFile(path string) ([]Parsed, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	certs, err := parseBytes(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("%s: no X.509 certificate found", path)
	}
	out := make([]Parsed, 0, len(certs))
	for i, c := range certs {
		src := path
		if len(certs) > 1 {
			src = fmt.Sprintf("%s#%d", path, i+1)
		}
		out = append(out, Parsed{Source: src, Cert: c})
	}
	return out, nil
}

// parseBytes decodes every certificate it can find in a PEM or DER blob.
func parseBytes(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	// Try PEM first: walk every block, keep CERTIFICATE blocks.
	rest := data
	sawPEM := false
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		sawPEM = true
		if block.Type != "CERTIFICATE" && block.Type != "TRUSTED CERTIFICATE" {
			continue // skip keys, CSRs, params, etc.
		}
		cs, err := x509.ParseCertificates(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("malformed PEM certificate block: %w", err)
		}
		certs = append(certs, cs...)
	}
	if sawPEM {
		return certs, nil
	}

	// No PEM armor: treat the whole file as DER (may hold a chain).
	cs, err := x509.ParseCertificates(data)
	if err != nil {
		return nil, fmt.Errorf("not PEM and not valid DER: %w", err)
	}
	return cs, nil
}
