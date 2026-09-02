package cert

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

// FetchServed opens a TLS connection to host:port and returns the leaf
// certificate the server presents, plus any intermediates in the chain.
//
// This is the ONLY function in leafwatch that touches the network, and it is
// reached only through the opt-in --connect flag. Verification is intentionally
// skipped: the goal is to INSPECT whatever certificate is served (including an
// expired or self-signed one) and report on it, not to gate the handshake.
func FetchServed(hostport string, timeout time.Duration) ([]Parsed, error) {
	host, port, err := splitHostPort(hostport)
	if err != nil {
		return nil, err
	}
	addr := net.JoinHostPort(host, port)

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, //nolint:gosec // inspection tool: report the cert, do not trust it
		MinVersion:         tls.VersionTLS10,
	})
	if err != nil {
		return nil, fmt.Errorf("connect %s: %w", addr, err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("connect %s: server presented no certificate", addr)
	}

	out := make([]Parsed, 0, len(state.PeerCertificates))
	for i, c := range state.PeerCertificates {
		label := hostport
		if i > 0 {
			label = fmt.Sprintf("%s (chain#%d)", hostport, i)
		}
		out = append(out, Parsed{Source: label, Cert: c})
	}
	return out, nil
}

// HostCoverage reports whether the connected host is covered by the leaf's SANs.
// Exposed so the CLI can annotate a served cert with a coverage note.
func HostCoverage(hostport string, e Entry) (host string, covered bool) {
	h, _, err := splitHostPort(hostport)
	if err != nil {
		return hostport, false
	}
	return h, hostMatchesSAN(h, e.SANs)
}

func splitHostPort(hostport string) (host, port string, err error) {
	hostport = strings.TrimSpace(hostport)
	if hostport == "" {
		return "", "", fmt.Errorf("empty host")
	}
	if strings.Contains(hostport, ":") {
		h, p, e := net.SplitHostPort(hostport)
		if e != nil {
			// Might be a bare IPv6 or a host with no port; default the port.
			return hostport, "443", nil
		}
		if p == "" {
			p = "443"
		}
		return h, p, nil
	}
	return hostport, "443", nil
}
