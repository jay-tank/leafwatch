// Package cert parses X.509 certificates and reports their expiry and health.
package cert

import "time"

// Flag is a single health finding on a certificate.
type Flag string

const (
	// FlagExpired marks a certificate whose notAfter is in the past.
	FlagExpired Flag = "EXPIRED"
	// FlagExpiring marks a still-valid certificate expiring within the warn window.
	FlagExpiring Flag = "EXPIRING"
	// FlagNotYetValid marks a certificate whose notBefore is in the future.
	FlagNotYetValid Flag = "NOT_YET_VALID"
	// FlagSelfSigned marks a certificate that is its own issuer.
	FlagSelfSigned Flag = "SELF_SIGNED"
	// FlagWeakKey marks an RSA key below 2048 bits (or a small DSA key).
	FlagWeakKey Flag = "WEAK_KEY"
	// FlagWeakSig marks a certificate signed with SHA-1 or MD5.
	FlagWeakSig Flag = "WEAK_SIG"
	// FlagSANExpiring is set when a covered SAN name will lose coverage soon
	// (the certificate carrying it is expiring). It is informational context.
	FlagSANExpiring Flag = "SAN_COVERAGE_ENDING"
)

// Severity is the worst level implied by a certificate's flags.
type Severity string

const (
	// SevOK means no flags fired.
	SevOK Severity = "ok"
	// SevWarn means a non-fatal flag fired (expiring, weak key/sig, self-signed).
	SevWarn Severity = "warn"
	// SevCrit means the certificate is expired or not yet valid.
	SevCrit Severity = "crit"
)

// Entry is the health report for a single parsed certificate.
type Entry struct {
	Source        string    `json:"source"`         // file path (with index) or host:port
	Subject       string    `json:"subject"`        // subject common name / DN
	SANs          []string  `json:"sans,omitempty"` // DNS + IP subject alternative names
	Issuer        string    `json:"issuer"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	DaysRemaining int       `json:"days_remaining"` // whole days until notAfter (negative if expired)
	KeyType       string    `json:"key_type"`       // e.g. RSA, ECDSA, Ed25519
	KeyBits       int       `json:"key_bits"`       // key size in bits (0 for Ed25519)
	SigAlgo       string    `json:"sig_algo"`       // signature algorithm name
	SelfSigned    bool      `json:"self_signed"`
	IsCA          bool      `json:"is_ca"`
	Flags         []Flag    `json:"flags"`
	Severity      Severity  `json:"severity"`
}

// Report is the full result across every parsed certificate.
type Report struct {
	GeneratedAt time.Time `json:"generated_at"`
	WarnDays    int       `json:"warn_days"`
	Entries     []Entry   `json:"entries"`
	Summary     Summary   `json:"summary"`
}

// Summary is the roll-up counts across the report.
type Summary struct {
	Total       int `json:"total"`
	Expired     int `json:"expired"`
	Expiring    int `json:"expiring"`
	WeakKey     int `json:"weak_key"`
	WeakSig     int `json:"weak_sig"`
	SelfSigned  int `json:"self_signed"`
	NotYetValid int `json:"not_yet_valid"`
	OK          int `json:"ok"`
}

// has reports whether the entry carries the given flag.
func (e Entry) has(f Flag) bool {
	for _, x := range e.Flags {
		if x == f {
			return true
		}
	}
	return false
}
