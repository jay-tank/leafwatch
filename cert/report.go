package cert

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ANSI color codes; suppressed when color is false.
const (
	cReset  = "\033[0m"
	cBold   = "\033[1m"
	cDim    = "\033[2m"
	cRed    = "\033[31m"
	cYellow = "\033[33m"
	cGreen  = "\033[32m"
	cCyan   = "\033[36m"
)

type painter struct{ on bool }

func (p painter) c(code, s string) string {
	if !p.on {
		return s
	}
	return code + s + cReset
}

// ToJSON renders the report as indented JSON.
func ToJSON(r Report) string {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(b)
}

// RenderText renders a human-readable report. Entries are already sorted by
// soonest expiry.
func RenderText(r Report, color bool) string {
	p := painter{on: color}
	var b strings.Builder

	fmt.Fprintf(&b, "%s  TLS/X.509 certificate report  (warn < %dd)\n\n",
		p.c(cBold, "leafwatch"), r.WarnDays)

	if len(r.Entries) == 0 {
		b.WriteString("  no certificates parsed\n")
		return b.String()
	}

	for _, e := range r.Entries {
		writeEntry(&b, p, e)
	}

	writeSummary(&b, p, r.Summary)
	return b.String()
}

func writeEntry(b *strings.Builder, p painter, e Entry) {
	var dot, dotColor string
	switch e.Severity {
	case SevCrit:
		dot, dotColor = "●", cRed
	case SevWarn:
		dot, dotColor = "●", cYellow
	default:
		dot, dotColor = "●", cGreen
	}

	fmt.Fprintf(b, "%s %s\n", p.c(dotColor, dot), p.c(cBold, e.Subject))
	fmt.Fprintf(b, "    source   %s\n", p.c(cDim, e.Source))
	fmt.Fprintf(b, "    issuer   %s\n", e.Issuer)

	key := e.KeyType
	if e.KeyBits > 0 {
		key = fmt.Sprintf("%s-%d", e.KeyType, e.KeyBits)
	}
	fmt.Fprintf(b, "    key/sig  %s, %s\n", key, e.SigAlgo)

	life := fmt.Sprintf("%s  →  %s",
		e.NotBefore.Format("2006-01-02"), e.NotAfter.Format("2006-01-02"))
	daysStr := formatDays(e.DaysRemaining)
	if e.Severity == SevCrit {
		daysStr = p.c(cRed, daysStr)
	} else if e.has(FlagExpiring) {
		daysStr = p.c(cYellow, daysStr)
	}
	fmt.Fprintf(b, "    valid    %s   (%s)\n", life, daysStr)

	if len(e.SANs) > 0 {
		fmt.Fprintf(b, "    sans     %s\n", p.c(cDim, strings.Join(e.SANs, ", ")))
	}
	if len(e.Flags) > 0 {
		fmt.Fprintf(b, "    flags    %s\n", p.c(dotColor, joinFlags(e.Flags)))
	}
	b.WriteString("\n")
}

func writeSummary(b *strings.Builder, p painter, s Summary) {
	fmt.Fprintf(b, "%s %d cert(s): ", p.c(cCyan, "summary"), s.Total)
	parts := []string{
		fmt.Sprintf("%d ok", s.OK),
	}
	if s.Expired > 0 {
		parts = append(parts, p.c(cRed, fmt.Sprintf("%d expired", s.Expired)))
	}
	if s.NotYetValid > 0 {
		parts = append(parts, p.c(cRed, fmt.Sprintf("%d not-yet-valid", s.NotYetValid)))
	}
	if s.Expiring > 0 {
		parts = append(parts, p.c(cYellow, fmt.Sprintf("%d expiring", s.Expiring)))
	}
	if s.WeakKey > 0 {
		parts = append(parts, p.c(cYellow, fmt.Sprintf("%d weak-key", s.WeakKey)))
	}
	if s.WeakSig > 0 {
		parts = append(parts, p.c(cYellow, fmt.Sprintf("%d weak-sig", s.WeakSig)))
	}
	if s.SelfSigned > 0 {
		parts = append(parts, fmt.Sprintf("%d self-signed", s.SelfSigned))
	}
	b.WriteString(strings.Join(parts, ", "))
	b.WriteString("\n")
}

func formatDays(d int) string {
	switch {
	case d < 0:
		return fmt.Sprintf("EXPIRED %d day(s) ago", -d)
	case d == 0:
		return "expires today"
	case d == 1:
		return "1 day left"
	default:
		return fmt.Sprintf("%d days left", d)
	}
}

func joinFlags(flags []Flag) string {
	s := make([]string, len(flags))
	for i, f := range flags {
		s[i] = string(f)
	}
	return strings.Join(s, "  ")
}
