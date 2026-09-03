// Command leafwatch — an offline-first TLS/X.509 certificate expiry & health
// reporter.
//
// It parses certificates from PEM/DER files, directories or bundles and reports,
// for each: subject/SANs, issuer, validity window, DAYS REMAINING, and health
// flags (EXPIRED, EXPIRING, self-signed, weak key, weak signature). Entries are
// sorted by soonest expiry. Output is a text report or --json.
//
// File mode makes NO network calls and is fully deterministic. An OPT-IN
// --connect host:443 mode fetches the served certificate over TLS to inspect it
// (the only code path that uses the network; off by default).
//
// Exit codes: 0 report produced · 1 --fail-on threshold met · 2 usage/bad input.
package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jay-tank/leafwatch/cert"
)

const version = "0.1.0"

// certExts are the file extensions walked when a directory is given.
var certExts = map[string]bool{
	".pem": true, ".crt": true, ".cer": true, ".cert": true,
	".der": true, ".ca": true, ".chain": true, ".fullchain": true,
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	var (
		paths    []string
		connect  string
		warnDays = 30
		failOn   = ""
		asJSON   = false
		color    = true
		timeout  = 8 * time.Second
	)

	for i := 0; i < len(args); i++ {
		a := args[i]
		next := func() (string, bool) {
			if i+1 >= len(args) {
				return "", false
			}
			i++
			return args[i], true
		}
		switch {
		case a == "-h" || a == "--help":
			printHelp(stdout)
			return 0
		case a == "--version":
			fmt.Fprintln(stdout, "leafwatch "+version)
			return 0
		case a == "--json":
			asJSON = true
		case a == "--no-color":
			color = false
		case a == "--warn":
			v, ok := next()
			if !ok {
				return usage(stderr, "--warn needs a number of days")
			}
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				return usage(stderr, "--warn needs a non-negative integer")
			}
			warnDays = n
		case a == "--fail-on":
			v, ok := next()
			if !ok {
				return usage(stderr, "--fail-on needs a value (expired|expiring)")
			}
			switch strings.ToLower(v) {
			case "expired", "expiring":
				failOn = strings.ToLower(v)
			default:
				return usage(stderr, "--fail-on must be 'expired' or 'expiring'")
			}
		case a == "--connect":
			v, ok := next()
			if !ok {
				return usage(stderr, "--connect needs host:port[,host:port]")
			}
			connect = v
		case a == "--timeout":
			v, ok := next()
			if !ok {
				return usage(stderr, "--timeout needs seconds")
			}
			n, err := strconv.Atoi(v)
			if err != nil || n <= 0 {
				return usage(stderr, "--timeout needs a positive integer (seconds)")
			}
			timeout = time.Duration(n) * time.Second
		case strings.HasPrefix(a, "-") && a != "-":
			return usage(stderr, "unknown flag "+strconv.Quote(a))
		default:
			paths = append(paths, a)
		}
	}

	if connect == "" && len(paths) == 0 {
		return usage(stderr, "give one or more cert files/dirs, or use --connect host:port")
	}

	var parsed []cert.Parsed

	// File mode (offline, deterministic).
	if len(paths) > 0 {
		files, err := expandInputs(paths)
		if err != nil {
			return usage(stderr, err.Error())
		}
		for _, f := range files {
			ps, err := cert.ParseFile(f)
			if err != nil {
				return usage(stderr, err.Error())
			}
			parsed = append(parsed, ps...)
		}
	}

	// Opt-in live mode (network).
	if connect != "" {
		for _, hp := range strings.Split(connect, ",") {
			hp = strings.TrimSpace(hp)
			if hp == "" {
				continue
			}
			ps, err := cert.FetchServed(hp, timeout)
			if err != nil {
				fmt.Fprintln(stderr, "leafwatch: "+err.Error())
				return 2
			}
			parsed = append(parsed, ps...)
		}
	}

	if len(parsed) == 0 {
		return usage(stderr, "no certificates found in the given input")
	}

	report := cert.Analyze(parsed, time.Now().UTC(), warnDays)

	if asJSON {
		fmt.Fprintln(stdout, cert.ToJSON(report))
	} else {
		fmt.Fprint(stdout, cert.RenderText(report, color))
	}

	return exitFor(failOn, report)
}

// exitFor maps the --fail-on threshold to an exit code.
func exitFor(failOn string, r cert.Report) int {
	switch failOn {
	case "expired":
		if r.Summary.Expired > 0 || r.Summary.NotYetValid > 0 {
			return 1
		}
	case "expiring":
		if r.Summary.Expired > 0 || r.Summary.NotYetValid > 0 || r.Summary.Expiring > 0 {
			return 1
		}
	}
	return 0
}

// expandInputs turns files, globs and directories into a sorted, de-duplicated
// list of candidate certificate files.
func expandInputs(inputs []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}

	for _, in := range inputs {
		info, err := os.Stat(in)
		if err != nil {
			// Try as a glob before giving up.
			matches, gerr := filepath.Glob(in)
			if gerr != nil || len(matches) == 0 {
				return nil, fmt.Errorf("path not found: %s", in)
			}
			for _, m := range matches {
				add(m)
			}
			continue
		}
		if info.IsDir() {
			err := filepath.Walk(in, func(path string, fi os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if fi.IsDir() {
					return nil
				}
				if certExts[strings.ToLower(filepath.Ext(path))] {
					add(path)
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			continue
		}
		add(in)
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("no certificate files found in the given paths")
	}
	sort.Strings(out)
	return out, nil
}

func usage(w io.Writer, msg string) int {
	fmt.Fprintln(w, "leafwatch: "+msg)
	fmt.Fprintln(w, "try 'leafwatch --help'")
	return 2
}

func printHelp(w io.Writer) {
	fmt.Fprint(w, `leafwatch — report TLS/X.509 certificate expiry & health (offline-first)

USAGE:
  leafwatch [files/dirs/globs...] [flags]
  leafwatch --connect host:443[,host:443] [flags]

INPUT (file mode — offline, deterministic):
  PEM or DER certificate files, a directory of them, a bundle/fullchain, or
  globs. Non-certificate PEM blocks (keys, CSRs) are skipped. When a directory
  is given, files ending in .pem/.crt/.cer/.cert/.der/.ca/.chain are read.

LIVE MODE (opt-in — the only networked path):
  --connect host:443[,host:443]
                   fetch the certificate each host serves over TLS and report
                   on it. Verification is skipped so an expired/self-signed cert
                   is still inspected. OFF by default; file mode never dials out.

REPORT (per certificate):
  subject & SANs, issuer, notBefore/notAfter, DAYS REMAINING, key type/size,
  signature algorithm, and health flags — sorted by soonest expiry:
    EXPIRED · EXPIRING (< --warn days) · NOT_YET_VALID · SELF_SIGNED
    WEAK_KEY (RSA/DSA < 2048) · WEAK_SIG (SHA-1/MD5)

FLAGS:
  --warn N         days-remaining threshold for EXPIRING (default 30)
  --fail-on WHICH  exit 1 when the report contains 'expired' (also not-yet-valid)
                   or 'expiring' (expired + expiring). Default: always exit 0.
  --connect LIST   comma-separated host:port to fetch live (opt-in network)
  --timeout N      per-host TLS dial timeout in seconds (default 8)
  --json           machine-readable JSON report
  --no-color       disable ANSI colors
  --version        print version
  -h, --help       show this help

EXIT CODES:
  0  report produced (and no --fail-on threshold met)
  1  --fail-on threshold met (CI gate)
  2  usage / bad input (unreadable file, no certificate, connect failure)

Uses only the Go standard library (crypto/x509). File mode is fully offline.
`)
}
