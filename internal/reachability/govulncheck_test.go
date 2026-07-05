package reachability

import (
	"strings"
	"testing"
)

const sample = `
{"config":{"protocol_version":"v1.0.0","scanner_name":"govulncheck"}}
{"progress":{"message":"Fetching vulnerabilities..."}}
{"osv":{"id":"GO-2021-0113","aliases":["CVE-2021-38561","GHSA- q449-3jhq-7vh4"],"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}}
{"osv":{"id":"GO-2022-0001","aliases":["CVE-2022-0001"],"database_specific":{"severity":"LOW"}}}
{"finding":{"osv":"GO-2021-0113","fixed_version":"v0.3.7","trace":[{"module":"golang.org/x/text","version":"v0.3.5","package":"golang.org/x/text/language","function":"Parse"},{"module":"example.com/app","function":"main"}]}}
{"finding":{"osv":"GO-2022-0001","fixed_version":"v1.2.3","trace":[{"module":"example.com/dep","package":"example.com/dep/pkg"}]}}
`

func TestParseGovulncheck(t *testing.T) {
	res := &Result{}
	nReach, nUnreach, err := parseGovulncheck(strings.NewReader(sample), "/", res, Options{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if nReach != 1 || nUnreach != 1 {
		t.Errorf("counts: got reachable=%d unreachable=%d, want 1/1", nReach, nUnreach)
	}

	if got := res.Lookup("GO-2021-0113"); got != StateReachable {
		t.Errorf("GO-2021-0113: got %q, want reachable", got)
	}

	if got := res.Lookup("cve-2021-38561"); got != StateReachable {
		t.Errorf("CVE alias: got %q, want reachable", got)
	}
	if got := res.Lookup("GO-2022-0001"); got != StateUnreachable {
		t.Errorf("GO-2022-0001: got %q, want unreachable", got)
	}
	if got := res.Lookup("CVE-2022-0001"); got != StateUnreachable {
		t.Errorf("CVE-2022-0001 alias: got %q, want unreachable", got)
	}

	if got := res.Lookup("CVE-9999-0000"); got != StateUnknown {
		t.Errorf("unseen id: got %q, want unknown", got)
	}

	if got := res.GOSeverity["GO-2021-0113"]; got != "CRITICAL" {
		t.Errorf("GO-2021-0113 severity: got %q want CRITICAL", got)
	}

	if got := res.GOSeverity["GO-2022-0001"]; got != "LOW" {
		t.Errorf("GO-2022-0001 severity: got %q want LOW", got)
	}
}

func TestLookupStrongestWins(t *testing.T) {
	r := &Result{}
	r.set("CVE-1", StateUnreachable)
	r.set("CVE-2", StateReachable)
	if got := r.Lookup("CVE-1", "CVE-2"); got != StateReachable {
		t.Errorf("mixed lookup: got %q, want reachable (strongest wins)", got)
	}

	r.set("CVE-2", StateUnreachable)
	if got := r.Lookup("CVE-2"); got != StateReachable {
		t.Errorf("sticky reachable: got %q, want reachable", got)
	}
}

func TestTailWriter(t *testing.T) {
	w := &tailWriter{max: 8}
	w.Write([]byte("abcdefghij"))
	if got := w.String(); got != "cdefghij" {
		t.Errorf("tail: got %q want %q", got, "cdefghij")
	}
	w.Write([]byte("KL"))
	if got := w.String(); got != "efghijKL" {
		t.Errorf("tail after second write: got %q want %q", got, "efghijKL")
	}
}

func TestLastLines(t *testing.T) {

	in := "govulncheck: loading packages:\n\n# backend\n./main.go:8:2: no required module provides package x\n\tgo get x\n"
	if got, want := lastLines(in, 2), "./main.go:8:2: no required module provides package x | go get x"; got != want {
		t.Errorf("lastLines(n=2): got %q want %q", got, want)
	}

	if got, want := lastLines("only one line\n", 4), "only one line"; got != want {
		t.Errorf("lastLines fewer: got %q want %q", got, want)
	}
	if got := lastLines("\n\n  \n", 3); got != "" {
		t.Errorf("blank-only: got %q want empty", got)
	}
}

func TestNilAndEmptyOracleAreUnknown(t *testing.T) {
	var nilRes *Result
	if got := nilRes.Lookup("CVE-1"); got != StateUnknown {
		t.Errorf("nil oracle: got %q, want unknown", got)
	}
	if got := (&Result{}).Lookup("CVE-1"); got != StateUnknown {
		t.Errorf("empty oracle: got %q, want unknown", got)
	}
}
