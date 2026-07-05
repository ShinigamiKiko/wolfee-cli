package reachability

import (
	"strings"
	"testing"
)

func atomReachablesSample() string {
	at := "\x40"
	return `{
  "reachables": [
    {"id": "1", "purls": ["pkg:npm/vite` + at + `5.4.21", "pkg:npm/%40babel/core` + at + `7.0.0"]},
    {"id": "2", "purls": ["pkg:npm/postcss` + at + `8.5.8?foo=bar"]},
    {"id": "3", "purls": []},
    {"id": "4"}
  ]
}`
}

func TestParseAtomReachables(t *testing.T) {
	res := &Result{}
	n, err := parseAtomReachables(strings.NewReader(atomReachablesSample()), "npm", res)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if n != 3 {
		t.Errorf("distinct packages = %d; want 3", n)
	}
	for _, want := range []string{
		"pkg:npm/vite",
		"pkg:npm/%40babel/core",
		"pkg:npm/postcss",
	} {
		if !res.AtomReachablePURLs[want] {
			t.Errorf("missing reachable purl %q in %v", want, res.AtomReachablePURLs)
		}
	}
}

func TestParseAtomReachables_TopLevelArray(t *testing.T) {
	at := "\x40"
	doc := `[
	  {"purls": ["pkg:npm/vite` + at + `5.4.21"]},
	  {"flows": [{"node": {"tags": "pkg:npm/postcss` + at + `8.5.8"}}]}
	]`
	res := &Result{}
	n, err := parseAtomReachables(strings.NewReader(doc), "npm", res)
	if err != nil {
		t.Fatalf("array form must parse: %v", err)
	}
	if n != 2 || !res.AtomReachablePURLs["pkg:npm/vite"] || !res.AtomReachablePURLs["pkg:npm/postcss"] {
		t.Errorf("array form: n=%d map=%v want vite+postcss", n, res.AtomReachablePURLs)
	}
}

func TestParseAtomReachables_Empty(t *testing.T) {
	for _, in := range []string{`{}`, `[]`, ``, "  \n"} {
		res := &Result{}
		n, err := parseAtomReachables(strings.NewReader(in), "npm", res)
		if err != nil {
			t.Fatalf("input %q must not error: %v", in, err)
		}
		if n != 0 {
			t.Errorf("input %q: n=%d want 0", in, n)
		}
	}
}

func TestAtomPreconditionFailure(t *testing.T) {

	jdk := "[atom] A Java JDK is not installed or can't be found. Please install JDK version 21 or higher."
	if msg := atomPreconditionFailure(jdk); msg == "" || !strings.Contains(msg, "JDK 21+") {
		t.Errorf("JDK-missing stderr: got %q want a JDK message", msg)
	}
	if msg := atomPreconditionFailure("java.lang.OutOfMemoryError: Java heap space"); msg == "" {
		t.Errorf("OOM stderr: got empty want a message")
	}

	if msg := atomPreconditionFailure("[atom] Generated reachables slice\n"); msg != "" {
		t.Errorf("clean run: got %q want empty", msg)
	}
	if msg := atomPreconditionFailure(""); msg != "" {
		t.Errorf("empty stderr: got %q want empty", msg)
	}
}

func TestAtomPackageUsage(t *testing.T) {

	r := &Result{}
	if got := r.AtomPackageUsage("npm", "pkg:npm/vite"); got != StateUnknown {
		t.Errorf("no atom data: got %q want unknown", got)
	}

	r = &Result{
		AtomEcosystems:     map[string]bool{"npm": true},
		AtomReachablePURLs: map[string]bool{"pkg:npm/vite": true},
	}
	if got := r.AtomPackageUsage("npm", "pkg:npm/vite"); got != StateReachable {
		t.Errorf("reachable npm pkg: got %q want reachable", got)
	}

	if got := r.AtomPackageUsage("npm", "pkg:npm/leftpad"); got != StateUnknown {
		t.Errorf("npm pkg not on flow: got %q want unknown", got)
	}

	if got := r.AtomPackageUsage("pypi", "pkg:pypi/requests"); got != StateUnknown {
		t.Errorf("unanalysed ecosystem: got %q want unknown", got)
	}
}
