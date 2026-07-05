package sbomscan

import (
	"testing"

	"sca-go/cli/internal/onlinescan"
	"sca-go/cli/internal/reachability"
)

func TestGoModulePath(t *testing.T) {
	at := "\x40"
	cases := []struct {
		purl, system, name, want string
	}{
		{"pkg:golang/github.com/jackc/pgx/v5" + at + "v5.7.2", "golang", "x", "github.com/jackc/pgx/v5"},
		{"pkg:golang/golang.org/x/crypto" + at + "v0.31.0", "", "", "golang.org/x/crypto"},
		{"", "golang", "github.com/jackc/pgx/v5", "github.com/jackc/pgx/v5"},
		{"pkg:npm/vite" + at + "5.4.21", "npm", "vite", ""},
	}
	for _, c := range cases {
		cr := ComponentReport{PURL: c.purl, System: c.system, Name: c.name}
		if got := goModulePath(&cr); got != c.want {
			t.Errorf("PURL=%q sys=%q: got %q want %q", c.purl, c.system, got, c.want)
		}
	}
}

func TestApplyReachability_InUseDeadRefinement(t *testing.T) {
	oracle := &reachability.Result{
		ByVuln: map[string]reachability.State{
			"GO-2026-4771": reachability.StateUnreachable,
			"GO-2026-4772": reachability.StateUnreachable,
		},
		HaveModuleUsage: true,
		Modules:         map[string]bool{"github.com/jackc/pgx/v5": true},
	}

	pgx := ComponentReport{
		System: "golang", Name: "github.com/jackc/pgx/v5",
		Vulnerabilities: []onlinescan.Vulnerability{
			{ID: "GO-2026-4771", CVE: "CVE-2026-33815"},
			{ID: "GO-2026-4772", CVE: "CVE-2026-33816"},
			{ID: "GHSA-j88v-2chj-qfwx", CVE: "CVE-2026-41889"},
		},
	}
	applyReachability(&pgx, oracle)
	if pgx.Vulnerabilities[0].Reachable != "unreachable" {
		t.Errorf("4771: got %q want unreachable", pgx.Vulnerabilities[0].Reachable)
	}

	if pgx.Vulnerabilities[2].Reachable != "" {
		t.Errorf("41889 (unknown CVE, pgx imported): got %q want empty - in-use belongs to PackageUsage, not vuln.Reachable", pgx.Vulnerabilities[2].Reachable)
	}
	if pgx.PackageUsage != "used" {
		t.Errorf("pgx PackageUsage: got %q want used", pgx.PackageUsage)
	}

	npm := ComponentReport{
		System: "npm", Name: "vite",
		Vulnerabilities: []onlinescan.Vulnerability{{ID: "GHSA-vite", CVE: "CVE-2026-39365"}},
	}
	applyReachability(&npm, oracle)
	if npm.PackageUsage != "" {
		t.Errorf("npm PackageUsage: got %q want empty (not applicable)", npm.PackageUsage)
	}
	if npm.Vulnerabilities[0].Reachable != "" {
		t.Errorf("npm vuln: got %q want empty (no Go module path)", npm.Vulnerabilities[0].Reachable)
	}

	dead := ComponentReport{
		System: "golang", Name: "example.com/ghost",
		Vulnerabilities: []onlinescan.Vulnerability{{ID: "GHSA-zzzz", CVE: "CVE-2099-1"}},
	}
	applyReachability(&dead, oracle)

	if dead.Vulnerabilities[0].Reachable != "" {
		t.Errorf("ghost: vuln=%q want empty - dead belongs to PackageUsage, not vuln.Reachable", dead.Vulnerabilities[0].Reachable)
	}
	if dead.PackageUsage != "unused" {
		t.Errorf("ghost PackageUsage: got %q want unused", dead.PackageUsage)
	}

	noData := &reachability.Result{ByVuln: map[string]reachability.State{}}
	c := ComponentReport{
		System: "golang", Name: "example.com/x",
		Vulnerabilities: []onlinescan.Vulnerability{{ID: "GHSA-q", CVE: "CVE-1"}},
	}
	applyReachability(&c, noData)
	if c.Vulnerabilities[0].Reachable != "" {
		t.Errorf("no data: vuln=%q want empty", c.Vulnerabilities[0].Reachable)
	}
}

func TestApplyReachability_AtomNonGo(t *testing.T) {
	at := "\x40"
	oracle := &reachability.Result{
		ByVuln:             map[string]reachability.State{},
		AtomEcosystems:     map[string]bool{"npm": true},
		AtomReachablePURLs: map[string]bool{"pkg:npm/vite": true},
	}

	vite := ComponentReport{
		PURL: "pkg:npm/vite" + at + "5.4.21", System: "npm", Name: "vite",
		Vulnerabilities: []onlinescan.Vulnerability{{ID: "GHSA-vite", CVE: "CVE-2026-39365"}},
	}
	applyReachability(&vite, oracle)
	if vite.Vulnerabilities[0].Reachable != "reachable" {
		t.Errorf("vite vuln: got %q want reachable", vite.Vulnerabilities[0].Reachable)
	}
	if vite.PackageUsage != "used" {
		t.Errorf("vite PackageUsage: got %q want used", vite.PackageUsage)
	}

	pc := ComponentReport{
		PURL: "pkg:npm/postcss" + at + "8.5.8", System: "npm", Name: "postcss",
		Vulnerabilities: []onlinescan.Vulnerability{{ID: "GHSA-pc", CVE: "CVE-2026-41305"}},
	}
	applyReachability(&pc, oracle)
	if pc.Vulnerabilities[0].Reachable != "" || pc.PackageUsage != "" {
		t.Errorf("postcss: vuln=%q usage=%q want empty/empty", pc.Vulnerabilities[0].Reachable, pc.PackageUsage)
	}

	py := ComponentReport{
		PURL: "pkg:pypi/requests" + at + "2.0", System: "pypi", Name: "requests",
		Vulnerabilities: []onlinescan.Vulnerability{{ID: "GHSA-rq", CVE: "CVE-1"}},
	}
	applyReachability(&py, oracle)
	if py.Vulnerabilities[0].Reachable != "" || py.PackageUsage != "" {
		t.Errorf("pypi (atom didn't run): vuln=%q usage=%q want empty/empty", py.Vulnerabilities[0].Reachable, py.PackageUsage)
	}
}
