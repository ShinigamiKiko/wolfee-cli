package output

import (
	"bytes"
	"strings"
	"testing"
)

type scopedComponent struct {
	PURL            string
	Group           string
	System          string
	Name            string
	Version         string
	Scope           string
	TopSeverity     string
	VulnCount       int
	DependencyPaths [][]string
}

type scopedDependency struct {
	Ref       string
	DependsOn []string
}

type scopedReport struct {
	Source       string
	Totals       tTotals
	Dependencies []scopedDependency
	Components   []scopedComponent
}

func renderRow(t *testing.T, r *scopedReport, pkg string) string {
	t.Helper()
	var buf bytes.Buffer
	if err := (Table{NoColor: true}).Render(&buf, r); err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), pkg+" ") {
			return line
		}
	}
	t.Fatalf("no row for %s in:\n%s", pkg, buf.String())
	return ""
}

func composerReport(deps []scopedDependency) *scopedReport {
	return &scopedReport{
		Source:       "fs:./app",
		Totals:       tTotals{Components: 2, Scanned: 2},
		Dependencies: deps,
		Components: []scopedComponent{
			// require-dev: cdxgen marks it optional, yet the root depends on it.
			{PURL: "pkg:composer/phpunit/phpunit@9.5.0", Group: "phpunit", System: "PACKAGIST",
				Name: "phpunit", Version: "9.5.0", Scope: "optional", TopSeverity: "HIGH", VulnCount: 1},
			{PURL: "pkg:composer/guzzlehttp/psr7@1.6.1", Group: "guzzlehttp", System: "PACKAGIST",
				Name: "psr7", Version: "1.6.1", Scope: "required", TopSeverity: "MEDIUM", VulnCount: 1,
				DependencyPaths: [][]string{{"guzzlehttp/guzzle@6.5.0", "guzzlehttp/psr7@1.6.1"}}},
		},
	}
}

func TestTable_DevDependencyIsDirectWithGraph(t *testing.T) {
	r := composerReport([]scopedDependency{{Ref: "pkg:composer/acme/app", DependsOn: []string{"pkg:composer/phpunit/phpunit@9.5.0"}}})

	row := renderRow(t, r, "phpunit/phpunit")
	if !strings.Contains(row, "direct") || strings.Contains(row, "transitive") {
		t.Errorf("dev dependency of the root must be direct: %q", row)
	}
	if row := renderRow(t, r, "guzzlehttp/psr7"); !strings.Contains(row, "transitive") {
		t.Errorf("package with a dependency path must stay transitive: %q", row)
	}
}

func TestTable_OptionalScopeWithoutGraphStaysTransitive(t *testing.T) {
	// No dependency graph (e.g. a hand-written SBOM): the optional scope is the
	// only hint left, as for Go's indirect modules.
	row := renderRow(t, composerReport(nil), "phpunit/phpunit")
	if !strings.Contains(row, "transitive") {
		t.Errorf("optional scope without a graph must read transitive: %q", row)
	}
}

func TestTable_ComponentsShowGroup(t *testing.T) {
	row := renderRow(t, composerReport(nil), "guzzlehttp/psr7")
	if !strings.Contains(row, "1.6.1") {
		t.Errorf("row = %q", row)
	}
}

type directComponent struct {
	PURL            string
	Group           string
	System          string
	Name            string
	Version         string
	Direct          *bool
	TopSeverity     string
	VulnCount       int
	DependencyPaths [][]string
	Vulnerabilities []tVuln
}

type directReport struct {
	Source     string
	Totals     tTotals
	Components []directComponent
}

func TestTable_DirectFieldDrivesOriginAndStar(t *testing.T) {
	yes, no := true, false
	vuln := []tVuln{{Severity: "HIGH", ID: "GHSA-twig", CVE: "CVE-2026-49981"}}
	r := &directReport{
		Source: "fs:./app",
		Totals: tTotals{Components: 2, Scanned: 2, WithVulns: 2, HIGH: 2},
		Components: []directComponent{
			// Required by composer.json and by twig-bundle.
			{PURL: "pkg:composer/twig/twig@v3.8.0", Group: "twig", System: "PACKAGIST", Name: "twig", Version: "v3.8.0",
				Direct: &yes, TopSeverity: "HIGH", VulnCount: 1, Vulnerabilities: vuln,
				DependencyPaths: [][]string{{"symfony/twig-bundle@v5.4.31", "twig/twig@v3.8.0"}}},
			{PURL: "pkg:composer/guzzlehttp/psr7@2.4.5", Group: "guzzlehttp", System: "PACKAGIST", Name: "psr7", Version: "2.4.5",
				Direct: &no, TopSeverity: "HIGH", VulnCount: 1, Vulnerabilities: vuln,
				DependencyPaths: [][]string{{"guzzlehttp/guzzle@7.6.1", "guzzlehttp/psr7@2.4.5"}}},
		},
	}
	var buf bytes.Buffer
	if err := (Table{NoColor: true}).Render(&buf, r); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	for _, line := range strings.Split(out, "\n") {
		l := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(l, "twig/twig ") && !strings.Contains(l, "direct"):
			t.Errorf("twig is required by the project: %q", line)
		case strings.HasPrefix(l, "guzzlehttp/psr7 ") && !strings.Contains(l, "transitive"):
			t.Errorf("psr7 is only pulled in by guzzle: %q", line)
		}
	}
	if !strings.Contains(out, "*twig/twig@v3.8.0 (vuln) direct dependency") {
		t.Errorf("a direct dependency must carry the star itself:\n%s", out)
	}
	if strings.Contains(out, "*symfony/twig-bundle") {
		t.Errorf("the parent of a direct dependency must not be marked for update:\n%s", out)
	}
	if !strings.Contains(out, "*guzzlehttp/guzzle@7.6.1 -> guzzlehttp/psr7@2.4.5") {
		t.Errorf("a transitive dependency keeps the star on its direct parent:\n%s", out)
	}
}
