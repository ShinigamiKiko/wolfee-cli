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
