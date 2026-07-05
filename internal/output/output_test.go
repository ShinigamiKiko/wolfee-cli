package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

type tReport struct {
	Source      string
	GeneratedAt string
	Totals      tTotals
	Components  []tComponent
}
type tTotals struct {
	Components, Scanned, Skipped, WithVulns, Malware, Toxic int
	CRITICAL, HIGH, MEDIUM, LOW                             int
}
type tComponent struct {
	PURL            string
	System          string
	Name            string
	Version         string
	Class           string
	Origin          string
	LayerDigest     string
	TopSeverity     string
	VulnCount       int
	DependencyPaths [][]string
	Vulnerabilities []tVuln
	Malware         tMalware
	Toxic           tToxic
}
type tVuln struct {
	Severity string
	ID       string
	CVE      string
}
type tMalware struct {
	Found     bool
	ID        string
	Summary   string
	Reference string
}
type tToxic struct {
	Found       bool
	Categories  []string
	Remediation *tRemediation
}
type tRemediation struct {
	Direct         string
	CurrentVersion string
	FixVersion     string
	Via            string
	Note           string
}

func sampleReport() *tReport {
	return &tReport{
		Source: "image:nginx:1.27",
		Totals: tTotals{
			Components: 3, Scanned: 3, WithVulns: 2, Malware: 1,
			CRITICAL: 1, HIGH: 1,
		},
		Components: []tComponent{
			{PURL: "pkg:npm/ngx-bootstrap@20.0.4", System: "NPM", Name: "ngx-bootstrap", Version: "20.0.4",
				TopSeverity: "", Malware: tMalware{Found: true, ID: "MAL-2025-47197", Summary: "Shai-Hulud worm"}},
			{PURL: "pkg:npm/lodash@4.17.20", System: "NPM", Name: "lodash", Version: "4.17.20",
				TopSeverity: "HIGH", VulnCount: 2},
			{PURL: "pkg:npm/clean@1.0.0", System: "NPM", Name: "clean", Version: "1.0.0"},
		},
	}
}

func TestJSON_Render_RoundTrips(t *testing.T) {
	var buf bytes.Buffer
	if err := (JSON{}).Render(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, buf.String())
	}
	totals, ok := got["Totals"].(map[string]any)
	if !ok {
		t.Fatal("Totals missing or wrong shape")
	}
	if totals["Malware"].(float64) != 1 {
		t.Errorf("Totals.Malware = %v; want 1", totals["Malware"])
	}
}

func TestTable_Render_HighlightsAffectedFirst(t *testing.T) {
	var buf bytes.Buffer
	tbl := Table{NoColor: true}
	if err := tbl.Render(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	mal := strings.Index(out, "ngx-bootstrap")
	hi := strings.Index(out, "lodash")
	if mal < 0 || hi < 0 {
		t.Fatalf("expected affected components in output:\n%s", out)
	}
	if !(mal < hi) {
		t.Errorf("expected MALWARE before HIGH; got mal=%d hi=%d\n%s", mal, hi, out)
	}
	if strings.Contains(out, "  clean  ") {
		t.Errorf("clean component must not appear in findings:\n%s", out)
	}
	if !strings.Contains(out, "MALWARE") {
		t.Error("MALWARE flag missing in table output")
	}
}

func TestTable_Render_DependencyPaths(t *testing.T) {
	r := &tReport{
		Source: "src:./app",
		Totals: tTotals{Components: 2, Scanned: 2, WithVulns: 1, HIGH: 1},
		Components: []tComponent{

			{PURL: "pkg:golang/golang.org/x/text@0.3.5", System: "GO",
				Name: "golang.org/x/text", Version: "0.3.5", TopSeverity: "HIGH", VulnCount: 1,
				Vulnerabilities: []tVuln{{Severity: "HIGH", CVE: "CVE-2022-0001"}},
				DependencyPaths: [][]string{
					{"github.com/foo/api@1.4.0", "github.com/bar/render@2.1.0", "golang.org/x/text@0.3.5"},
					{"github.com/baz/cli@0.9.0", "golang.org/x/text@0.3.5"},
				}},

			{PURL: "pkg:golang/y@1", System: "GO", Name: "y", Version: "1",
				DependencyPaths: [][]string{{"github.com/foo/api@1.4.0", "y@1"}}},
		},
	}
	var buf bytes.Buffer
	if err := (Table{NoColor: true}).Render(&buf, r); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	if !strings.Contains(out, "Dependency paths") {
		t.Fatalf("missing Dependency paths section:\n%s", out)
	}

	if !strings.Contains(out, "golang.org/x/text@0.3.5 (vuln)") {
		t.Errorf("missing (vuln) label:\n%s", out)
	}

	if !strings.Contains(out, "*github.com/foo/api@1.4.0 -> github.com/bar/render@2.1.0 -> golang.org/x/text@0.3.5") {
		t.Errorf("missing full starred route:\n%s", out)
	}
	if !strings.Contains(out, "*github.com/baz/cli@0.9.0 -> golang.org/x/text@0.3.5") {
		t.Errorf("missing second starred route:\n%s", out)
	}

	if strings.Contains(out, "y@1 (vuln)") || strings.Contains(out, "-> y@1") {
		t.Errorf("non-vulnerable component should not appear in dependency paths:\n%s", out)
	}
}

func TestSplitNameVer(t *testing.T) {
	cases := []struct{ in, name, ver string }{
		{"golang.org/x/crypto@v0.31.0", "golang.org/x/crypto", "v0.31.0"},
		{"@vitejs/plugin-react@4.7.0", "@vitejs/plugin-react", "4.7.0"},
		{"@scope/pkg", "@scope/pkg", ""},
		{"lodash", "lodash", ""},
	}
	for _, c := range cases {
		n, v := splitNameVer(c.in)
		if n != c.name || v != c.ver {
			t.Errorf("splitNameVer(%q) = (%q,%q), want (%q,%q)", c.in, n, v, c.name, c.ver)
		}
	}
}

func TestTable_Render_DependencyPathsPinVulnVersion(t *testing.T) {
	// In --compare the path is grafted from the source SBOM and can carry a
	// different (require-edge) version than the one actually flagged. The
	// rendered chain must end at the flagged version so it matches the "(vuln)"
	// header instead of showing an unexplained second version.
	r := &tReport{
		Totals: tTotals{Components: 1, Scanned: 1, WithVulns: 1, HIGH: 1},
		Components: []tComponent{
			{PURL: "pkg:golang/golang.org/x/crypto@v0.49.0", System: "GO",
				Name: "golang.org/x/crypto", Version: "v0.49.0", TopSeverity: "HIGH", VulnCount: 1,
				Vulnerabilities: []tVuln{{Severity: "HIGH"}},
				DependencyPaths: [][]string{{"github.com/jackc/pgx/v5@v5.7.2", "golang.org/x/crypto@v0.31.0"}}},
		},
	}
	var buf bytes.Buffer
	if err := (Table{NoColor: true}).Render(&buf, r); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "golang.org/x/crypto@v0.49.0 (vuln)") {
		t.Errorf("header should show the flagged version:\n%s", out)
	}
	if !strings.Contains(out, "github.com/jackc/pgx/v5@v5.7.2 -> golang.org/x/crypto@v0.49.0") {
		t.Errorf("chain should end at the flagged version:\n%s", out)
	}
	if strings.Contains(out, "v0.31.0") {
		t.Errorf("stale source-graph version should not leak into the path:\n%s", out)
	}
}

func TestTable_Render_CleanReport(t *testing.T) {
	var buf bytes.Buffer
	r := &tReport{Totals: tTotals{Components: 1, Scanned: 1}}
	r.Components = []tComponent{{Name: "x", Version: "1", System: "NPM"}}
	if err := (Table{NoColor: true}).Render(&buf, r); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "No vulnerabilities") {
		t.Errorf("clean report should announce no findings; got:\n%s", buf.String())
	}
}

func TestOriginLabel(t *testing.T) {
	cases := []struct {
		system, origin string
		transitive     bool
		want           string
	}{
		{"deb", "base", false, "DEB"},
		{"deb", "app", false, "DEB"},
		{"deb", "image", false, "DEB(image)"},
		{"apk", "image", false, "APK(image)"},
		{"apk", "", false, "APK"},
		{"rpm", "", false, "RPM"},
		{"npm", "app", false, "APP"},
		{"npm", "app", true, "APP(T)"},
		{"npm", "image", false, "LIB(image)"},
		{"golang", "image", false, "LIB(image)"},
		{"npm", "base", false, "BASE"},
		{"npm", "", false, "-"},
		{"npm", "unknown", false, "-"},

		{"golang", "app", false, "APP"},
		{"golang", "app", true, "APP(T)"},
		{"golang", "base", false, "BASE"},
		{"golang", "", false, "-"},
	}
	for _, c := range cases {
		if got := originLabel(c.system, c.origin, c.transitive); got != c.want {
			t.Errorf("originLabel(%q,%q,%v) = %q, want %q", c.system, c.origin, c.transitive, got, c.want)
		}
	}
}

func TestTable_Render_OriginColumn(t *testing.T) {
	r := &tReport{
		Source: "image:my-app:latest",
		Totals: tTotals{Components: 2, Scanned: 2, WithVulns: 2, HIGH: 2},
		Components: []tComponent{
			{Name: "left-pad", Version: "1.3.0", System: "npm", Class: "lang-pkgs",
				Origin: "app", LayerDigest: "sha256:app0", TopSeverity: "HIGH", VulnCount: 1},
			{Name: "apt", Version: "2.6", System: "deb", Class: "os-pkgs",
				Origin: "base", LayerDigest: "sha256:base0", TopSeverity: "HIGH", VulnCount: 1},
		},
	}
	var buf bytes.Buffer
	if err := (Table{NoColor: true}).Render(&buf, r); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "ORIGIN") {
		t.Errorf("ORIGIN column header missing:\n%s", out)
	}
	if !strings.Contains(out, "APP") {
		t.Errorf("APP token missing for app-layer package:\n%s", out)
	}
	if !strings.Contains(out, "DEB") {
		t.Errorf("DEB token missing for deb package:\n%s", out)
	}
}

func TestTable_Render_OriginNotEcosystemForLangPkgs(t *testing.T) {
	r := &tReport{
		Source: "image:app:latest",
		Totals: tTotals{Components: 1, Scanned: 1, WithVulns: 1, HIGH: 1},
		Components: []tComponent{
			{Name: "golang.org/x/net", Version: "0.52.0", System: "golang",
				Class: "os-pkgs", Origin: "app", LayerDigest: "sha256:app0",
				TopSeverity: "HIGH", VulnCount: 1},
		},
	}
	var buf bytes.Buffer
	if err := (Table{NoColor: true}).Render(&buf, r); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "GOLANG") {
		t.Errorf("ORIGIN must not echo the ecosystem as GOLANG:\n%s", out)
	}
	if !strings.Contains(out, "APP") {
		t.Errorf("Go module in an app layer must render APP:\n%s", out)
	}
}

func TestTable_Render_BaseHint(t *testing.T) {
	mk := func(origin string) *tReport {
		return &tReport{
			Source: "image:app:latest",
			Totals: tTotals{Components: 1, Scanned: 1, WithVulns: 1, HIGH: 1},
			Components: []tComponent{{
				Name: "golang.org/x/net", Version: "0.52.0", System: "golang",
				Origin: origin, LayerDigest: "sha256:app0", TopSeverity: "HIGH", VulnCount: 1,
			}},
		}
	}
	const hint = "pass --scout"

	var noBase bytes.Buffer
	if err := (Table{NoColor: true}).Render(&noBase, mk("")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(noBase.String(), hint) {
		t.Errorf("expected base hint when nothing is attributed:\n%s", noBase.String())
	}

	var withBase bytes.Buffer
	if err := (Table{NoColor: true}).Render(&withBase, mk("app")); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(withBase.String(), hint) {
		t.Errorf("base hint must disappear once a base is established:\n%s", withBase.String())
	}
}

func TestTable_Render_OriginAndLangForNonImage(t *testing.T) {
	r := &tReport{
		Source: "sbom:app.cdx.json",
		Totals: tTotals{Components: 2, Scanned: 2, WithVulns: 2, HIGH: 2},
		Components: []tComponent{
			{PURL: "pkg:npm/express@4.17.1", System: "NPM", Name: "express", Version: "4.17.1",
				TopSeverity: "HIGH", VulnCount: 1},
			{PURL: "pkg:npm/cookie@0.4.0", System: "NPM", Name: "cookie", Version: "0.4.0",
				TopSeverity: "HIGH", VulnCount: 1,
				DependencyPaths: [][]string{{"express@4.17.1", "cookie@0.4.0"}}},
		},
	}
	var buf bytes.Buffer
	if err := (Table{NoColor: true}).Render(&buf, r); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "ORIGIN") || !strings.Contains(out, "LANG") {
		t.Errorf("ORIGIN/LANG columns must be shown for non-image scans:\n%s", out)
	}
	// express is direct (no path); cookie is transitive (has a dep path).
	if !strings.Contains(out, "direct") || !strings.Contains(out, "transitive") {
		t.Errorf("expected both direct and transitive origins:\n%s", out)
	}
	if !strings.Contains(out, "js") {
		t.Errorf("expected npm packages to show js language:\n%s", out)
	}
}

func TestTable_Render_ToxicInDependencyPaths(t *testing.T) {
	r := &tReport{
		Source: "sbom:app.cdx.json",
		Totals: tTotals{Components: 2, Scanned: 2, Toxic: 1},
		Components: []tComponent{
			{PURL: "pkg:npm/vite@7.3.2", System: "NPM", Name: "vite", Version: "7.3.2"},
			{PURL: "pkg:npm/acorn@8.16.0", System: "NPM", Name: "acorn", Version: "8.16.0",
				Toxic: tToxic{Found: true, Categories: []string{"political_slogans"},
					Remediation: &tRemediation{Direct: "acorn", CurrentVersion: "8.16.0",
						FixVersion: "8.17.0", Via: "override", Note: "toxic-repos"}},
				DependencyPaths: [][]string{{"vite@7.3.2", "acorn@8.16.0"}}},
		},
	}
	var buf bytes.Buffer
	if err := (Table{NoColor: true}).Render(&buf, r); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	// The Findings TOXIC cell must no longer carry the inline fix.
	if strings.Contains(out, "acorn@8.17.0") && strings.Contains(out, "TOXIC[political_slogans] → acorn@8.17.0") {
		t.Errorf("toxic fix must not appear in the Findings TOXIC cell:\n%s", out)
	}
	// It appears in Dependency paths as (toxic) with a fix line instead.
	if !strings.Contains(out, "acorn@8.16.0 (toxic)") {
		t.Errorf("toxic lib should appear in Dependency paths labelled (toxic):\n%s", out)
	}
	if !strings.Contains(out, "pin acorn → 8.17.0") {
		t.Errorf("toxic fix line missing from Dependency paths:\n%s", out)
	}
}

func TestSARIF_Render_ProducesValidShape(t *testing.T) {
	var buf bytes.Buffer
	if err := (SARIF{}).Render(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	var doc sarifDoc
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("SARIF not valid JSON: %v", err)
	}
	if doc.Version != "2.1.0" {
		t.Errorf("SARIF version = %q; want 2.1.0", doc.Version)
	}
	if !strings.Contains(doc.Schema, "sarif-schema-2.1.0") {
		t.Errorf("$schema mismatch: %q", doc.Schema)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(doc.Runs))
	}
	if doc.Runs[0].Tool.Driver.Name != "wolfee" {
		t.Errorf("driver name = %q; want wolfee", doc.Runs[0].Tool.Driver.Name)
	}
}

func TestSARIF_Render_MalwareSurfacesAsError(t *testing.T) {
	var buf bytes.Buffer
	if err := (SARIF{}).Render(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	var doc sarifDoc
	_ = json.Unmarshal(buf.Bytes(), &doc)

	foundMalRule := false
	for _, rule := range doc.Runs[0].Tool.Driver.Rules {
		if rule.ID == "MAL-2025-47197" {
			foundMalRule = true
			if sev, ok := rule.Properties["security-severity"].(string); !ok || sev != "10.0" {
				t.Errorf("malware rule security-severity = %v; want 10.0", rule.Properties["security-severity"])
			}
		}
	}
	if !foundMalRule {
		t.Error("malware rule MAL-2025-47197 missing from SARIF output")
	}

	foundMalResult := false
	for _, res := range doc.Runs[0].Results {
		if res.RuleID == "MAL-2025-47197" && res.Level == "error" {
			foundMalResult = true
		}
	}
	if !foundMalResult {
		t.Error("malware result missing or not level=error")
	}
}

func TestSARIF_Render_OriginProperty(t *testing.T) {
	r := &tReport{
		Source: "image:my-app:latest",
		Components: []tComponent{
			{Name: "evil", Version: "1.0", System: "npm", Origin: "app",
				Malware: tMalware{Found: true, ID: "MAL-1", Summary: "bad"}},
		},
	}
	var buf bytes.Buffer
	if err := (SARIF{}).Render(&buf, r); err != nil {
		t.Fatal(err)
	}
	var doc sarifDoc
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("SARIF not valid JSON: %v", err)
	}
	if len(doc.Runs[0].Results) == 0 {
		t.Fatal("expected at least one result")
	}
	got, _ := doc.Runs[0].Results[0].Properties["origin"].(string)
	if got != "app" {
		t.Errorf("result origin property = %q, want app", got)
	}
}

func TestSARIF_Render_EmptyReport(t *testing.T) {
	var buf bytes.Buffer
	if err := (SARIF{}).Render(&buf, &tReport{}); err != nil {
		t.Fatal(err)
	}
	var doc sarifDoc
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("empty SARIF should still parse: %v", err)
	}
	if len(doc.Runs) != 1 {
		t.Errorf("empty report should still produce 1 run for SARIF tooling; got %d", len(doc.Runs))
	}
}
