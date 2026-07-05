package output

import (
	"bytes"
	"strings"
	"testing"
)

func TestLangLabel(t *testing.T) {
	cases := []struct {
		name     string
		system   string
		purl     string
		language string
		want     string
	}{
		{"explicit js", "npm", "", "js", "relevant-js"},
		{"system fallback", "npm", "", "", "relevant-js"},
		{"python compact", "pypi", "", "python", "relevant-py"},
		{"java", "maven", "", "java", "relevant-java"},
		{"runtime package", "deb", "", "", "runtime/os"},
		{"purl ecosystem fallback", "", "pkg:golang/golang.org/x/net@v0.1.0", "", "relevant-go"},
		{"unknown ecosystem", "", "", "", "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := langLabel(tc.system, tc.purl, tc.language)
			if got != tc.want {
				t.Fatalf("langLabel(...) = %q, want %q", got, tc.want)
			}
		})
	}
}

type langTableReport struct {
	Totals     langTableTotals
	Components []langTableComponent
}

type langTableTotals struct {
	Components int
	Scanned    int
	WithVulns  int
	HIGH       int
}

type langTableComponent struct {
	PURL              string
	System            string
	Name              string
	Version           string
	Language          string
	LanguageRelevance string
	Relevant          *bool
	PackageUsage      string
	TopSeverity       string
	VulnCount         int
}

func boolPtr(b bool) *bool { return &b }

func TestTable_Render_LangColumnLast(t *testing.T) {
	r := &langTableReport{
		Totals: langTableTotals{Components: 2, Scanned: 2, WithVulns: 2, HIGH: 2},
		Components: []langTableComponent{
			{Name: "lodash", Version: "4.17.20", System: "npm", PURL: "pkg:npm/lodash@4.17.20", Language: "js", LanguageRelevance: "used", TopSeverity: "HIGH", VulnCount: 1},
			{Name: "log4j-core", Version: "2.14.0", System: "maven", PURL: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0", Language: "java", LanguageRelevance: "irrelevant", TopSeverity: "HIGH", VulnCount: 1},
		},
	}

	var buf bytes.Buffer
	if err := (Table{NoColor: true}).Render(&buf, r); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	header := ""
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "PACKAGE") && strings.Contains(line, "LANG") {
			header = line
			break
		}
	}
	if header == "" {
		t.Fatalf("LANG header missing:\n%s", out)
	}
	if !strings.HasSuffix(strings.TrimSpace(header), "LANG") {
		t.Fatalf("LANG should be the last findings column, header=%q", header)
	}
	if !strings.Contains(out, "lodash") || !strings.Contains(out, "js") {
		t.Fatalf("missing js language label:\n%s", out)
	}
	if !strings.Contains(out, "log4j-core") || !strings.Contains(out, "java") {
		t.Fatalf("missing java language label:\n%s", out)
	}
	for _, unwanted := range []string{"js:used", "java:not-repo", "not-repo", "irrelevant"} {
		if strings.Contains(out, unwanted) {
			t.Fatalf("language column should not print %q:\n%s", unwanted, out)
		}
	}
}

func TestTable_Render_LangRelevanceColors(t *testing.T) {
	r := &langTableReport{
		Totals: langTableTotals{Components: 2, Scanned: 2, WithVulns: 2, HIGH: 2},
		Components: []langTableComponent{
			{Name: "golang.org/x/net", Version: "0.1.0", System: "golang", PURL: "pkg:golang/golang.org/x/net@v0.1.0", Language: "go", Relevant: boolPtr(true), TopSeverity: "HIGH", VulnCount: 1},
			{Name: "monolog", Version: "2.0.0", System: "composer", PURL: "pkg:composer/monolog/monolog@2.0.0", Language: "php", Relevant: boolPtr(false), TopSeverity: "HIGH", VulnCount: 1},
		},
	}

	var buf bytes.Buffer
	if err := (Table{NoColor: false}).Render(&buf, r); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	const green = "\x1b[32m"
	const red = "\x1b[31m"
	if !strings.Contains(out, green+"relevant-go\x1b[0m") {
		t.Fatalf("matching language should be green relevant-go:\n%s", out)
	}
	if !strings.Contains(out, red+"relevant-php\x1b[0m") {
		t.Fatalf("mismatched language should be red relevant-php:\n%s", out)
	}
}

func TestTable_Render_PlainLangWithoutRelevance(t *testing.T) {
	r := &langTableReport{
		Totals: langTableTotals{Components: 1, Scanned: 1, WithVulns: 1, HIGH: 1},
		Components: []langTableComponent{
			{Name: "lodash", Version: "4.17.20", System: "npm", PURL: "pkg:npm/lodash@4.17.20", TopSeverity: "HIGH", VulnCount: 1},
		},
	}

	var buf bytes.Buffer
	if err := (Table{NoColor: true}).Render(&buf, r); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	// LANG is always shown now; without reachability it is the plain ecosystem
	// language, not the "relevant-" framing.
	if !strings.Contains(out, "LANG") || !strings.Contains(out, "js") {
		t.Fatalf("expected plain js language column:\n%s", out)
	}
	if strings.Contains(out, "relevant-js") {
		t.Fatalf("relevant- framing must not appear without reachability data:\n%s", out)
	}
}
