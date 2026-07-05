package cli

import (
	"strings"
	"testing"

	"sca-go/cli/internal/onlinescan"
	"sca-go/cli/internal/sbomscan"
)

func TestScanOpts_ValidateRequiresOneInput(t *testing.T) {
	o := &scanOpts{format: "table", failOn: "none"}
	if err := o.validate(); err == nil {
		t.Fatal("expected error when no input mode is set")
	}
}

func TestScanOpts_ValidateMutexInputs(t *testing.T) {
	cases := []struct {
		name string
		o    scanOpts
	}{
		{"image+bom", scanOpts{image: "x", bom: "y"}},
		{"image+purl", scanOpts{image: "x", purl: "pkg:npm/x@1"}},
		{"bom+purl", scanOpts{bom: "x", purl: "pkg:npm/x@1"}},
		{"all-three", scanOpts{image: "x", bom: "y", purl: "pkg:npm/x@1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.o.validate()
			if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
				t.Errorf("expected mutex error, got %v", err)
			}
		})
	}
}

func TestScanOpts_ValidateAcceptsAnyOneInput(t *testing.T) {
	cases := []scanOpts{
		{image: "nginx:1.27"},
		{bom: "/tmp/x.json"},
		{purl: "pkg:npm/lodash@4.17.21"},
	}
	for i, o := range cases {
		if err := o.validate(); err != nil {
			t.Errorf("case %d: validate failed: %v", i, err)
		}
	}
}

func TestScanOpts_ValidateFormat(t *testing.T) {
	for _, f := range []string{"table", "json", "sarif", "TABLE", "JSON"} {
		o := scanOpts{image: "x", format: f}
		if err := o.validate(); err != nil {
			t.Errorf("format %q rejected: %v", f, err)
		}
	}
	o := scanOpts{image: "x", format: "yaml"}
	if err := o.validate(); err == nil {
		t.Error("expected error for unsupported format")
	}
}

func TestScanOpts_ValidateFailOn(t *testing.T) {
	for _, level := range []string{"", "none", "low", "medium", "high", "critical", "HIGH"} {
		o := scanOpts{image: "x", failOn: level}
		if err := o.validate(); err != nil {
			t.Errorf("fail-on %q rejected: %v", level, err)
		}
	}
	o := scanOpts{image: "x", failOn: "catastrophic"}
	if err := o.validate(); err == nil {
		t.Error("expected error for unsupported fail-on")
	}
}

func TestScanOpts_ServerRequiresProject(t *testing.T) {
	o := &scanOpts{image: "x", server: "https://example.com"}
	err := o.validate()
	if err == nil || !strings.Contains(err.Error(), "project") {
		t.Errorf("expected --server to require --project, got: %v", err)
	}
}

func TestArrayFlag_Accumulates(t *testing.T) {
	var a arrayFlag
	_ = a.Set("--profile=research")
	_ = a.Set("--no-recurse")
	_ = a.Set("--skip-something")
	if len(a) != 3 {
		t.Fatalf("expected 3 entries, got %d: %v", len(a), a)
	}
	if a[0] != "--profile=research" || a[2] != "--skip-something" {
		t.Errorf("order not preserved: %v", a)
	}
}

func TestParseScanFlags_DefaultsAreSane(t *testing.T) {
	o, err := parseScanFlags([]string{"--image", "nginx"})
	if err != nil {
		t.Fatal(err)
	}
	if o.format != "table" {
		t.Errorf("default format should be table, got %q", o.format)
	}
	if o.failOn != "none" {
		t.Errorf("default fail-on should be none, got %q", o.failOn)
	}
	if o.deep || o.requiredOnly {
		t.Errorf("cdxgen flags should default off")
	}
}

func TestParseScanFlags_PositionalPath(t *testing.T) {
	o, err := parseScanFlags([]string{"./my-project"})
	if err != nil {
		t.Fatal(err)
	}
	if o.path != "./my-project" {
		t.Errorf("path not captured: %q", o.path)
	}
	if o.image != "" || o.bom != "" || o.purl != "" {
		t.Errorf("path mode should leave other inputs empty: %+v", o)
	}
}

func TestParseScanFlags_PathLeadingThenFlags(t *testing.T) {
	o, err := parseScanFlags([]string{"./", "--format", "json", "--output", "report.json"})
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if o.path != "./" {
		t.Errorf("path not captured: %q", o.path)
	}
	if o.format != "json" || o.outFile != "report.json" {
		t.Errorf("flags after path not parsed: format=%q out=%q", o.format, o.outFile)
	}
}

func TestParseScanFlags_PathTrailingAfterFlags(t *testing.T) {
	o, err := parseScanFlags([]string{"--format", "json", "--output", "report.json", "./"})
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if o.path != "./" {
		t.Errorf("trailing path not captured: %q", o.path)
	}
	if o.format != "json" || o.outFile != "report.json" {
		t.Errorf("leading flags lost: format=%q out=%q", o.format, o.outFile)
	}
}

func TestParseScanFlags_RejectMultiplePositional(t *testing.T) {
	_, err := parseScanFlags([]string{"./a", "./b"})
	if err == nil {
		t.Fatal("expected error on multiple positional paths")
	}
}

func TestParseScanFlags_RejectPathBothEnds(t *testing.T) {
	_, err := parseScanFlags([]string{"./a", "--format", "json", "./b"})
	if err == nil {
		t.Fatal("expected error when path given before AND after flags")
	}
}

func TestValidate_PathExclusiveWithOtherModes(t *testing.T) {
	cases := []struct {
		name    string
		opts    scanOpts
		wantErr bool
	}{
		{"path only", scanOpts{path: "./", format: "table", failOn: "none"}, false},
		{"image only", scanOpts{image: "nginx", format: "table", failOn: "none"}, false},
		{"path + image", scanOpts{path: "./", image: "nginx", format: "table", failOn: "none"}, true},
		{"path + bom", scanOpts{path: "./", bom: "f.json", format: "table", failOn: "none"}, true},
		{"path + purl", scanOpts{path: "./", purl: "pkg:npm/x@1", format: "table", failOn: "none"}, true},
		{"nothing", scanOpts{format: "table", failOn: "none"}, true},
	}
	for _, c := range cases {
		err := c.opts.validate()
		if (err != nil) != c.wantErr {
			t.Errorf("%s: validate() err=%v, wantErr=%v", c.name, err, c.wantErr)
		}
	}
}

func TestEvalFailOn(t *testing.T) {
	mk := func(sev string, mal bool) sbomscan.ComponentReport {
		c := sbomscan.ComponentReport{TopSeverity: sev}
		c.Malware = onlinescan.Malware{Found: mal}
		return c
	}

	cases := []struct {
		name     string
		level    string
		comps    []sbomscan.ComponentReport
		wantCode int
	}{
		{"none-blocks-nothing", "none", []sbomscan.ComponentReport{mk("CRITICAL", true)}, 0},
		{"low-passes-clean", "low", []sbomscan.ComponentReport{mk("", false)}, 0},
		{"low-fails-on-low", "low", []sbomscan.ComponentReport{mk("LOW", false)}, 2},
		{"medium-fails-on-medium", "medium", []sbomscan.ComponentReport{mk("MEDIUM", false)}, 2},
		{"high-fails-on-critical", "high", []sbomscan.ComponentReport{mk("CRITICAL", false)}, 2},
		{"high-passes-on-medium", "high", []sbomscan.ComponentReport{mk("MEDIUM", false)}, 0},
		{"critical-fails-on-malware", "critical", []sbomscan.ComponentReport{mk("", true)}, 2},
		{"empty-report-passes", "high", nil, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &sbomscan.Report{Components: tc.comps}
			got := evalFailOn(tc.level, r)
			if got != tc.wantCode {
				t.Errorf("evalFailOn(%q) = %d; want %d", tc.level, got, tc.wantCode)
			}
		})
	}
}

func TestSeverityRank_Ordering(t *testing.T) {

	prev := 99
	for _, s := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"} {
		r := severityRank(s)
		if r >= prev {
			t.Errorf("severityRank(%q)=%d should be < %d", s, r, prev)
		}
		prev = r
	}
}
