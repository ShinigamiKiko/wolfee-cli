package output

import (
	"bytes"
	"strings"
	"testing"
)

func TestSARIF_Render_QualifiesGroupedPackageNames(t *testing.T) {
	report := &tReport{Components: []tComponent{
		{System: "PACKAGIST", Group: "symfony", Name: "yaml", Version: "v7.3.0",
			Vulnerabilities: []tVuln{{ID: "GHSA-c2p3-7m5p-cv8x", Severity: "MEDIUM"}}},
		{System: "NPM", Group: "@angular", Name: "core", Version: "17.0.0",
			Vulnerabilities: []tVuln{{ID: "GHSA-aaaa-bbbb-cccc", Severity: "LOW"}}},
		{System: "NPM", Name: "lodash", Version: "4.17.20",
			Vulnerabilities: []tVuln{{ID: "GHSA-35jh-r3h4-6jhm", Severity: "HIGH"}}},
	}}

	var buf bytes.Buffer
	if err := (SARIF{}).Render(&buf, report); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"packagist/symfony/yaml@v7.3.0", "npm/@angular/core@17.0.0", "npm/lodash@4.17.20"} {
		if !strings.Contains(out, want) {
			t.Errorf("SARIF lacks %q", want)
		}
	}
	if strings.Contains(out, "packagist/yaml@") {
		t.Error("composer package reported without its vendor namespace")
	}
}
