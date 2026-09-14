package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func licenseReport(source, layer string) *tReport {
	return &tReport{
		Source: source,
		Totals: tTotals{Components: 3, Scanned: 3, WithVulns: 1, HIGH: 1, LicenseHigh: 1, LicenseMedium: 1},
		Components: []tComponent{
			{PURL: "pkg:npm/gpl-lib@1.0.0", System: "NPM", Name: "gpl-lib", Version: "1.0.0", LayerDigest: layer,
				License: "AGPL-3.0-only", LicenseRisk: "high"},
			{PURL: "pkg:npm/mpl-lib@2.0.0", System: "NPM", Name: "mpl-lib", Version: "2.0.0", LayerDigest: layer,
				License: "MPL-2.0", LicenseRisk: "medium", TopSeverity: "HIGH", VulnCount: 1,
				Vulnerabilities: []tVuln{{Severity: "HIGH", ID: "CVE-2024-1", CVE: "CVE-2024-1"}}},
			{PURL: "pkg:npm/mit-lib@3.0.0", System: "NPM", Name: "mit-lib", Version: "3.0.0", LayerDigest: layer,
				License: "MIT", LicenseRisk: "low"},
		},
	}
}

func TestTable_Render_LicenseColumnAndRisks(t *testing.T) {
	for _, tc := range []struct{ name, source, layer string }{
		{"sbom", "sbom:app.cdx.json", ""},
		{"image", "image:app:latest", "sha256:layer0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := (Table{NoColor: true}).Render(&buf, licenseReport(tc.source, tc.layer)); err != nil {
				t.Fatal(err)
			}
			out := buf.String()
			for _, want := range []string{"LICENSE", "MPL-2.0", "Risky licenses", "Weak-copyleft licenses", "License risks"} {
				if !strings.Contains(out, want) {
					t.Errorf("missing %q:\n%s", want, out)
				}
			}
			// Image scans hide clean components from Findings, but the GPL lib
			// must still surface in the License risks section.
			risks := out[strings.Index(out, "License risks"):]
			if !strings.Contains(risks, "gpl-lib@1.0.0") || !strings.Contains(risks, "AGPL-3.0-only") {
				t.Errorf("high-risk license missing from License risks:\n%s", risks)
			}
			if strings.Contains(risks, "mit-lib") {
				t.Errorf("permissive license must not be listed as a risk:\n%s", risks)
			}
		})
	}
}

func TestTable_Render_HighRiskLicenseIsRed(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	var buf bytes.Buffer
	if err := (Table{}).Render(&buf, licenseReport("sbom:app.cdx.json", "")); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "\x1b[1;31mAGPL-3.0-only\x1b[0m") {
		t.Errorf("high-risk license should be bold red:\n%q", out)
	}
	if !strings.Contains(out, "\x1b[33mMPL-2.0\x1b[0m") {
		t.Errorf("weak-copyleft license should be yellow:\n%q", out)
	}
	if strings.Contains(out, "\x1b[1;31mMIT\x1b[0m") {
		t.Errorf("permissive license must not be red:\n%q", out)
	}
}

func TestSARIF_Render_Licenses(t *testing.T) {
	var buf bytes.Buffer
	if err := (SARIF{}).Render(&buf, licenseReport("sbom:app.cdx.json", "")); err != nil {
		t.Fatal(err)
	}
	var doc sarifDoc
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("SARIF not valid JSON: %v", err)
	}
	levels := map[string]string{}
	var vulnLicense any
	for _, res := range doc.Runs[0].Results {
		levels[res.RuleID] = res.Level
		if res.RuleID == "CVE-2024-1" {
			vulnLicense = res.Properties["license"]
		}
	}
	if levels["WOLFEE-LICENSE-HIGH-RISK"] != "error" {
		t.Errorf("high-risk license result missing or not error: %v", levels)
	}
	if levels["WOLFEE-LICENSE-WEAK-COPYLEFT"] != "warning" {
		t.Errorf("weak-copyleft license result missing or not warning: %v", levels)
	}
	if vulnLicense != "MPL-2.0" {
		t.Errorf("vulnerability result must carry the package license, got %v", vulnLicense)
	}
	for id := range levels {
		if strings.Contains(id, "LICENSE") && strings.Contains(buf.String(), "mit-lib is licensed") {
			t.Errorf("permissive license must not produce a SARIF result")
		}
	}
}

func TestFixPlan_Render_LicenseRisksWithoutPlan(t *testing.T) {
	type report struct {
		Source     string
		FixPlan    *tFixPlan
		Components []tComponent
	}
	r := report{Components: []tComponent{
		{Name: "gpl-lib", Version: "1.0.0", System: "NPM", License: "GPL-3.0-only", LicenseRisk: "high"},
	}}
	var buf bytes.Buffer
	if err := (FixPlan{NoColor: true}).Render(&buf, r); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "No remediation plan available.") {
		t.Errorf("expected the no-plan notice:\n%s", out)
	}
	if !strings.Contains(out, "License risks") || !strings.Contains(out, "gpl-lib@1.0.0") {
		t.Errorf("license risks must be rendered even without a remediation plan:\n%s", out)
	}
}

func TestFixPlan_Render_License(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	var buf bytes.Buffer
	report := tFixPlanReport{FixPlan: &tFixPlan{Groups: []tFixGroup{{
		Direct: "express", CurrentVersion: "4.18.2", FixVersion: "4.21.2",
		Packages: []tFixPackage{{Package: "qs@6.11.0", License: "GPL-3.0", LicenseRisk: "high",
			Vulnerabilities: []tFixVulnerability{{CVE: "CVE-1", Severity: "HIGH"}}}},
	}}}}
	if err := (FixPlan{}).Render(&buf, report); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "LICENSE") || !strings.Contains(buf.String(), "\x1b[1;31mGPL-3.0\x1b[0m") {
		t.Errorf("fix-plan must show the license in red:\n%q", buf.String())
	}
}
