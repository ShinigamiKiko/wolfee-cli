package sbomscan

import "testing"

func TestClassifyLicenseExpression(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"MIT", LicenseRiskLow},
		{"Apache-2.0", LicenseRiskLow},
		{"BSD-3-Clause", LicenseRiskLow},
		{"BSL-1.0", LicenseRiskLow},
		{"ISC", LicenseRiskLow},
		{"GPL-3.0-only", LicenseRiskHigh},
		{"GPL-2.0+", LicenseRiskHigh},
		{"AGPL-3.0-or-later", LicenseRiskHigh},
		{"SSPL-1.0", LicenseRiskHigh},
		{"BUSL-1.1", LicenseRiskHigh},
		{"CC-BY-NC-4.0", LicenseRiskHigh},
		{"GNU General Public License v3", LicenseRiskHigh},
		{"LGPL-2.1-or-later", LicenseRiskMedium},
		{"GNU Lesser General Public License", LicenseRiskMedium},
		{"MPL-2.0", LicenseRiskMedium},
		{"EPL-2.0", LicenseRiskMedium},
		{"GPL-2.0-only WITH Classpath-exception-2.0", LicenseRiskMedium},
		{"MIT OR GPL-3.0", LicenseRiskLow},
		{"(MIT AND GPL-2.0)", LicenseRiskHigh},
		{"MIT AND MPL-2.0", LicenseRiskMedium},
		{"GPL-3.0-only AND (MIT OR Apache-2.0)", LicenseRiskHigh},
		{"(MIT OR Apache-2.0) AND GPL-3.0-only", LicenseRiskHigh},
		{"MIT OR GPL-3.0 AND Apache-2.0", LicenseRiskLow},
		{"(MIT OR GPL-3.0) AND Apache-2.0", LicenseRiskLow},
		{"LGPL-2.1 OR (GPL-2.0 AND MIT)", LicenseRiskMedium},
		{"(GPL-2.0-only WITH Classpath-exception-2.0) OR AGPL-3.0", LicenseRiskMedium},
		{"((MIT))", LicenseRiskLow},
		{"MIT/GPL-2.0", LicenseRiskLow},
		{"GPL-3.0 AND (MIT", LicenseRiskHigh},
		{"SEE LICENSE IN LICENSE.md", LicenseRiskUnknown},
		{"", ""},
	}
	for _, c := range cases {
		if got := classifyLicenseExpression(c.in); got != c.want {
			t.Errorf("classifyLicenseExpression(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSummarizeLicenses(t *testing.T) {
	display, risk := summarizeLicenses([]LicenseChoice{
		{License: &License{ID: "MIT"}},
		{License: &License{Name: "GPL-2.0-only"}},
		{Expression: "Apache-2.0 OR LGPL-3.0"},
		{License: &License{ID: "mit"}},
	})
	if display != "MIT, GPL-2.0-only, Apache-2.0 OR LGPL-3.0" {
		t.Errorf("display = %q", display)
	}
	if risk != LicenseRiskHigh {
		t.Errorf("risk = %q, want high", risk)
	}
	if d, r := summarizeLicenses(nil); d != "" || r != "" {
		t.Errorf("empty licenses should give empty summary, got %q/%q", d, r)
	}
}

func TestAnnotateLicensesAndTotals(t *testing.T) {
	r := &Report{Components: []ComponentReport{
		{Name: "a", Licenses: trivyLicenses([]string{"AGPL-3.0"})},
		{Name: "b", Licenses: trivyLicenses([]string{"MPL-2.0"})},
		{Name: "c", Licenses: trivyLicenses([]string{"MIT"})},
		{Name: "d"},
	}}
	annotateLicenses(r.Components)
	countLicenseTotals(r)
	if r.Components[0].LicenseRisk != LicenseRiskHigh || r.Components[1].LicenseRisk != LicenseRiskMedium ||
		r.Components[2].LicenseRisk != LicenseRiskLow || r.Components[3].LicenseRisk != "" {
		t.Errorf("unexpected risks: %+v", r.Components)
	}
	if r.Totals.LicenseHigh != 1 || r.Totals.LicenseMedium != 1 {
		t.Errorf("totals = %+v", r.Totals)
	}
}
