package sbomscan

import (
	"testing"

	"github.com/shinigamikiko/wolfee-cli/internal/onlinescan"
)

func TestBuildFixPlanGroupsPackagesAndKeepsUnresolved(t *testing.T) {
	rem := &onlinescan.Remediation{Direct: "express", CurrentVersion: "4.18.2", FixVersion: "4.21.2", Via: "parent-bump"}
	r := &Report{Components: []ComponentReport{
		{
			PURL: "pkg:npm/qs@6.11.0", Name: "qs", Version: "6.11.0",
			DependencyPaths: [][]string{{"app", "express", "qs"}},
			Vulnerabilities: []onlinescan.Vulnerability{{ID: "GHSA-qs", CVE: "CVE-2022-24999", Severity: onlinescan.SevHigh, Remediation: rem}},
		},
		{
			PURL: "pkg:npm/path-to-regexp@0.1.7", Name: "path-to-regexp", Version: "0.1.7",
			DependencyPaths: [][]string{{"app", "express", "path-to-regexp"}},
			Vulnerabilities: []onlinescan.Vulnerability{{ID: "CVE-2024-45296", Severity: onlinescan.SevHigh, Remediation: rem}},
		},
		{
			PURL: "pkg:npm/left-pad@1.3.0", Name: "left-pad", Version: "1.3.0",
			Vulnerabilities: []onlinescan.Vulnerability{{ID: "CVE-UNRESOLVED", Severity: onlinescan.SevMedium}},
		},
		{
			PURL: "pkg:composer/symfony/cache@v5.4.3", Name: "cache", Version: "v5.4.3",
			DependencyPaths: [][]string{{"app", "cache"}},
			Vulnerabilities: []onlinescan.Vulnerability{{ID: "CVE-OSV-FIXED", Severity: onlinescan.SevHigh, Fixed: []string{"v5.4.45"}}},
		},
	}}

	plan := BuildFixPlan(r)
	if plan == nil || len(plan.Groups) != 2 {
		t.Fatalf("plan groups = %#v, want two groups", plan)
	}
	var expressGroup *FixPlanGroup
	for i := range plan.Groups {
		if plan.Groups[i].Direct == "express" {
			expressGroup = &plan.Groups[i]
		}
	}
	if expressGroup == nil {
		t.Fatalf("express group missing: %#v", plan.Groups)
	}
	if got := len(expressGroup.Packages); got != 2 {
		t.Fatalf("group packages = %d, want 2", got)
	}
	if got := len(expressGroup.Packages[0].Vulnerabilities); got != 1 {
		t.Errorf("first package vulnerabilities = %d, want 1", got)
	}
	if len(plan.Unresolved) != 1 || plan.Unresolved[0].Package != "left-pad@1.3.0" {
		t.Errorf("unresolved = %#v", plan.Unresolved)
	}
	var foundFallback bool
	for _, group := range plan.Groups {
		if group.Direct == "cache" && group.FixVersion == "v5.4.45" && group.Via == "osv-fixed" {
			foundFallback = true
		}
	}
	if !foundFallback {
		t.Errorf("missing OSV fallback group: %#v", plan.Groups)
	}
}
