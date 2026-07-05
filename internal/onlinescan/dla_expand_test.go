package onlinescan

import "testing"

func TestExpandAdvisoryRows_InheritsWorstSeverityFromConstituentCVE(t *testing.T) {
	idx := &dlaIndex{
		loaded: true,
		byAdvisory: map[string][]string{
			"DLA-2513-1": {"CVE-2020-1971", "CVE-2020-2604"},
		},
	}
	results := []*ComponentResult{

		{
			Component: Component{System: "DEBIAN", Name: "openssl", Version: "1.0.1t-1"},
			Vulnerabilities: []Vulnerability{
				{ID: "CVE-2020-1971", CVE: "CVE-2020-1971", Severity: SevHigh, SeveritySource: "OSV"},
			},
		},

		{
			Component: Component{System: "DEBIAN", Name: "libp11-kit0", Version: "0.23.3-2"},
			Vulnerabilities: []Vulnerability{
				{ID: "DLA-2513-1", CVE: "", Severity: ""},
			},
		},
	}

	expandAdvisoryRows(results, idx)

	v := &results[1].Vulnerabilities[0]
	if v.Severity != SevHigh {
		t.Errorf("DLA severity = %q; want %q (inherited from constituent CVE)", v.Severity, SevHigh)
	}
	if v.SeveritySource != "dla-expand:CVE-2020-1971" {
		t.Errorf("severity source must attribute the donor CVE, got %q", v.SeveritySource)
	}
	if len(v.RelatedAdvisories) != 1 || v.RelatedAdvisories[0] != "DLA-2513-1" {
		t.Errorf("relatedAdvisories should record the advisory id, got %v", v.RelatedAdvisories)
	}
	if !containsStr(v.Aliases, "CVE-2020-1971") || !containsStr(v.Aliases, "CVE-2020-2604") {
		t.Errorf("aliases should expose constituent CVEs, got %v", v.Aliases)
	}
}

func TestExpandAdvisoryRows_PicksMaxSeverityAcrossCVEs(t *testing.T) {
	idx := &dlaIndex{
		loaded: true,
		byAdvisory: map[string][]string{
			"DLA-9999-1": {"CVE-A", "CVE-B", "CVE-C"},
		},
	}
	results := []*ComponentResult{
		{Vulnerabilities: []Vulnerability{
			{CVE: "CVE-A", Severity: SevLow},
			{CVE: "CVE-B", Severity: SevCritical},
			{CVE: "CVE-C", Severity: SevMedium},
			{ID: "DLA-9999-1"},
		}},
	}
	expandAdvisoryRows(results, idx)
	v := &results[0].Vulnerabilities[3]
	if v.Severity != SevCritical {
		t.Errorf("expected CRITICAL (max across CVEs), got %q", v.Severity)
	}
	if v.SeveritySource != "dla-expand:CVE-B" {
		t.Errorf("expected attribution to CVE-B, got %q", v.SeveritySource)
	}
}

func TestExpandAdvisoryRows_NoOpWhenNoConstituentSeverityAvailable(t *testing.T) {
	idx := &dlaIndex{
		loaded:     true,
		byAdvisory: map[string][]string{"DLA-9998-1": {"CVE-A"}},
	}
	results := []*ComponentResult{
		{Vulnerabilities: []Vulnerability{
			{CVE: "CVE-A", Severity: ""},
			{ID: "DLA-9998-1"},
		}},
	}
	expandAdvisoryRows(results, idx)
	if got := results[0].Vulnerabilities[1].Severity; got != "" {
		t.Errorf("severity must stay empty, got %q", got)
	}
}

func TestExpandAdvisoryRows_LeavesRowsWithCVEAlone(t *testing.T) {
	idx := &dlaIndex{
		loaded:     true,
		byAdvisory: map[string][]string{"DLA-9998-1": {"CVE-OTHER"}},
	}
	results := []*ComponentResult{
		{Vulnerabilities: []Vulnerability{
			{CVE: "CVE-OTHER", Severity: SevCritical},
			{ID: "DLA-9998-1", CVE: "CVE-A", Severity: SevLow},
		}},
	}
	expandAdvisoryRows(results, idx)
	if got := results[0].Vulnerabilities[1].Severity; got != SevLow {
		t.Errorf("row with CVE must not be reclassified, got %q", got)
	}
}

func TestExpandAdvisoryRows_SkipsNonAdvisoryIDs(t *testing.T) {
	idx := &dlaIndex{
		loaded:     true,
		byAdvisory: map[string][]string{"DLA-9998-1": {"CVE-A"}},
	}
	results := []*ComponentResult{
		{Vulnerabilities: []Vulnerability{
			{CVE: "CVE-A", Severity: SevHigh},
			{ID: "GHSA-xxxx-yyyy-zzzz", CVE: ""},
		}},
	}
	expandAdvisoryRows(results, idx)
	if got := results[0].Vulnerabilities[1].Severity; got != "" {
		t.Errorf("GHSA row must not be touched, got %q", got)
	}
}

func TestExpandAdvisoryRows_IsIdempotent(t *testing.T) {
	idx := &dlaIndex{
		loaded:     true,
		byAdvisory: map[string][]string{"DLA-9998-1": {"CVE-A"}},
	}
	results := []*ComponentResult{
		{Vulnerabilities: []Vulnerability{
			{CVE: "CVE-A", Severity: SevHigh},
			{ID: "DLA-9998-1"},
		}},
	}
	expandAdvisoryRows(results, idx)
	expandAdvisoryRows(results, idx)
	v := &results[0].Vulnerabilities[1]
	if len(v.RelatedAdvisories) != 1 {
		t.Errorf("relatedAdvisories duplicated on second run: %v", v.RelatedAdvisories)
	}
	if len(v.Aliases) != 1 {
		t.Errorf("aliases duplicated on second run: %v", v.Aliases)
	}
}

func TestIsAdvisoryRow_RecognisesShapes(t *testing.T) {
	cases := []struct {
		v    Vulnerability
		want bool
	}{
		{Vulnerability{ID: "DLA-3712-1", CVE: ""}, true},
		{Vulnerability{ID: "DSA-5800-1", CVE: ""}, true},
		{Vulnerability{ID: "USN-6789-1", CVE: ""}, true},
		{Vulnerability{ID: "DLA-3712-1", CVE: "CVE-X"}, false},
		{Vulnerability{ID: "GHSA-x-y-z", CVE: ""}, false},
		{Vulnerability{ID: "CVE-2024-1234", CVE: ""}, false},
		{Vulnerability{ID: "", CVE: ""}, false},
	}
	for i, c := range cases {
		got := isAdvisoryRow(&c.v)
		if got != c.want {
			t.Errorf("[%d] isAdvisoryRow(%+v) = %v; want %v", i, c.v, got, c.want)
		}
	}
}
