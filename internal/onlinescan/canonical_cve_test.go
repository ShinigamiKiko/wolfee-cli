package onlinescan

import "testing"

func TestCanonicalCVE(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"CVE-2023-4911", "CVE-2023-4911"},
		{" CVE-2023-4911 ", "CVE-2023-4911"},
		{"DEBIAN-CVE-2023-4911", "CVE-2023-4911"},
		{"UBUNTU-CVE-2023-4911", "CVE-2023-4911"},
		{"USN-1234-1-CVE-2023-4911", "CVE-2023-4911"},
		{"", ""},
		{"GHSA-1234-5678-9abc", ""},
		{"DLA-1234-1", ""},
	}
	for _, c := range cases {
		if got := canonicalCVE(c.in); got != c.want {
			t.Errorf("canonicalCVE(%q) = %q; want %q", c.in, got, c.want)
		}
	}
}

func TestUniqueCVEs_CanonicalisesPrefixedValues(t *testing.T) {
	results := []*ComponentResult{
		{Vulnerabilities: []Vulnerability{
			{CVE: "DEBIAN-CVE-2023-4911"},
			{CVE: "CVE-2023-4911"},
			{CVE: "UBUNTU-CVE-2023-1234"},
			{CVE: "GHSA-xxxx"},
		}},
	}
	got := uniqueCVEs(results)
	if len(got) != 2 {
		t.Fatalf("expected 2 unique canonical CVEs, got %d (%v)", len(got), got)
	}
	want := map[string]bool{"CVE-2023-4911": true, "CVE-2023-1234": true}
	for _, c := range got {
		if !want[c] {
			t.Errorf("unexpected CVE in result: %q", c)
		}
	}
}

func TestNormaliseCVEFields_IsIdempotent(t *testing.T) {
	results := []*ComponentResult{
		{Vulnerabilities: []Vulnerability{
			{CVE: "DEBIAN-CVE-2023-4911"},
			{CVE: "CVE-2024-0001"},
			{CVE: ""},
		}},
	}
	normaliseCVEFields(results)
	if results[0].Vulnerabilities[0].CVE != "CVE-2023-4911" {
		t.Errorf("prefixed CVE not canonicalised: %q", results[0].Vulnerabilities[0].CVE)
	}
	if results[0].Vulnerabilities[1].CVE != "CVE-2024-0001" {
		t.Errorf("canonical CVE altered: %q", results[0].Vulnerabilities[1].CVE)
	}

	normaliseCVEFields(results)
	if results[0].Vulnerabilities[0].CVE != "CVE-2023-4911" {
		t.Errorf("second normalisation pass changed value: %q", results[0].Vulnerabilities[0].CVE)
	}
}
