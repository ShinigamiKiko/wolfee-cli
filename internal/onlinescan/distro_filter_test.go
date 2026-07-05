package onlinescan

import "testing"

func TestApplyDistroFiltering_DebianResolvedEqualFixIsFixedInInstalled(t *testing.T) {
	results := []*ComponentResult{
		{
			Component: Component{
				System:  "DEBIAN",
				Name:    "libxml2",
				Version: "2.9.14+dfsg-1.3~deb12u1",
			},
			Vulnerabilities: []Vulnerability{
				{
					ID:       "DEBIAN-CVE-2022-2309",
					Severity: SevHigh,
					DistroStatus: []DistroStatus{
						{Distro: "debian", Release: "12", Status: "resolved", FixVersion: "2.9.14+dfsg-1.3~deb12u1"},
					},
				},
			},
		},
	}

	applyDistroFiltering(results, &ImageOS{Family: "debian", Version: "12", Codename: "bookworm"})

	if got := len(results[0].Vulnerabilities); got != 1 {
		t.Fatalf("installed==fixed should surface as fixed_in_installed, got %d vulns", got)
	}
	if got := results[0].Vulnerabilities[0].Status; got != statusFixedInInstalled {
		t.Errorf("expected status %q, got %q", statusFixedInInstalled, got)
	}
}

func TestApplyDistroFiltering_DebianInstalledAboveFixDropped(t *testing.T) {
	results := []*ComponentResult{
		{
			Component: Component{
				System:  "DEBIAN",
				Name:    "libxml2",
				Version: "2.9.14+dfsg-1.3~deb12u2",
			},
			Vulnerabilities: []Vulnerability{
				{
					ID:       "DEBIAN-CVE-2022-2309",
					Severity: SevHigh,
					DistroStatus: []DistroStatus{
						{Distro: "debian", Release: "12", Status: "resolved", FixVersion: "2.9.14+dfsg-1.3~deb12u1"},
					},
				},
			},
		},
	}

	applyDistroFiltering(results, &ImageOS{Family: "debian", Version: "12", Codename: "bookworm"})

	if got := len(results[0].Vulnerabilities); got != 0 {
		t.Fatalf("installed>fixed should be dropped silently, got %d vulns", got)
	}
}

func TestApplyDistroFiltering_DebianLowerThanFixRetained(t *testing.T) {
	results := []*ComponentResult{
		{
			Component: Component{
				System:  "DEBIAN",
				Name:    "libxml2",
				Version: "2.9.14+dfsg-1.3~deb12u1",
			},
			Vulnerabilities: []Vulnerability{
				{
					ID:       "DEBIAN-CVE-2022-2309",
					Severity: SevHigh,
					DistroStatus: []DistroStatus{
						{Distro: "debian", Release: "12", Status: "resolved", FixVersion: "2.9.14+dfsg-1.3~deb12u2"},
					},
				},
			},
		},
	}

	applyDistroFiltering(results, &ImageOS{Family: "debian", Version: "12", Codename: "bookworm"})

	if got := len(results[0].Vulnerabilities); got != 1 {
		t.Fatalf("vulnerability lower than fixed Debian version must remain, got %d", got)
	}
	if got := results[0].Vulnerabilities[0].Status; got != statusAffected {
		t.Errorf("expected status %q, got %q", statusAffected, got)
	}
}

func TestApplyDistroFiltering_WithoutDistroStatusKeepsCurrentBehavior(t *testing.T) {
	results := []*ComponentResult{
		{
			Component: Component{
				System:  "DEBIAN",
				Name:    "libxml2",
				Version: "2.9.14+dfsg-1.3~deb12u1",
			},
			Vulnerabilities: []Vulnerability{
				{
					ID:       "DEBIAN-CVE-2022-2309",
					Severity: SevHigh,
					Fixed:    []string{"2.9.14+dfsg-1.3~deb12u1"},
				},
			},
		},
	}

	applyDistroFiltering(results, &ImageOS{Family: "debian", Version: "12"})

	if got := len(results[0].Vulnerabilities); got != 1 {
		t.Fatalf("without distroStatus filtering should not alter behavior, got %d", got)
	}
}

func TestApplyDistroFiltering_AliasesCodenameWithNumeric(t *testing.T) {
	results := []*ComponentResult{
		{
			Component: Component{
				System:  "DEBIAN",
				Name:    "linux-libc-dev",
				Version: "3.16.81-1",
			},
			Vulnerabilities: []Vulnerability{
				{
					ID: "CVE-2023-0001",
					DistroStatus: []DistroStatus{
						{Distro: "debian", Release: "9", Status: "open"},
					},
				},
			},
		},
	}

	applyDistroFiltering(results, &ImageOS{Family: "debian", Codename: "stretch"})

	if got := len(results[0].Vulnerabilities); got != 1 {
		t.Fatalf("codename should alias to numeric release, got %d", got)
	}
	if got := results[0].Vulnerabilities[0].Status; got != statusAffected {
		t.Errorf("status = %q; want %q", got, statusAffected)
	}
}

func TestApplyDistroFiltering_OtherReleaseClassifiedAsLikelyAffected(t *testing.T) {
	results := []*ComponentResult{
		{
			Component: Component{
				System:  "DEBIAN",
				Name:    "openssl",
				Version: "1.0.1t-1+deb8u12",
			},
			Vulnerabilities: []Vulnerability{
				{
					ID: "CVE-2024-0001",
					DistroStatus: []DistroStatus{
						{Distro: "debian", Release: "12", Status: "resolved", FixVersion: "3.0.0"},
					},
				},
			},
		},
	}

	applyDistroFiltering(results, &ImageOS{Family: "debian", Version: "9", Codename: "stretch"})

	if got := len(results[0].Vulnerabilities); got != 1 {
		t.Fatalf("CVE without release row must be retained, got %d", got)
	}
	if got := results[0].Vulnerabilities[0].Status; got != statusLikelyAffected {
		t.Errorf("status = %q; want %q", got, statusLikelyAffected)
	}
}

func TestApplyDistroFiltering_LikelyFixedWhenInstalledAboveOtherReleaseFix(t *testing.T) {
	results := []*ComponentResult{
		{
			Component: Component{
				System:  "DEBIAN",
				Name:    "openssl",
				Version: "1.1.1n-0+deb11u5",
			},
			Vulnerabilities: []Vulnerability{
				{
					ID: "CVE-2024-0001",
					DistroStatus: []DistroStatus{
						{Distro: "debian", Release: "12", Status: "resolved", FixVersion: "1.1.1k-1"},
					},
				},
			},
		},
	}

	applyDistroFiltering(results, &ImageOS{Family: "debian", Version: "9", Codename: "stretch"})

	if got := len(results[0].Vulnerabilities); got != 1 {
		t.Fatalf("likely_fixed must remain visible (just tagged), got %d", got)
	}
	if got := results[0].Vulnerabilities[0].Status; got != statusLikelyFixed {
		t.Errorf("status = %q; want %q", got, statusLikelyFixed)
	}
}

func TestApplyDistroFiltering_LikelyAffectedWhenInstalledBelowEveryFix(t *testing.T) {
	results := []*ComponentResult{
		{
			Component: Component{
				System:  "DEBIAN",
				Name:    "libudev1",
				Version: "232-25+deb9u6",
			},
			Vulnerabilities: []Vulnerability{
				{
					ID: "CVE-2017-1000082",
					DistroStatus: []DistroStatus{
						{Distro: "debian", Release: "11", Status: "resolved", FixVersion: "234-1"},
						{Distro: "debian", Release: "12", Status: "resolved", FixVersion: "247-1"},
					},
				},
			},
		},
	}

	applyDistroFiltering(results, &ImageOS{Family: "debian", Version: "9", Codename: "stretch"})

	if got := len(results[0].Vulnerabilities); got != 1 {
		t.Fatalf("installed below every fix must remain, got %d", got)
	}
	if got := results[0].Vulnerabilities[0].Status; got != statusLikelyAffected {
		t.Errorf("status = %q; want %q", got, statusLikelyAffected)
	}
}

func TestApplyDistroFiltering_AllUnimportantMapsToWillNotFix(t *testing.T) {
	results := []*ComponentResult{
		{
			Component: Component{
				System:  "DEBIAN",
				Name:    "linux-libc-dev",
				Version: "4.9.320-2",
			},
			Vulnerabilities: []Vulnerability{
				{
					ID: "CVE-2004-0230",
					DistroStatus: []DistroStatus{
						{Distro: "debian", Release: "11", Status: "open", Urgency: "unimportant"},
						{Distro: "debian", Release: "12", Status: "open", Urgency: "unimportant"},
					},
				},
			},
		},
	}

	applyDistroFiltering(results, &ImageOS{Family: "debian", Version: "9", Codename: "stretch"})

	if got := len(results[0].Vulnerabilities); got != 1 {
		t.Fatalf("all-unimportant CVE must remain (tagged), got %d", got)
	}
	if got := results[0].Vulnerabilities[0].Status; got != statusWillNotFix {
		t.Errorf("status = %q; want %q", got, statusWillNotFix)
	}
}

func TestApplyDistroFiltering_AllOpenMapsToLikelyAffected(t *testing.T) {
	results := []*ComponentResult{
		{
			Component: Component{
				System:  "DEBIAN",
				Name:    "libudev1",
				Version: "232-25+deb9u6",
			},
			Vulnerabilities: []Vulnerability{
				{
					ID: "CVE-2013-4392",
					DistroStatus: []DistroStatus{
						{Distro: "debian", Release: "11", Status: "open"},
						{Distro: "debian", Release: "12", Status: "open"},
					},
				},
			},
		},
	}

	applyDistroFiltering(results, &ImageOS{Family: "debian", Version: "9", Codename: "stretch"})

	if got := len(results[0].Vulnerabilities); got != 1 {
		t.Fatalf("all-open CVE must remain, got %d", got)
	}
	if got := results[0].Vulnerabilities[0].Status; got != statusLikelyAffected {
		t.Errorf("status = %q; want %q", got, statusLikelyAffected)
	}
}

func TestApplyDistroFiltering_BackportSuffixSortsCorrectly(t *testing.T) {
	results := []*ComponentResult{
		{
			Component: Component{
				System:  "DEBIAN",
				Name:    "libfoo",
				Version: "1.2.3-1+deb9u1",
			},
			Vulnerabilities: []Vulnerability{
				{
					ID: "CVE-2024-0004",
					DistroStatus: []DistroStatus{
						{Distro: "debian", Release: "12", Status: "resolved", FixVersion: "1.2.3-1+deb12u1"},
					},
				},
			},
		},
	}

	applyDistroFiltering(results, &ImageOS{Family: "debian", Version: "9", Codename: "stretch"})

	if got := len(results[0].Vulnerabilities); got != 1 {
		t.Fatalf("stretch binary at +deb9u1 below bookworm +deb12u1, must remain, got %d", got)
	}
	if got := results[0].Vulnerabilities[0].Status; got != statusLikelyAffected {
		t.Errorf("status = %q; want %q (installed below fix)", got, statusLikelyAffected)
	}
}

func TestEarliestDebianVersion_PicksMinimum(t *testing.T) {
	got := earliestDebianVersion([]string{"3.0.5-1", "1.1.1n-0+deb11u3", "2.0-1"}, isDebianPatched)
	if got != "1.1.1n-0+deb11u3" {
		t.Errorf("earliest = %q; want 1.1.1n-0+deb11u3", got)
	}
}

func TestApplyDistroFiltering_MixedUrgencyOpenRowsMapToLikelyAffected(t *testing.T) {
	results := []*ComponentResult{
		{
			Component: Component{System: "DEBIAN", Name: "linux", Version: "4.9-1"},
			Vulnerabilities: []Vulnerability{
				{
					ID: "CVE-2024-XYZ",
					DistroStatus: []DistroStatus{
						{Distro: "debian", Release: "11", Status: "open", Urgency: "unimportant"},
						{Distro: "debian", Release: "12", Status: "open", Urgency: "low"},
					},
				},
			},
		},
	}

	applyDistroFiltering(results, &ImageOS{Family: "debian", Version: "9", Codename: "stretch"})

	if got := results[0].Vulnerabilities[0].Status; got != statusLikelyAffected {
		t.Errorf("status = %q; want %q", got, statusLikelyAffected)
	}
}

func TestApplyDistroFiltering_NoDSAMapsToWillNotFix(t *testing.T) {
	results := []*ComponentResult{
		{
			Component: Component{System: "DEBIAN", Name: "libfoo", Version: "1.0-1"},
			Vulnerabilities: []Vulnerability{
				{
					ID: "CVE-2024-9999",
					DistroStatus: []DistroStatus{
						{Distro: "debian", Release: "9", Status: "no-dsa"},
					},
				},
			},
		},
	}
	applyDistroFiltering(results, &ImageOS{Family: "debian", Version: "9"})
	if got := len(results[0].Vulnerabilities); got != 1 {
		t.Fatalf("no-dsa should retain the vuln, got %d", got)
	}
	if got := results[0].Vulnerabilities[0].Status; got != statusWillNotFix {
		t.Errorf("status = %q; want %q", got, statusWillNotFix)
	}
}

func TestApplyDistroFiltering_PostponedMapsToFixDeferred(t *testing.T) {
	results := []*ComponentResult{
		{
			Component: Component{System: "DEBIAN", Name: "libfoo", Version: "1.0-1"},
			Vulnerabilities: []Vulnerability{
				{
					ID: "CVE-2024-9999",
					DistroStatus: []DistroStatus{
						{Distro: "debian", Release: "12", Status: "open", Urgency: "postponed"},
					},
				},
			},
		},
	}
	applyDistroFiltering(results, &ImageOS{Family: "debian", Version: "12"})
	if got := results[0].Vulnerabilities[0].Status; got != statusFixDeferred {
		t.Errorf("status = %q; want %q", got, statusFixDeferred)
	}
}

func TestApplyDistroFiltering_TrivyDBNoDSAWinsOverTrackerEndOfLife(t *testing.T) {
	results := []*ComponentResult{
		{
			Component: Component{System: "DEBIAN", Name: "libfoo", Version: "1.0-1+deb9u3"},
			Vulnerabilities: []Vulnerability{
				{
					ID: "CVE-2020-0001",
					DistroStatus: []DistroStatus{

						{Distro: "debian", Release: "stretch", Status: "end-of-life", Urgency: "unimportant"},

						{Distro: "debian", Release: "9", Status: "no-dsa"},
					},
				},
			},
		},
	}
	applyDistroFiltering(results, &ImageOS{Family: "debian", Version: "9", Codename: "stretch"})
	if got := len(results[0].Vulnerabilities); got != 1 {
		t.Fatalf("no-dsa CVE should be kept, got %d", got)
	}
	if got := results[0].Vulnerabilities[0].Status; got != statusWillNotFix {
		t.Errorf("status = %q; want %q (Trivy DB no-dsa must beat tracker end-of-life)", got, statusWillNotFix)
	}
}

func TestApplyDistroFiltering_TrivyDBResolvedWinsOverTrackerEndOfLife(t *testing.T) {
	results := []*ComponentResult{
		{
			Component: Component{System: "DEBIAN", Name: "openssl", Version: "1.1.0j-1+deb9u6"},
			Vulnerabilities: []Vulnerability{
				{
					ID: "CVE-2019-0001",
					DistroStatus: []DistroStatus{
						{Distro: "debian", Release: "stretch", Status: "end-of-life"},
						{Distro: "debian", Release: "9", Status: "resolved", FixVersion: "1.1.0l-1~deb9u9"},
					},
				},
			},
		},
	}
	applyDistroFiltering(results, &ImageOS{Family: "debian", Version: "9", Codename: "stretch"})
	if got := len(results[0].Vulnerabilities); got != 1 {
		t.Fatalf("resolved CVE below fix should be kept, got %d", got)
	}
	if got := results[0].Vulnerabilities[0].Status; got != statusAffected {
		t.Errorf("status = %q; want %q (installed below +deb9u9)", got, statusAffected)
	}
}

func TestApplyDistroFiltering_UrgencyCollectedFromAnyMatchingEntry(t *testing.T) {
	results := []*ComponentResult{
		{
			Component: Component{System: "DEBIAN", Name: "curl", Version: "7.52.1-5+deb9u9"},
			Vulnerabilities: []Vulnerability{
				{
					ID:       "CVE-2021-0001",
					Severity: "HIGH",
					DistroStatus: []DistroStatus{

						{Distro: "debian", Release: "stretch", Status: "end-of-life", Urgency: "unimportant"},

						{Distro: "debian", Release: "9", Status: "no-dsa"},
					},
				},
			},
		},
	}
	applyDistroFiltering(results, &ImageOS{Family: "debian", Version: "9", Codename: "stretch"})
	if got := len(results[0].Vulnerabilities); got != 1 {
		t.Fatalf("CVE should remain, got %d", got)
	}
	v := results[0].Vulnerabilities[0]
	if v.Status != statusWillNotFix {
		t.Errorf("status = %q; want will_not_fix", v.Status)
	}

	if v.Severity != SevLow {
		t.Errorf("severity = %q; want LOW (urgency:unimportant from tracker must still cap NVD HIGH)", v.Severity)
	}
}

func TestApplyDistroFiltering_LanguageEcosystemUntouched(t *testing.T) {
	results := []*ComponentResult{
		{
			Component: Component{System: "npm", Name: "lodash", Version: "4.17.20"},
			Vulnerabilities: []Vulnerability{
				{ID: "CVE-2024-1234", Severity: SevHigh},
			},
		},
	}
	applyDistroFiltering(results, &ImageOS{Family: "debian", Version: "12"})
	if got := len(results[0].Vulnerabilities); got != 1 {
		t.Fatalf("language vulns should pass through, got %d", got)
	}
	if got := results[0].Vulnerabilities[0].Status; got != "" {
		t.Errorf("language vulns must not be stamped, got %q", got)
	}
}
