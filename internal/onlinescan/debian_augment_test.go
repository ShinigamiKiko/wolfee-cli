package onlinescan

import "testing"

func TestAugmentFromDebianTracker_AddsTrackerOnlyCVEs(t *testing.T) {
	idx := newDebianIndex()
	idx.loaded = true
	idx.bySrc = map[string]map[string]debianCVE{
		"linux": {
			"CVE-2024-0001": {
				Releases: map[string]debianRelease{
					"stretch":     {Status: "open", Urgency: "low"},
					"stretch-lts": {Status: "open"},
				},
			},
			"CVE-2024-9999": {
				Releases: map[string]debianRelease{
					"bookworm": {Status: "resolved", FixedVersion: "6.1.0"},
				},
			},
		},
	}

	results := []*ComponentResult{
		{
			Component: Component{System: "DEBIAN", Name: "linux", Version: "4.9.320-2"},
		},
	}

	augmentFromDebianTracker(results, idx, &ImageOS{Family: "debian", Version: "9", Codename: "stretch"}, nil, false)

	if got := len(results[0].Vulnerabilities); got != 1 {
		t.Fatalf("expected 1 tracker-sourced CVE, got %d (%+v)", got, results[0].Vulnerabilities)
	}
	v := results[0].Vulnerabilities[0]
	if v.CVE != "CVE-2024-0001" {
		t.Errorf("expected CVE-2024-0001, got %q", v.CVE)
	}
	if v.SeveritySource != "debian-tracker" {
		t.Errorf("CVE-2024-0001 SeveritySource = %q; want debian-tracker", v.SeveritySource)
	}
	if len(v.DistroStatus) == 0 {
		t.Error("CVE-2024-0001 DistroStatus should be populated from the tracker")
	}
}

func TestAugmentFromDebianTracker_ExcludesBookwormOnlyCVE(t *testing.T) {
	idx := newDebianIndex()
	idx.loaded = true
	idx.bySrc = map[string]map[string]debianCVE{
		"linux": {
			"CVE-2024-OPEN": {
				Releases: map[string]debianRelease{
					"bookworm": {Status: "open", Urgency: "medium"},
				},
			},
		},
	}

	results := []*ComponentResult{
		{Component: Component{System: "DEBIAN", Name: "linux", Version: "4.9.320-2"}},
	}
	augmentFromDebianTracker(results, idx, &ImageOS{Family: "debian", Version: "9", Codename: "stretch"}, nil, false)

	if got := len(results[0].Vulnerabilities); got != 0 {
		t.Fatalf("bookworm-only CVE should be excluded by tracker stage, got %d", got)
	}
}

func TestAugmentFromDebianTracker_MergesWithExistingOSVEntry(t *testing.T) {
	idx := newDebianIndex()
	idx.loaded = true
	idx.bySrc = map[string]map[string]debianCVE{
		"openssl": {
			"CVE-2024-1234": {
				Releases: map[string]debianRelease{
					"stretch": {Status: "no-dsa"},
				},
			},
		},
	}

	results := []*ComponentResult{
		{
			Component: Component{System: "DEBIAN", Name: "openssl", Version: "1.0.1t-1"},
			Vulnerabilities: []Vulnerability{
				{
					ID:  "CVE-2024-1234",
					CVE: "CVE-2024-1234",
				},
			},
		},
	}

	augmentFromDebianTracker(results, idx, &ImageOS{Family: "debian", Version: "9", Codename: "stretch"}, nil, false)

	if got := len(results[0].Vulnerabilities); got != 1 {
		t.Fatalf("must not duplicate existing CVE, got %d", got)
	}
	if got := len(results[0].Vulnerabilities[0].DistroStatus); got != 1 {
		t.Fatalf("tracker row should have been merged in, got %d", got)
	}
	if results[0].Vulnerabilities[0].DistroStatus[0].Status != "no-dsa" {
		t.Errorf("expected merged status = no-dsa, got %+v", results[0].Vulnerabilities[0].DistroStatus[0])
	}
}

func TestTrackerHasRelevantRelease_HandlesLTSAlias(t *testing.T) {
	rec := debianCVE{Releases: map[string]debianRelease{"stretch-lts": {Status: "open"}}}
	releases := map[string]struct{}{"stretch": {}, "9": {}}
	if !trackerHasRelevantRelease(rec, releases) {
		t.Error("stretch-lts should match stretch in the release set")
	}
}

func TestMergeStringSet_DedupesPreservesOrder(t *testing.T) {
	got := mergeStringSet([]string{"DSA-1"}, []string{"DSA-1", "DLA-2", "DLA-2"})
	if len(got) != 2 || got[0] != "DSA-1" || got[1] != "DLA-2" {
		t.Errorf("mergeStringSet result = %v", got)
	}
}

func TestSeverityFromTrackerUrgency_PicksReleaseMatchedRow(t *testing.T) {
	rec := debianCVE{Releases: map[string]debianRelease{
		"stretch":  {Urgency: "low"},
		"bullseye": {Urgency: "high"},
	}}
	releases := map[string]struct{}{"stretch": {}, "9": {}}
	if got := severityFromTrackerUrgency(rec, releases); got != SevLow {
		t.Errorf("matched-row urgency = %q; want LOW", got)
	}
}

func TestSeverityFromTrackerUrgency_FallsBackToAnyUrgency(t *testing.T) {
	rec := debianCVE{Releases: map[string]debianRelease{
		"trixie": {Urgency: "high"},
	}}
	if got := severityFromTrackerUrgency(rec, map[string]struct{}{"stretch": {}}); got != SevHigh {
		t.Errorf("fallback urgency = %q; want HIGH", got)
	}
}

func TestSeverityFromTrackerUrgency_UnknownUrgencyLeavesEmpty(t *testing.T) {
	rec := debianCVE{Releases: map[string]debianRelease{
		"stretch": {Urgency: "not yet assigned"},
	}}
	if got := severityFromTrackerUrgency(rec, map[string]struct{}{"stretch": {}}); got != "" {
		t.Errorf("unknown urgency should be empty (let NVD try), got %q", got)
	}
}

func TestSeverityFromTrackerUrgency_StripsAsteriskSuffix(t *testing.T) {
	rec := debianCVE{Releases: map[string]debianRelease{"stretch": {Urgency: "low**"}}}
	if got := severityFromTrackerUrgency(rec, map[string]struct{}{"stretch": {}}); got != SevLow {
		t.Errorf("urgency low** = %q; want LOW", got)
	}
}

func TestAugmentFromDebianTracker_AssignsSeverityFromUrgency(t *testing.T) {
	idx := newDebianIndex()
	idx.loaded = true
	idx.bySrc = map[string]map[string]debianCVE{
		"linux": {
			"CVE-2024-0001": {Releases: map[string]debianRelease{
				"stretch": {Status: "open", Urgency: "high"},
			}},
		},
	}
	results := []*ComponentResult{
		{Component: Component{System: "DEBIAN", Name: "linux", Version: "4.9.320-2"}},
	}
	augmentFromDebianTracker(results, idx, &ImageOS{Family: "debian", Version: "9", Codename: "stretch"}, nil, false)

	if len(results[0].Vulnerabilities) != 1 {
		t.Fatalf("expected one CVE, got %d", len(results[0].Vulnerabilities))
	}
	v := results[0].Vulnerabilities[0]
	if v.Severity != SevHigh {
		t.Errorf("Severity = %q; want HIGH (from urgency)", v.Severity)
	}
	if v.SeveritySource != "debian-tracker" {
		t.Errorf("SeveritySource = %q; want debian-tracker", v.SeveritySource)
	}
}

func TestDebianIndex_IsLoadedFalseWhenEmpty(t *testing.T) {
	idx := newDebianIndex()
	if idx.IsLoaded() {
		t.Error("fresh index should not report loaded")
	}
	idx.loaded = true
	if idx.IsLoaded() {
		t.Error("loaded flag without entries should still report not-loaded")
	}
	idx.bySrc = map[string]map[string]debianCVE{"pkg": {"CVE-X": {}}}
	if !idx.IsLoaded() {
		t.Error("loaded + non-empty should report loaded")
	}
}

func TestAugmentFromDebianTracker_KeyingOnSourceField(t *testing.T) {
	idx := newDebianIndex()
	idx.loaded = true
	idx.bySrc = map[string]map[string]debianCVE{
		"gcc-6": {
			"CVE-2018-12886": {
				Releases: map[string]debianRelease{
					"stretch": {Status: "open", Urgency: "medium"},
				},
			},
		},
	}

	results := []*ComponentResult{
		{Component: Component{System: "DEBIAN", Name: "libstdc++6", Source: "gcc-6", Version: "6.3.0-18+deb9u1"}},
		{Component: Component{System: "DEBIAN", Name: "libasan3", Source: "gcc-6", Version: "6.3.0-18+deb9u1"}},
		{Component: Component{System: "DEBIAN", Name: "libgcc1", Source: "gcc-6", Version: "1:6.3.0-18+deb9u1"}},
	}
	augmentFromDebianTracker(results, idx, &ImageOS{Family: "debian", Version: "9", Codename: "stretch"}, nil, false)

	for _, r := range results {
		if len(r.Vulnerabilities) != 1 {
			t.Errorf("%s: expected 1 CVE via source keying, got %d", r.Name, len(r.Vulnerabilities))
			continue
		}
		if r.Vulnerabilities[0].CVE != "CVE-2018-12886" {
			t.Errorf("%s: got %q, want CVE-2018-12886", r.Name, r.Vulnerabilities[0].CVE)
		}
	}
}

func TestAugmentFromDebianTracker_NameFallbackWhenSourceEmpty(t *testing.T) {
	idx := newDebianIndex()
	idx.loaded = true
	idx.bySrc = map[string]map[string]debianCVE{
		"openssl": {
			"CVE-2024-AAAA": {
				Releases: map[string]debianRelease{
					"stretch": {Status: "open", Urgency: "high"},
				},
			},
		},
	}
	results := []*ComponentResult{
		{Component: Component{System: "DEBIAN", Name: "openssl", Version: "1.0.1t-1"}},
	}
	augmentFromDebianTracker(results, idx, &ImageOS{Family: "debian", Version: "9", Codename: "stretch"}, nil, false)
	if len(results[0].Vulnerabilities) != 1 {
		t.Fatalf("expected 1 CVE via Name fallback, got %d", len(results[0].Vulnerabilities))
	}
}
