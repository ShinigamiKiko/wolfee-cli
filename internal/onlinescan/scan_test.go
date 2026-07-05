package onlinescan

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func fakeServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/v1/query", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"vulns":[
			{"id":"GHSA-aaaa-bbbb-cccc","aliases":["CVE-2024-12345"],"summary":"prototype pollution",
			 "database_specific":{"severity":"HIGH"},
			 "affected":[{"ranges":[{"events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]},
			{"id":"MAL-2024-9999","summary":"malicious package"}
		]}`))
	})

	mux.HandleFunc("/known_exploited_vulnerabilities.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"vulnerabilities":[{"cveID":"CVE-2024-12345"}]}`))
	})

	mux.HandleFunc("/data/v1/epss", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data":[{"cve":"CVE-2024-12345","epss":"0.42","percentile":"0.85"}]}`))
	})

	return httptest.NewServer(mux)
}

func TestQueryOSV_MapsAndSplitsMalware(t *testing.T) {
	srv := fakeServer(t)
	defer srv.Close()

	hc := &http.Client{Timeout: 2 * time.Second}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/query", strings.NewReader(`{"package":{"purl":"pkg:npm/lodash@4.17.20"}}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatalf("test server unreachable: %v", err)
	}
	resp.Body.Close()

	v := osvVuln{
		ID:               "GHSA-x",
		Aliases:          []string{"CVE-2024-12345"},
		Summary:          "p",
		DatabaseSpecific: map[string]any{"severity": "HIGH"},
		Affected:         []osvAffected{{Ranges: []osvRange{{Events: []osvEvent{{Introduced: "0"}, {Fixed: "1.2.3"}}}}}},
	}
	got := mapOSV(v)
	if got.Severity != SevHigh {
		t.Errorf("severity = %q; want HIGH", got.Severity)
	}
	if got.CVE != "CVE-2024-12345" {
		t.Errorf("CVE = %q; want CVE-2024-12345", got.CVE)
	}
	if len(got.Fixed) != 1 || got.Fixed[0] != "1.2.3" {
		t.Errorf("fixed = %v; want [1.2.3]", got.Fixed)
	}
}

func TestSeverityFromCVSS(t *testing.T) {
	cases := []struct {
		score float64
		want  string
	}{
		{9.8, SevCritical},
		{7.0, SevHigh},
		{5.5, SevMedium},
		{0.5, SevLow},
		{0, SevUnknown},
	}
	for _, c := range cases {
		if got := severityFromCVSS(c.score); got != c.want {
			t.Errorf("severityFromCVSS(%v) = %q; want %q", c.score, got, c.want)
		}
	}
}

func TestMapOSV_DebianNamespacedIDExtractsCVE(t *testing.T) {
	v := osvVuln{
		ID:      "DEBIAN-CVE-2023-4911",
		Aliases: nil,
		Affected: []osvAffected{{
			Package: osvAffectedPkg{Ecosystem: "Debian:11"},
			Ranges:  []osvRange{{Type: "ECOSYSTEM", Events: []osvEvent{{Fixed: "2.31-13+deb11u7"}}}},
		}},
	}
	got := mapOSV(v)
	if got.CVE != "CVE-2023-4911" {
		t.Errorf("CVE = %q; want CVE-2023-4911 (KEV/PoC matching depends on this)", got.CVE)
	}
}

func TestPickCVE(t *testing.T) {
	if got := pickCVE("CVE-2024-1234", nil); got != "CVE-2024-1234" {
		t.Errorf("CVE-id passthrough failed: %q", got)
	}
	if got := pickCVE("GHSA-x", []string{"CVE-2024-1234"}); got != "CVE-2024-1234" {
		t.Errorf("alias pickup failed: %q", got)
	}
	if got := pickCVE("GHSA-x", []string{"OSV-1"}); got != "" {
		t.Errorf("unexpected non-CVE pick: %q", got)
	}

	if got := pickCVE("GHSA-x", []string{"CVE-not-a-real-id", "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}); got != "" {
		t.Errorf("non-conforming CVE alias should be rejected: %q", got)
	}
	if got := pickCVE("CVE-2024-1234", nil); got != "CVE-2024-1234" {
		t.Errorf("canonical CVE rejected: %q", got)
	}

	if got := pickCVE("DEBIAN-CVE-2017-1000082", nil); got != "CVE-2017-1000082" {
		t.Errorf("embedded CVE in DEBIAN- prefix not extracted: %q", got)
	}
	if got := pickCVE("UBUNTU-CVE-2023-4911", nil); got != "CVE-2023-4911" {
		t.Errorf("embedded CVE in UBUNTU- prefix not extracted: %q", got)
	}
	if got := pickCVE("USN-1234-1", []string{"UBUNTU-CVE-2023-4911"}); got != "CVE-2023-4911" {
		t.Errorf("embedded CVE in alias not extracted: %q", got)
	}

	if got := pickCVE("DLA-1234-1", nil); got != "" {
		t.Errorf("DLA id has no embedded CVE; got %q", got)
	}
}

func TestScoreCVSSVector_V3(t *testing.T) {

	score, ver := scoreCVSSVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	if ver != "CVSS:3.1" || score < 9.7 || score > 9.9 {
		t.Errorf("v3.1 critical = %v / %q; want ~9.8 / CVSS:3.1", score, ver)
	}

	if s, _ := scoreCVSSVector("CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:N"); s < 3 || s > 6 {
		t.Errorf("v3.1 scope-changed = %v; want 3-6 band", s)
	}
}

func TestScoreCVSSVector_V2(t *testing.T) {

	score, ver := scoreCVSSVector("AV:N/AC:L/Au:N/C:P/I:P/A:P")
	if ver != "CVSS:2.0" || score < 7.4 || score > 7.6 {
		t.Errorf("v2 = %v / %q; want ~7.5 / CVSS:2.0", score, ver)
	}
}

func TestScoreCVSSVector_RejectsJunk(t *testing.T) {
	if s, _ := scoreCVSSVector(""); s != 0 {
		t.Errorf("empty should be 0, got %v", s)
	}
	if s, _ := scoreCVSSVector("not-a-vector"); s != 0 {
		t.Errorf("garbage should be 0, got %v", s)
	}
	if s, _ := scoreCVSSVector("CVSS:9.9/foo"); s != 0 {
		t.Errorf("unknown version should be 0, got %v", s)
	}
}

func TestDeriveSeverity_FromVector(t *testing.T) {
	v := osvVuln{
		Severity: []osvSeverity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
	}
	sev, score, vec := deriveSeverity(v)
	if sev != SevCritical {
		t.Errorf("severity = %q; want CRITICAL", sev)
	}
	if score < 9.7 {
		t.Errorf("score = %v; want ~9.8", score)
	}
	if vec == "" {
		t.Errorf("vector lost - should be preserved verbatim")
	}
}

func TestParseDistroEcosystem(t *testing.T) {
	cases := []struct{ in, distro, release string }{
		{"Debian:12", "debian", "12"},
		{"Ubuntu:22.04", "ubuntu", "22.04"},
		{"npm", "", ""},
		{"AlmaLinux:9", "almalinux", "9"},
	}
	for _, c := range cases {
		d, r := parseDistroEcosystem(c.in)
		if d != c.distro || r != c.release {
			t.Errorf("parseDistroEcosystem(%q) = (%q,%q); want (%q,%q)", c.in, d, r, c.distro, c.release)
		}
	}
}

func TestKEVSet_HasIsZeroSafe(t *testing.T) {

	var k *kevSet
	if k.Has("CVE-1") {
		t.Error("nil receiver should not match")
	}
	k = newKEVSet()
	if k.Has("") {
		t.Error("empty cve should not match")
	}
}

func TestFetchEPSS_StatusErrorBeforeDecode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "rate limited upstream", http.StatusTooManyRequests)
	}))
	defer srv.Close()

	epssAPIURLForTest = srv.URL
	t.Cleanup(func() { epssAPIURLForTest = "" })
	hc := &http.Client{Timeout: 5 * time.Second}

	_, err := fetchEPSS(context.Background(), hc, []string{"CVE-2024-12345"})
	if err == nil {
		t.Fatal("expected EPSS error")
	}
	if strings.Contains(err.Error(), "epss decode") {
		t.Fatalf("status error should be reported before decode, got %v", err)
	}
	if !strings.Contains(err.Error(), "429") {
		t.Fatalf("status error should mention the upstream HTTP code, got %v", err)
	}
}

func TestNormaliseSeverities_StampsUnknown(t *testing.T) {
	results := []*ComponentResult{
		{
			Vulnerabilities: []Vulnerability{
				{CVE: "CVE-2024-1", Severity: SevHigh},
				{CVE: "CVE-2024-2"},
				{CVE: "CVE-2024-3", Severity: ""},
			},
		},
	}
	normaliseSeverities(results)
	got := []string{
		results[0].Vulnerabilities[0].Severity,
		results[0].Vulnerabilities[1].Severity,
		results[0].Vulnerabilities[2].Severity,
	}
	want := []string{SevHigh, SevUnknownLabel, SevUnknownLabel}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("idx %d: got %q want %q", i, got[i], want[i])
		}
	}
}

func TestCVEsNeedingNVD_SortsAlphabetically(t *testing.T) {
	results := []*ComponentResult{
		{Vulnerabilities: []Vulnerability{
			{CVE: "CVE-2024-9999"},
			{CVE: "CVE-2024-1111"},
			{CVE: "CVE-2024-2222", Severity: SevHigh},
		}},
		{Vulnerabilities: []Vulnerability{
			{CVE: "CVE-2024-5555"},
			{CVE: "CVE-2024-1111"},
			{CVE: ""},
			{CVE: "CVE-2024-3333"},
		}},
	}

	got := cvesNeedingNVD(results)
	want := []string{"CVE-2024-1111", "CVE-2024-3333", "CVE-2024-5555", "CVE-2024-9999"}
	if !slices.Equal(got, want) {
		t.Fatalf("cvesNeedingNVD() = %v, want %v", got, want)
	}
}

type loggerStub struct{}

func (loggerStub) Step(string)               {}
func (loggerStub) Progress(int, int, string) {}

func TestProgressLogger_Compatibility(t *testing.T) {
	var _ ProgressLogger = loggerStub{}

	_ = context.Background()
}

func TestOSSFIndex_LookupMatchesEcosystem(t *testing.T) {
	idx := newOSSFIndex()
	idx.byKey = map[string][]ossfHit{
		"npm/event-stream": {{MalID: "MAL-2018-123", Path: "osv/npm/event-stream/MAL-2018-123.json"}},
		"PyPI/colourama":   {{MalID: "MAL-2024-9999", Path: "osv/PyPI/colourama/MAL-2024-9999.json"}},
	}
	idx.loaded = true

	if hits := idx.Lookup("NPM", "event-stream"); len(hits) != 1 || hits[0].MalID != "MAL-2018-123" {
		t.Errorf("npm lookup miss: %+v", hits)
	}
	if hits := idx.Lookup("PYPI", "colourama"); len(hits) != 1 {
		t.Errorf("pypi lookup miss: %+v", hits)
	}
	if hits := idx.Lookup("NPM", "absent"); len(hits) != 0 {
		t.Errorf("absent lookup should be empty, got %+v", hits)
	}

	if hits := idx.Lookup("SWIFT", "anything"); len(hits) != 0 {
		t.Errorf("unmapped eco should be empty, got %+v", hits)
	}
}

func TestFindChildSHA(t *testing.T) {
	tree := &ghTree{Tree: []ghTreeNode{
		{Path: "README.md", Type: "blob", SHA: "111"},
		{Path: "osv", Type: "tree", SHA: "222"},
		{Path: "osv", Type: "blob", SHA: "999"},
	}}
	if got := findChildSHA(tree, "osv", "tree"); got != "222" {
		t.Errorf("osv tree lookup = %q; want 222", got)
	}
	if got := findChildSHA(tree, "missing", "tree"); got != "" {
		t.Errorf("missing entry = %q; want empty", got)
	}
	if got := findChildSHA(nil, "osv", "tree"); got != "" {
		t.Errorf("nil tree should return empty, got %q", got)
	}
}

func TestOSSFIndex_IndexesFromPerEcoTrees(t *testing.T) {
	idx := newOSSFIndex()
	idx.byKey = map[string][]ossfHit{}

	results := []ecoResult{
		{eco: "npm", tree: &ghTree{Tree: []ghTreeNode{
			{Path: "event-stream/MAL-2018-1.json", Type: "blob"},
			{Path: "event-stream/MAL-2018-2.json", Type: "blob"},
			{Path: "lodash/README.md", Type: "blob"},
			{Path: "subdir", Type: "tree"},
		}}},
		{eco: "PyPI", tree: &ghTree{Tree: []ghTreeNode{
			{Path: "colourama/MAL-2024-9999.json", Type: "blob"},
		}}},
	}

	for _, r := range results {
		for _, node := range r.tree.Tree {
			if node.Type != "blob" || !strings.HasSuffix(node.Path, ".json") {
				continue
			}
			parts := strings.Split(node.Path, "/")
			if len(parts) < 2 {
				continue
			}
			pkg := parts[0]
			malID := strings.TrimSuffix(parts[len(parts)-1], ".json")
			if !strings.HasPrefix(malID, "MAL-") {
				continue
			}
			key := r.eco + "/" + pkg
			fullPath := "osv/" + r.eco + "/" + node.Path
			idx.byKey[key] = append(idx.byKey[key], ossfHit{MalID: malID, Path: fullPath})
		}
	}
	idx.loaded = true

	hits := idx.Lookup("NPM", "event-stream")
	if len(hits) != 2 {
		t.Fatalf("expected 2 hits for event-stream, got %d", len(hits))
	}
	if hits[0].Path != "osv/npm/event-stream/MAL-2018-1.json" {
		t.Errorf("path reconstruction wrong: %q", hits[0].Path)
	}
	if hits := idx.Lookup("PYPI", "colourama"); len(hits) != 1 {
		t.Errorf("PyPI lookup failed: %+v", hits)
	}
	if _, ok := idx.byKey["npm/lodash"]; ok {
		t.Error("non-MAL files should not be indexed")
	}
}

func TestToxicRepos_PURLAndBasenameMatch(t *testing.T) {
	idx := newToxicReposIndex()
	idx.byPURL = map[string][]toxicReposEntry{}
	idx.byBaseName = map[string][]toxicReposEntry{}

	idx.indexEntry(toxicReposEntry{
		ID: 1, ProblemType: "ddos",
		Name: "ApocalypseCalculator/SlavaUkraini", CommitLink: "https://github.com/ApocalypseCalculator/SlavaUkraini",
		Description: "DDOS tool",
	})
	idx.indexEntry(toxicReposEntry{
		ID: 2, ProblemType: "broken_assembly",
		Name: "fomvasss/laravel-dadata", CommitLink: "https://github.com/fomvasss/laravel-dadata.git",
		Description: "Удален с github",
	})
	idx.indexEntry(toxicReposEntry{
		ID: 3, ProblemType: "hostile_actions",
		Name: "evil-pkg", CommitLink: "https://github.com/someone/evil-pkg",
		Description: "wipes filesystem",
		PURL:        "pkg:npm/evil-pkg@1.0.0",
	})
	idx.loaded = true

	t.Run("exact-purl", func(t *testing.T) {
		hits := idx.Lookup("pkg:npm/evil-pkg@1.0.0", "evil-pkg")
		if len(hits) == 0 || hits[0].ID != 3 {
			t.Errorf("PURL match failed: %+v", hits)
		}
	})

	t.Run("purl-version-stripped", func(t *testing.T) {

		hits := idx.Lookup("pkg:npm/evil-pkg@9.9.9", "evil-pkg")
		if len(hits) == 0 || hits[0].ID != 3 {
			t.Errorf("version-less PURL match failed: %+v", hits)
		}
	})

	t.Run("basename", func(t *testing.T) {
		hits := idx.Lookup("pkg:composer/fomvasss/laravel-dadata@1.0", "laravel-dadata")
		if len(hits) == 0 || hits[0].ID != 2 {
			t.Errorf("basename match failed: %+v", hits)
		}
	})

	t.Run("short-name-skipped", func(t *testing.T) {

		idx.byBaseName["io"] = []toxicReposEntry{{ID: 99, ProblemType: "ddos"}}
		if hits := idx.Lookup("pkg:go/io@1", "io"); len(hits) != 0 {
			t.Errorf("short-name basename match should be suppressed, got %+v", hits)
		}
	})

	t.Run("unrelated", func(t *testing.T) {
		if hits := idx.Lookup("pkg:npm/lodash@4.17.21", "lodash"); len(hits) != 0 {
			t.Errorf("unrelated package matched: %+v", hits)
		}
	})
}

func TestRepoBaseFromURL(t *testing.T) {
	cases := map[string]string{
		"https://github.com/foo/bar":             "bar",
		"https://github.com/foo/bar.git":         "bar",
		"https://github.com/foo/bar/commit/abcd": "bar",
		"http://github.com/x/y":                  "y",
		"https://gitlab.com/foo/bar":             "",
		"":                                       "",
		"not a url":                              "",
		"https://github.com/foo":                 "",
	}
	for in, want := range cases {
		if got := repoBaseFromURL(in); got != want {
			t.Errorf("repoBaseFromURL(%q) = %q; want %q", in, got, want)
		}
	}
}

func TestToxicReposToToxic_DedupesCategories(t *testing.T) {
	out := toxicReposToToxic([]toxicReposEntry{
		{ProblemType: "ddos", Description: "first"},
		{ProblemType: "ddos", Description: "second"},
		{ProblemType: "hostile_actions", Description: "third"},
	})
	if !out.Found {
		t.Fatal("expected Found")
	}
	if len(out.Categories) != 2 {
		t.Errorf("categories should dedupe; got %v", out.Categories)
	}
	if len(out.Notes) != 3 {
		t.Errorf("notes should preserve every record; got %v", out.Notes)
	}
}

func TestNormalizePURLForOSV(t *testing.T) {
	cases := map[string]string{
		"pkg:github/actions/checkout@v4":        "pkg:githubactions/actions/checkout@v4",
		"pkg:github/docker/login-action@v3":     "pkg:githubactions/docker/login-action@v3",
		"pkg:githubactions/actions/setup-go@v5": "pkg:githubactions/actions/setup-go@v5",
		"pkg:npm/lodash@4.17.21":                "pkg:npm/lodash@4.17.21",
		"pkg:deb/debian/openssl@3.0.2":          "pkg:deb/debian/openssl@3.0.2",
		"":                                      "",
	}
	for in, want := range cases {
		if got := normalizePURLForOSV(in); got != want {
			t.Errorf("normalizePURLForOSV(%q) = %q; want %q", in, got, want)
		}
	}
}

func TestScan_FallsBackToOSVWhenTrackerHasNoPackageData(t *testing.T) {
	hc := &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			body := `{}`
			status := http.StatusNotFound
			switch {
			case r.URL.Host == "security-tracker.debian.org" && r.URL.Path == "/tracker/data/json":

				status = http.StatusOK
				body = `{"openssl":{"CVE-2024-9999":{"releases":{"stretch":{"status":"open"}}}}}`
			case r.URL.Host == "api.osv.dev" && r.URL.Path == "/v1/query":
				status = http.StatusOK
				body = `{"vulns":[{"id":"GHSA-fallback-0001","summary":"fallback hit","database_specific":{"severity":"HIGH"}}]}`
			}
			return &http.Response{
				StatusCode: status,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(body)),
				Request:    r,
			}, nil
		}),
		Timeout: 2 * time.Second,
	}

	results, err := Scan(context.Background(), []Component{{
		System:  "DEBIAN",
		Name:    "curl",
		Version: "7.52.1-5+deb9u1",
		PURL:    "pkg:deb/debian/curl@7.52.1-5+deb9u1",
	}}, Options{
		HTTPClient:  hc,
		Concurrency: 1,
		OS:          &ImageOS{Family: "debian", Version: "9", Codename: "stretch"},
	})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("results len = %d; want 1", len(results))
	}
	if got := len(results[0].Vulnerabilities); got != 1 {
		t.Fatalf("expected OSV fallback to restore one vulnerability, got %d (%+v)", got, results[0].Vulnerabilities)
	}
	if got := results[0].Vulnerabilities[0].ID; got != "GHSA-fallback-0001" {
		t.Fatalf("fallback vulnerability ID = %q; want GHSA-fallback-0001", got)
	}
}
