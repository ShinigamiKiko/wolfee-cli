package onlinescan

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func fixedAffected(name, purl string, fixes ...string) osvAffected {
	a := osvAffected{Package: osvAffectedPkg{Name: name, Purl: purl}}
	for _, f := range fixes {
		a.Ranges = append(a.Ranges, osvRange{Type: "ECOSYSTEM", Events: []osvEvent{{Introduced: "0"}, {Fixed: f}}})
	}
	return a
}

// GHSA-3p32-j457-pg5x: one advisory, two packages, different fixed releases.
var laravelAdvisory = []osvAffected{
	fixedAffected("laravel/framework", "pkg:composer/laravel/framework", "8.22.1", "6.20.11", "7.30.2"),
	fixedAffected("illuminate/database", "pkg:composer/illuminate/database", "7.30.3", "8.22.1", "6.20.12"),
}

func TestCollectFixedVersions_OnlyQueriedPackage(t *testing.T) {
	got := collectFixedVersions(laravelAdvisory, purlPackageKey("pkg:composer/illuminate/database@v6.20.10"))
	if fmt.Sprint(got) != "[7.30.3 8.22.1 6.20.12]" {
		t.Errorf("fixes = %v, want only illuminate/database's", got)
	}
	v := mapOSV(osvVuln{ID: "GHSA-3p32-j457-pg5x", Affected: laravelAdvisory}, "v6.20.10", purlPackageKey("pkg:composer/illuminate/database@v6.20.10"))
	if len(v.Fixed) == 0 || v.Fixed[0] != "6.20.12" {
		t.Errorf("first fix = %v, want 6.20.12 (6.20.11 is laravel/framework's fix)", v.Fixed)
	}
}

func TestCollectFixedVersions_FallsBackWhenNoEntryMatches(t *testing.T) {
	// Debian names the source package (openssl) while the PURL carries the
	// binary one (libssl3): keep every fix rather than none.
	aff := []osvAffected{fixedAffected("openssl", "pkg:deb/debian/openssl?arch=source", "3.0.13-1")}
	got := collectFixedVersions(aff, purlPackageKey("pkg:deb/debian/libssl3@3.0.11-1?distro=debian-12"))
	if fmt.Sprint(got) != "[3.0.13-1]" {
		t.Errorf("fixes = %v, want fallback to all entries", got)
	}
	if got := collectFixedVersions(laravelAdvisory, ""); len(got) != 5 {
		t.Errorf("no package key must keep every fix, got %v", got)
	}
}

func TestAffectsPackage(t *testing.T) {
	cases := []struct {
		name  string
		a     osvAffected
		query string
		want  bool
	}{
		{"npm scope encoded", fixedAffected("@babel/traverse", "pkg:npm/%40babel/traverse"), "pkg:npm/%40babel/traverse@7.20.0", true},
		{"npm scope plain", fixedAffected("@babel/traverse", "pkg:npm/%40babel/traverse"), "pkg:npm/@babel/traverse@7.20.0", true},
		{"npm other package", fixedAffected("babel-traverse", "pkg:npm/babel-traverse"), "pkg:npm/%40babel/traverse@7.20.0", false},
		{"pypi normalised", fixedAffected("jinja2", "pkg:pypi/jinja2"), "pkg:pypi/Jinja2@2.10", true},
		{"pypi separators", fixedAffected("zope.interface", ""), "pkg:pypi/zope-interface@5.0", true},
		{"maven by name", fixedAffected("org.springframework:spring-web", ""), "pkg:maven/org.springframework/spring-web@5.3.0", true},
		{"composer case", fixedAffected("symfony/http-kernel", "pkg:composer/symfony/http-kernel"), "pkg:composer/Symfony/Http-Kernel@v4.4.0", true},
	}
	for _, tc := range cases {
		if got := affectsPackage(tc.a, purlPackageKey(tc.query)); got != tc.want {
			t.Errorf("%s: affectsPackage = %v, want %v (key %q)", tc.name, got, tc.want, purlPackageKey(tc.query))
		}
	}
}

type cannedTransport struct{ body string }

func (c cannedTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(c.body)),
	}, nil
}

func TestQueryOSV_VersionlessKeepsOnlyMalware(t *testing.T) {
	hc := &http.Client{Transport: cannedTransport{body: `{"vulns":[
		{"id":"MAL-2024-1","summary":"malicious"},
		{"id":"GHSA-xxxx-yyyy-zzzz","affected":[{"package":{"name":"requests","purl":"pkg:pypi/requests"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.3.0"}]}]}]}
	]}`}}

	vulns, mal, err := queryOSV(context.Background(), hc, "pkg:pypi/requests")
	if err != nil {
		t.Fatal(err)
	}
	if len(vulns) != 0 {
		t.Errorf("versionless PURL must not report advisories, got %d", len(vulns))
	}
	if !mal.Found {
		t.Error("malware must still be reported without a version")
	}

	vulns, _, err = queryOSV(context.Background(), hc, "pkg:pypi/requests@2.2.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(vulns) != 1 {
		t.Errorf("versioned PURL must report the advisory, got %d", len(vulns))
	}
}
