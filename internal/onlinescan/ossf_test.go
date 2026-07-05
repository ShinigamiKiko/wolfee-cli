package onlinescan

import (
	"errors"
	"strings"
	"testing"
)

func TestIsRateLimitErr_DetectsGitHub403And429(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{errors.New("github tree abc123: status 403"), true},
		{errors.New("github tree abc123: status 429"), true},
		{errors.New("github tree abc123: status 500"), false},
		{errors.New("dial tcp: timeout"), false},
		{nil, false},
	}
	for _, c := range cases {
		if got := isRateLimitErr(c.err); got != c.want {
			t.Errorf("isRateLimitErr(%v) = %v; want %v", c.err, got, c.want)
		}
	}
}

func TestFormatOSSFPartialReason_SurfacesActionableHints(t *testing.T) {
	got := formatOSSFPartialReason([]string{"npm", "PyPI"}, nil, nil)
	if !strings.Contains(got, "GITHUB_TOKEN") {
		t.Errorf("rate-limited reason must mention GITHUB_TOKEN, got %q", got)
	}
	if !strings.Contains(got, "npm,PyPI") {
		t.Errorf("rate-limited reason must list affected ecos, got %q", got)
	}

	got = formatOSSFPartialReason(nil, []string{"npm"}, nil)
	if !strings.Contains(got, "100k") || !strings.Contains(got, "truncated") {
		t.Errorf("truncated reason must explain the upstream cap, got %q", got)
	}

	got = formatOSSFPartialReason(nil, nil, []string{"Go"})
	if !strings.Contains(got, "network") || !strings.Contains(got, "Go") {
		t.Errorf("transient reason must mention network and the eco, got %q", got)
	}

	got = formatOSSFPartialReason([]string{"npm"}, []string{"PyPI"}, []string{"Go"})
	for _, want := range []string{"GITHUB_TOKEN", "100k", "network"} {
		if !strings.Contains(got, want) {
			t.Errorf("combined reason missing %q in %q", want, got)
		}
	}

	if got := formatOSSFPartialReason(nil, nil, nil); !strings.Contains(got, "cause unknown") {
		t.Errorf("empty-input fallback unexpected: %q", got)
	}
}
