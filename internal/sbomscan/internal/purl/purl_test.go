package purl

import "testing"

func TestParse(t *testing.T) {
	tests := []struct {
		in       string
		wantSys  string
		wantName string
		wantVer  string
		wantOK   bool
	}{

		{"pkg:npm/lodash@4.17.21", "NPM", "lodash", "4.17.21", true},
		{"pkg:pypi/Django@4.2.0", "PYPI", "Django", "4.2.0", true},
		{"pkg:golang/github.com/foo/bar@v1.2.3", "GO", "github.com/foo/bar", "v1.2.3", true},
		{"pkg:cargo/serde@1.0.0", "CARGO", "serde", "1.0.0", true},
		{"pkg:nuget/Newtonsoft.Json@13.0.1", "NUGET", "Newtonsoft.Json", "13.0.1", true},
		{"pkg:gem/rails@7.0.0", "RUBYGEMS", "rails", "7.0.0", true},
		{"pkg:composer/symfony/console@6.0", "PACKAGIST", "symfony/console", "6.0", true},

		{"pkg:maven/org.apache.logging.log4j/log4j-core@2.17.0",
			"MAVEN", "org.apache.logging.log4j:log4j-core", "2.17.0", true},

		{"pkg:npm/%40types/node@20.0.0", "NPM", "@types/node", "20.0.0", true},
		{"pkg:npm/%40angular%2Fcore@17.0.0", "NPM", "@angular/core", "17.0.0", true},

		{"pkg:npm/foo@1.0.0?type=tgz", "NPM", "foo", "1.0.0", true},
		{"pkg:npm/foo@1.0.0#subpath/here", "NPM", "foo", "1.0.0", true},

		{"pkg:npm/foo", "NPM", "foo", "", true},

		{"pkg:deb/debian/openssl@1.1.1n-0+deb11u3", "DEBIAN", "openssl", "1.1.1n-0+deb11u3", true},
		{"pkg:deb/ubuntu/curl@7.81.0-1ubuntu1.10", "DEBIAN", "curl", "7.81.0-1ubuntu1.10", true},
		{"pkg:rpm/rhel/glibc@2.34-60.el9", "RPM", "glibc", "2.34-60.el9", true},
		{"pkg:apk/alpine/musl@1.2.3-r5", "ALPINE", "musl", "1.2.3-r5", true},

		{"", "", "", "", false},
		{"not-a-purl", "", "", "", false},
		{"pkg:", "", "", "", false},
		{"pkg:unknown-ecosystem/foo@1.0", "", "", "", false},
		{"pkg:npm/", "", "", "", false},
	}
	for _, tc := range tests {
		gotSys, gotName, gotVer, gotOK := Parse(tc.in)
		if gotOK != tc.wantOK {
			t.Errorf("Parse(%q) ok = %v; want %v", tc.in, gotOK, tc.wantOK)
			continue
		}
		if !tc.wantOK {
			continue
		}
		if gotSys != tc.wantSys || gotName != tc.wantName || gotVer != tc.wantVer {
			t.Errorf("Parse(%q) = (%q, %q, %q); want (%q, %q, %q)",
				tc.in, gotSys, gotName, gotVer, tc.wantSys, tc.wantName, tc.wantVer)
		}
	}
}

func TestParse_PreservesPyPICase(t *testing.T) {
	_, name, _, _ := Parse("pkg:pypi/Django@4.2.0")
	if name != "Django" {
		t.Errorf("PyPI case should be preserved; got %q want Django", name)
	}
}

func TestParse_GitHubActions(t *testing.T) {
	cases := []struct {
		in       string
		wantName string
		wantVer  string
	}{

		{"pkg:github/actions/checkout@v4", "actions/checkout", "v4"},
		{"pkg:github/docker/build-push-action@v6", "docker/build-push-action", "v6"},

		{"pkg:githubactions/actions/setup-go@v5", "actions/setup-go", "v5"},
	}
	for _, c := range cases {
		sys, name, ver, ok := Parse(c.in)
		if !ok || sys != "GITHUB_ACTIONS" || name != c.wantName || ver != c.wantVer {
			t.Errorf("Parse(%q) = (%q,%q,%q,%v); want (GITHUB_ACTIONS,%q,%q,true)",
				c.in, sys, name, ver, ok, c.wantName, c.wantVer)
		}
	}
}
