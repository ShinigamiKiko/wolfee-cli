package sbomscan

import (
	"testing"

	"sca-go/cli/internal/trivy"
)

func TestPinnedRef(t *testing.T) {
	cases := []struct {
		name, digest, want string
	}{
		{"debian:bookworm-slim", "sha256:abc", "debian@sha256:abc"},
		{"ghcr.io/x/y:1.2", "sha256:def", "ghcr.io/x/y@sha256:def"},
		{"registry:5000/x/y:tag", "sha256:fff", "registry:5000/x/y@sha256:fff"},
		{"debian:bookworm-slim", "", "debian:bookworm-slim"},
		{"alpine@sha256:old", "sha256:new", "alpine@sha256:new"},
		{"", "sha256:abc", ""},
		{"", "", ""},
	}
	for _, c := range cases {
		if got := pinnedRef(c.name, c.digest); got != c.want {
			t.Errorf("pinnedRef(%q,%q) = %q, want %q", c.name, c.digest, got, c.want)
		}
	}
}

func TestLocalBaseRef_PrefersDigestLabel(t *testing.T) {
	tr := &trivy.Report{Metadata: trivy.Metadata{ImageConfig: trivy.ImageConfig{
		Config: trivy.ConfigBlock{Labels: map[string]string{
			labelBaseName:   "debian:bookworm-slim",
			labelBaseDigest: "sha256:abc",
		}},
	}}}
	ref, src := localBaseRef(tr)
	if ref != "debian@sha256:abc" {
		t.Errorf("ref = %q, want digest-pinned debian@sha256:abc", ref)
	}
	if src != "image base labels" {
		t.Errorf("src = %q", src)
	}
}

func TestLocalBaseRef_NoneAvailable(t *testing.T) {
	tr := &trivy.Report{}
	if ref, _ := localBaseRef(tr); ref != "" {
		t.Errorf("ref = %q, want empty when neither labels nor history present", ref)
	}
}

func TestBaseRefFromHistory(t *testing.T) {
	mk := func(createdBy ...string) *trivy.Report {
		h := make([]trivy.History, len(createdBy))
		for i, c := range createdBy {
			h[i] = trivy.History{CreatedBy: c}
		}
		return &trivy.Report{Metadata: trivy.Metadata{ImageConfig: trivy.ImageConfig{History: h}}}
	}
	cases := []struct {
		name string
		rep  *trivy.Report
		want string
	}{
		{"alpine minirootfs", mk("ADD alpine-minirootfs-3.19.9-x86_64.tar.gz / # buildkit", "COPY app /"), "alpine:3.19.9"},
		{"two-part version", mk("ADD alpine-minirootfs-3.21-x86_64.tar.gz /"), "alpine:3.21"},
		{"anonymised add (no version)", mk("/bin/sh -c #(nop) ADD file:abc123 in / "), ""},
		{"no rootfs at all", mk("RUN apk add curl", "COPY . /app"), ""},
	}
	for _, c := range cases {
		if got := baseRefFromHistory(c.rep); got != c.want {
			t.Errorf("%s: baseRefFromHistory = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestLocalBaseRef_LabelsBeatHistory(t *testing.T) {
	withHistory := func(createdBy string, labels map[string]string) *trivy.Report {
		return &trivy.Report{Metadata: trivy.Metadata{ImageConfig: trivy.ImageConfig{
			Config:  trivy.ConfigBlock{Labels: labels},
			History: []trivy.History{{CreatedBy: createdBy}},
		}}}
	}

	tr := withHistory("ADD alpine-minirootfs-3.19.9-x86_64.tar.gz /", map[string]string{
		labelBaseName: "alpine:3.19", labelBaseDigest: "sha256:abc",
	})
	if ref, src := localBaseRef(tr); ref != "alpine@sha256:abc" || src != "image base labels" {
		t.Errorf("labels must win: ref=%q src=%q, want alpine@sha256:abc / image base labels", ref, src)
	}

	tr = withHistory("ADD alpine-minirootfs-3.19.9-x86_64.tar.gz /", nil)
	if ref, src := localBaseRef(tr); ref != "alpine:3.19.9" || src != "rootfs in image history" {
		t.Errorf("history fallback: ref=%q src=%q, want alpine:3.19.9 / rootfs in image history", ref, src)
	}

	if ref, _ := localBaseRef(&trivy.Report{}); ref != "" {
		t.Errorf("no signal: ref=%q, want empty", ref)
	}
}

func TestBasePrefixSet(t *testing.T) {
	app := []string{"sha256:a", "sha256:b", "sha256:c", "sha256:d"}

	t.Run("valid prefix", func(t *testing.T) {
		set, ok := basePrefixSet([]string{"sha256:a", "sha256:b"}, app)
		if !ok {
			t.Fatal("expected ok")
		}
		if len(set) != 2 || !set["sha256:a"] || !set["sha256:b"] || set["sha256:c"] {
			t.Errorf("set = %v", set)
		}
	})

	t.Run("not a prefix (diverges)", func(t *testing.T) {
		if _, ok := basePrefixSet([]string{"sha256:a", "sha256:X"}, app); ok {
			t.Error("expected rejection when base diverges from the image stack")
		}
	})

	t.Run("base longer than image", func(t *testing.T) {
		if _, ok := basePrefixSet([]string{"sha256:a", "sha256:b", "sha256:c", "sha256:d", "sha256:e"}, app); ok {
			t.Error("base cannot have more layers than the image")
		}
	})

	t.Run("empty base", func(t *testing.T) {
		if _, ok := basePrefixSet(nil, app); ok {
			t.Error("empty base must be rejected")
		}
	})

	t.Run("whole image is base", func(t *testing.T) {
		if _, ok := basePrefixSet(app, app); !ok {
			t.Error("an image identical to its base is a valid (all-base) prefix")
		}
	})
}

func TestBaseAttribution_Classify(t *testing.T) {
	known := baseAttribution{
		known: true,
		set:   map[string]bool{"sha256:base0": true, "sha256:base1": true},
	}
	if got := known.classify("sha256:base0"); got != OriginBase {
		t.Errorf("base layer => %q, want base", got)
	}
	if got := known.classify("sha256:app9"); got != OriginApp {
		t.Errorf("non-base layer => %q, want app", got)
	}
	if got := known.classify("  "); got != OriginUnknown {
		t.Errorf("missing layer => %q, want unknown", got)
	}

	unknown := baseAttribution{}
	if got := unknown.classify("sha256:base0"); got != "" {
		t.Errorf("unknown base => %q, want empty", got)
	}
}
