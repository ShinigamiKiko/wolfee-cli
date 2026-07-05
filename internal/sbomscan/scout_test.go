package sbomscan

import "testing"

func TestParseScoutBaseImage(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "quickview table row",
			in:   "  Target      │  myimg:latest\n  Base image   │  alpine:3.19\n",
			want: "alpine:3.19",
		},
		{
			name: "ansi colors and recommended update keeps current base",
			in:   "\x1b[1mBase image\x1b[0m │ \x1b[32malpine:3.19\x1b[0m → alpine:3.21",
			want: "alpine:3.19",
		},
		{
			name: "ascii arrow recommended update",
			in:   "Base image | alpine:3.19 -> alpine:3.21",
			want: "alpine:3.19",
		},
		{
			name: "digest-pinned base",
			in:   "Base image │ library/python@sha256:abcdef1234567",
			want: "library/python@sha256:abcdef1234567",
		},
		{
			name: "registry path with port and slim tag",
			in:   "  Base image  │  registry:5000/team/python:3.11-slim",
			want: "registry:5000/team/python:3.11-slim",
		},
		{
			name: "label is case-insensitive",
			in:   "BASE IMAGE: ubuntu:22.04",
			want: "ubuntu:22.04",
		},
		{
			name: "no base image row",
			in:   "  Target  │  x:1\n  Digest  │  sha256:deadbeef\n",
			want: "",
		},
		{

			name: "prose: base not detected is not a ref",
			in:   "i Base image was not detected for this image",
			want: "",
		},
		{

			name: "prose with docs url is not a ref",
			in:   "No base image was identified. Learn more at https://docs.docker.com/go/scout/",
			want: "",
		},
		{
			name: "empty",
			in:   "",
			want: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := parseScoutBaseImage(c.in); got != c.want {
				t.Errorf("parseScoutBaseImage() = %q, want %q", got, c.want)
			}
		})
	}
}

func TestParseScoutBaseImage_IgnoresBareVersion(t *testing.T) {
	if got := parseScoutBaseImage("Base image │ 3.19 alpine:3.19"); got != "alpine:3.19" {
		t.Errorf("got %q, want alpine:3.19", got)
	}
}
