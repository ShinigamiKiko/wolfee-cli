package purl

import "strings"

func Parse(p string) (system, name, version string, ok bool) {
	if !strings.HasPrefix(p, "pkg:") {
		return "", "", "", false
	}
	if i := strings.Index(p, "#"); i >= 0 {
		p = p[:i]
	}
	if i := strings.Index(p, "?"); i >= 0 {
		p = p[:i]
	}

	rest := strings.TrimPrefix(p, "pkg:")
	slash := strings.Index(rest, "/")
	if slash <= 0 {
		return "", "", "", false
	}
	pType := strings.ToLower(rest[:slash])
	rest = rest[slash+1:]

	if at := strings.LastIndex(rest, "@"); at >= 0 {
		version = rest[at+1:]
		name = rest[:at]
	} else {
		name = rest
	}

	typeMap := map[string]string{
		"npm":       "NPM",
		"maven":     "MAVEN",
		"pypi":      "PYPI",
		"gem":       "RUBYGEMS",
		"golang":    "GO",
		"cargo":     "CARGO",
		"nuget":     "NUGET",
		"composer":  "PACKAGIST",
		"swift":     "SWIFT",
		"cocoapods": "COCOAPODS",

		"deb":  "DEBIAN",
		"rpm":  "RPM",
		"apk":  "ALPINE",
		"alpm": "ARCHLINUX",

		"github":        "GITHUB_ACTIONS",
		"githubactions": "GITHUB_ACTIONS",
	}
	system, ok = typeMap[pType]
	if !ok {
		return "", "", "", false
	}

	name = strings.ReplaceAll(name, "%40", "@")
	name = strings.ReplaceAll(name, "%2F", "/")
	name = strings.ReplaceAll(name, "%2f", "/")

	if pType == "maven" {
		name = strings.ReplaceAll(name, "/", ":")
	}

	switch pType {
	case "deb", "rpm", "apk", "alpm":
		if i := strings.Index(name, "/"); i >= 0 {
			name = name[i+1:]
		}
	}
	if name == "" {
		return "", "", "", false
	}
	return system, name, version, true
}
