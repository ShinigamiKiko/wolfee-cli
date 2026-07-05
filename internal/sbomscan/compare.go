package sbomscan

import (
	"encoding/json"
	"strings"

	"sca-go/cli/internal/onlinescan"
	"sca-go/cli/internal/reachability"
)

func SourceLibSet(bom []byte) map[string]bool {
	set := map[string]bool{}
	if len(bom) == 0 {
		return set
	}
	var doc struct {
		Components []struct {
			PURL string `json:"purl"`
		} `json:"components"`
	}
	if err := json.Unmarshal(bom, &doc); err != nil {
		return set
	}
	for _, c := range doc.Components {
		if c.PURL == "" {
			continue
		}
		set[sourceMemberKey(c.PURL)] = true
	}
	return set
}

// sourceMemberKey identifies a library by name AND version so that a copy of the
// same module riding into the image at a different version (e.g. a bundled CLI's
// golang.org/x/crypto@v0.49.0 when your code uses v0.31.0) is not mistaken for
// one of your own dependencies.
func sourceMemberKey(purl string) string {
	base := purlNoVersion(purl)
	if base == "" {
		return ""
	}
	ver := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(purlVersion(purl))), "v")
	return base + "@" + ver
}

func SourceScopeMap(bom []byte) map[string]string {
	out := map[string]string{}
	if len(bom) == 0 {
		return out
	}
	var doc struct {
		Components []struct {
			PURL       string `json:"purl"`
			Scope      string `json:"scope"`
			Properties []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"properties"`
		} `json:"components"`
	}
	if err := json.Unmarshal(bom, &doc); err != nil {
		return out
	}
	for _, c := range doc.Components {
		if c.PURL == "" {
			continue
		}
		scope := strings.ToLower(strings.TrimSpace(c.Scope))
		if scope == "" {
			for _, p := range c.Properties {
				if strings.EqualFold(p.Name, "cdx:go:indirect") && strings.EqualFold(p.Value, "true") {
					scope = "optional"
					break
				}
			}
		}
		if scope == "" {
			continue
		}
		out[strings.ToLower(purlNoVersion(c.PURL))] = scope
	}
	return out
}

func MergeSourceVulns(image, source *Report, reach *reachability.Result) {
	if image == nil || source == nil {
		return
	}

	if len(image.Dependencies) == 0 && len(source.Dependencies) > 0 {
		image.Dependencies = source.Dependencies
	}
	normVer := func(v string) string {
		return strings.TrimPrefix(strings.ToLower(strings.TrimSpace(v)), "v")
	}
	// Match components by name AND version. A version-agnostic key let a source
	// finding for one version (e.g. x/crypto v0.31.0) merge into an image
	// component of a different version (v0.49.0) and contaminate it with CVEs
	// that don't apply there. Vulnerability lists are version-specific, so the
	// match has to be too.
	key := func(c *ComponentReport) string {
		base := strings.ToLower(c.System + "|" + c.Name)
		if c.PURL != "" {
			base = strings.ToLower(purlNoVersion(c.PURL))
		}
		return base + "@" + normVer(c.Version)
	}
	idx := make(map[string]int, len(image.Components))
	for i := range image.Components {
		idx[key(&image.Components[i])] = i
	}
	for si := range source.Components {
		sc := &source.Components[si]
		k := key(sc)
		if ii, ok := idx[k]; ok {
			ic := &image.Components[ii]
			if ic.Origin != OriginApp {
				continue
			}
			if ic.Scope == "" {
				ic.Scope = sc.Scope
			}

			if len(ic.DependencyPaths) == 0 {
				ic.DependencyPaths = sc.DependencyPaths
			}
			ic.Vulnerabilities = dedupeVulns(unionVulns(ic.Vulnerabilities, sc.Vulnerabilities))
			ic.TopSeverity, ic.VulnCount = topAndCount(ic.Vulnerabilities)
			continue
		}
		if len(sc.Vulnerabilities) == 0 {
			continue
		}
		add := *sc
		add.Origin = OriginApp
		add.Vulnerabilities = dedupeVulns(add.Vulnerabilities)
		add.TopSeverity, add.VulnCount = topAndCount(add.Vulnerabilities)
		image.Components = append(image.Components, add)
		idx[k] = len(image.Components) - 1
	}
	markImageLibs(image.Components)
	filterVulnsByVersion(image.Components)
	computeImageTotals(image, reach, true)
}

func unionVulns(into, extra []onlinescan.Vulnerability) []onlinescan.Vulnerability {
	have := map[string]bool{}
	mark := func(v onlinescan.Vulnerability) {
		if v.CVE != "" {
			have[strings.ToUpper(v.CVE)] = true
		}
		if v.ID != "" {
			have[strings.ToUpper(v.ID)] = true
		}
		for _, a := range v.Aliases {
			have[strings.ToUpper(a)] = true
		}
	}
	for _, v := range into {
		mark(v)
	}
	for _, v := range extra {
		dup := (v.CVE != "" && have[strings.ToUpper(v.CVE)]) || (v.ID != "" && have[strings.ToUpper(v.ID)])
		if !dup {
			for _, a := range v.Aliases {
				if have[strings.ToUpper(a)] {
					dup = true
					break
				}
			}
		}
		if dup {
			continue
		}
		into = append(into, v)
		mark(v)
	}
	return into
}

func fromSource(cr *ComponentReport, sourceLibs map[string]bool, reach *reachability.Result) bool {
	if cr.PURL != "" && sourceLibs[sourceMemberKey(cr.PURL)] {
		return true
	}
	if reach != nil && reach.GoVersion != "" &&
		strings.EqualFold(strings.TrimSpace(cr.Name), "stdlib") &&
		sameGoVersion(cr.Version, reach.GoVersion) {
		return true
	}
	return false
}

func sameGoVersion(a, b string) bool {
	norm := func(s string) string {
		s = strings.ToLower(strings.TrimSpace(s))
		s = strings.TrimPrefix(s, "go")
		s = strings.TrimPrefix(s, "v")
		return s
	}
	return norm(a) != "" && norm(a) == norm(b)
}
