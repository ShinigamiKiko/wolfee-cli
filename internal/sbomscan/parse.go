package sbomscan

import "strings"

type parsedComp struct {
	raw                cdxComponent
	sys                string
	name               string
	source             string
	ver                string
	layer              string
	createdBy          string
	skip               bool
	target             string
	class              string
	pkgType            string
	introducedBy       string
	occurrences        []string
	hashes             []Hash
	licenses           []LicenseChoice
	evidenceIdentities []EvidenceIdentity
	properties         []Property
	scope              string
}

func inferClass(system string) string {
	switch strings.ToLower(system) {
	case "dpkg", "rpm", "apk", "apkdb", "wolfi":
		return "os-pkgs"
	case "npm", "pip", "pypi", "maven", "gradle", "gem", "nuget",
		"composer", "cargo", "go", "golang", "hex", "pub", "swift", "conan":
		return "lang-pkgs"
	}
	return ""
}

func isOSEcosystem(system string) bool {
	switch strings.ToLower(system) {
	case "deb", "dpkg", "rpm", "apk", "apkdb", "wolfi":
		return true
	}
	return false
}

type componentMeta struct {
	layerDigest    string
	layerCreatedBy string
	class          string
	pkgType        string
	target         string
	introducedBy   string
	occurrences    []string
}

type layerLookup interface {
	Lookup(path string) string
}

func extractComponentMeta(c cdxComponent, lr layerLookup) componentMeta {
	var m componentMeta

	for _, p := range c.Properties {
		switch p.Name {
		case "wolfee:layer:diffid":
			m.layerDigest = strings.TrimSpace(p.Value)
		case "wolfee:layer:createdBy":
			m.layerCreatedBy = p.Value
		}
	}
	if m.layerDigest != "" {
		return m
	}

	for _, p := range c.Properties {
		n := strings.ToLower(p.Name)
		v := strings.TrimSpace(p.Value)
		if m.layerDigest == "" {
			if (strings.Contains(n, "layer") && (strings.Contains(n, "digest") || strings.Contains(n, "hash"))) ||
				n == "oci:image:layer" {
				if strings.HasPrefix(v, "sha256:") {
					m.layerDigest = v
				}
			}
		}
		switch n {
		case "wolfee:class":
			m.class = v
		case "wolfee:type":
			m.pkgType = v
		case "wolfee:target":
			m.target = v
		case "wolfee:path", "wolfee:introduced-by":
			if m.introducedBy == "" {
				m.introducedBy = sanitizePath(v)
			}
		case "wolfee:layer:createdby":
			m.layerCreatedBy = v
		}
	}

	if c.Evidence != nil {
		for _, o := range c.Evidence.Occurrences {
			loc := strings.TrimSpace(o.Location)
			if loc == "" {
				continue
			}
			if m.layerDigest == "" && lr != nil {
				if d := lr.Lookup(loc); d != "" {
					m.layerDigest = d
				}
			}
			clean := sanitizePath(loc)
			m.occurrences = append(m.occurrences, clean)
			if m.introducedBy == "" {
				m.introducedBy = clean
			}
		}
	}
	return m
}
