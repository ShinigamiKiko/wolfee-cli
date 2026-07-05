package sbomscan

import (
	"encoding/json"
	"errors"
	"strings"
)

func goModulePath(cr *ComponentReport) string {
	const pfx = "pkg:golang/"
	if p := cr.PURL; strings.HasPrefix(p, pfx) {
		rest := p[len(pfx):]
		if i := strings.IndexAny(rest, "@?#"); i >= 0 {
			rest = rest[:i]
		}
		return rest
	}
	if strings.EqualFold(cr.System, "golang") || strings.EqualFold(cr.System, "go") {
		return cr.Name
	}
	return ""
}

func purlEcosystem(p string) string {
	const pfx = "pkg:"
	if !strings.HasPrefix(p, pfx) {
		return ""
	}
	rest := p[len(pfx):]
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		return strings.ToLower(rest[:i])
	}
	return ""
}

func purlNoVersion(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	if i := strings.LastIndexByte(p, '@'); i >= 0 {
		p = p[:i]
	}
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	return strings.ToLower(p)
}

func purlVersion(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	if i := strings.LastIndexByte(p, '@'); i >= 0 {
		return p[i+1:]
	}
	return ""
}

func SyntheticSBOMFromPURL(p string) ([]byte, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return nil, errors.New("empty purl")
	}
	doc := cdxBOM{Components: []cdxComponent{{Purl: p}}}
	return json.Marshal(doc)
}
