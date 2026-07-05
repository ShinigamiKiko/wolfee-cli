package sbomscan

import (
	"encoding/json"
	"strings"
)

func buildDependencies(deps []cdxDependency) []Dependency {
	if len(deps) == 0 {
		return nil
	}
	out := make([]Dependency, 0, len(deps))
	for _, d := range deps {
		if d.Ref == "" {
			continue
		}
		var on []string
		if len(d.DependsOn) > 0 {
			seen := make(map[string]struct{}, len(d.DependsOn))
			for _, r := range d.DependsOn {
				if r == "" {
					continue
				}
				if _, ok := seen[r]; ok {
					continue
				}
				seen[r] = struct{}{}
				on = append(on, r)
			}
		}
		out = append(out, Dependency{Ref: d.Ref, DependsOn: on})
	}
	return out
}

func toReportHashes(hs []cdxHash) []Hash {
	if len(hs) == 0 {
		return nil
	}
	out := make([]Hash, 0, len(hs))
	for _, h := range hs {
		if h.Alg == "" && h.Content == "" {
			continue
		}
		out = append(out, Hash{Alg: h.Alg, Content: h.Content})
	}
	return out
}

func toReportLicenses(ls []cdxLicense) []LicenseChoice {
	if len(ls) == 0 {
		return nil
	}
	out := make([]LicenseChoice, 0, len(ls))
	for _, l := range ls {
		var lc LicenseChoice
		if l.Expression != "" {
			lc.Expression = l.Expression
		}
		if l.License != nil {
			inner := &License{
				ID:   l.License.ID,
				Name: l.License.Name,
				URL:  l.License.URL,
			}
			if l.License.Text != nil &&
				(l.License.Text.Content != "" || l.License.Text.ContentType != "") {
				inner.Text = &LicenseText{
					ContentType: l.License.Text.ContentType,
					Encoding:    l.License.Text.Encoding,
					Content:     l.License.Text.Content,
				}
			}
			if inner.ID != "" || inner.Name != "" || inner.URL != "" || inner.Text != nil {
				lc.License = inner
			}
		}
		if lc.License == nil && lc.Expression == "" {
			continue
		}
		out = append(out, lc)
	}
	return out
}

func buildAnnotations(ans []cdxAnnotation) []Annotation {
	if len(ans) == 0 {
		return nil
	}
	out := make([]Annotation, 0, len(ans))
	for _, a := range ans {
		ann := Annotation{
			BOMRef:    a.BOMRef,
			Subjects:  append([]string(nil), a.Subjects...),
			Timestamp: a.Timestamp,
			Text:      a.Text,
		}
		if a.Annotator != nil {
			actor := &AnnotationActor{}
			if a.Annotator.Component != nil {
				c := a.Annotator.Component
				actor.Component = &ToolComponent{
					BOMRef:    c.BOMRef,
					Type:      c.Type,
					Group:     c.Group,
					Name:      c.Name,
					Version:   c.Version,
					PURL:      c.Purl,
					Publisher: c.Publisher,
				}
			}
			if a.Annotator.Service != nil {
				s := a.Annotator.Service
				ts := &ToolService{
					BOMRef:  s.BOMRef,
					Name:    s.Name,
					Version: s.Version,
				}
				if s.Provider != nil {
					ts.Provider = s.Provider.Name
				}
				actor.Service = ts
			}
			if actor.Component != nil || actor.Service != nil {
				ann.Annotator = actor
			}
		}
		if isDocumentAnnotation(ann) {
			rewriteAsWolfee(&ann)
		}
		if ann.Text == "" && ann.BOMRef == "" && len(ann.Subjects) == 0 && ann.Annotator == nil {
			continue
		}
		out = append(out, ann)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func isDocumentAnnotation(a Annotation) bool {
	if strings.EqualFold(a.BOMRef, "metadata-annotations") {
		return true
	}
	if a.Annotator != nil && a.Annotator.Component != nil &&
		strings.EqualFold(a.Annotator.Component.Name, "cdxgen") &&
		len(a.Subjects) <= 1 {
		return true
	}
	return false
}

func toReportProperties(ps []cdxProperty) []Property {
	if len(ps) == 0 {
		return nil
	}
	out := make([]Property, 0, len(ps))
	for _, p := range ps {
		if strings.HasPrefix(strings.ToLower(p.Name), "wolfee:") {
			continue
		}
		if p.Name == "" {
			continue
		}
		out = append(out, Property{Name: p.Name, Value: sanitizePath(p.Value)})
	}
	return out
}

func parseEvidenceIdentity(e *cdxEvidence) []EvidenceIdentity {
	if e == nil || len(e.Identity) == 0 {
		return nil
	}
	trimmed := strings.TrimLeft(string(e.Identity), " \t\r\n")
	var raws []cdxIdentity
	if strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal(e.Identity, &raws); err != nil {
			return nil
		}
	} else {
		var one cdxIdentity
		if err := json.Unmarshal(e.Identity, &one); err != nil {
			return nil
		}
		raws = []cdxIdentity{one}
	}
	out := make([]EvidenceIdentity, 0, len(raws))
	for _, id := range raws {
		ei := EvidenceIdentity{
			Field:      id.Field,
			Confidence: id.Confidence,
		}
		for _, m := range id.Methods {
			if m.Technique == "" && m.Value == "" && m.Confidence == 0 {
				continue
			}
			ei.Methods = append(ei.Methods, EvidenceMethod{
				Technique:  m.Technique,
				Confidence: m.Confidence,
				Value:      sanitizePath(m.Value),
			})
		}
		if ei.Field == "" && ei.Confidence == 0 && len(ei.Methods) == 0 {
			continue
		}
		out = append(out, ei)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
