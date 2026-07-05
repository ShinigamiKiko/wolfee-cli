package sbomscan

import (
	"encoding/json"
	"strings"
	"time"
)

var wolfeeTool = ToolComponent{
	Type:      "application",
	Name:      "wolfee",
	Publisher: "Wolfee",
}

func SetWolfeeVersion(v string) {
	wolfeeTool.Version = strings.TrimSpace(v)
}

func buildDocument(doc *cdxBOM) *Document {
	if doc == nil {
		return nil
	}

	specVersion := strings.TrimSpace(doc.SpecVersion)
	if specVersion == "" {
		specVersion = "1.6"
	}
	bomFormat := strings.TrimSpace(doc.BOMFormat)
	if bomFormat == "" {
		bomFormat = "CycloneDX"
	}
	d := Document{
		BOMFormat:    bomFormat,
		SpecVersion:  specVersion,
		SerialNumber: doc.SerialNumber,
		Version:      doc.Version,
	}
	md := DocumentMetadata{}
	if doc.Metadata != nil {
		md.Timestamp = doc.Metadata.Timestamp
		for _, lc := range doc.Metadata.Lifecycles {
			if lc.Phase == "" && lc.Name == "" && lc.Description == "" {
				continue
			}
			md.Lifecycles = append(md.Lifecycles, Lifecycle{
				Phase:       lc.Phase,
				Name:        lc.Name,
				Description: lc.Description,
			})
		}
		md.Tools = parseTools(doc.Metadata.Tools)

		_ = doc.Metadata.Authors
		if doc.Metadata.Component != nil {
			c := doc.Metadata.Component
			mc := &DocumentComponent{
				BOMRef:    c.BOMRef,
				Type:      c.Type,
				Name:      c.Name,
				Group:     c.Group,
				Version:   c.Version,
				PURL:      c.Purl,
				Publisher: c.Publisher,
			}
			for _, a := range c.Authors {
				if a.Name == "" && a.Email == "" {
					continue
				}
				mc.Authors = append(mc.Authors, Author{Name: a.Name, Email: a.Email})
			}
			if mc.BOMRef != "" || mc.Name != "" || mc.PURL != "" || mc.Version != "" || mc.Publisher != "" {
				md.Component = mc
			}
		}
	}

	md.Tools = appendWolfeeTool(md.Tools)

	md.Authors = []Author{{Name: "Wolfee"}}

	if md.Timestamp != "" || len(md.Lifecycles) > 0 || md.Tools != nil ||
		len(md.Authors) > 0 || md.Component != nil {
		d.Metadata = &md
	}
	return &d
}

func parseTools(raw json.RawMessage) *Tools {
	if len(raw) == 0 {
		return nil
	}
	trimmed := strings.TrimLeft(string(raw), " \t\r\n")
	if strings.HasPrefix(trimmed, "{") {
		var obj struct {
			Components []cdxComponent `json:"components,omitempty"`
			Services   []cdxService   `json:"services,omitempty"`
		}
		if err := json.Unmarshal(raw, &obj); err != nil {
			return nil
		}
		t := &Tools{}
		for _, c := range obj.Components {
			tc := ToolComponent{
				BOMRef:    c.BOMRef,
				Type:      c.Type,
				Group:     c.Group,
				Name:      c.Name,
				Version:   c.Version,
				PURL:      c.Purl,
				Publisher: c.Publisher,
			}
			if tc.Name == "" && tc.Version == "" && tc.PURL == "" {
				continue
			}
			t.Components = append(t.Components, tc)
		}
		for _, s := range obj.Services {
			ts := ToolService{
				BOMRef:  s.BOMRef,
				Name:    s.Name,
				Version: s.Version,
			}
			if s.Provider != nil {
				ts.Provider = s.Provider.Name
			}
			if ts.Name == "" && ts.Version == "" {
				continue
			}
			t.Services = append(t.Services, ts)
		}
		if len(t.Components) == 0 && len(t.Services) == 0 {
			return nil
		}
		return t
	}

	var arr []cdxTool
	if err := json.Unmarshal(raw, &arr); err != nil {
		return nil
	}
	t := &Tools{}
	for _, raw := range arr {
		vendor := raw.Vendor
		if vendor == "" && raw.Manufacturer != nil {
			vendor = raw.Manufacturer.Name
		}
		if raw.Name == "" && raw.Version == "" && vendor == "" {
			continue
		}
		t.Components = append(t.Components, ToolComponent{
			Name:      raw.Name,
			Version:   raw.Version,
			Publisher: vendor,
		})
	}
	if len(t.Components) == 0 {
		return nil
	}
	return t
}

func appendWolfeeTool(t *Tools) *Tools {
	if t == nil {
		t = &Tools{}
	}
	for _, c := range t.Components {
		if strings.EqualFold(c.Name, "wolfee") {
			return t
		}
	}
	t.Components = append(t.Components, wolfeeTool)
	return t
}

func rewriteAsWolfee(a *Annotation) {
	tool := wolfeeTool
	a.Annotator = &AnnotationActor{Component: &tool}
	if a.Timestamp == "" {
		a.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	a.Text = "This Software Bill-of-Materials (SBOM) was generated with Wolfee. " +
		"Wolfee catalogues an artefact's components (via cdxgen for filesystem " +
		"scans and built-in stream analyzers for container images), then " +
		"enriches each finding with OSV.dev, CISA KEV, EPSS, public PoCs, " +
		"and ossf/malicious-packages to produce a single ready-to-triage report."
}
