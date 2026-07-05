package sbomscan

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

type fakeLayerResolver map[string]string

func (f fakeLayerResolver) Lookup(path string) string { return f[path] }

func TestSyntheticSBOMFromPURL_RoundTrip(t *testing.T) {
	bom, err := SyntheticSBOMFromPURL("pkg:npm/lodash@4.17.21")
	if err != nil {
		t.Fatalf("synth: %v", err)
	}
	var doc cdxBOM
	if err := json.Unmarshal(bom, &doc); err != nil {
		t.Fatalf("parse synth: %v", err)
	}
	if len(doc.Components) != 1 || doc.Components[0].Purl != "pkg:npm/lodash@4.17.21" {
		t.Fatalf("unexpected synth bom: %+v", doc)
	}
}

func TestSyntheticSBOMFromPURL_RejectsEmpty(t *testing.T) {
	if _, err := SyntheticSBOMFromPURL(""); err == nil {
		t.Fatal("expected error for empty purl")
	}
	if _, err := SyntheticSBOMFromPURL("   "); err == nil {
		t.Fatal("expected error for whitespace-only purl")
	}
}

func TestScanBOM_RejectsEmptyInput(t *testing.T) {
	_, err := ScanBOM(context.Background(), Options{})
	if err == nil {
		t.Fatal("expected error for empty bom bytes")
	}
}

func TestScanBOM_RejectsInvalidJSON(t *testing.T) {
	_, err := ScanBOM(context.Background(), Options{BOMBytes: []byte("{not json")})
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
	if !strings.Contains(err.Error(), "parse cyclonedx") {
		t.Errorf("error should mention cyclonedx parsing, got: %v", err)
	}
}

func TestScanBOM_EmptyComponentList(t *testing.T) {
	r, err := ScanBOM(context.Background(), Options{
		BOMBytes: []byte(`{"components":[]}`),
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if r == nil {
		t.Fatal("nil report for empty input")
	}
	if r.Totals.Scanned != 0 || len(r.Components) != 0 {
		t.Errorf("expected empty report; got %+v", r.Totals)
	}
}

func TestScanBOM_SkipsUnparseablePurl(t *testing.T) {
	bom := `{"components":[
		{"name":"random","version":"1.0","purl":""},
		{"name":"weird","version":"1.0","purl":"not-a-purl"}
	]}`
	r, err := ScanBOM(context.Background(), Options{BOMBytes: []byte(bom)})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if r.Totals.Skipped != 2 {
		t.Errorf("expected 2 skipped, got %d", r.Totals.Skipped)
	}
}

func TestInferClass(t *testing.T) {
	tests := []struct {
		system string
		want   string
	}{
		{"dpkg", "os-pkgs"},
		{"rpm", "os-pkgs"},
		{"apk", "os-pkgs"},
		{"apkdb", "os-pkgs"},
		{"wolfi", "os-pkgs"},
		{"npm", "lang-pkgs"},
		{"pip", "lang-pkgs"},
		{"pypi", "lang-pkgs"},
		{"maven", "lang-pkgs"},
		{"gradle", "lang-pkgs"},
		{"gem", "lang-pkgs"},
		{"nuget", "lang-pkgs"},
		{"composer", "lang-pkgs"},
		{"cargo", "lang-pkgs"},
		{"go", "lang-pkgs"},
		{"hex", "lang-pkgs"},
		{"pub", "lang-pkgs"},
		{"swift", "lang-pkgs"},
		{"conan", "lang-pkgs"},
		{"DPKG", "os-pkgs"},
		{"NPM", "lang-pkgs"},
		{"unknown", ""},
		{"", ""},
	}
	for _, tc := range tests {
		got := inferClass(tc.system)
		if got != tc.want {
			t.Errorf("inferClass(%q) = %q, want %q", tc.system, got, tc.want)
		}
	}
}

func TestExtractComponentMeta_WolfeeInjected(t *testing.T) {

	c := cdxComponent{
		Properties: []cdxProperty{
			{Name: "wolfee:layer:diffid", Value: "sha256:deadbeef"},
			{Name: "wolfee:layer:createdBy", Value: "RUN apt-get install -y curl"},
		},
	}
	m := extractComponentMeta(c, nil)
	if m.layerDigest != "sha256:deadbeef" {
		t.Errorf("layerDigest = %q, want sha256:deadbeef", m.layerDigest)
	}
	if m.layerCreatedBy != "RUN apt-get install -y curl" {
		t.Errorf("layerCreatedBy = %q, want %q", m.layerCreatedBy, "RUN apt-get install -y curl")
	}
}

func TestExtractComponentMeta_CdxgenForkProperty(t *testing.T) {

	c := cdxComponent{
		Properties: []cdxProperty{
			{Name: "oci:image:layer", Value: "sha256:cafebabe"},
			{Name: "wolfee:class", Value: "os-pkgs"},
		},
	}
	m := extractComponentMeta(c, nil)
	if m.layerDigest != "sha256:cafebabe" {
		t.Errorf("layerDigest = %q, want sha256:cafebabe", m.layerDigest)
	}
	if m.class != "os-pkgs" {
		t.Errorf("class = %q, want os-pkgs", m.class)
	}
}

func TestExtractComponentMeta_NoResolver(t *testing.T) {

	c := cdxComponent{
		Evidence: &cdxEvidence{Occurrences: []cdxOccurrence{{Location: "/app/go.sum"}}},
	}
	m := extractComponentMeta(c, nil)
	if m.layerDigest != "" || m.class != "" {
		t.Errorf("expected empty meta for nil resolver, got %+v", m)
	}

	if !strings.Contains(m.introducedBy, "go.sum") {
		t.Errorf("introducedBy = %q, want contains go.sum", m.introducedBy)
	}
}

func TestScanBOM_FullCycloneDXExtraction(t *testing.T) {
	bom := `{
	  "bomFormat": "CycloneDX",
	  "specVersion": "1.6",
	  "serialNumber": "urn:uuid:00000000-1111-2222-3333-444444444444",
	  "version": 1,
	  "metadata": {
	    "timestamp": "2026-05-11T10:00:00Z",
	    "lifecycles": [{"phase": "build"}],
	    "tools": {"components": [{"name": "cdxgen", "version": "12.1.5", "group": "@cyclonedx", "type": "application", "purl": "pkg:npm/%40cyclonedx/cdxgen@12.1.5"}]},
	    "authors": [{"name": "wolfee", "email": "noreply@example.com"}],
	    "component": {
	      "bom-ref": "pkg:app",
	      "type": "application",
	      "name": "demo",
	      "version": "0.0.0",
	      "publisher": "Wolfee Inc",
	      "authors": [{"name": "wolfee team"}]
	    }
	  },
	  "components": [
	    {
	      "bom-ref": "pkg:golang/example.com/root@v1.0.0",
	      "type": "library",
	      "group": "example.com",
	      "name": "root",
	      "version": "v1.0.0",
	      "purl": "pkg:golang/example.com/root@v1.0.0",
	      "scope": "required",
	      "hashes": [{"alg": "SHA-256", "content": "aabbcc"}],
	      "licenses": [{"license": {"id": "MIT"}}],
	      "properties": [
	        {"name": "ModuleGoVersion", "value": "1.22"},
	        {"name": "SrcFile", "value": "/app/go.mod"}
	      ],
	      "evidence": {
	        "identity": {
	          "field": "purl",
	          "confidence": 1.0,
	          "methods": [{"technique": "manifest-analysis", "confidence": 1.0, "value": "/app/go.mod"}]
	        },
	        "occurrences": [{"location": "/app/go.mod"}, {"location": "/app/vendor/example.com/root"}]
	      }
	    },
	    {
	      "bom-ref": "pkg:golang/example.com/dep@v0.5.0",
	      "type": "library",
	      "name": "dep",
	      "version": "v0.5.0",
	      "purl": "pkg:golang/example.com/dep@v0.5.0",
	      "licenses": [{"license": {"name": "CUSTOM", "text": {"contentType": "text/plain", "content": "Apache License\nVersion 2.0..."}}}],
	      "properties": [
	        {"name": "cdx:go:indirect", "value": "true"}
	      ]
	    }
	  ],
	  "dependencies": [
	    {"ref": "pkg:golang/example.com/root@v1.0.0", "dependsOn": ["pkg:golang/example.com/dep@v0.5.0"]},
	    {"ref": "pkg:golang/example.com/dep@v0.5.0"}
	  ],
	  "annotations": [
	    {
	      "bom-ref": "metadata-annotations",
	      "subjects": ["pkg:app"],
	      "annotator": {"component": {"name": "cdxgen", "version": "12.1.5"}},
	      "timestamp": "2026-05-11T10:00:00Z",
	      "text": "This SBOM was created on Monday, May 11"
	    }
	  ]
	}`

	r, err := ScanBOM(context.Background(), Options{BOMBytes: []byte(bom)})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if r.Document == nil {
		t.Fatal("expected Document to be populated")
	}
	if r.Document.BOMFormat != "CycloneDX" || r.Document.SpecVersion != "1.6" {
		t.Errorf("doc bomFormat/specVersion mismatch: %+v", r.Document)
	}
	if r.Document.SerialNumber == "" || r.Document.Version != 1 {
		t.Errorf("doc serial/version mismatch: %+v", r.Document)
	}
	if r.Document.Metadata == nil {
		t.Fatal("expected Document.Metadata populated")
	}
	if r.Document.Metadata.Timestamp != "2026-05-11T10:00:00Z" {
		t.Errorf("timestamp mismatch: %q", r.Document.Metadata.Timestamp)
	}

	if len(r.Document.Metadata.Lifecycles) != 1 || r.Document.Metadata.Lifecycles[0].Phase != "build" {
		t.Errorf("lifecycles mismatch: %+v", r.Document.Metadata.Lifecycles)
	}

	if r.Document.Metadata.Tools == nil || len(r.Document.Metadata.Tools.Components) != 2 {
		t.Fatalf("expected 2 tool components (cdxgen + wolfee), got %+v", r.Document.Metadata.Tools)
	}
	toolNames := []string{
		r.Document.Metadata.Tools.Components[0].Name,
		r.Document.Metadata.Tools.Components[1].Name,
	}
	hasCdxgen, hasWolfee := false, false
	for _, n := range toolNames {
		if n == "cdxgen" {
			hasCdxgen = true
		}
		if n == "wolfee" {
			hasWolfee = true
		}
	}
	if !hasCdxgen || !hasWolfee {
		t.Errorf("expected both cdxgen and wolfee in tools, got %v", toolNames)
	}

	if len(r.Document.Metadata.Authors) != 1 || r.Document.Metadata.Authors[0].Name != "Wolfee" {
		t.Errorf("authors should be rewritten to Wolfee, got %+v", r.Document.Metadata.Authors)
	}
	if r.Document.Metadata.Component == nil || r.Document.Metadata.Component.Name != "demo" {
		t.Errorf("metadata.component mismatch: %+v", r.Document.Metadata.Component)
	}
	if r.Document.Metadata.Component.Publisher != "Wolfee Inc" {
		t.Errorf("metadata.component.publisher mismatch: %q", r.Document.Metadata.Component.Publisher)
	}
	if len(r.Document.Metadata.Component.Authors) != 1 || r.Document.Metadata.Component.Authors[0].Name != "wolfee team" {
		t.Errorf("metadata.component.authors mismatch: %+v", r.Document.Metadata.Component.Authors)
	}

	if len(r.Dependencies) != 2 {
		t.Fatalf("expected 2 dependency edges, got %d: %+v", len(r.Dependencies), r.Dependencies)
	}
	var rootEdge *Dependency
	for i := range r.Dependencies {
		if r.Dependencies[i].Ref == "pkg:golang/example.com/root@v1.0.0" {
			rootEdge = &r.Dependencies[i]
		}
	}
	if rootEdge == nil || len(rootEdge.DependsOn) != 1 || rootEdge.DependsOn[0] != "pkg:golang/example.com/dep@v0.5.0" {
		t.Errorf("root dependency edge mismatch: %+v", rootEdge)
	}

	if len(r.Annotations) != 1 {
		t.Fatalf("expected 1 annotation, got %d", len(r.Annotations))
	}
	if r.Annotations[0].Annotator == nil ||
		r.Annotations[0].Annotator.Component == nil ||
		r.Annotations[0].Annotator.Component.Name != "wolfee" {
		t.Errorf("annotation actor not rewritten to wolfee: %+v", r.Annotations[0].Annotator)
	}
	if !strings.Contains(r.Annotations[0].Text, "Wolfee") ||
		strings.Contains(r.Annotations[0].Text, "Monday, May 11") {
		t.Errorf("annotation text not rewritten: %q", r.Annotations[0].Text)
	}

	byName := map[string]ComponentReport{}
	for _, c := range r.Components {
		byName[c.Name] = c
	}
	root, ok := byName["root"]
	if !ok {
		t.Fatalf("root component not in report: %+v", r.Components)
	}
	if root.BOMRef != "pkg:golang/example.com/root@v1.0.0" {
		t.Errorf("root bom-ref: %q", root.BOMRef)
	}
	if root.Group != "example.com" {
		t.Errorf("root group: %q", root.Group)
	}
	if root.Scope != "required" {
		t.Errorf("root scope: %q", root.Scope)
	}
	if len(root.Hashes) != 1 || root.Hashes[0].Alg != "SHA-256" || root.Hashes[0].Content != "aabbcc" {
		t.Errorf("root hashes: %+v", root.Hashes)
	}

	if len(root.Licenses) != 1 || root.Licenses[0].License == nil || root.Licenses[0].License.ID != "MIT" {
		t.Errorf("root licenses: %+v", root.Licenses)
	}
	if len(root.Occurrences) != 2 {
		t.Errorf("root occurrences: %+v", root.Occurrences)
	}
	if len(root.EvidenceIdentities) != 1 ||
		root.EvidenceIdentities[0].Field != "purl" ||
		len(root.EvidenceIdentities[0].Methods) != 1 ||
		root.EvidenceIdentities[0].Methods[0].Technique != "manifest-analysis" {
		t.Errorf("root evidence.identity: %+v", root.EvidenceIdentities)
	}
	gotProps := map[string]string{}
	for _, p := range root.Properties {
		gotProps[p.Name] = p.Value
	}
	if gotProps["ModuleGoVersion"] != "1.22" || gotProps["SrcFile"] != "/app/go.mod" {
		t.Errorf("root properties: %+v", root.Properties)
	}

	dep, ok := byName["dep"]
	if !ok {
		t.Fatalf("dep component not in report")
	}
	if dep.Scope != "optional" {
		t.Errorf("dep should have scope=optional (from cdx:go:indirect=true), got %q", dep.Scope)
	}

	if len(dep.Licenses) != 1 || dep.Licenses[0].License == nil ||
		dep.Licenses[0].License.Name != "CUSTOM" ||
		dep.Licenses[0].License.Text == nil ||
		dep.Licenses[0].License.Text.Content == "" {
		t.Errorf("dep CUSTOM license + text mismatch: %+v", dep.Licenses)
	}

	if r.Totals.Direct != 1 || r.Totals.Transitive != 1 {
		t.Errorf("totals direct/transitive: %d/%d", r.Totals.Direct, r.Totals.Transitive)
	}
}

func TestParseTools_LegacyArrayForm(t *testing.T) {

	raw := []byte(`[{"vendor":"OWASP","name":"cdxgen","version":"10.0.0"}]`)
	got := parseTools(raw)
	if got == nil || len(got.Components) != 1 ||
		got.Components[0].Name != "cdxgen" ||
		got.Components[0].Version != "10.0.0" ||
		got.Components[0].Publisher != "OWASP" {
		t.Errorf("parseTools(legacy) = %+v", got)
	}
}

func TestParseTools_ObjectFormWithGroupAndPurl(t *testing.T) {

	raw := []byte(`{"components":[{"group":"@cyclonedx","name":"cdxgen","version":"12.1.5","type":"application","purl":"pkg:npm/%40cyclonedx/cdxgen@12.1.5"}]}`)
	got := parseTools(raw)
	if got == nil || len(got.Components) != 1 {
		t.Fatalf("expected 1 component, got %+v", got)
	}
	c := got.Components[0]
	if c.Name != "cdxgen" || c.Group != "@cyclonedx" || c.Version != "12.1.5" || c.Type != "application" || c.PURL == "" {
		t.Errorf("parseTools(object) = %+v", c)
	}
}

func TestToReportLicenses_BothShapes(t *testing.T) {
	got := toReportLicenses([]cdxLicense{
		{License: &cdxLicenseInner{ID: "MIT"}},
		{Expression: "Apache-2.0 OR MIT"},
		{License: &cdxLicenseInner{Name: "Custom", URL: "https://example.com/lic"}},
		{},
	})
	if len(got) != 3 {
		t.Fatalf("expected 3 licenses, got %d: %+v", len(got), got)
	}
	if got[0].License == nil || got[0].License.ID != "MIT" {
		t.Errorf("first license: %+v", got[0])
	}
	if got[1].Expression != "Apache-2.0 OR MIT" {
		t.Errorf("second license: %+v", got[1])
	}
	if got[2].License == nil || got[2].License.Name != "Custom" || got[2].License.URL != "https://example.com/lic" {
		t.Errorf("third license: %+v", got[2])
	}
}

func TestToReportLicenses_PreservesText(t *testing.T) {

	got := toReportLicenses([]cdxLicense{
		{License: &cdxLicenseInner{
			Name: "CUSTOM",
			Text: &cdxLicenseText{ContentType: "text/plain", Content: "Apache License\nVersion 2.0..."},
		}},
	})
	if len(got) != 1 || got[0].License == nil || got[0].License.Text == nil {
		t.Fatalf("expected license with text, got %+v", got)
	}
	if got[0].License.Text.ContentType != "text/plain" {
		t.Errorf("contentType: %q", got[0].License.Text.ContentType)
	}
	if !strings.HasPrefix(got[0].License.Text.Content, "Apache License") {
		t.Errorf("license text content not preserved: %q", got[0].License.Text.Content)
	}
}

func TestBuildAnnotations_RewritesDocumentLevel(t *testing.T) {

	got := buildAnnotations([]cdxAnnotation{
		{
			BOMRef:    "metadata-annotations",
			Subjects:  []string{"pkg:app"},
			Annotator: &cdxAnnotationActor{Component: &cdxComponent{Name: "cdxgen", Version: "12.1.5"}},
			Timestamp: "2026-05-11T10:00:00Z",
			Text:      "This Software Bill-of-Materials was created with cdxgen",
		},
		{},
	})
	if len(got) != 1 {
		t.Fatalf("expected 1 annotation, got %d", len(got))
	}
	if got[0].Annotator == nil || got[0].Annotator.Component == nil ||
		got[0].Annotator.Component.Name != "wolfee" {
		t.Errorf("annotation actor should be rewritten to wolfee: %+v", got[0].Annotator)
	}
	if !strings.Contains(got[0].Text, "Wolfee") {
		t.Errorf("annotation text lacks Wolfee credit: %q", got[0].Text)
	}

	if strings.Contains(strings.ToLower(got[0].Text), "created with cdxgen") {
		t.Errorf("annotation text still claims cdxgen authorship: %q", got[0].Text)
	}
}

func TestBuildAnnotations_KeepsComponentLevel(t *testing.T) {

	got := buildAnnotations([]cdxAnnotation{{
		BOMRef:    "annot-1",
		Subjects:  []string{"pkg:npm/foo@1", "pkg:npm/bar@2"},
		Annotator: &cdxAnnotationActor{Component: &cdxComponent{Name: "policy-engine", Version: "0.1"}},
		Text:      "manually approved",
	}})
	if len(got) != 1 {
		t.Fatalf("expected 1 annotation, got %d", len(got))
	}
	if got[0].Annotator.Component.Name != "policy-engine" {
		t.Errorf("component-level annotation was rewritten: %+v", got[0].Annotator)
	}
	if got[0].Text != "manually approved" {
		t.Errorf("component-level text changed: %q", got[0].Text)
	}
}

func TestAppendWolfeeTool_Idempotent(t *testing.T) {

	t1 := appendWolfeeTool(nil)
	t2 := appendWolfeeTool(t1)
	if t2 == nil || len(t2.Components) != 1 {
		t.Fatalf("expected idempotent injection, got %+v", t2)
	}
}

func TestBuildDocument_DefaultsBomFormatAndSpec(t *testing.T) {

	d := buildDocument(&cdxBOM{})
	if d == nil {
		t.Fatal("expected non-nil document")
	}
	if d.BOMFormat != "CycloneDX" || d.SpecVersion != "1.6" {
		t.Errorf("defaults: bomFormat=%q specVersion=%q", d.BOMFormat, d.SpecVersion)
	}

	if d.Metadata == nil || d.Metadata.Tools == nil ||
		len(d.Metadata.Tools.Components) != 1 ||
		d.Metadata.Tools.Components[0].Name != "wolfee" {
		t.Errorf("wolfee not injected: %+v", d.Metadata)
	}
}

func TestToReportProperties_StripsWolfeeMarkers(t *testing.T) {
	got := toReportProperties([]cdxProperty{
		{Name: "wolfee:layer:diffid", Value: "sha256:abc"},
		{Name: "ModuleGoVersion", Value: "1.22"},
		{Name: "WOLFEE:class", Value: "x"},
		{Name: "", Value: "ignore-empty-name"},
		{Name: "SrcFile", Value: "/app/go.mod"},
	})
	if len(got) != 2 {
		t.Fatalf("expected 2 properties, got %d: %+v", len(got), got)
	}
	if got[0].Name != "ModuleGoVersion" || got[1].Name != "SrcFile" {
		t.Errorf("unexpected properties: %+v", got)
	}
}

func TestParseEvidenceIdentity_SingleObject(t *testing.T) {
	e := &cdxEvidence{Identity: []byte(`{"field":"purl","confidence":0.9,"methods":[{"technique":"manifest-analysis","confidence":0.9,"value":"/x"}]}`)}
	got := parseEvidenceIdentity(e)
	if len(got) != 1 || got[0].Field != "purl" || got[0].Confidence != 0.9 {
		t.Fatalf("single-object identity: %+v", got)
	}
	if len(got[0].Methods) != 1 || got[0].Methods[0].Technique != "manifest-analysis" {
		t.Errorf("methods: %+v", got[0].Methods)
	}
}

func TestParseEvidenceIdentity_ArrayForm(t *testing.T) {
	e := &cdxEvidence{Identity: []byte(`[{"field":"purl"},{"field":"name","confidence":0.5}]`)}
	got := parseEvidenceIdentity(e)
	if len(got) != 2 {
		t.Fatalf("expected 2 identities, got %d", len(got))
	}
	if got[1].Field != "name" || got[1].Confidence != 0.5 {
		t.Errorf("second identity: %+v", got[1])
	}
}

func TestParseEvidenceIdentity_Empty(t *testing.T) {
	if got := parseEvidenceIdentity(nil); got != nil {
		t.Errorf("expected nil for nil evidence, got %+v", got)
	}
	if got := parseEvidenceIdentity(&cdxEvidence{}); got != nil {
		t.Errorf("expected nil for empty identity, got %+v", got)
	}
}

func TestSyntheticSBOM_DocumentStillCreditsWolfee(t *testing.T) {

	bom, _ := SyntheticSBOMFromPURL("pkg:npm/lodash@4.17.21")
	r, err := ScanBOM(context.Background(), Options{BOMBytes: bom})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if r.Document == nil {
		t.Fatal("expected non-nil Document with defaults + wolfee tool")
	}
	if r.Document.BOMFormat != "CycloneDX" || r.Document.SpecVersion != "1.6" {
		t.Errorf("default doc fields: %+v", r.Document)
	}
	if r.Document.Metadata == nil || r.Document.Metadata.Tools == nil ||
		len(r.Document.Metadata.Tools.Components) != 1 ||
		r.Document.Metadata.Tools.Components[0].Name != "wolfee" {
		t.Errorf("wolfee not injected for synthetic BOM: %+v", r.Document.Metadata)
	}

	if r.Document.Metadata.Timestamp != "" || len(r.Document.Metadata.Lifecycles) != 0 ||
		r.Document.Metadata.Component != nil {
		t.Errorf("expected no source-derived metadata, got %+v", r.Document.Metadata)
	}
}

func TestExtractComponentMeta_FromPropertiesAndEvidence(t *testing.T) {
	c := cdxComponent{
		Properties: []cdxProperty{
			{Name: "wolfee:class", Value: "lang-pkgs"},
			{Name: "wolfee:type", Value: "npm"},
			{Name: "wolfee:target", Value: "image:demo:latest"},
			{Name: "wolfee:layer:createdby", Value: "RUN npm ci"},
		},
		Evidence: &cdxEvidence{Occurrences: []cdxOccurrence{{Location: "/app/package-lock.json"}}},
	}
	m := extractComponentMeta(c, fakeLayerResolver{"/app/package-lock.json": "sha256:abc"})
	if m.layerDigest != "sha256:abc" {
		t.Fatalf("layer digest mismatch: %q", m.layerDigest)
	}
	if m.class != "lang-pkgs" || m.pkgType != "npm" {
		t.Fatalf("class/type mismatch: %#v", m)
	}
	if m.introducedBy == "" || !strings.Contains(m.introducedBy, "package-lock.json") {
		t.Fatalf("introducedBy should come from evidence location, got %q", m.introducedBy)
	}
	if m.layerCreatedBy != "RUN npm ci" {
		t.Fatalf("layerCreatedBy mismatch: %q", m.layerCreatedBy)
	}
}

func TestSanitizePath_HomeDirVariants(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"/home/anyany/go/pkg/mod/cache/download/golang.org/x/sys/@v/v0.43.0.mod", "~/go/pkg/mod/cache/download/golang.org/x/sys/@v/v0.43.0.mod"},
		{"/Users/alice/src/app/go.mod", "~/src/app/go.mod"},
		{"/root/project/go.sum", "~/project/go.sum"},
		{"/root", "~"},
		{"/mnt/c/Users/bob/Documents/app", "~/Documents/app"},
		{`C:\Users\carol\app\go.mod`, "~/app/go.mod"},
		{`c:\Users\carol\app`, "~/app"},
		{"C:/Users/carol/app", "~/app"},

		{"/app/go.mod", "/app/go.mod"},
		{"app/go.mod", "app/go.mod"},
		{"pkg:npm/lodash@4.17.21", "pkg:npm/lodash@4.17.21"},
		{"", ""},
	}
	for _, tc := range cases {
		got := sanitizePath(tc.in)
		if got != tc.want {
			t.Errorf("sanitizePath(%q) = %q; want %q", tc.in, got, tc.want)
		}
	}
}

func TestToReportProperties_SanitizesValues(t *testing.T) {

	got := toReportProperties([]cdxProperty{
		{Name: "SrcGoMod", Value: "/home/anyany/go/pkg/mod/cache/download/golang.org/x/sys/@v/v0.43.0.mod"},
		{Name: "cdx:go:local_dir", Value: "/home/anyany/go/pkg/mod/golang.org/x/sys@v0.43.0"},
		{Name: "ModuleGoVersion", Value: "1.22"},
	})
	if len(got) != 3 {
		t.Fatalf("expected 3 properties, got %d", len(got))
	}
	for _, p := range got {
		if strings.Contains(p.Value, "anyany") {
			t.Errorf("property %q leaks username: %q", p.Name, p.Value)
		}
	}
	if got[0].Value != "~/go/pkg/mod/cache/download/golang.org/x/sys/@v/v0.43.0.mod" {
		t.Errorf("SrcGoMod not sanitised: %q", got[0].Value)
	}
}

func TestParseEvidenceIdentity_SanitizesValues(t *testing.T) {
	e := &cdxEvidence{Identity: []byte(`{"field":"purl","methods":[{"technique":"manifest-analysis","confidence":1.0,"value":"/home/anyany/repo/go.mod"}]}`)}
	got := parseEvidenceIdentity(e)
	if len(got) != 1 || len(got[0].Methods) != 1 {
		t.Fatalf("unexpected identity shape: %+v", got)
	}
	v := got[0].Methods[0].Value
	if strings.Contains(v, "anyany") {
		t.Errorf("evidence value leaks username: %q", v)
	}
	if v != "~/repo/go.mod" {
		t.Errorf("evidence value not sanitised: %q", v)
	}
}

func TestExtractComponentMeta_SanitizesOccurrencePaths(t *testing.T) {

	c := cdxComponent{
		Evidence: &cdxEvidence{Occurrences: []cdxOccurrence{
			{Location: "/home/anyany/project/go.mod"},
			{Location: "/Users/alice/src/lib"},
		}},
	}
	m := extractComponentMeta(c, nil)
	for _, occ := range m.occurrences {
		if strings.Contains(occ, "anyany") || strings.Contains(occ, "alice") {
			t.Errorf("occurrence leaks username: %q", occ)
		}
	}
	if strings.Contains(m.introducedBy, "anyany") {
		t.Errorf("introducedBy leaks username: %q", m.introducedBy)
	}
}

func TestExtractComponentMeta_LayerResolverSeesRawPath(t *testing.T) {

	c := cdxComponent{
		Evidence: &cdxEvidence{Occurrences: []cdxOccurrence{
			{Location: "/home/anyany/project/go.mod"},
		}},
	}
	resolver := fakeLayerResolver{"/home/anyany/project/go.mod": "sha256:layer-abc"}
	m := extractComponentMeta(c, resolver)
	if m.layerDigest != "sha256:layer-abc" {
		t.Errorf("layer digest lost: %q (resolver should have received raw path)", m.layerDigest)
	}
}
