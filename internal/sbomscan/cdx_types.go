package sbomscan

import "encoding/json"

type cdxBOM struct {
	BOMFormat    string          `json:"bomFormat,omitempty"`
	SpecVersion  string          `json:"specVersion,omitempty"`
	SerialNumber string          `json:"serialNumber,omitempty"`
	Version      int             `json:"version,omitempty"`
	Metadata     *cdxMetadata    `json:"metadata,omitempty"`
	Components   []cdxComponent  `json:"components"`
	Dependencies []cdxDependency `json:"dependencies,omitempty"`
	Annotations  []cdxAnnotation `json:"annotations,omitempty"`
}

type cdxMetadata struct {
	Timestamp  string          `json:"timestamp,omitempty"`
	Lifecycles []cdxLifecycle  `json:"lifecycles,omitempty"`
	Tools      json.RawMessage `json:"tools,omitempty"`
	Authors    []cdxAuthor     `json:"authors,omitempty"`
	Component  *cdxComponent   `json:"component,omitempty"`
}

type cdxLifecycle struct {
	Phase       string `json:"phase,omitempty"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

type cdxAuthor struct {
	Name  string `json:"name,omitempty"`
	Email string `json:"email,omitempty"`
}

type cdxTool struct {
	Vendor       string  `json:"vendor,omitempty"`
	Name         string  `json:"name,omitempty"`
	Version      string  `json:"version,omitempty"`
	Manufacturer *cdxOrg `json:"manufacturer,omitempty"`
}

type cdxOrg struct {
	Name string `json:"name,omitempty"`
}

type cdxComponent struct {
	BOMRef     string        `json:"bom-ref,omitempty"`
	Type       string        `json:"type,omitempty"`
	Group      string        `json:"group,omitempty"`
	Name       string        `json:"name"`
	Version    string        `json:"version"`
	Purl       string        `json:"purl"`
	Scope      string        `json:"scope,omitempty"`
	Publisher  string        `json:"publisher,omitempty"`
	Authors    []cdxAuthor   `json:"authors,omitempty"`
	Hashes     []cdxHash     `json:"hashes,omitempty"`
	Licenses   []cdxLicense  `json:"licenses,omitempty"`
	Properties []cdxProperty `json:"properties,omitempty"`
	Evidence   *cdxEvidence  `json:"evidence,omitempty"`
}

type cdxHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type cdxLicense struct {
	License    *cdxLicenseInner `json:"license,omitempty"`
	Expression string           `json:"expression,omitempty"`
}

type cdxLicenseInner struct {
	ID   string          `json:"id,omitempty"`
	Name string          `json:"name,omitempty"`
	URL  string          `json:"url,omitempty"`
	Text *cdxLicenseText `json:"text,omitempty"`
}

type cdxLicenseText struct {
	ContentType string `json:"contentType,omitempty"`
	Encoding    string `json:"encoding,omitempty"`
	Content     string `json:"content,omitempty"`
}

type cdxAnnotation struct {
	BOMRef    string              `json:"bom-ref,omitempty"`
	Subjects  []string            `json:"subjects,omitempty"`
	Annotator *cdxAnnotationActor `json:"annotator,omitempty"`
	Timestamp string              `json:"timestamp,omitempty"`
	Text      string              `json:"text,omitempty"`
}

type cdxAnnotationActor struct {
	Component *cdxComponent `json:"component,omitempty"`
	Service   *cdxService   `json:"service,omitempty"`
}

type cdxService struct {
	BOMRef   string  `json:"bom-ref,omitempty"`
	Name     string  `json:"name,omitempty"`
	Version  string  `json:"version,omitempty"`
	Provider *cdxOrg `json:"provider,omitempty"`
}

type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type cdxEvidence struct {
	Occurrences []cdxOccurrence `json:"occurrences,omitempty"`

	Identity json.RawMessage `json:"identity,omitempty"`
}

type cdxOccurrence struct {
	Location string `json:"location,omitempty"`
}

type cdxIdentity struct {
	Field      string        `json:"field,omitempty"`
	Confidence float64       `json:"confidence,omitempty"`
	Methods    []cdxIdMethod `json:"methods,omitempty"`
}

type cdxIdMethod struct {
	Technique  string  `json:"technique,omitempty"`
	Confidence float64 `json:"confidence,omitempty"`
	Value      string  `json:"value,omitempty"`
}

type cdxDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}
