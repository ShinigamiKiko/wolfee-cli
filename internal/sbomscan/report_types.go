package sbomscan

import "sca-go/cli/internal/onlinescan"

type Report struct {
	Generator    string            `json:"generator,omitempty"`
	Source       string            `json:"source"`
	GeneratedAt  string            `json:"generatedAt"`
	OS           *ReportOS         `json:"os,omitempty"`
	Totals       Totals            `json:"totals"`
	Document     *Document         `json:"document,omitempty"`
	Dependencies []Dependency      `json:"dependencies,omitempty"`
	Annotations  []Annotation      `json:"annotations,omitempty"`
	Components   []ComponentReport `json:"components"`
}

type ReportOS struct {
	Family   string `json:"family,omitempty"`
	Name     string `json:"name,omitempty"`
	Version  string `json:"version,omitempty"`
	Codename string `json:"codename,omitempty"`
	Arch     string `json:"arch,omitempty"`
}

type Totals struct {
	Components int `json:"components"`
	Scanned    int `json:"scanned"`
	Skipped    int `json:"skipped"`
	Direct     int `json:"direct"`
	Transitive int `json:"transitive"`
	WithVulns  int `json:"withVulns"`

	Reachable    int `json:"reachable,omitempty"`
	Unreachable  int `json:"unreachable,omitempty"`
	ReachUnknown int `json:"reachUnknown,omitempty"`

	PackageUsed   int `json:"packageUsed,omitempty"`
	PackageUnused int `json:"packageUnused,omitempty"`
	Malware       int `json:"malware"`
	Toxic         int `json:"toxic"`
	KEV           int `json:"kev"`
	PoC           int `json:"poc"`
	CRITICAL      int `json:"CRITICAL"`
	HIGH          int `json:"HIGH"`
	MEDIUM        int `json:"MEDIUM"`
	LOW           int `json:"LOW"`
	UNKNOWN       int `json:"UNKNOWN"`
}

type Document struct {
	BOMFormat    string            `json:"bomFormat,omitempty"`
	SpecVersion  string            `json:"specVersion,omitempty"`
	SerialNumber string            `json:"serialNumber,omitempty"`
	Version      int               `json:"version,omitempty"`
	Metadata     *DocumentMetadata `json:"metadata,omitempty"`
}

type DocumentMetadata struct {
	Timestamp  string             `json:"timestamp,omitempty"`
	Lifecycles []Lifecycle        `json:"lifecycles,omitempty"`
	Tools      *Tools             `json:"tools,omitempty"`
	Authors    []Author           `json:"authors,omitempty"`
	Component  *DocumentComponent `json:"component,omitempty"`
}

type Lifecycle struct {
	Phase       string `json:"phase,omitempty"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

type Tools struct {
	Components []ToolComponent `json:"components,omitempty"`
	Services   []ToolService   `json:"services,omitempty"`
}

type ToolComponent struct {
	BOMRef    string `json:"bom-ref,omitempty"`
	Type      string `json:"type,omitempty"`
	Group     string `json:"group,omitempty"`
	Name      string `json:"name,omitempty"`
	Version   string `json:"version,omitempty"`
	PURL      string `json:"purl,omitempty"`
	Publisher string `json:"publisher,omitempty"`
}

type ToolService struct {
	BOMRef   string `json:"bom-ref,omitempty"`
	Name     string `json:"name,omitempty"`
	Version  string `json:"version,omitempty"`
	Provider string `json:"provider,omitempty"`
}

type Author struct {
	Name  string `json:"name,omitempty"`
	Email string `json:"email,omitempty"`
}

type DocumentComponent struct {
	BOMRef    string   `json:"bom-ref,omitempty"`
	Type      string   `json:"type,omitempty"`
	Name      string   `json:"name,omitempty"`
	Group     string   `json:"group,omitempty"`
	Version   string   `json:"version,omitempty"`
	PURL      string   `json:"purl,omitempty"`
	Publisher string   `json:"publisher,omitempty"`
	Authors   []Author `json:"authors,omitempty"`
}

type Dependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

type Annotation struct {
	BOMRef    string           `json:"bom-ref,omitempty"`
	Subjects  []string         `json:"subjects,omitempty"`
	Annotator *AnnotationActor `json:"annotator,omitempty"`
	Timestamp string           `json:"timestamp,omitempty"`
	Text      string           `json:"text,omitempty"`
}

type AnnotationActor struct {
	Component *ToolComponent `json:"component,omitempty"`
	Service   *ToolService   `json:"service,omitempty"`
}

type Hash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type LicenseChoice struct {
	License    *License `json:"license,omitempty"`
	Expression string   `json:"expression,omitempty"`
}

type License struct {
	ID   string       `json:"id,omitempty"`
	Name string       `json:"name,omitempty"`
	URL  string       `json:"url,omitempty"`
	Text *LicenseText `json:"text,omitempty"`
}

type LicenseText struct {
	ContentType string `json:"contentType,omitempty"`
	Encoding    string `json:"encoding,omitempty"`
	Content     string `json:"content,omitempty"`
}

type EvidenceIdentity struct {
	Field      string           `json:"field,omitempty"`
	Confidence float64          `json:"confidence,omitempty"`
	Methods    []EvidenceMethod `json:"methods,omitempty"`
}

type EvidenceMethod struct {
	Technique  string  `json:"technique,omitempty"`
	Confidence float64 `json:"confidence,omitempty"`
	Value      string  `json:"value,omitempty"`
}

type Property struct {
	Name  string `json:"name"`
	Value string `json:"value,omitempty"`
}

type ComponentReport struct {
	BOMRef string `json:"bom-ref,omitempty"`
	PURL   string `json:"purl"`
	System string `json:"system"`

	Group   string `json:"group,omitempty"`
	Name    string `json:"name"`
	Version string `json:"version"`

	Scope string `json:"scope,omitempty"`

	PackageUsage string `json:"packageUsage,omitempty"`

	Language          string `json:"language,omitempty"`
	LanguageRelevance string `json:"languageRelevance,omitempty"`
	Relevant          *bool  `json:"relevant,omitempty"`

	ImportSite string `json:"importSite,omitempty"`

	ImportLine string `json:"importLine,omitempty"`
	Target     string `json:"target,omitempty"`
	Class      string `json:"class,omitempty"`
	Type       string `json:"type,omitempty"`

	IntroducedBy string `json:"introducedBy,omitempty"`

	DependencyPaths [][]string `json:"dependencyPaths,omitempty"`

	Origin string `json:"origin,omitempty"`

	LayerDigest string `json:"layerDigest,omitempty"`

	LayerCreatedBy string `json:"layerCreatedBy,omitempty"`

	Hashes []Hash `json:"hashes,omitempty"`

	Licenses []LicenseChoice `json:"licenses,omitempty"`

	Occurrences []string `json:"occurrences,omitempty"`

	EvidenceIdentities []EvidenceIdentity `json:"evidenceIdentity,omitempty"`

	Properties []Property `json:"properties,omitempty"`

	TopSeverity     string                     `json:"topSeverity"`
	VulnCount       int                        `json:"vulnCount"`
	Malware         onlinescan.Malware         `json:"malware"`
	Toxic           onlinescan.Toxic           `json:"toxic"`
	Vulnerabilities []onlinescan.Vulnerability `json:"vulnerabilities,omitempty"`
	Error           string                     `json:"error,omitempty"`
}
