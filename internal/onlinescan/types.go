package onlinescan

const (
	SevCritical = "CRITICAL"
	SevHigh     = "HIGH"
	SevMedium   = "MEDIUM"
	SevLow      = "LOW"

	SevUnknown      = ""
	SevUnknownLabel = "UNKNOWN"
)

const (
	SeveritySourceOSV           = "OSV"
	SeveritySourceNVD           = "NVD"
	SeveritySourceDebianTracker = "debian-tracker"

	SeveritySourceTrivyDB = "trivy-db"
)

type Vulnerability struct {
	ID          string   `json:"id"`
	Aliases     []string `json:"aliases,omitempty"`
	CVE         string   `json:"cve,omitempty"`
	Title       string   `json:"title,omitempty"`
	Description string   `json:"description,omitempty"`
	Summary     string   `json:"summary,omitempty"`
	Severity    string   `json:"severity"`
	CVSS        float64  `json:"cvss,omitempty"`
	CVSSVector  string   `json:"cvssVector,omitempty"`
	CWEs        []string `json:"cwes,omitempty"`
	Published   string   `json:"published,omitempty"`
	Modified    string   `json:"modified,omitempty"`
	Fixed       []string `json:"fixed,omitempty"`
	Reference   string   `json:"reference,omitempty"`

	InKEV          bool     `json:"inKev"`
	EPSS           float64  `json:"epss,omitempty"`
	EPSSPercentile float64  `json:"epssPercentile,omitempty"`
	PoCs           []string `json:"pocs,omitempty"`

	Reachable string `json:"reachable,omitempty"`

	CallSite string `json:"callSite,omitempty"`

	CallLine string `json:"callLine,omitempty"`

	VulnerableSymbols []VulnImport `json:"vulnerableSymbols,omitempty"`

	SeveritySource string `json:"severitySource,omitempty"`

	Status string `json:"status,omitempty"`

	DistroStatus []DistroStatus `json:"distroStatus,omitempty"`

	RelatedAdvisories []string `json:"relatedAdvisories,omitempty"`

	// Remediation, for a transitive finding, tells you which direct
	// ("father") dependency to bump and to what version so this vuln's
	// package resolves to a fixed release. Computed online via deps.dev
	// (resolved dependency graphs) cross-checked against OSV.dev.
	Remediation *Remediation `json:"remediation,omitempty"`
}

// Remediation describes the actionable upgrade for a (usually transitive)
// vulnerability: bump Direct from CurrentVersion to FixVersion, after which
// the vulnerable package resolves to ChildFixed (or is dropped entirely).
type Remediation struct {
	// Direct is the nearest direct dependency in the path ("father"): the
	// lever you actually control in your manifest.
	Direct string `json:"direct"`

	CurrentVersion string `json:"currentVersion,omitempty"`

	// FixVersion is the version of Direct that drops the vulnerable release.
	FixVersion string `json:"fixVersion,omitempty"`

	// ChildFixed is the version the vulnerable package resolves to under
	// Direct@FixVersion. "(removed)" means the dependency is no longer pulled.
	ChildFixed string `json:"childFixed,omitempty"`

	// Via is how the fix is applied: "direct-bump" (the vulnerable package is
	// itself a direct dependency), "parent-bump" (bump Direct), or "override"
	// (no parent version helps - pin the child via overrides/resolutions).
	Via string `json:"via,omitempty"`

	Note string `json:"note,omitempty"`
}

type VulnImport struct {
	Path    string   `json:"path"`
	Symbols []string `json:"symbols,omitempty"`
}

type DistroStatus struct {
	Distro     string `json:"distro"`
	Release    string `json:"release,omitempty"`
	Status     string `json:"status"`
	FixVersion string `json:"fixVersion,omitempty"`
	Urgency    string `json:"urgency,omitempty"`

	Source string `json:"source,omitempty"`
}

type Malware struct {
	Found     bool     `json:"found"`
	ID        string   `json:"id,omitempty"`
	Summary   string   `json:"summary,omitempty"`
	Reference string   `json:"reference,omitempty"`
	Sources   []string `json:"sources,omitempty"`
	MalIDs    []string `json:"malIds,omitempty"`
}

type Toxic struct {
	Found      bool     `json:"found"`
	Categories []string `json:"categories,omitempty"`
	Notes      []string `json:"notes,omitempty"`

	// Remediation suggests an upgrade off the flagged (protestware/toxic)
	// release, treated like a vulnerability fix. Computed via deps.dev.
	Remediation *Remediation `json:"remediation,omitempty"`
}
