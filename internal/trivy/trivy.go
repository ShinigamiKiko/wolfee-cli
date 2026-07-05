package trivy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"sca-go/cli/internal/output"
)

type Options struct {
	Image    string
	Platform string

	Bin string

	ExtraArgs []string

	SaveSBOM string

	Logger output.Logger
}

type Report struct {
	SchemaVersion int
	ArtifactName  string
	ArtifactType  string
	Metadata      Metadata
	Results       []Result
}

type Metadata struct {
	OS *OS

	DiffIDs []string

	ImageConfig ImageConfig
}

type OS struct {
	Family string
	Name   string
	EOSL   bool
}

type ImageConfig struct {
	Architecture string      `json:"architecture"`
	Config       ConfigBlock `json:"config"`
	RootFS       RootFS      `json:"rootfs"`
	History      []History   `json:"history"`
}

type ConfigBlock struct {
	Labels map[string]string `json:"Labels"`
}

type RootFS struct {
	Type    string   `json:"type"`
	DiffIDs []string `json:"diff_ids"`
}

type History struct {
	Created    string `json:"created"`
	CreatedBy  string `json:"created_by"`
	EmptyLayer bool   `json:"empty_layer"`
	Comment    string `json:"comment"`
}

func (m Metadata) DiffIDOrder() []string {
	if len(m.DiffIDs) > 0 {
		return m.DiffIDs
	}
	return m.ImageConfig.RootFS.DiffIDs
}

func (m Metadata) LayerCreatedBy() map[string]string {
	diffIDs := m.DiffIDOrder()
	if len(diffIDs) == 0 || len(m.ImageConfig.History) == 0 {
		return nil
	}
	out := make(map[string]string, len(diffIDs))
	idx := 0
	for _, h := range m.ImageConfig.History {
		if h.EmptyLayer {
			continue
		}
		if idx >= len(diffIDs) {
			break
		}

		if _, ok := out[diffIDs[idx]]; !ok {
			out[diffIDs[idx]] = h.CreatedBy
		}
		idx++
	}
	return out
}

type Result struct {
	Target          string
	Class           string
	Type            string
	Packages        []Package
	Vulnerabilities []Vulnerability
}

type Package struct {
	ID         string
	Name       string
	Version    string
	Arch       string
	SrcName    string
	Identifier Identifier
	Layer      Layer
}

type Identifier struct {
	PURL string
	UID  string
}

type Layer struct {
	Digest string
	DiffID string
}

type Vulnerability struct {
	VulnerabilityID  string
	PkgName          string
	PkgID            string
	PkgIdentifier    Identifier
	InstalledVersion string
	FixedVersion     string
	Status           string
	Severity         string
	SeveritySource   string
	Title            string
	Description      string
	PrimaryURL       string
	References       []string
	PublishedDate    string
	LastModifiedDate string
	Layer            Layer
	CVSS             map[string]CVSS
}

type CVSS struct {
	V2Vector string
	V3Vector string
	V2Score  float64
	V3Score  float64
}

func Scan(ctx context.Context, o Options) (*Report, error) {
	if strings.TrimSpace(o.Image) == "" {
		return nil, errors.New("trivy: empty image reference")
	}
	bin, err := resolveBin(o.Bin)
	if err != nil {
		return nil, err
	}

	tmp, err := os.CreateTemp("", "wolfee-trivy-*.json")
	if err != nil {
		return nil, fmt.Errorf("trivy: tempfile: %w", err)
	}
	tmp.Close()
	defer os.Remove(tmp.Name())

	args := []string{
		"image",
		"--format", "json",
		"--output", tmp.Name(),
		"--quiet",
		"--scanners", "vuln",

		"--list-all-pkgs",
	}
	args = append(args, o.commonArgs()...)

	if err := o.run(ctx, bin, args); err != nil {
		return nil, fmt.Errorf("trivy run: %w (image=%s)", err, o.Image)
	}

	raw, err := os.ReadFile(tmp.Name())
	if err != nil {
		return nil, fmt.Errorf("trivy: read report: %w", err)
	}
	if len(raw) == 0 {
		return nil, errors.New("trivy produced an empty report - check image reference and trivy logs")
	}
	var rep Report
	if err := json.Unmarshal(raw, &rep); err != nil {
		return nil, fmt.Errorf("trivy: parse report: %w", err)
	}

	if o.SaveSBOM != "" {
		sbomArgs := []string{
			"image",
			"--format", "cyclonedx",
			"--output", o.SaveSBOM,
			"--quiet",
		}
		sbomArgs = append(sbomArgs, o.commonArgs()...)
		if err := o.run(ctx, bin, sbomArgs); err != nil {
			if o.Logger != nil {
				o.Logger.Warn("could not save SBOM to %s: %v", o.SaveSBOM, err)
			}
		} else if o.Logger != nil {
			o.Logger.Step(fmt.Sprintf("Saved CycloneDX SBOM to %s", o.SaveSBOM))
		}
	}

	return &rep, nil
}

func (o Options) commonArgs() []string {
	var a []string
	if o.Platform != "" {
		a = append(a, "--platform", o.Platform)
	}
	a = append(a, o.ExtraArgs...)
	a = append(a, o.Image)
	return a
}

func (o Options) run(ctx context.Context, bin string, args []string) error {
	if o.Logger != nil {
		o.Logger.Debug("trivy invocation: %s %s", bin, strings.Join(args, " "))
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	if o.Logger != nil {
		cmd.Stderr = output.LineWriter(o.Logger.Debug, "[trivy] ")
	} else {
		cmd.Stderr = os.Stderr
	}
	cmd.Stdout = nil
	return cmd.Run()
}

func resolveBin(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	path, err := exec.LookPath("trivy")
	if err != nil {
		return "", fmt.Errorf("trivy not found on PATH - install it (https://trivy.dev/latest/getting-started/installation/) or pass --trivy-bin")
	}
	return path, nil
}
