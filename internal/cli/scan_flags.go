package cli

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
)

const scanUsage = `wolfee scan - scan a project directory, image, SBOM, or single package

USAGE:
  wolfee scan <path>               [flags]   # local project directory
  wolfee scan --reachable <dir>    [flags]   # source + call-graph reachability
  wolfee scan --image <image-ref>  [flags]
  wolfee scan --bom   <file.json>  [flags]
  wolfee scan --purl  <purl>       [flags]

INPUT (exactly one required, mutually exclusive):
  <path>             Local project directory - runs cdxgen on it, then enriches
  --reachable <dir>  Source tree - runs cdxgen on it, then enriches AND tags
                     vulnerable components reachable/unreachable via call-graph
                     analysis (Go via govulncheck today). Source only - not
                     combinable with --image/--bom/--purl.
  --image <ref>      Container image reference (e.g. nginx:1.27, ghcr.io/x/y@sha256:..)
  --bom <path>       Existing CycloneDX SBOM (JSON)
  --purl <purl>      Single package URL (pkg:npm/lodash@4.17.21)

IMAGE MODE (detection + severity via the trivy subprocess, then enriched):
  --platform OS/ARCH Pin a manifest from a multi-arch index (linux/amd64, linux/arm64, ...)
  --scout            Tag each finding by where the package comes from - BASE
                     (base image) vs APP (your layers), by matching layer
                     DiffIDs. OS packages render as DEB/APK/RPM. Finds the
                     base local-first (OCI base labels, then the rootfs-import
                     line in history); for arbitrary images with neither it
                     falls back to docker scout - which needs the scout plugin
                     + docker login and uploads image metadata to Docker's
                     cloud (not air-gapped). Any base is hash-verified, so a
                     wrong guess yields "-", not a mislabel. Off by default.
  --compare DIR      Compare the image against the application's own SBOM
                     (cdxgen over the source tree at DIR). Reports vulns from
                     BOTH the image (trivy) and the sources (OSV), and tags
                     every package in ORIGIN: APP - one of our libraries (in
                     our SBOM); IMAGE - only in the image (base/OS package or
                     a binary added at build time), unrelated to our code.
                     Transitive (indirect) APP dependencies are flagged
                     "transitive" from their SBOM scope. APP findings are also
                     marked reachable/unreachable by the call-graph analyzers
                     (govulncheck for Go, atom for js/python/java/php).
                     Mutually exclusive with --scout (both own ORIGIN).
  --trivy-bin PATH   Path to trivy binary (default: looks up "trivy" on PATH)
  --trivy-arg X      Forward a raw flag to trivy (repeatable), e.g.
                     --trivy-arg=--offline-scan --trivy-arg=--db-repository=<mirror>

FILESYSTEM (project path) MODE - cdxgen tuning:
  --deep             Pass --deep to cdxgen (transitive deps walk)
  --required-only    Pass --required-only to cdxgen (production deps only)
  --cdxgen-arg X     Forward a raw flag to cdxgen (repeatable)
  --cdxgen-bin PATH  Path to cdxgen binary (default: looks up "cdxgen" on PATH)

REACHABILITY (only with --reachable):
  --govulncheck-bin PATH  Path to govulncheck - Go symbol-level (default: PATH)
  --atom-bin PATH         Path to atom - js/python/java/php package-level
                          (default: PATH). Unknown verdicts never downgrade a
                          finding; a missing analyzer degrades gracefully.

SBOM SAVE (filesystem + image modes):
  --save-sbom PATH   Also write a CycloneDX SBOM to PATH (image mode: via
                     a second "trivy image --format cyclonedx" run)

OUTPUT:
  --format FMT       table | json | sarif (default: table)
  --output PATH      Write report to file instead of stdout
  --fail-on LEVEL    Exit non-zero if a finding >= LEVEL exists: none|low|medium|high|critical
                     (default: none - never fail on findings)
  --quiet            Suppress progress logs

SERVER UPLOAD (optional - fire-and-forget alongside local output):
  --server URL       Wolfee server URL (e.g. https://wolfee.example.com)
  --token TOKEN      API token (or pass via WOLFEE_TOKEN env var)
  --project NAME     Project name or UUID (auto-create if missing)

SCAN:
  --concurrency N    Parallel OSV queries (default: 16)

TRIVY DB:
  --trivy-db-skip    Disable Trivy DB stage (fall back to tracker + OSV only)
  --trivy-db-mirror  Custom OCI registry host for trivy-db pulls (default: ghcr.io)

EXAMPLES:
  wolfee --image nginx:latest
  wolfee scan --image my-app:latest --scout
  wolfee scan --image registry/some/image:tag --scout
  wolfee scan --image my-app:latest --compare ./src
  wolfee scan --image my-app:latest --fail-on high
  wolfee scan --image my-app:latest --format sarif --output report.sarif
  wolfee scan --bom existing.cdx.json --format sarif --output report.sarif
  wolfee scan --purl pkg:npm/ngx-bootstrap@20.0.4
  wolfee scan --reachable ./my-go-service --fail-on high
`

func parseScanFlags(args []string) (*scanOpts, error) {
	o := &scanOpts{}

	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		o.path = args[0]
		args = args[1:]
	}

	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { fmt.Fprint(os.Stderr, scanUsage) }
	fs.StringVar(&o.image, "image", "", "container image reference")
	fs.StringVar(&o.platform, "platform", "", "platform to pull from multi-arch manifest (e.g. linux/amd64, linux/arm64)")
	fs.StringVar(&o.trivyBin, "trivy-bin", "", "path to trivy binary (--image mode; default: looks up \"trivy\" on PATH)")
	fs.Var(&o.trivyExtra, "trivy-arg", "extra arg forwarded to trivy in --image mode (repeatable, e.g. --trivy-arg=--offline-scan)")
	fs.BoolVar(&o.scout, "scout", false, "tag each package BASE/APP by layer (--image mode): local-first base detection (OCI labels, rootfs in history), else docker scout (needs docker login; uploads to Docker cloud)")
	fs.StringVar(&o.compare, "compare", "", "application source dir (--image mode): run govulncheck/atom on it and tag image findings reachable/unreachable where the package also appears in our sources")
	fs.StringVar(&o.bom, "bom", "", "existing CycloneDX SBOM file")
	fs.StringVar(&o.purl, "purl", "", "single PURL to scan")
	fs.BoolVar(&o.deep, "deep", false, "pass --deep to cdxgen")
	fs.BoolVar(&o.requiredOnly, "required-only", false, "pass --required-only to cdxgen")
	fs.Var(&o.cdxgenExtra, "cdxgen-arg", "extra arg forwarded to cdxgen (repeatable)")
	fs.StringVar(&o.cdxgenBin, "cdxgen-bin", "", "path to cdxgen binary")
	fs.StringVar(&o.saveSBOM, "save-sbom", "", "write generated SBOM here")
	fs.StringVar(&o.reachable, "reachable", "", "source dir - cdxgen + call-graph reachability (source-only mode)")
	fs.StringVar(&o.govulncheckBin, "govulncheck-bin", "", "path to govulncheck binary")
	fs.StringVar(&o.atomBin, "atom-bin", "", "path to atom binary (js/python/java/php reachability)")
	fs.StringVar(&o.format, "format", "table", "output format: table|json|sarif")
	fs.StringVar(&o.outFile, "output", "", "write output here instead of stdout")
	fs.StringVar(&o.failOn, "fail-on", "none", "exit non-zero on this severity: none|low|medium|high|critical")
	fs.BoolVar(&o.quiet, "quiet", false, "suppress progress logs")
	fs.BoolVar(&o.debug, "debug", false, "show verbose debug output (govulncheck traces, atom calls, etc.)")
	fs.StringVar(&o.server, "server", "", "Wolfee server URL")
	fs.StringVar(&o.token, "token", "", "API token (or WOLFEE_TOKEN env)")
	fs.StringVar(&o.project, "project", "", "project name/UUID")
	fs.IntVar(&o.concurrency, "concurrency", 0, "parallel scans (0 = auto)")
	fs.BoolVar(&o.trivyDBSkip, "trivy-db-skip", false, "disable Trivy DB stage")
	fs.StringVar(&o.trivyDBMirror, "trivy-db-mirror", "", "custom OCI registry host for trivy-db (default: ghcr.io)")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	if fs.NArg() > 0 {
		if o.path != "" {
			return nil, fmt.Errorf("path given both before and after flags: %q and %v - pick one", o.path, fs.Args())
		}
		if fs.NArg() > 1 {
			return nil, fmt.Errorf("expected at most one positional path argument, got %d: %v", fs.NArg(), fs.Args())
		}
		o.path = fs.Arg(0)
	}
	return o, nil
}

func (o *scanOpts) validate() error {
	provided := 0
	if o.image != "" {
		provided++
	}
	if o.bom != "" {
		provided++
	}
	if o.purl != "" {
		provided++
	}
	if o.path != "" {
		provided++
	}
	if o.reachable != "" {
		provided++
	}
	if provided == 0 {
		return errors.New("one of --image, --bom, --purl, --reachable, or a project path is required (run 'wolfee scan --help')")
	}
	if provided > 1 {

		if o.reachable != "" {
			return errors.New("--reachable scans source only and is not combinable with --image, --bom, --purl, or a positional path")
		}
		return errors.New("--image, --bom, --purl and a project path are mutually exclusive")
	}
	switch strings.ToLower(o.format) {
	case "", "table", "json", "sarif":
	default:
		return fmt.Errorf("unsupported --format %q (table|json|sarif)", o.format)
	}
	switch strings.ToLower(o.failOn) {
	case "", "none", "low", "medium", "high", "critical":
	default:
		return fmt.Errorf("unsupported --fail-on %q", o.failOn)
	}
	if o.server != "" && o.project == "" {
		return errors.New("--server requires --project")
	}
	if o.scout && o.image == "" {
		return errors.New("--scout only applies to --image mode (it attributes image layers base-vs-app)")
	}
	if o.compare != "" {
		if o.image == "" {
			return errors.New("--compare only applies to --image mode (it attributes image packages APP-vs-IMAGE by SBOM membership)")
		}
		if o.scout {
			return errors.New("--compare and --scout both drive the ORIGIN column (SBOM membership vs base-image layers) - pick one")
		}
		st, err := os.Stat(o.compare)
		if err != nil {
			return fmt.Errorf("--compare %s: %w", o.compare, err)
		}
		if !st.IsDir() {
			return fmt.Errorf("--compare %s is not a directory (it takes the application source tree)", o.compare)
		}
	}
	return nil
}
