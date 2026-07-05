package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
)

const usage = `wolfee - SCA scanner for container images, project sources, and SBOMs.
Catalogue → OSV.dev + ossf/malicious-packages + KEV + EPSS + PoC GitHub.

USAGE:
  wolfee <path>                  # implicit filesystem scan (current dir, etc.)
  wolfee --image <image-ref>     # implicit image scan
  wolfee scan <flags>            # full scan options
  wolfee version

QUICK START:
  wolfee ./                      # scan the current project
  wolfee --image nginx:latest
  wolfee --image my-app:1.0 --format json --output report.json
  wolfee --bom existing.cdx.json
  wolfee --purl pkg:npm/lodash@4.17.21

Run 'wolfee scan --help' for the complete flag list.

Image scans use built-in stream analyzers (no cdxgen required).
Project / filesystem scans require cdxgen on PATH - install with
'npm i -g @cyclonedx/cdxgen'.

All data feeds (OSV, CISA KEV, EPSS, PoC-in-GitHub, ossf/malicious-packages,
toxic-repos/toxic-repos) are fetched from their canonical URLs by default -
no configuration required.
`

func Run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		fmt.Print(usage)
		return errors.New("no command given")
	}

	first := args[0]
	cmd := strings.ToLower(first)

	if strings.HasPrefix(first, "-") && !isHelpFlag(cmd) && !isVersionFlag(cmd) {
		return runScan(ctx, args)
	}

	if isExistingDir(first) {
		return runScan(ctx, args)
	}

	rest := args[1:]
	switch cmd {
	case "-h", "--help", "help":
		fmt.Print(usage)
		return nil
	case "version", "-v", "--version":
		return runVersion(rest)
	case "scan":
		return runScan(ctx, rest)
	}
	return fmt.Errorf("unknown command %q (run 'wolfee --help')", cmd)
}

func isExistingDir(p string) bool {
	if p == "" {
		return false
	}
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

func isHelpFlag(s string) bool { return s == "-h" || s == "--help" }
func isVersionFlag(s string) bool {
	return s == "-v" || s == "--version"
}
