package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"sca-go/cli/internal/cdxgen"
	"sca-go/cli/internal/output"
	"sca-go/cli/internal/reachability"
	"sca-go/cli/internal/sbomscan"
	"sca-go/cli/internal/upload"
)

type scanOpts struct {
	image    string
	bom      string
	purl     string
	path     string
	platform string

	trivyBin   string
	trivyExtra arrayFlag

	scout bool

	compare string

	deep         bool
	requiredOnly bool
	cdxgenExtra  arrayFlag
	cdxgenBin    string
	saveSBOM     string

	format  string
	outFile string
	failOn  string
	quiet   bool
	debug   bool

	server  string
	token   string
	project string

	reachable      string
	govulncheckBin string
	atomBin        string

	concurrency int

	trivyDBSkip   bool
	trivyDBMirror string
}

type arrayFlag []string

func (a *arrayFlag) String() string     { return strings.Join(*a, " ") }
func (a *arrayFlag) Set(v string) error { *a = append(*a, v); return nil }

func runScan(ctx context.Context, args []string) error {
	o, err := parseScanFlags(args)
	if err != nil {
		return err
	}
	if err := o.validate(); err != nil {
		return err
	}

	if o.token == "" {
		o.token = strings.TrimSpace(os.Getenv("WOLFEE_TOKEN"))
	}

	logger := output.NewLogger(o.quiet, o.debug)

	var report *sbomscan.Report

	var bomBytes []byte

	if o.image != "" {

		var reach *reachability.Result
		var sourceLibs map[string]bool
		var sourceScope map[string]string
		var sourceReport *sbomscan.Report
		if o.compare != "" {
			abs, aerr := filepath.Abs(o.compare)
			if aerr != nil {
				return fmt.Errorf("resolve --compare path: %w", aerr)
			}
			logger.Step(fmt.Sprintf("Cataloguing %s with cdxgen (compare)", abs))
			bom, cerr := cdxgen.GenerateFilesystemSBOM(ctx, abs, cdxgen.Options{
				ExtraArgs: o.cdxgenExtra,
				Bin:       o.cdxgenBin,
				Logger:    logger,
			})
			if cerr != nil {
				logger.Warn("compare: cdxgen failed: %v - APP/IMAGE attribution skipped", cerr)
			} else {
				sourceLibs = sbomscan.SourceLibSet(bom)
				sourceScope = sbomscan.SourceScopeMap(bom)
				logger.Step(fmt.Sprintf("Compare: %d source libraries to match against the image", len(sourceLibs)))
			}

			logger.Step(fmt.Sprintf("Reachability analysis on %s (compare)", abs))
			reach, err = reachability.Analyze(ctx, reachability.Options{
				Dir:            abs,
				GovulncheckBin: o.govulncheckBin,
				AtomBin:        o.atomBin,
				Logger:         logger,
			})
			if err != nil {
				logger.Warn("reachability analysis failed: %v - APP findings stay unmarked", err)
			}

			if len(bom) > 0 {
				logger.Step("Scanning application SBOM (compare, OSV)")
				sourceReport, err = sbomscan.ScanBOM(ctx, sbomscan.Options{
					BOMBytes:      bom,
					Source:        "compare:" + o.compare,
					Concurrency:   o.concurrency,
					Logger:        logger,
					TrivyDBSkip:   o.trivyDBSkip,
					TrivyDBMirror: o.trivyDBMirror,
					Reachability:  reach,
				})
				if err != nil {
					logger.Warn("compare: source SBOM scan failed: %v - image findings only", err)
					sourceReport = nil
				}
			}
		}

		report, err = sbomscan.ScanImage(ctx, sbomscan.ImageOptions{
			Image:          o.image,
			Platform:       o.platform,
			Source:         "image:" + o.image,
			Concurrency:    o.concurrency,
			Logger:         logger,
			TrivyBin:       o.trivyBin,
			TrivyExtraArgs: o.trivyExtra,
			SaveSBOM:       o.saveSBOM,
			Scout:          o.scout,
			Reachability:   reach,
			SourceLibs:     sourceLibs,
			SourceScope:    sourceScope,
		})
		if err != nil {
			return fmt.Errorf("scan image: %w", err)
		}

		if sourceReport != nil {
			sbomscan.MergeSourceVulns(report, sourceReport, reach)
		}
	} else {

		var source string
		bomBytes, source, err = obtainSBOM(ctx, logger, o)
		if err != nil {
			return fmt.Errorf("obtain sbom: %w", err)
		}

		var reach *reachability.Result
		if o.reachable != "" {
			logger.Step(fmt.Sprintf("Reachability analysis on %s", o.reachable))
			reach, err = reachability.Analyze(ctx, reachability.Options{
				Dir:            o.reachable,
				GovulncheckBin: o.govulncheckBin,
				AtomBin:        o.atomBin,
				Logger:         logger,
			})
			if err != nil {
				logger.Warn("reachability analysis failed: %v - findings stay unmarked", err)
			}
		}

		report, err = sbomscan.ScanBOM(ctx, sbomscan.Options{
			BOMBytes:      bomBytes,
			Source:        source,
			Concurrency:   o.concurrency,
			Logger:        logger,
			TrivyDBSkip:   o.trivyDBSkip,
			TrivyDBMirror: o.trivyDBMirror,
			Reachability:  reach,
		})
		if err != nil {
			return fmt.Errorf("scan: %w", err)
		}
	}

	if err := writeReport(o, report); err != nil {
		return fmt.Errorf("write report: %w", err)
	}

	if o.server != "" {
		if len(bomBytes) == 0 {
			logger.Warn("server upload skipped: trivy image mode produces no CycloneDX SBOM to upload")
		} else {
			logger.Step(fmt.Sprintf("Uploading SBOM to %s (project=%s)", o.server, o.project))
			if err := upload.SendBOM(ctx, upload.Params{
				ServerURL:   o.server,
				Token:       o.token,
				ProjectName: o.project,
				BOMBytes:    bomBytes,
				Logger:      logger,
			}); err != nil {
				logger.Warn("upload failed: %v", err)
			}
		}
	}

	if exit := evalFailOn(o.failOn, report); exit != 0 {
		return &exitError{code: exit, msg: fmt.Sprintf("findings exceed --fail-on=%s threshold", o.failOn)}
	}
	return nil
}

func obtainSBOM(ctx context.Context, log output.Logger, o *scanOpts) ([]byte, string, error) {
	switch {
	case o.path != "":
		b, err := obtainDirSBOM(ctx, log, o, o.path)
		return b, "fs:" + o.path, err
	case o.reachable != "":

		b, err := obtainDirSBOM(ctx, log, o, o.reachable)
		return b, "src:" + o.reachable, err
	case o.bom != "":
		log.Step(fmt.Sprintf("Reading SBOM from %s", o.bom))
		b, err := os.ReadFile(o.bom)
		return b, "sbom:" + o.bom, err
	case o.purl != "":
		log.Step(fmt.Sprintf("Scanning single PURL %s", o.purl))
		b, err := sbomscan.SyntheticSBOMFromPURL(o.purl)
		return b, "purl:" + o.purl, err
	}
	return nil, "", errors.New("no input mode set (validate() bug)")
}

func obtainDirSBOM(ctx context.Context, log output.Logger, o *scanOpts, dir string) ([]byte, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("resolve path: %w", err)
	}
	st, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", abs, err)
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("%s is not a directory; --bom takes a file, --purl takes a single package, --reachable and a positional path must be a project root", abs)
	}
	log.Step(fmt.Sprintf("Cataloguing %s with cdxgen", abs))
	bom, err := cdxgen.GenerateFilesystemSBOM(ctx, abs, cdxgen.Options{
		Deep:         o.deep,
		RequiredOnly: o.requiredOnly,
		ExtraArgs:    o.cdxgenExtra,
		Bin:          o.cdxgenBin,
		SaveTo:       o.saveSBOM,
		Logger:       log,
	})
	if err != nil {
		return nil, err
	}
	return bom, nil
}

func writeReport(o *scanOpts, report *sbomscan.Report) error {
	var renderer output.Renderer
	switch strings.ToLower(o.format) {
	case "json":
		renderer = output.JSON{}
	case "sarif":
		renderer = output.SARIF{}
	default:
		renderer = output.Table{NoColor: o.outFile != ""}
	}
	if o.outFile != "" {
		f, err := os.Create(o.outFile)
		if err != nil {
			return err
		}
		defer f.Close()
		return renderer.Render(f, report)
	}
	return renderer.Render(os.Stdout, report)
}
