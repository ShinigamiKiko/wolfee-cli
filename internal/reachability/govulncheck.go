package reachability

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"sca-go/cli/internal/onlinescan"
	"sca-go/cli/internal/output"
)

type gvkMessage struct {
	Config  *gvkConfig  `json:"config,omitempty"`
	OSV     *gvkOSV     `json:"osv,omitempty"`
	Finding *gvkFinding `json:"finding,omitempty"`
}

type gvkConfig struct {
	GoVersion string `json:"go_version"`
}

type gvkOSV struct {
	ID               string             `json:"id"`
	Aliases          []string           `json:"aliases,omitempty"`
	Affected         []gvkAffected      `json:"affected,omitempty"`
	Severity         []gvkSeverityEntry `json:"severity,omitempty"`
	DatabaseSpecific map[string]any     `json:"database_specific,omitempty"`
}

type gvkSeverityEntry struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type gvkAffected struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
}

type gvkFinding struct {
	OSV   string     `json:"osv"`
	Trace []gvkFrame `json:"trace,omitempty"`
}

type gvkPosition struct {
	Filename string `json:"filename,omitempty"`
	Line     int    `json:"line,omitempty"`
}

type gvkFrame struct {
	Module   string       `json:"module,omitempty"`
	Package  string       `json:"package,omitempty"`
	Function string       `json:"function,omitempty"`
	Position *gvkPosition `json:"position,omitempty"`
}

func findGoModDirs(root string) []string {
	var dirs []string
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		name := d.Name()
		if name == "vendor" || name == ".git" || (strings.HasPrefix(name, ".") && path != root) {
			return filepath.SkipDir
		}
		if _, statErr := os.Stat(filepath.Join(path, "go.mod")); statErr == nil {
			dirs = append(dirs, path)
			if path != root {

				return filepath.SkipDir
			}
		}
		return nil
	})
	return dirs
}

func goReachability(ctx context.Context, o Options, res *Result) error {
	dir, err := filepath.Abs(o.Dir)
	if err != nil {
		return fmt.Errorf("resolve dir: %w", err)
	}
	modDirs := findGoModDirs(dir)
	if len(modDirs) == 0 {
		if o.Logger != nil {
			o.Logger.Warn("reachability(go): no go.mod found under %s - govulncheck skipped", dir)
		}
		return nil
	}
	for _, modDir := range modDirs {

		goPackageUsage(ctx, modDir, o, res)
		if err := runGovulncheck(ctx, modDir, o, res); err != nil {
			if o.Logger != nil {
				rel, _ := filepath.Rel(dir, modDir)
				o.Logger.Warn("reachability(go): %v (module at %s)", err, rel)
			}
		}
	}
	return nil
}

func runGovulncheck(ctx context.Context, dir string, o Options, res *Result) error {
	bin := o.GovulncheckBin
	if bin == "" {
		p, lookErr := exec.LookPath("govulncheck")
		if lookErr != nil {
			return errors.New("govulncheck not found on PATH - install it with 'go install golang.org/x/vuln/cmd/govulncheck@latest' or pass --govulncheck-bin")
		}
		bin = p
	}

	tmp, err := os.CreateTemp("", "wolfee-gvk-*.json")
	if err != nil {
		return fmt.Errorf("tempfile: %w", err)
	}
	tmp.Close()
	defer os.Remove(tmp.Name())

	out, err := os.Create(tmp.Name())
	if err != nil {
		return fmt.Errorf("open scratch: %w", err)
	}

	args := []string{"-json", "./..."}
	if o.Logger != nil {
		o.Logger.Debug("govulncheck invocation: %s %s (dir=%s)", bin, strings.Join(args, " "), dir)
	}

	tail := &tailWriter{max: 8 << 10}
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir
	cmd.Stdout = out
	if o.Logger != nil {
		lw := output.LineWriter(o.Logger.Debug, "[govulncheck] ")
		defer lw.Close()
		cmd.Stderr = io.MultiWriter(lw, tail)
	} else {
		cmd.Stderr = io.MultiWriter(os.Stderr, tail)
	}

	runErr := cmd.Run()
	out.Close()
	if runErr != nil {

		var ee *exec.ExitError
		if !errors.As(runErr, &ee) {
			return fmt.Errorf("run: %w", runErr)
		}
		if code := ee.ExitCode(); code != 0 && code != 3 {
			if detail := lastLines(tail.String(), 4); detail != "" {
				return fmt.Errorf("govulncheck exited %d: %s", code, detail)
			}
			return fmt.Errorf("govulncheck exited %d (run with --debug for full output)", code)
		}
	}

	f, err := os.Open(tmp.Name())
	if err != nil {
		return fmt.Errorf("read output: %w", err)
	}
	defer f.Close()

	nReach, nUnreach, err := parseGovulncheck(f, dir, res, o)
	if err != nil {
		return err
	}
	if o.Logger != nil {
		o.Logger.Step(fmt.Sprintf("Reachability(go): govulncheck - %d called, %d imported-but-not-called", nReach, nUnreach))
		for id, mod := range res.CalledModules {
			o.Logger.Debug("govulncheck called: %s in module %s", id, mod)
		}
	}
	return nil
}

func parseGovulncheck(r io.Reader, dir string, res *Result, o Options) (reachable, unreachable int, err error) {
	aliases := map[string][]string{}
	called := map[string]bool{}
	seen := map[string]bool{}
	callSites := map[string]string{}
	callLines := map[string]string{}
	calledMod := map[string]string{}
	osvModules := map[string][]string{}
	severity := map[string]string{}

	dec := json.NewDecoder(r)
	for {
		var m gvkMessage
		if decErr := dec.Decode(&m); decErr != nil {
			if errors.Is(decErr, io.EOF) {
				break
			}
			return 0, 0, fmt.Errorf("decode govulncheck json: %w", decErr)
		}
		switch {
		case m.Config != nil && m.Config.GoVersion != "" && res.GoVersion == "":
			res.GoVersion = m.Config.GoVersion
		case m.OSV != nil && m.OSV.ID != "":
			aliases[m.OSV.ID] = m.OSV.Aliases
			for _, a := range m.OSV.Affected {
				if strings.EqualFold(a.Package.Ecosystem, "Go") && a.Package.Name != "" {
					osvModules[m.OSV.ID] = append(osvModules[m.OSV.ID], a.Package.Name)
				}
			}
			if sev := gvkExtractSeverity(m.OSV); sev != "" {
				severity[m.OSV.ID] = sev
			}
		case m.Finding != nil && m.Finding.OSV != "":
			id := m.Finding.OSV
			seen[id] = true
			if len(m.Finding.Trace) > 0 && m.Finding.Trace[0].Function != "" {
				called[id] = true

				if calledMod[id] == "" {
					for _, fr := range m.Finding.Trace {
						if o.Logger != nil {
							o.Logger.Debug("govulncheck trace frame: id=%s module=%q package=%q function=%q", id, fr.Module, fr.Package, fr.Function)
						}
						if fr.Module != "" {
							calledMod[id] = fr.Module
							break
						}
						if fr.Package != "" && len(res.Modules) > 0 {
							if mod := longestModuleMatch(fr.Package, res.Modules); mod != "" {
								calledMod[id] = mod
								break
							}
						}
					}
				}

				if _, exists := callSites[id]; !exists {
					for _, fr := range m.Finding.Trace {
						pos := fr.Position
						if pos == nil || pos.Filename == "" {
							continue
						}
						if fr.Module == "stdlib" {
							continue
						}
						if res.HaveModuleUsage && res.Modules[fr.Module] && fr.Module != res.MainModule {
							continue
						}
						callSites[id] = fmt.Sprintf("%s:%d", pos.Filename, pos.Line)
						callLines[id] = readFileLine(filepath.Join(dir, pos.Filename), pos.Line)
						break
					}
				}
			}
		}
	}

	for id := range seen {
		st := StateUnreachable
		if called[id] {
			st = StateReachable
			reachable++

			mod := calledMod[id]
			if len(osvModules[id]) > 0 {
				mod = osvModules[id][0]
			}
			if mod != "" {
				if res.CalledModules == nil {
					res.CalledModules = map[string]string{}
				}
				res.CalledModules[id] = mod
			}
			if als := aliases[id]; len(als) > 0 {
				if res.GOAliases == nil {
					res.GOAliases = map[string][]string{}
				}
				res.GOAliases[id] = als
			}
			if s := callSites[id]; s != "" {
				if res.CallSites == nil {
					res.CallSites = map[string]string{}
				}
				if res.CallLines == nil {
					res.CallLines = map[string]string{}
				}
				res.CallSites[id] = s
				res.CallLines[id] = callLines[id]
				for _, a := range aliases[id] {
					nid := normID(a)
					if res.CallSites[nid] == "" {
						res.CallSites[nid] = s
						res.CallLines[nid] = callLines[id]
					}
				}
			}
		} else {
			unreachable++
		}
		res.set(id, st)
		for _, a := range aliases[id] {
			res.set(a, st)
		}
	}

	for id, sev := range severity {
		if res.GOSeverity == nil {
			res.GOSeverity = map[string]string{}
		}
		res.GOSeverity[id] = sev
	}
	return reachable, unreachable, nil
}

func gvkExtractSeverity(osv *gvkOSV) string {
	if osv == nil {
		return ""
	}
	if ds := osv.DatabaseSpecific; ds != nil {
		if s, ok := ds["severity"].(string); ok {
			if norm := normGVKSev(s); norm != "" {
				return norm
			}
		}
	}
	for _, sv := range osv.Severity {
		score, _ := onlinescan.ScoreCVSSVector(sv.Score)
		if sev := onlinescan.SeverityFromScore(score); sev != "" {
			return sev
		}
	}
	return ""
}

func normGVKSev(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return "CRITICAL"
	case "HIGH":
		return "HIGH"
	case "MEDIUM", "MODERATE":
		return "MEDIUM"
	case "LOW":
		return "LOW"
	}
	return ""
}

func readFileLine(filename string, n int) string {
	if n <= 0 {
		return ""
	}
	f, err := os.Open(filename)
	if err != nil {
		return ""
	}
	data, err := io.ReadAll(io.LimitReader(f, 512<<10))
	f.Close()
	if err != nil {
		return ""
	}
	lines := strings.SplitN(string(data), "\n", n+1)
	if n > len(lines) {
		return ""
	}
	return strings.TrimSpace(lines[n-1])
}

func hasGoModule(dir string) bool {
	st, err := os.Stat(filepath.Join(dir, "go.mod"))
	return err == nil && !st.IsDir()
}

type tailWriter struct {
	max int
	buf []byte
}

func (t *tailWriter) Write(p []byte) (int, error) {
	t.buf = append(t.buf, p...)
	if len(t.buf) > t.max {
		t.buf = t.buf[len(t.buf)-t.max:]
	}
	return len(p), nil
}

func (t *tailWriter) String() string { return string(t.buf) }

func lastLines(s string, n int) string {
	var kept []string
	for _, ln := range strings.Split(s, "\n") {
		if ln = strings.TrimSpace(ln); ln != "" {
			kept = append(kept, ln)
		}
	}
	if len(kept) > n {
		kept = kept[len(kept)-n:]
	}
	return strings.Join(kept, " | ")
}
