package reachability

import (
	"bytes"
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

	"sca-go/cli/internal/output"
)

type atomLang struct {
	lang      string
	ecosystem string
	manifests []string
}

var atomLangs = []atomLang{
	{"javascript", "npm", []string{"package.json"}},
	{"python", "pypi", []string{"requirements.txt", "pyproject.toml", "setup.py", "Pipfile", "poetry.lock"}},
	{"java", "maven", []string{"pom.xml", "build.gradle", "build.gradle.kts"}},
	{"php", "composer", []string{"composer.json"}},
}

type atomTarget struct {
	atomLang
	dir string
}

func atomReachability(ctx context.Context, o Options, res *Result) {
	dir, err := filepath.Abs(o.Dir)
	if err != nil {
		return
	}
	targets := detectAtomTargets(dir)
	if len(targets) == 0 {
		return
	}
	bin := o.AtomBin
	if bin == "" {
		p, lookErr := exec.LookPath("atom")
		if lookErr != nil {
			if o.Logger != nil {
				o.Logger.Warn("reachability: atom not found on PATH - js/python/java/php reachability skipped (npm i -g @appthreat/atom)")
			}
			return
		}
		bin = p
	}
	for _, t := range targets {
		n, err := runAtomReachables(ctx, bin, t.dir, t.atomLang, o, res)
		if err != nil {
			if o.Logger != nil {
				o.Logger.Warn("reachability(%s): atom failed: %v - %s findings stay unknown", t.lang, err, t.ecosystem)
			}
			continue
		}
		if res.AtomEcosystems == nil {
			res.AtomEcosystems = map[string]bool{}
		}
		res.AtomEcosystems[t.ecosystem] = true
		if o.Logger != nil {
			o.Logger.Step(fmt.Sprintf("Reachability(%s): atom - %d packages on a reachable flow", t.lang, n))
		}
	}
}

func detectAtomTargets(root string) []atomTarget {
	var out []atomTarget
	for _, al := range atomLangs {

		for _, m := range al.manifests {
			if st, err := os.Stat(filepath.Join(root, m)); err == nil && !st.IsDir() {
				out = append(out, atomTarget{atomLang: al, dir: root})
				goto nextLang
			}
		}

		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || !d.IsDir() || path == root {
				return nil
			}
			name := d.Name()
			if name == "node_modules" || name == "vendor" || name == ".git" ||
				strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			for _, m := range al.manifests {
				if st, statErr := os.Stat(filepath.Join(path, m)); statErr == nil && !st.IsDir() {
					out = append(out, atomTarget{atomLang: al, dir: path})
					return filepath.SkipAll
				}
			}
			return nil
		})
	nextLang:
	}
	return out
}

func runAtomReachables(ctx context.Context, bin, dir string, al atomLang, o Options, res *Result) (int, error) {
	tmp, err := os.CreateTemp("", "wolfee-atom-*.json")
	if err != nil {
		return 0, fmt.Errorf("tempfile: %w", err)
	}
	tmp.Close()
	defer os.Remove(tmp.Name())
	atomFile := tmp.Name() + ".atom"
	defer os.Remove(atomFile)

	args := []string{"reachables", "-l", al.lang, "-o", atomFile, "-s", tmp.Name(), dir}
	if o.Logger != nil {
		o.Logger.Debug("atom invocation: %s %s", bin, strings.Join(args, " "))
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir
	cmd.Stdout = nil

	var stderr bytes.Buffer
	capture := io.Writer(&stderr)
	if o.Logger != nil {
		lw := output.LineWriter(o.Logger.Debug, "[atom] ")
		defer lw.Close()
		capture = io.MultiWriter(&stderr, lw)
	}
	cmd.Stderr = capture
	runErr := cmd.Run()
	if msg := atomPreconditionFailure(stderr.String()); msg != "" {
		return 0, fmt.Errorf("%s", msg)
	}
	if runErr != nil {
		return 0, fmt.Errorf("run: %w", runErr)
	}

	f, err := os.Open(tmp.Name())
	if err != nil {
		return 0, fmt.Errorf("read slices: %w", err)
	}
	defer f.Close()
	return parseAtomReachables(f, al.ecosystem, res)
}

func atomPreconditionFailure(stderr string) string {
	s := strings.ToLower(stderr)
	switch {
	case strings.Contains(s, "jdk is not installed"),
		strings.Contains(s, "please install jdk"):
		return "atom needs a JDK 21+ on PATH but none was found - install it (the wolfee Docker image ships one)"
	case strings.Contains(s, "outofmemoryerror"):
		return "atom ran out of memory building the code graph - findings stay unknown"
	}
	return ""
}

func parseAtomReachables(r io.Reader, ecosystem string, res *Result) (int, error) {
	var doc any
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return 0, nil
		}
		return 0, fmt.Errorf("decode atom reachables: %w", err)
	}
	if res.AtomReachablePURLs == nil {
		res.AtomReachablePURLs = map[string]bool{}
	}
	seen := map[string]struct{}{}
	collectPURLs(doc, 0, func(p string) {
		key := purlNoVersion(p)
		if key == "" {
			return
		}
		res.AtomReachablePURLs[key] = true
		seen[key] = struct{}{}
	})
	return len(seen), nil
}

func collectPURLs(v any, depth int, emit func(string)) {
	if depth > 256 {
		return
	}
	switch t := v.(type) {
	case string:
		if strings.HasPrefix(t, "pkg:") {
			emit(t)
		}
	case []any:
		for _, e := range t {
			collectPURLs(e, depth+1, emit)
		}
	case map[string]any:
		for _, e := range t {
			collectPURLs(e, depth+1, emit)
		}
	}
}

func purlNoVersion(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	if i := strings.LastIndexByte(p, '@'); i >= 0 {
		p = p[:i]
	}
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	return strings.ToLower(p)
}
