package reachability

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"sca-go/cli/internal/output"
)

type goListPkg struct {
	Module *struct {
		Path string `json:"Path"`
		Main bool   `json:"Main"`
	} `json:"Module"`
}

func goModulesInUse(ctx context.Context, dir string, log output.Logger) (map[string]bool, error) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		return nil, errors.New("go toolchain not found on PATH - module-usage (in-use/dead) skipped")
	}

	tmp, err := os.CreateTemp("", "wolfee-golist-*.json")
	if err != nil {
		return nil, fmt.Errorf("tempfile: %w", err)
	}
	tmp.Close()
	defer os.Remove(tmp.Name())

	out, err := os.Create(tmp.Name())
	if err != nil {
		return nil, fmt.Errorf("open scratch: %w", err)
	}

	cmd := exec.CommandContext(ctx, goBin, "list", "-deps", "-json", "./...")
	cmd.Dir = dir
	cmd.Stdout = out
	if log != nil {
		lw := output.LineWriter(log.Debug, "[go list] ")
		defer lw.Close()
		cmd.Stderr = lw
	} else {
		cmd.Stderr = os.Stderr
	}
	if runErr := cmd.Run(); runErr != nil {

		out.Close()
		return nil, fmt.Errorf("go list: %w", runErr)
	}
	out.Close()

	f, err := os.Open(tmp.Name())
	if err != nil {
		return nil, fmt.Errorf("read output: %w", err)
	}
	defer f.Close()
	mods, _, err := parseGoList(f)
	return mods, err
}

func parseGoList(r io.Reader) (mods map[string]bool, mainMod string, err error) {
	mods = map[string]bool{}
	dec := json.NewDecoder(r)
	for {
		var p goListPkg
		if decErr := dec.Decode(&p); decErr != nil {
			if errors.Is(decErr, io.EOF) {
				break
			}
			return nil, "", fmt.Errorf("decode go list json: %w", decErr)
		}
		if p.Module != nil {
			if path := strings.TrimSpace(p.Module.Path); path != "" {
				mods[path] = true
				if p.Module.Main && mainMod == "" {
					mainMod = path
				}
			}
		}
	}
	return mods, mainMod, nil
}

func goPackageUsage(ctx context.Context, dir string, o Options, res *Result) {
	mods, err := goModulesInUse(ctx, dir, o.Logger)
	if err != nil {
		if o.Logger != nil {
			o.Logger.Warn("reachability(go): module-usage probe failed: %v - in-use/dead unavailable", err)
		}
		return
	}
	res.Modules = mods
	res.HaveModuleUsage = true

	if goBin, lookErr := exec.LookPath("go"); lookErr == nil {
		listM := exec.CommandContext(ctx, goBin, "list", "-m")
		listM.Dir = dir
		if out, runErr := listM.CombinedOutput(); runErr == nil {
			if m := strings.TrimSpace(string(out)); m != "" {
				res.MainModule = m
			}
		}
	}
	if o.Logger != nil {
		o.Logger.Step(fmt.Sprintf("Reachability(go): module-usage - %d modules imported by the build", len(mods)))
	}

	sites, lines := scanGoImports(dir, mods)
	if len(sites) == 0 {
		return
	}
	if res.GoImportSites == nil {
		res.GoImportSites = map[string]string{}
	}
	if res.GoImportLines == nil {
		res.GoImportLines = map[string]string{}
	}
	for mod, site := range sites {
		res.GoImportSites[mod] = site
		res.GoImportLines[mod] = lines[mod]
	}
}

func scanGoImports(projectDir string, modules map[string]bool) (sites, lines map[string]string) {
	sites = map[string]string{}
	lines = map[string]string{}
	fset := token.NewFileSet()

	_ = filepath.WalkDir(projectDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if name == "vendor" || name == "testdata" || name == ".git" ||
				strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, parseErr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if parseErr != nil {
			return nil
		}
		rel, _ := filepath.Rel(projectDir, path)
		for _, imp := range f.Imports {

			importPath := strings.Trim(imp.Path.Value, `"`)
			mod := longestModuleMatch(importPath, modules)
			if mod == "" || sites[mod] != "" {
				continue
			}
			pos := fset.Position(imp.Path.Pos())
			sites[mod] = fmt.Sprintf("%s:%d", rel, pos.Line)

			if imp.Name != nil {
				lines[mod] = fmt.Sprintf("import %s %s", imp.Name.Name, imp.Path.Value)
			} else {
				lines[mod] = fmt.Sprintf("import %s", imp.Path.Value)
			}
		}
		return nil
	})
	if len(sites) == 0 {
		return nil, nil
	}
	return sites, lines
}

func longestModuleMatch(importPath string, modules map[string]bool) string {
	best := ""
	for mod := range modules {
		if len(mod) <= len(best) {
			continue
		}
		if importPath == mod || strings.HasPrefix(importPath, mod+"/") {
			best = mod
		}
	}
	return best
}
