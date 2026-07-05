package reachability

import (
	"context"

	"sca-go/cli/internal/output"
)

type Options struct {
	Dir string

	GovulncheckBin string

	AtomBin string

	Logger output.Logger
}

func Analyze(ctx context.Context, o Options) (*Result, error) {
	res := &Result{ByVuln: map[string]State{}}
	if o.Dir == "" {
		return res, nil
	}
	if langs := detectProjectLanguages(o.Dir); len(langs) > 0 {
		res.ProjectLanguages = langs
	}

	if err := goReachability(ctx, o, res); err != nil && o.Logger != nil {
		o.Logger.Warn("reachability(go): %v - Go findings stay unknown", err)
	}

	atomReachability(ctx, o, res)

	pkgImportUsage(ctx, o, res)
	return res, nil
}
