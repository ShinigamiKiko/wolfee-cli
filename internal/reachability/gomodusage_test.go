package reachability

import (
	"strings"
	"testing"
)

const goListSample = `
{"ImportPath":"fmt"}
{"ImportPath":"example.com/app","Module":{"Path":"example.com/app"}}
{"ImportPath":"github.com/jackc/pgx/v5/pgxpool","Module":{"Path":"github.com/jackc/pgx/v5"}}
{"ImportPath":"github.com/jackc/pgx/v5/pgconn","Module":{"Path":"github.com/jackc/pgx/v5"}}
`

func TestParseGoList(t *testing.T) {
	mods, _, err := parseGoList(strings.NewReader(goListSample))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !mods["github.com/jackc/pgx/v5"] {
		t.Errorf("pgx module not detected: %v", mods)
	}
	if mods["fmt"] {
		t.Errorf("stdlib must not be recorded as a module")
	}
	if len(mods) != 2 {
		t.Errorf("module count = %d; want 2 (app + pgx)", len(mods))
	}
}

func TestPackageUsage(t *testing.T) {

	r := &Result{}
	if got := r.PackageUsage("github.com/jackc/pgx/v5"); got != StateUnknown {
		t.Errorf("no usage data: got %q, want unknown", got)
	}

	r = &Result{HaveModuleUsage: true, Modules: map[string]bool{"github.com/jackc/pgx/v5": true}}
	if got := r.PackageUsage("github.com/jackc/pgx/v5"); got != StateInUse {
		t.Errorf("imported module: got %q, want in-use", got)
	}
	if got := r.PackageUsage("example.com/unused"); got != StateDead {
		t.Errorf("absent module: got %q, want dead", got)
	}

	if got := r.PackageUsage(""); got != StateUnknown {
		t.Errorf("empty path: got %q, want unknown (not applicable)", got)
	}
}
