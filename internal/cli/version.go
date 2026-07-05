package cli

import (
	"flag"
	"fmt"
	"runtime"

	"sca-go/cli/internal/sbomscan"
)

var (
	Version = "dev"
	Commit  = "unknown"
	Built   = "unknown"
)

func init() {
	sbomscan.SetWolfeeVersion(Version)
}

func runVersion(args []string) error {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	fmt.Printf("wolfee %s\n", Version)
	fmt.Printf("  commit:   %s\n", Commit)
	fmt.Printf("  built:    %s\n", Built)
	fmt.Printf("  go:       %s\n", runtime.Version())
	fmt.Printf("  platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	return nil
}
