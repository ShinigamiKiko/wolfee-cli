package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"sca-go/cli/internal/trivydb"
)

func main() {
	ctx := context.Background()
	dbPath, wasDownloaded, err := trivydb.EnsureDB(ctx, http.DefaultClient, "/tmp/trivydbcache", "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "EnsureDB: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("DB path: %s (downloaded=%v)\n", dbPath, wasDownloaded)
	r, err := trivydb.Open(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Open: %v\n", err)
		os.Exit(1)
	}
	defer r.Close()
	platforms, err := r.ListPlatforms()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ListPlatforms: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Total platforms: %d\n", len(platforms))
	for _, p := range platforms {
		fmt.Println(p)
	}

	fmt.Println("\n--- top-level buckets ---")
	buckets, err := r.ListTopBuckets()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ListTopBuckets: %v\n", err)
		os.Exit(1)
	}
	for _, b := range buckets {
		fmt.Println(b)
	}

	advs, err := r.Lookup("debian 9", "libsystemd0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Lookup error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("\n--- debian 9 / libsystemd0 advisories: %d ---\n", len(advs))
	for _, a := range advs {
		fmt.Printf("  %s status=%d fixed=%q\n", a.VulnerabilityID, a.Status, a.FixedVersion)
	}

	fmt.Println("\n--- first 20 packages in debian 9 ---")
	r.ListPackages("debian 9", 20, func(pkg string) {
		fmt.Println(" ", pkg)
	})

	for _, pkg := range []string{"systemd", "libsystemd0", "libudev1", "libsystemd0-dev", "tzdata"} {
		a2, _ := r.Lookup("debian 9", pkg)
		fmt.Printf("debian 9 / %s: %d advisories\n", pkg, len(a2))
	}
}
