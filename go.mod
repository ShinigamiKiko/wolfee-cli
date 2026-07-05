module sca-go/cli

go 1.25.0

// The CLI hits OSV.dev / CISA KEV / first.org EPSS / nomi-sec
// PoC-in-GitHub / NVD / Debian security tracker directly over HTTP.
// Image scanning (--image) shells out to the trivy binary for
// detection + severity; the other input modes use the OSV pipeline.

require (
	deps.dev/util/semver v0.0.0-20260617025149-7d3577045631
	github.com/knqyf263/go-deb-version v0.0.0-20241115132648-6f4aee6ccd23
	go.etcd.io/bbolt v1.3.11
)

require (
	github.com/stretchr/testify v1.10.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.43.0 // indirect
)
