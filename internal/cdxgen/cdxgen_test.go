package cdxgen

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func fakeBin(t *testing.T, dumpArgvTo string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake-bin trick uses /bin/sh; run on Unix")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "cdxgen")
	script := `#!/bin/sh
# Capture every argument verbatim, one per line, so tests can grep.
{
  for a in "$@"; do echo "$a"; done
} > "` + dumpArgvTo + `"

# Find the value passed to -o and emit a tiny SBOM there.
out=""
prev=""
for a in "$@"; do
  if [ "$prev" = "-o" ]; then out="$a"; fi
  prev="$a"
done
if [ -n "$out" ]; then
  cat > "$out" <<'EOF'
{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
  {"name":"lodash","version":"4.17.21","purl":"pkg:npm/lodash@4.17.21"}
]}
EOF
fi
exit 0
`
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestGenerateImageSBOM_PassesExpectedArgs(t *testing.T) {
	argvDump := filepath.Join(t.TempDir(), "argv")
	bin := fakeBin(t, argvDump)

	bom, err := GenerateImageSBOM(context.Background(), Options{
		Image:        "nginx:1.27",
		Deep:         true,
		RequiredOnly: false,
		ExtraArgs:    []string{"--profile=research"},
		Bin:          bin,
	})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if !strings.Contains(string(bom), "lodash") {
		t.Error("expected lodash in returned SBOM")
	}

	argv, err := os.ReadFile(argvDump)
	if err != nil {
		t.Fatal(err)
	}
	args := string(argv)
	for _, want := range []string{"-t", "docker", "--spec-version", "1.6", "--deep", "--profile=research", "nginx:1.27"} {
		if !strings.Contains(args, want+"\n") {
			t.Errorf("expected %q in cdxgen argv, got:\n%s", want, args)
		}
	}
	if strings.Contains(args, "--required-only\n") {
		t.Error("--required-only was set false but ended up in argv")
	}
}

func TestGenerateImageSBOM_RejectsEmptyImage(t *testing.T) {
	if _, err := GenerateImageSBOM(context.Background(), Options{Bin: "/bin/false"}); err == nil {
		t.Fatal("expected error for empty image")
	}
}

func TestGenerateImageSBOM_PropagatesNonZeroExit(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "cdxgen")

	_ = os.WriteFile(bin, []byte("#!/bin/sh\nexit 17\n"), 0o755)
	if runtime.GOOS == "windows" {
		t.Skip("fake-bin trick uses /bin/sh")
	}

	_, err := GenerateImageSBOM(context.Background(), Options{
		Image: "nginx:1.27", Bin: bin,
	})
	if err == nil {
		t.Fatal("expected non-nil error when cdxgen exits non-zero")
	}
}

func TestGenerateImageSBOM_SaveTo(t *testing.T) {
	argvDump := filepath.Join(t.TempDir(), "argv")
	bin := fakeBin(t, argvDump)
	saveTo := filepath.Join(t.TempDir(), "saved.json")

	if _, err := GenerateImageSBOM(context.Background(), Options{
		Image: "nginx", Bin: bin, SaveTo: saveTo,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(saveTo); err != nil {
		t.Errorf("SaveTo file not created: %v", err)
	}
}
