package cdxgen

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"sca-go/cli/internal/output"
)

type Options struct {
	Image        string
	Deep         bool
	RequiredOnly bool
	ExtraArgs    []string

	Bin string

	SaveTo string

	Logger output.Logger
}

func GenerateFilesystemSBOM(ctx context.Context, dir string, o Options) ([]byte, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("cdxgen: empty directory")
	}
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("cdxgen: not a directory: %s", dir)
	}

	bin, err := resolveBin(o.Bin)
	if err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp("", "wolfee-sbom-*.json")
	if err != nil {
		return nil, fmt.Errorf("cdxgen: tempfile: %w", err)
	}
	tmp.Close()
	defer os.Remove(tmp.Name())

	args := []string{
		"-o", tmp.Name(),
		"--spec-version", "1.6",
		"--no-banner",
	}
	if o.Deep {
		args = append(args, "--deep")
	}
	if o.RequiredOnly {
		args = append(args, "--required-only")
	}
	args = append(args, o.ExtraArgs...)
	args = append(args, dir)

	if o.Logger != nil {
		o.Logger.Debug("cdxgen invocation: %s %s", bin, strings.Join(args, " "))
	}

	cmd := exec.CommandContext(ctx, bin, args...)
	if o.Logger != nil {
		lw := output.LineWriter(o.Logger.Debug, "[cdxgen] ")
		defer lw.Close()
		cmd.Stderr = lw
	} else {
		cmd.Stderr = os.Stderr
	}
	cmd.Stdout = nil

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("cdxgen run: %w (dir=%s)", err, dir)
	}
	bom, err := os.ReadFile(tmp.Name())
	if err != nil {
		return nil, fmt.Errorf("cdxgen: read sbom: %w", err)
	}
	if len(bom) == 0 {
		return nil, errors.New("cdxgen produced an empty SBOM - check directory contents and cdxgen logs")
	}
	if o.SaveTo != "" {
		if err := saveCopy(o.SaveTo, bom); err != nil && o.Logger != nil {
			o.Logger.Warn("could not save SBOM to %s: %v", o.SaveTo, err)
		}
	}
	return bom, nil
}

func resolveBin(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	path, err := exec.LookPath("cdxgen")
	if err != nil {
		return "", fmt.Errorf("cdxgen not found on PATH - install it with 'npm i -g @cyclonedx/cdxgen' or pass --cdxgen-bin")
	}
	return path, nil
}

func GenerateImageSBOM(ctx context.Context, o Options) ([]byte, error) {
	if strings.TrimSpace(o.Image) == "" {
		return nil, errors.New("cdxgen: empty image reference")
	}

	bin := o.Bin
	if bin == "" {

		path, err := exec.LookPath("cdxgen")
		if err != nil {
			return nil, fmt.Errorf("cdxgen not found on PATH - install it with 'npm i -g @cyclonedx/cdxgen' or pass --cdxgen-bin")
		}
		bin = path
	}

	tmp, err := os.CreateTemp("", "wolfee-sbom-*.json")
	if err != nil {
		return nil, fmt.Errorf("cdxgen: tempfile: %w", err)
	}
	tmp.Close()

	defer os.Remove(tmp.Name())

	args := []string{
		"-t", "docker",
		"-o", tmp.Name(),
		"--spec-version", "1.6",

		"--no-banner",
	}
	if o.Deep {
		args = append(args, "--deep")
	}
	if o.RequiredOnly {
		args = append(args, "--required-only")
	}
	args = append(args, o.ExtraArgs...)
	args = append(args, o.Image)

	if o.Logger != nil {
		o.Logger.Debug("cdxgen invocation: %s %s", bin, strings.Join(args, " "))
	}

	cmd := exec.CommandContext(ctx, bin, args...)

	if o.Logger != nil {
		cmd.Stderr = output.LineWriter(o.Logger.Debug, "[cdxgen] ")
	} else {
		cmd.Stderr = os.Stderr
	}
	cmd.Stdout = nil

	if err := cmd.Run(); err != nil {

		return nil, fmt.Errorf("cdxgen run: %w (image=%s)", err, o.Image)
	}

	bom, err := os.ReadFile(tmp.Name())
	if err != nil {
		return nil, fmt.Errorf("cdxgen: read sbom: %w", err)
	}
	if len(bom) == 0 {
		return nil, errors.New("cdxgen produced an empty SBOM - check image reference and cdxgen logs")
	}

	if o.SaveTo != "" {

		if err := saveCopy(o.SaveTo, bom); err != nil && o.Logger != nil {
			o.Logger.Warn("could not save SBOM to %s: %v", o.SaveTo, err)
		}
	}
	return bom, nil
}

func saveCopy(dst string, data []byte) error {
	if dir := filepath.Dir(dst); dir != "" {
		_ = os.MkdirAll(dir, 0o755)
	}
	return os.WriteFile(dst, data, 0o644)
}
