package trivy

import (
	"encoding/json"
	"slices"
	"testing"
)

func TestMetadata_ParsesImageConfigAndDiffIDs(t *testing.T) {
	const raw = `{
	  "SchemaVersion": 2,
	  "ArtifactName": "my-app:latest",
	  "Metadata": {
	    "OS": {"Family": "debian", "Name": "12.5"},
	    "ImageID": "sha256:img",
	    "DiffIDs": ["sha256:base0", "sha256:base1", "sha256:app0"],
	    "ImageConfig": {
	      "architecture": "amd64",
	      "config": {
	        "Labels": {
	          "org.opencontainers.image.base.name": "debian:bookworm-slim",
	          "org.opencontainers.image.base.digest": "sha256:deadbeef"
	        }
	      },
	      "rootfs": {
	        "type": "layers",
	        "diff_ids": ["sha256:base0", "sha256:base1", "sha256:app0"]
	      },
	      "history": [
	        {"created_by": "/bin/sh -c #(nop) ADD file:... in / ", "empty_layer": false},
	        {"created_by": "RUN apt-get install -y curl", "empty_layer": false},
	        {"created_by": "ENV PATH=/usr/bin", "empty_layer": true},
	        {"created_by": "COPY app /app", "empty_layer": false}
	      ]
	    }
	  }
	}`

	var rep Report
	if err := json.Unmarshal([]byte(raw), &rep); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	wantDiff := []string{"sha256:base0", "sha256:base1", "sha256:app0"}
	if !slices.Equal(rep.Metadata.DiffIDs, wantDiff) {
		t.Errorf("DiffIDs = %v, want %v", rep.Metadata.DiffIDs, wantDiff)
	}
	if !slices.Equal(rep.Metadata.DiffIDOrder(), wantDiff) {
		t.Errorf("DiffIDOrder() = %v, want %v", rep.Metadata.DiffIDOrder(), wantDiff)
	}
	if !slices.Equal(rep.Metadata.ImageConfig.RootFS.DiffIDs, wantDiff) {
		t.Errorf("rootfs.diff_ids = %v, want %v", rep.Metadata.ImageConfig.RootFS.DiffIDs, wantDiff)
	}
	labels := rep.Metadata.ImageConfig.Config.Labels
	if labels["org.opencontainers.image.base.name"] != "debian:bookworm-slim" {
		t.Errorf("base.name label = %q", labels["org.opencontainers.image.base.name"])
	}
	if labels["org.opencontainers.image.base.digest"] != "sha256:deadbeef" {
		t.Errorf("base.digest label = %q", labels["org.opencontainers.image.base.digest"])
	}

	cb := rep.Metadata.LayerCreatedBy()
	if got := cb["sha256:base1"]; got != "RUN apt-get install -y curl" {
		t.Errorf("createdBy[base1] = %q", got)
	}
	if got := cb["sha256:app0"]; got != "COPY app /app" {
		t.Errorf("createdBy[app0] = %q (empty_layer entry not skipped?)", got)
	}
}

func TestMetadata_DiffIDOrderFallsBackToRootFS(t *testing.T) {
	m := Metadata{ImageConfig: ImageConfig{RootFS: RootFS{DiffIDs: []string{"sha256:a", "sha256:b"}}}}
	if got := m.DiffIDOrder(); !slices.Equal(got, []string{"sha256:a", "sha256:b"}) {
		t.Errorf("DiffIDOrder() = %v, want rootfs fallback", got)
	}
}

func TestCommonArgs_ExtraArgsBeforeImage(t *testing.T) {
	o := Options{
		Image:     "php:7.0",
		Platform:  "linux/arm64",
		ExtraArgs: []string{"--offline-scan", "--db-repository=mirror.corp/trivy-db"},
	}
	got := o.commonArgs()
	want := []string{
		"--platform", "linux/arm64",
		"--offline-scan", "--db-repository=mirror.corp/trivy-db",
		"php:7.0",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("commonArgs() = %v, want %v", got, want)
	}
	if got[len(got)-1] != "php:7.0" {
		t.Errorf("image must be the last arg, got %q", got[len(got)-1])
	}
}

func TestCommonArgs_NoPlatformNoExtras(t *testing.T) {
	got := Options{Image: "nginx:latest"}.commonArgs()
	if !slices.Equal(got, []string{"nginx:latest"}) {
		t.Fatalf("commonArgs() = %v, want [nginx:latest]", got)
	}
}
