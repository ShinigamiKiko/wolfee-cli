package reachability

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type npmPkgLock struct {
	LockfileVersion int                     `json:"lockfileVersion"`
	Packages        map[string]npmLockPkg   `json:"packages"`
	Dependencies    map[string]npmLockDepV1 `json:"dependencies"`
}

type npmLockPkg struct {
	Dependencies     map[string]string `json:"dependencies"`
	PeerDependencies map[string]string `json:"peerDependencies"`
}

type npmLockDepV1 struct {
	Dependencies map[string]npmLockDepV1 `json:"dependencies"`
}

func buildNPMTransitivePURLs(dir string, directPURLs map[string]bool) map[string]bool {
	f, err := os.Open(filepath.Join(dir, "package-lock.json"))
	if err != nil {
		return nil
	}

	data, err := io.ReadAll(io.LimitReader(f, 32<<20))
	f.Close()
	if err != nil {
		return nil
	}
	var lock npmPkgLock
	if json.Unmarshal(data, &lock) != nil {
		return nil
	}

	adj := map[string][]string{}
	if lock.LockfileVersion >= 2 && lock.Packages != nil {
		for key, pkg := range lock.Packages {
			name := npmLockKeyToName(key)
			if name == "" {
				continue
			}
			for dep := range pkg.Dependencies {
				adj[name] = append(adj[name], dep)
			}
			for dep := range pkg.PeerDependencies {
				adj[name] = append(adj[name], dep)
			}
		}
	} else if lock.Dependencies != nil {
		buildAdjV1(lock.Dependencies, adj)
	} else {
		return nil
	}

	queue := make([]string, 0, len(directPURLs))
	visited := map[string]bool{}
	for purlKey := range directPURLs {
		name := purlKeyToNPMName(purlKey)
		if name != "" && !visited[name] {
			visited[name] = true
			queue = append(queue, name)
		}
	}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, dep := range adj[cur] {
			if !visited[dep] {
				visited[dep] = true
				queue = append(queue, dep)
			}
		}
	}

	result := map[string]bool{}
	for name := range visited {
		purlKey := npmSpecToPURLKey(name)
		if purlKey == "" || directPURLs[purlKey] {
			continue
		}
		result[purlKey] = true
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func npmLockKeyToName(key string) string {
	if key == "" {
		return ""
	}
	const prefix = "node_modules/"

	if idx := strings.LastIndex(key, prefix); idx >= 0 {
		return key[idx+len(prefix):]
	}
	return ""
}

func buildAdjV1(deps map[string]npmLockDepV1, adj map[string][]string) {
	for name, dep := range deps {
		for child := range dep.Dependencies {
			adj[name] = append(adj[name], child)
		}
		if dep.Dependencies != nil {
			buildAdjV1(dep.Dependencies, adj)
		}
	}
}

func purlKeyToNPMName(purlKey string) string {
	name, ok := strings.CutPrefix(purlKey, "pkg:npm/")
	if !ok {
		return ""
	}
	if strings.HasPrefix(name, "%40") {
		name = "@" + name[3:]
	}
	return name
}
