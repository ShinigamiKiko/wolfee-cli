package sbomscan

import "strings"

func sanitizePath(s string) string {
	if s == "" {
		return s
	}

	if rest, ok := stripUserPrefix(s, "/mnt/c/Users/"); ok {
		return "~/" + rest
	}
	if rest, ok := stripUserPrefix(s, "/home/"); ok {
		return "~/" + rest
	}
	if rest, ok := stripUserPrefix(s, "/Users/"); ok {
		return "~/" + rest
	}

	if strings.HasPrefix(s, "/root/") {
		return "~/" + s[len("/root/"):]
	}
	if s == "/root" {
		return "~"
	}

	for _, p := range []string{`C:\Users\`, `c:\Users\`, "C:/Users/", "c:/Users/"} {
		if strings.HasPrefix(s, p) {
			rest := s[len(p):]

			rest = strings.ReplaceAll(rest, `\`, "/")
			if i := strings.IndexByte(rest, '/'); i >= 0 {
				return "~/" + rest[i+1:]
			}
			return "~"
		}
	}
	return s
}

func stripUserPrefix(s, prefix string) (string, bool) {
	if !strings.HasPrefix(s, prefix) {
		return "", false
	}
	rest := s[len(prefix):]
	if rest == "" {
		return "", false
	}
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		return rest[i+1:], true
	}

	return "", true
}

func truncate(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	if n <= 3 {
		return s[:n]
	}
	return s[:n-3] + "..."
}
