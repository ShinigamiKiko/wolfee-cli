package onlinescan

import (
	"fmt"
	"os"
	"strings"
)

func debugPkg() string {
	return strings.TrimSpace(os.Getenv("WOLFEE_DEBUG_PKG"))
}

func debugLog(log ProgressLogger, pkg, format string, args ...any) {
	if log == nil || pkg == "" || debugPkg() == "" {
		return
	}
	if !strings.EqualFold(pkg, debugPkg()) {
		return
	}
	log.Step("[DEBUG " + pkg + "] " + fmt.Sprintf(format, args...))
}

func debugCVE() string {
	return strings.ToUpper(strings.TrimSpace(os.Getenv("WOLFEE_DEBUG_CVE")))
}

func debugCVELog(log ProgressLogger, pkg, cve, format string, args ...any) {
	if log == nil || cve == "" || debugCVE() == "" {
		return
	}
	if !strings.EqualFold(cve, debugCVE()) {
		return
	}
	log.Step("[DEBUG-CVE " + cve + " pkg=" + pkg + "] " + fmt.Sprintf(format, args...))
}
