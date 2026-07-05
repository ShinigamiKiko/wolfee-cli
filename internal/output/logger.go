package output

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

type Logger interface {
	Step(msg string)
	Warn(format string, args ...any)
	Debug(format string, args ...any)
	Progress(done, total int, label string)
}

type stderrLogger struct {
	mu      sync.Mutex
	quiet   bool
	verbose bool
}

func NewLogger(quiet, verbose bool) Logger {
	return &stderrLogger{quiet: quiet, verbose: verbose}
}

func (l *stderrLogger) Step(msg string) {
	if l.quiet {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(os.Stderr, "→ %s\n", msg)
}

func (l *stderrLogger) Warn(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(os.Stderr, "! "+format+"\n", args...)
}

func (l *stderrLogger) Debug(format string, args ...any) {
	if l.quiet || !l.verbose {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(os.Stderr, "  "+format+"\n", args...)
}

func (l *stderrLogger) Progress(done, total int, label string) {
	if l.quiet || total <= 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if total == done {
		fmt.Fprintf(os.Stderr, "\r  [%d/%d] done                                          \n", done, total)
		return
	}
	if len(label) > 60 {
		label = label[:57] + "..."
	}
	fmt.Fprintf(os.Stderr, "\r  [%d/%d] %s          ", done, total, label)
}

func LineWriter(emit func(string, ...any), prefix string) io.WriteCloser {
	r, w := io.Pipe()
	go func() {
		defer r.Close()
		s := bufio.NewScanner(r)
		s.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for s.Scan() {
			line := strings.TrimRight(s.Text(), "\r")
			if line == "" {
				continue
			}
			emit("%s%s", prefix, line)
		}
	}()
	return w
}
