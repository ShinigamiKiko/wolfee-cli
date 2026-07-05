package output

import (
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"
)

var ansiSGR = regexp.MustCompile("\x1b\\[[0-9;]*m")

func visibleLen(s string) int {
	return utf8.RuneCountInString(ansiSGR.ReplaceAllString(s, ""))
}

type grid struct{ rows [][]string }

func (g *grid) add(cells ...string) { g.rows = append(g.rows, cells) }

func (g *grid) render(w io.Writer) {
	var widths []int
	for _, r := range g.rows {
		for i, cell := range r {
			vl := visibleLen(cell)
			if i >= len(widths) {
				widths = append(widths, vl)
			} else if vl > widths[i] {
				widths[i] = vl
			}
		}
	}
	for _, r := range g.rows {
		var b strings.Builder
		b.WriteString("  ")
		for i, cell := range r {
			b.WriteString(cell)
			if i < len(r)-1 {
				b.WriteString(strings.Repeat(" ", widths[i]-visibleLen(cell)+2))
			}
		}
		fmt.Fprintln(w, strings.TrimRight(b.String(), " "))
	}
}
