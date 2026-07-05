package output

import (
	"encoding/json"
	"io"
)

type Renderer interface {
	Render(w io.Writer, report any) error
}

type JSON struct{}

func (JSON) Render(w io.Writer, report any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(report)
}
