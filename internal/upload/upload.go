package upload

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"sca-go/cli/internal/output"
)

type Params struct {
	ServerURL   string
	Token       string
	ProjectName string
	BOMBytes    []byte
	Logger      output.Logger
	HTTP        *http.Client
}

type uploadRequest struct {
	ProjectName string `json:"projectName"`
	AutoCreate  bool   `json:"autoCreate"`
	BOM         string `json:"bom"`
}

type uploadResponse struct {
	Token string `json:"token"`
}

func SendBOM(ctx context.Context, p Params) error {
	if p.ServerURL == "" {
		return errors.New("upload: server URL required")
	}
	if p.ProjectName == "" {
		return errors.New("upload: project name required")
	}
	if len(p.BOMBytes) == 0 {
		return errors.New("upload: empty bom")
	}

	body, err := json.Marshal(uploadRequest{
		ProjectName: p.ProjectName,
		AutoCreate:  true,
		BOM:         base64.StdEncoding.EncodeToString(p.BOMBytes),
	})
	if err != nil {
		return err
	}

	endpoint := strings.TrimRight(p.ServerURL, "/") + "/api/v1/bom"
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if p.Token != "" {

		req.Header.Set("X-Api-Key", p.Token)
	}

	client := p.HTTP
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {

		buf, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("upload: status %d: %s", resp.StatusCode, strings.TrimSpace(string(buf)))
	}

	var out uploadResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err == nil && p.Logger != nil && out.Token != "" {
		p.Logger.Step(fmt.Sprintf("Server queued job token=%s", out.Token))
	}
	return nil
}
