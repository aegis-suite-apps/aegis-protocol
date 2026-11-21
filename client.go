package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"
)

type HTTPError struct {
	Status  int
	Code    string
	Message string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("HTTP %d (%s): %s", e.Status, e.Code, e.Message)
}

// Client speaks Aegis Protocol v2 over HTTPS (HTTP permitted only on localhost/127.0.0.1).
type Client struct {
	HTTP *http.Client
}

func NewClient() *Client {
	return &Client{HTTP: &http.Client{Timeout: 20 * time.Second}}
}

func NormalizeBaseURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return "", fmt.Errorf("invalid Aegis RD URL: %q", raw)
	}
	host := u.Hostname()
	if u.Scheme == "http" && host != "localhost" && host != "127.0.0.1" {
		return "", errors.New("Aegis RD URL must use https (http only allowed for localhost)")
	}
	return u.Scheme + "://" + u.Host, nil
}

func defaultOSArch() string {
	return runtime.GOOS + "/" + runtime.GOARCH
}

func parseServerTimeUnix(raw string) (int64, error) {
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return 0, err
	}
	return t.Unix(), nil
}

func (c *Client) Enroll(ctx context.Context, baseURL, code string, req EnrollRequest) (EnrollResponse, error) {
	base, err := NormalizeBaseURL(baseURL)
	if err != nil {
		return EnrollResponse{}, err
	}
	code = strings.TrimSpace(code)
	if code == "" {
		return EnrollResponse{}, errors.New("enrollment code is required")
	}
	if req.Hostname == "" {
		req.Hostname, _ = os.Hostname()
	}
	if req.OSArch == "" {
		req.OSArch = defaultOSArch()
	}
	if req.MachineFingerprint == "" {
		req.MachineFingerprint = ComputeMachineFingerprint()
	}

	body, err := json.Marshal(req)
	if err != nil {
		return EnrollResponse{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/v2/agent/enroll", bytes.NewReader(body))
	if err != nil {
		return EnrollResponse{}, err
	}
	httpReq.Header.Set("content-type", "application/json")
	httpReq.Header.Set("authorization", "Bearer "+code)

	var out EnrollResponse
	if err := c.do(httpReq, http.StatusCreated, &out); err != nil {
		return EnrollResponse{}, err
	}
	if out.InstallID == "" || out.InstallationToken == "" || out.LeaseToken == "" {
		return EnrollResponse{}, errors.New("Aegis RD returned incomplete enrollment response")
	}
	return out, nil
}

func (c *Client) RefreshLease(ctx context.Context, baseURL, token string, req LeaseRequest) (string, error) {
	base, err := NormalizeBaseURL(baseURL)
	if err != nil {
		return "", err
	}
	if req.Hostname == "" {
		req.Hostname, _ = os.Hostname()
	}
	if req.OSArch == "" {
		req.OSArch = defaultOSArch()
	}
	if req.MachineFingerprint == "" {
		req.MachineFingerprint = ComputeMachineFingerprint()
	}

	body, err := json.Marshal(req)
	if err != nil {
		return "", err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/v2/agent/lease", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("content-type", "application/json")
	httpReq.Header.Set("authorization", "Bearer "+token)

	var out LeaseResponse
	if err := c.do(httpReq, http.StatusOK, &out); err != nil {
		return "", err
	}
	if out.LeaseToken == "" {
		return "", errors.New("Aegis RD returned empty lease_token")
	}
	return out.LeaseToken, nil
}

func (c *Client) SendEvents(ctx context.Context, baseURL, token string, events []TelemetryEvent) error {
	base, err := NormalizeBaseURL(baseURL)
	if err != nil {
		return err
	}
	if len(events) == 0 {
		return nil
	}
	body, err := json.Marshal(map[string]any{"events": events})
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/v2/agent/events", bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpReq.Header.Set("content-type", "application/json")
	httpReq.Header.Set("authorization", "Bearer "+token)

	resp, err := c.HTTP.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		return readHTTPError(resp)
	}
	return nil
}

func (c *Client) CheckUpdates(ctx context.Context, baseURL, token, currentVersion, channel string) (UpdateManifest, error) {
	base, err := NormalizeBaseURL(baseURL)
	if err != nil {
		return UpdateManifest{}, err
	}
	if channel == "" {
		channel = "stable"
	}
	u := fmt.Sprintf("%s/api/v2/agent/updates?version=%s&channel=%s", base, url.QueryEscape(currentVersion), url.QueryEscape(channel))
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return UpdateManifest{}, err
	}
	httpReq.Header.Set("authorization", "Bearer "+token)

	var out UpdateManifest
	if err := c.do(httpReq, http.StatusOK, &out); err != nil {
		return UpdateManifest{}, err
	}
	return out, nil
}

func (c *Client) do(req *http.Request, wantStatus int, out any) error {
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != wantStatus {
		return readHTTPError(resp)
	}
	if out == nil {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return err
	}
	return json.Unmarshal(body, out)
}

func readHTTPError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var parsed struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &parsed)
	code := parsed.Error.Code
	if code == "" {
		code = "http_error"
	}
	msg := parsed.Error.Message
	if msg == "" {
		msg = strings.TrimSpace(string(body))
	}
	return &HTTPError{Status: resp.StatusCode, Code: code, Message: msg}
}
