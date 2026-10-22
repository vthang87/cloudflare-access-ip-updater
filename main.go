package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"
)

const defaultTraceURL = "https://cloudflare.com/cdn-cgi/trace"

type config struct {
	token, account, app, policy, ipURL string
	interval                           time.Duration
	dry                                bool
}

type apiResponse struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Result json.RawMessage `json:"result"`
}

type policy struct {
	ID                            string            `json:"id"`
	Name                          string            `json:"name"`
	Decision                      string            `json:"decision"`
	Include                       []json.RawMessage `json:"include"`
	Exclude                       []json.RawMessage `json:"exclude,omitempty"`
	Require                       []json.RawMessage `json:"require,omitempty"`
	Precedence                    int               `json:"precedence"`
	PurposeJustificationRequired  bool              `json:"purpose_justification_required"`
	ApprovalRequired              bool              `json:"approval_required"`
}

type publicAddrs struct {
	v4, v6 string // CIDR form: /32 or /128
}

func required(name string) string {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		slog.Error("missing environment variable", "name", name)
		os.Exit(2)
	}
	return v
}

func env(k, fallback string) string {
	if s := strings.TrimSpace(os.Getenv(k)); s != "" {
		return s
	}
	return fallback
}

func load() config {
	c := config{
		token:    required("CF_API_TOKEN"),
		account:  required("CF_ACCOUNT_ID"),
		app:      strings.TrimSpace(os.Getenv("CF_APP_ID")),
		policy:   required("CF_POLICY_ID"),
		ipURL:    env("IP_CHECK_URL", defaultTraceURL),
		interval: 5 * time.Minute,
		dry:      strings.EqualFold(os.Getenv("DRY_RUN"), "true"),
	}
	if v := os.Getenv("CHECK_INTERVAL"); v != "" {
		d, e := time.ParseDuration(v)
		if e != nil || d < time.Minute {
			slog.Error("CHECK_INTERVAL must be >= 1m", "value", v)
			os.Exit(2)
		}
		c.interval = d
	}
	return c
}

func clientForNetwork(network string) *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, addr)
			},
		},
	}
}

func parseTraceIP(body string) (net.IP, error) {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "ip=") {
			continue
		}
		ip := net.ParseIP(strings.TrimPrefix(line, "ip="))
		if ip == nil {
			return nil, errors.New("cdn-cgi/trace ip= was not a valid address")
		}
		return ip, nil
	}
	return nil, errors.New("cdn-cgi/trace response missing ip=")
}

func fetchTraceIP(ctx context.Context, network, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	res, err := clientForNetwork(network).Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("trace endpoint returned %d", res.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, 4096))
	if err != nil {
		return "", err
	}
	ip, err := parseTraceIP(string(b))
	if err != nil {
		return "", err
	}
	if network == "tcp4" {
		if ip.To4() == nil {
			return "", errors.New("expected IPv4 from tcp4 trace")
		}
		return ip.String() + "/32", nil
	}
	if ip.To4() != nil {
		return "", errors.New("expected IPv6 from tcp6 trace")
	}
	return ip.String() + "/128", nil
}

func detectPublicAddrs(ctx context.Context, url string) (publicAddrs, error) {
	v4, err := fetchTraceIP(ctx, "tcp4", url)
	if err != nil {
		return publicAddrs{}, fmt.Errorf("IPv4: %w", err)
	}
	v6, err := fetchTraceIP(ctx, "tcp6", url)
	if err != nil {
		return publicAddrs{}, fmt.Errorf("IPv6: %w", err)
	}
	return publicAddrs{v4: v4, v6: v6}, nil
}

func api(ctx context.Context, client *http.Client, c config, method, endpoint string, body io.Reader) (json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, method, "https://api.cloudflare.com/client/v4"+endpoint, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var out apiResponse
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("unexpected API response (%d): %w", res.StatusCode, err)
	}
	if !out.Success || res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("Cloudflare API status %d: %+v", res.StatusCode, out.Errors)
	}
	return out.Result, nil
}

func policyEndpoint(c config) string {
	if c.app == "" {
		return fmt.Sprintf("/accounts/%s/access/policies/%s", c.account, c.policy)
	}
	return fmt.Sprintf("/accounts/%s/access/apps/%s/policies/%s", c.account, c.app, c.policy)
}

func selectorIP(raw json.RawMessage) (string, bool) {
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil {
		return "", false
	}
	v, ok := obj["ip"]
	if !ok {
		return "", false
	}
	var s struct {
		IP string `json:"ip"`
	}
	if json.Unmarshal(v, &s) != nil || s.IP == "" {
		return "", false
	}
	return normalizeCIDR(s.IP)
}

func normalizeCIDR(s string) (string, bool) {
	if ip := net.ParseIP(s); ip != nil {
		if ip.To4() != nil {
			return ip.String() + "/32", true
		}
		return ip.String() + "/128", true
	}
	ip, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		return "", false
	}
	ones, bits := ipNet.Mask.Size()
	if ip.To4() != nil {
		if ones != 32 || bits != 32 {
			return "", false
		}
		return ip.To4().String() + "/32", true
	}
	if ones != 128 || bits != 128 {
		return "", false
	}
	return ip.String() + "/128", true
}

func policyIPs(include []json.RawMessage) ([]string, error) {
	if len(include) == 0 || len(include) > 2 {
		return nil, fmt.Errorf("expected 1–2 Include IP selectors, found %d", len(include))
	}
	out := make([]string, 0, len(include))
	for _, raw := range include {
		cidr, ok := selectorIP(raw)
		if !ok {
			return nil, errors.New("refusing to modify policy: every Include selector must be a single-host IP range")
		}
		out = append(out, cidr)
	}
	sort.Strings(out)
	return out, nil
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func ipSelectors(cidrs ...string) ([]json.RawMessage, error) {
	out := make([]json.RawMessage, 0, len(cidrs))
	for _, c := range cidrs {
		raw, err := json.Marshal(map[string]any{"ip": map[string]string{"ip": c}})
		if err != nil {
			return nil, err
		}
		out = append(out, raw)
	}
	return out, nil
}

func syncOnce(ctx context.Context, client *http.Client, c config) error {
	addrs, err := detectPublicAddrs(ctx, c.ipURL)
	if err != nil {
		return fmt.Errorf("detect IP: %w", err)
	}
	desired := []string{addrs.v4, addrs.v6}
	sort.Strings(desired)

	endpoint := policyEndpoint(c)
	raw, err := api(ctx, client, c, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("read policy: %w", err)
	}
	var p policy
	if err := json.Unmarshal(raw, &p); err != nil {
		return err
	}
	if p.Decision != "bypass" {
		return fmt.Errorf("refusing to modify policy %q: decision must be bypass", p.Decision)
	}
	// Dedicated Bypass policy: only single-host IP Include selectors (IPv4 and/or IPv6).
	old, err := policyIPs(p.Include)
	if err != nil {
		return fmt.Errorf("refusing to modify policy: %w", err)
	}
	if sameSet(old, desired) {
		slog.Info("IP unchanged", "ipv4", addrs.v4, "ipv6", addrs.v6, "policy", p.Name)
		return nil
	}
	slog.Info("IP changed", "previous", old, "ipv4", addrs.v4, "ipv6", addrs.v6, "policy", p.Name, "dry_run", c.dry)
	if c.dry {
		return nil
	}

	var full map[string]json.RawMessage
	if err := json.Unmarshal(raw, &full); err != nil {
		return err
	}
	selectors, err := ipSelectors(addrs.v4, addrs.v6)
	if err != nil {
		return err
	}
	include, err := json.Marshal(selectors)
	if err != nil {
		return err
	}
	full["include"] = include

	writable := map[string]bool{
		"name": true, "decision": true, "include": true, "exclude": true, "require": true,
		"precedence": true, "purpose_justification_required": true, "approval_required": true,
		"session_duration": true, "isolation_required": true, "purpose_justification_prompt": true,
		"approval_groups": true,
	}
	// Reusable policies have no precedence of their own; it is set per application.
	if c.app == "" {
		delete(writable, "precedence")
	}
	payload := map[string]json.RawMessage{}
	for k, v := range full {
		if writable[k] {
			payload[k] = v
		}
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if _, err := api(ctx, client, c, http.MethodPut, endpoint, strings.NewReader(string(data))); err != nil {
		return fmt.Errorf("update policy: %w", err)
	}
	slog.Info("Access bypass IP updated", "ipv4", addrs.v4, "ipv6", addrs.v6, "policy", p.Name)
	return nil
}

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	c := load()
	client := &http.Client{Timeout: 15 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	run := func() {
		rctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		if err := syncOnce(rctx, client, c); err != nil {
			slog.Error("sync failed", "error", err)
		}
	}
	slog.Info("starting", "interval", c.interval.String(), "dry_run", c.dry, "reusable_policy", c.app == "", "ip_check_url", c.ipURL)
	run()
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			slog.Info("stopped")
			return
		case <-ticker.C:
			run()
		}
	}
}
