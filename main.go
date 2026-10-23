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
	v4, v6 string // CIDR form: IPv4 /32, IPv6 LAN /64
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
	cidr, ok := ipv6LAN(ip)
	if !ok {
		return "", errors.New("could not derive IPv6 /64 LAN prefix")
	}
	return cidr, nil
}

func detectPublicAddrs(ctx context.Context, url string) (publicAddrs, error) {
	v4, err := fetchTraceIP(ctx, "tcp4", url)
	if err != nil {
		return publicAddrs{}, fmt.Errorf("IPv4: %w", err)
	}
	addrs := publicAddrs{v4: v4}
	v6, err := fetchTraceIP(ctx, "tcp6", url)
	if err != nil {
		// Many Docker hosts lack IPv6 egress; keep syncing IPv4 and preserve any existing IPv6 in the policy.
		slog.Warn("IPv6 detection failed; will preserve existing IPv6 Include if present", "error", err)
		return addrs, nil
	}
	addrs.v6 = v6
	return addrs, nil
}

func ipv6LAN(ip net.IP) (string, bool) {
	ip = ip.To16()
	if ip == nil || ip.To4() != nil {
		return "", false
	}
	n := &net.IPNet{IP: ip, Mask: net.CIDRMask(64, 128)}
	return n.IP.Mask(n.Mask).String() + "/64", true
}

func isIPv6CIDR(cidr string) bool {
	ip, _, err := net.ParseCIDR(cidr)
	return err == nil && ip != nil && ip.To4() == nil
}

func desiredCIDRs(addrs publicAddrs, existing []string) []string {
	out := []string{addrs.v4}
	if addrs.v6 != "" {
		out = append(out, addrs.v6)
	} else {
		for _, c := range existing {
			if isIPv6CIDR(c) {
				// Expand a stored host /128 (or any v6) to the LAN /64 so Bypass covers the whole prefix.
				out = append(out, c)
				break
			}
		}
	}
	sort.Strings(out)
	return out
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

func selectorIP(raw json.RawMessage) (stored string, canonical string, ok bool) {
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil {
		return "", "", false
	}
	v, ok := obj["ip"]
	if !ok {
		return "", "", false
	}
	var s struct {
		IP string `json:"ip"`
	}
	if json.Unmarshal(v, &s) != nil || s.IP == "" {
		return "", "", false
	}
	canonical, ok = normalizeCIDR(s.IP)
	if !ok {
		return "", "", false
	}
	return s.IP, canonical, true
}

func isCanonicalCIDR(s string) bool {
	ip, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		return false
	}
	ones, bits := ipNet.Mask.Size()
	if v4 := ip.To4(); v4 != nil {
		return ones == 32 && bits == 32
	}
	return ones == 64 && bits == 128
}

func normalizeCIDR(s string) (string, bool) {
	if ip := net.ParseIP(s); ip != nil {
		if ip.To4() != nil {
			return ip.String() + "/32", true
		}
		return ipv6LAN(ip)
	}
	ip, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		return "", false
	}
	ones, bits := ipNet.Mask.Size()
	if v4 := ip.To4(); v4 != nil {
		if ones != 32 || bits != 32 {
			return "", false
		}
		return v4.String() + "/32", true
	}
	// IPv6: accept host or prefix and canonicalize to the LAN /64.
	if bits != 128 || ones < 64 {
		return "", false
	}
	return ipv6LAN(ip)
}

func policyIPs(include []json.RawMessage) (canonical []string, needsRewrite bool, err error) {
	if len(include) == 0 || len(include) > 2 {
		return nil, false, fmt.Errorf("expected 1–2 Include IP selectors, found %d", len(include))
	}
	out := make([]string, 0, len(include))
	for _, raw := range include {
		stored, cidr, ok := selectorIP(raw)
		if !ok {
			return nil, false, errors.New("refusing to modify policy: Include must be IPv4 /32 or IPv6 /64 (LAN)")
		}
		if !isCanonicalCIDR(stored) {
			// e.g. host /128 in Cloudflare → rewrite as LAN /64
			needsRewrite = true
		}
		out = append(out, cidr)
	}
	sort.Strings(out)
	return out, needsRewrite, nil
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
	// Dedicated Bypass policy: IPv4 /32 and optional IPv6 LAN /64 only.
	old, needsRewrite, err := policyIPs(p.Include)
	if err != nil {
		return fmt.Errorf("refusing to modify policy: %w", err)
	}
	desired := desiredCIDRs(addrs, old)
	if sameSet(old, desired) && !needsRewrite {
		slog.Info("IP unchanged", "ipv4", addrs.v4, "ipv6", addrs.v6, "include", desired, "policy", p.Name)
		return nil
	}
	slog.Info("IP changed", "previous", old, "ipv4", addrs.v4, "ipv6", addrs.v6, "include", desired, "policy", p.Name, "dry_run", c.dry)
	if c.dry {
		return nil
	}

	var full map[string]json.RawMessage
	if err := json.Unmarshal(raw, &full); err != nil {
		return err
	}
	selectors, err := ipSelectors(desired...)
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
	slog.Info("Access bypass IP updated", "ipv4", addrs.v4, "ipv6", addrs.v6, "include", desired, "policy", p.Name)
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
