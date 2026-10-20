package project

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"

	"aidetector/cli/internal/config"
)

// hostish matches a bare host[:port][/path] typed without a scheme:
// "api.example.com", "localhost:8080/v1", "10.0.0.5:9000".
var hostish = regexp.MustCompile(`^(localhost|[a-z0-9-]+(\.[a-z0-9-]+)+|\[[0-9a-f:]+\])(:\d+)?(/\S*)?$`)

// LooksLikeTarget says whether a command-line word names an API rather than a
// subcommand: it has a scheme, or it is a dotted host / localhost. A bare word
// such as "scans" never does, so subcommands keep working.
func LooksLikeTarget(arg string) bool {
	if strings.Contains(arg, "://") {
		return true
	}
	return hostish.MatchString(strings.ToLower(arg))
}

// NormalizeTarget turns what a person typed into the URL a scan stores, and
// the form two targets are compared in. With no scheme it assumes https, except
// for this machine, where plain http is the norm for a dev server.
func NormalizeTarget(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("empty target")
	}
	if !strings.Contains(raw, "://") {
		scheme := "https://"
		if u, err := url.Parse("http://" + raw); err == nil && config.IsLoopback(u.Hostname()) {
			scheme = "http://"
		}
		raw = scheme + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("target %q is not a URL: %w", raw, err)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("target %q must be http:// or https://", raw)
	}
	if u.Hostname() == "" {
		return "", fmt.Errorf("target %q has no host", raw)
	}
	if u.User != nil {
		return "", fmt.Errorf("target %q carries credentials in the URL; use an identity instead", raw)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("target %q must be a base URL, without a query or fragment", raw)
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
		port = ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		host = net.JoinHostPort(strings.Trim(host, "[]"), port)
	}
	path := strings.TrimRight(u.EscapedPath(), "/")
	return u.Scheme + "://" + host + path, nil
}

// SameTarget compares two targets in normal form. A value that does not parse
// matches nothing, so a malformed row can never be picked up by accident.
func SameTarget(a, b string) bool {
	na, errA := NormalizeTarget(a)
	nb, errB := NormalizeTarget(b)
	return errA == nil && errB == nil && na == nb
}

// IsLoopbackTarget says whether a normalized target names this machine.
func IsLoopbackTarget(target string) bool {
	u, err := url.Parse(target)
	return err == nil && config.IsLoopback(u.Hostname())
}
