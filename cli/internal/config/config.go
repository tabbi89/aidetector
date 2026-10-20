// Package config stores which servers the CLI talks to and the API keys it uses.
//
// A file holds named profiles — one server and key each — plus which profile is
// current, so one machine can talk to production and staging without rewriting
// the file. A flat {server, api_key} file from an earlier version still loads
// as the "default" profile.
//
// A key is a credential, so the file is written 0600 and refused on read if
// anyone else can open it — the same posture ssh takes with a private key.
// AIDETECTOR_PROFILE selects a profile; AIDETECTOR_SERVER and
// AIDETECTOR_API_KEY override its values, which is how CI supplies them
// without anything touching disk.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
)

// Profile is one saved connection.
type Profile struct {
	Server string `json:"server"`
	APIKey string `json:"api_key,omitempty"`
}

// Store is the on-disk file: every saved profile and which one is current.
type Store struct {
	Current  string             `json:"current,omitempty"`
	Profiles map[string]Profile `json:"profiles,omitempty"`
}

// Config is the connection Load resolved, with the environment applied.
// Profile is always set: AIDETECTOR_PROFILE, else the file's current profile,
// else "default".
type Config struct {
	Profile        string
	ProfileFromEnv bool
	Server         string
	APIKey         string
	ServerFromEnv  bool
}

// Path is where the config lives: override, else the user config dir.
func Path(override string) (string, error) {
	if override != "" {
		return override, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("no user config directory: %w", err)
	}
	return filepath.Join(dir, "aidetector", "config.json"), nil
}

// ReadStore reads the saved profiles without applying the environment. A
// missing file is an empty store, not an error.
func ReadStore(path string) (Store, error) {
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
	case errors.Is(err, os.ErrNotExist):
		return Store{}, nil
	default:
		return Store{}, err
	}
	if err := checkMode(path); err != nil {
		return Store{}, err
	}
	var raw struct {
		// The flat fields are the previous file format, read as "default".
		Server   string             `json:"server"`
		APIKey   string             `json:"api_key"`
		Current  string             `json:"current"`
		Profiles map[string]Profile `json:"profiles"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return Store{}, fmt.Errorf("config %s is not valid JSON: %w", path, err)
	}
	if raw.Profiles == nil {
		if raw.Server == "" && raw.APIKey == "" {
			return Store{}, nil
		}
		return Store{Current: "default", Profiles: map[string]Profile{
			"default": {Server: raw.Server, APIKey: raw.APIKey},
		}}, nil
	}
	return Store{Current: raw.Current, Profiles: raw.Profiles}, nil
}

// Load reads the saved profiles, selects one and applies the environment. A
// missing file is not an error: CI runs with the environment alone.
func Load(path string, getenv func(string) string) (Config, error) {
	st, err := ReadStore(path)
	if err != nil {
		return Config{}, err
	}
	var c Config
	name := getenv("AIDETECTOR_PROFILE")
	if name != "" {
		c.ProfileFromEnv = true
		if !ValidProfileName(name) {
			return Config{}, UnknownProfileError(name, st)
		}
		if _, ok := st.Profiles[name]; !ok {
			return Config{}, UnknownProfileError(name, st)
		}
	}
	if name == "" {
		name = st.Current
	}
	if name == "" {
		name = "default"
	}
	c.Profile = name
	if p, ok := st.Profiles[name]; ok {
		c.Server, c.APIKey = p.Server, p.APIKey
	}
	if v := getenv("AIDETECTOR_SERVER"); v != "" {
		// A saved key belongs to its profile's server. When the environment
		// points somewhere else, sending that key there would hand it to a
		// host it was never issued for, so it needs AIDETECTOR_API_KEY too.
		if !sameServer(v, c.Server) {
			c.APIKey = ""
		}
		c.Server, c.ServerFromEnv = v, true
	}
	if v := getenv("AIDETECTOR_API_KEY"); v != "" {
		c.APIKey = v
	}
	return c, nil
}

// sameServer compares two server URLs as typed: case and a trailing slash
// do not matter. Anything else counts as a different server.
func sameServer(a, b string) bool {
	norm := func(s string) string { return strings.TrimRight(strings.ToLower(strings.TrimSpace(s)), "/") }
	return norm(a) == norm(b)
}

// Names returns the saved profile names, sorted.
func (s Store) Names() []string {
	names := make([]string, 0, len(s.Profiles))
	for name := range s.Profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// UnknownProfileError names the profiles that do exist, so a typo is obvious.
func UnknownProfileError(name string, st Store) error {
	known := "none saved"
	if names := st.Names(); len(names) > 0 {
		known = strings.Join(names, ", ")
	}
	return fmt.Errorf("unknown profile %q; known profiles: %s", name, known)
}

// profileNameRE is the profile name format: 1-32 lowercase letters, digits,
// '-' or '_', starting with a letter or digit.
var profileNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

// ValidProfileName reports whether name can be used as a profile.
func ValidProfileName(name string) bool { return profileNameRE.MatchString(name) }

// checkMode refuses a config another user could read. Windows has no unix
// modes, so the check is skipped there.
// CheckPrivateFile refuses a file (a saved key, a secrets file) that anyone but
// its owner can open.
func CheckPrivateFile(path string) error { return checkMode(path) }

func checkMode(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("config %s is readable by others (mode %#o); run: chmod 600 %s",
			path, info.Mode().Perm(), path)
	}
	return nil
}

// Save writes the profiles 0600, creating their directory 0700.
func Save(path string, s Store) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	// WriteFile does not tighten an existing file's mode, so remove first.
	_ = os.Remove(path)
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

// Clear deletes the saved config. Deleting nothing is fine.
func Clear(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// NormalizeServer validates a server URL and returns it without a trailing
// slash. The API key travels in a header, so plain http is only accepted for a
// loopback host unless the caller explicitly allows it.
func NormalizeServer(raw string, allowInsecureHTTP bool) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("%q is not a server URL (expected https://host[:port])", raw)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !allowInsecureHTTP && !isLoopback(u.Hostname()) {
			return "", fmt.Errorf("refusing http://%s: the API key would cross the network in "+
				"clear text; use https, or pass --insecure-http", u.Host)
		}
	default:
		return "", fmt.Errorf("unsupported scheme %q (use https)", u.Scheme)
	}
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawQuery, u.Fragment = "", ""
	return u.String(), nil
}

// DefaultServer is the hosted service. `login` uses it when --server is not
// given, and a client with no server configured talks to it.
const DefaultServer = "https://runpentests.com"

// IsLoopback reports whether a host name or address is this machine.
func IsLoopback(host string) bool { return isLoopback(host) }

func isLoopback(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
