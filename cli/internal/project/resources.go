package project

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Resource ids: values for path parameters the scan cannot invent, such as an
// existing merchant or project on a staging target. The grammar is the
// server's (app/api/schemas/common.py): a name is identifier-shaped, an id is
// opaque but cannot break out of the path segment it is rendered into.
var (
	resourceNameRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,79}$`)
	resourceIDRE   = regexp.MustCompile(`^[^/?#\r\n]{1,256}$`)
)

// MaxResourceIDs bounds the map, as the server's run request does.
const MaxResourceIDs = 50

// maxResourceFileBytes bounds a resource-id file: fifty short pairs.
const maxResourceFileBytes = 64 << 10

// ValidateResourceIDs checks a name -> id map against the server's grammar.
// Errors name the resource, never the id: ids are target data.
func ValidateResourceIDs(ids map[string]string) error {
	if len(ids) > MaxResourceIDs {
		return fmt.Errorf("at most %d resource ids", MaxResourceIDs)
	}
	names := make([]string, 0, len(ids))
	for name := range ids {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		trimmed := strings.TrimSpace(name)
		if !resourceNameRE.MatchString(trimmed) {
			return fmt.Errorf("%q is not a resource name: start with a letter, then letters, digits, '_', '.' or '-' (at most 80)", name)
		}
		if !resourceIDRE.MatchString(strings.TrimSpace(ids[name])) {
			return fmt.Errorf("the id for %q must be 1-256 characters with no '/', '?', '#' or line break", trimmed)
		}
	}
	return nil
}

// LoadResourceIDs reads a local resource-id file: a JSON or YAML mapping of
// resource name to id. Ids are target data, not secrets, so the file needs no
// special mode; it is bounded and validated like the inline map.
func LoadResourceIDs(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("resource ids: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxResourceFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("resource ids: %w", err)
	}
	if len(data) > maxResourceFileBytes {
		return nil, fmt.Errorf("resource ids: %s is larger than %d KiB", path, maxResourceFileBytes>>10)
	}
	out := map[string]string{}
	trimmed := bytes.TrimSpace(data)
	if bytes.HasPrefix(trimmed, []byte("{")) {
		dec := json.NewDecoder(bytes.NewReader(trimmed))
		if err := dec.Decode(&out); err != nil {
			return nil, fmt.Errorf("resource ids: %s is not a JSON object of name -> id string", path)
		}
	} else if len(trimmed) > 0 {
		if err := yaml.Unmarshal(trimmed, &out); err != nil {
			return nil, fmt.Errorf("resource ids: %s is not a mapping of name -> id string", path)
		}
	}
	if err := ValidateResourceIDs(out); err != nil {
		return nil, fmt.Errorf("resource ids in %s: %w", path, err)
	}
	return out, nil
}

// MergeResourceIDs layers maps left to right (later wins), trimming as the
// server does. A name given twice in different spellings of one key is the
// caller's concern: the binding preview reports it as ambiguous.
func MergeResourceIDs(maps ...map[string]string) (map[string]string, error) {
	out := map[string]string{}
	for _, m := range maps {
		for k, v := range m {
			out[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	if err := ValidateResourceIDs(out); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}
