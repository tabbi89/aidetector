package commands

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"runpentests/cli/internal/api"
	"runpentests/cli/internal/project"
)

// Known resource ids let a read-only scan reach real objects: without one,
// GET /merchants/{merchantId} is sent an invented id, answers 404 and tests
// nothing. The map stays on this machine — the runner gets it on stdin — and
// what leaves for the server is the names, so it can say which routes each fills.

// previewResourceIDs asks the server which route parameters each name fills
// and prints it, before the run is claimed and its budget spent. Two names
// that fill the same parameter are refused (only one would be used); a name
// that fills nothing is a warning. Ids are never printed.
func previewResourceIDs(ctx context.Context, e *Env, c *api.Client, scanID string, ids map[string]string) int {
	if len(ids) == 0 {
		return ExitOK
	}
	names := make([]string, 0, len(ids))
	for name := range ids {
		names = append(names, name)
	}
	sort.Strings(names)
	b, err := c.ResourceBindings(ctx, scanID, names)
	if err != nil {
		var apiErr *api.APIError
		if errors.As(err, &apiErr) && apiErr.Status == 404 && apiErr.Detail == "Not Found" {
			e.errorf("resource ids: %d supplied (%s); this server cannot preview which routes they fill\n",
				len(names), strings.Join(names, ", "))
			return ExitOK
		}
		return e.exitFor(err)
	}
	ambiguous := false
	for _, n := range b.Names {
		switch {
		case len(n.AmbiguousWith) > 0:
			ambiguous = true
			e.errorf("resource ids: %s and %s are the same resource (%q); keep one\n",
				printable(n.Name), printable(strings.Join(n.AmbiguousWith, ", ")), printable(n.Key))
		case len(n.Routes) == 0:
			e.errorf("resource ids: warning: %s fills no route parameter in this spec\n", printable(n.Name))
		default:
			e.errorf("resource ids: %s fills %s\n", printable(n.Name), routeList(n.Routes))
		}
	}
	if ambiguous {
		return e.usage("ambiguous resource ids: nothing was run")
	}
	if len(b.Unbound) > 0 {
		e.errorf("resource ids: %d route parameter(s) still get a placeholder value: %s\n",
			len(b.Unbound), routeList(b.Unbound))
	}
	return ExitOK
}

// routeList is "{merchantId} on GET /merchants/{merchantId}, …", at most five.
func routeList(routes []api.ResourceRoute) string {
	var parts []string
	for i, r := range routes {
		if i == 5 {
			parts = append(parts, fmt.Sprintf("and %d more", len(routes)-5))
			break
		}
		parts = append(parts, fmt.Sprintf("{%s} on %s %s", printable(r.Param), printable(r.Method), printable(r.Path)))
	}
	return strings.Join(parts, ", ")
}

// resolveResourceIDs layers the project file's inline map, its
// resource_ids_file and --resource-ids (later wins).
func resolveResourceIDs(file *project.Loaded, flagPath string) (map[string]string, error) {
	var layers []map[string]string
	if file != nil {
		layers = append(layers, file.ResourceIDs)
		if file.ResourceIDsFile != "" {
			fromFile, err := project.LoadResourceIDs(file.Resolve(file.ResourceIDsFile))
			if err != nil {
				return nil, err
			}
			layers = append(layers, fromFile)
		}
	}
	if flagPath != "" {
		fromFlag, err := project.LoadResourceIDs(flagPath)
		if err != nil {
			return nil, err
		}
		layers = append(layers, fromFlag)
	}
	return project.MergeResourceIDs(layers...)
}

// projectContext loads ./runpentests.yml, when there is one, and the secrets
// its identities name by secret_env, found in this environment. Commands that
// run the engine outside the target form (retest, auth check) use it so they
// see what an everyday scan would.
func projectContext(e *Env) (*project.Loaded, map[string]string, int) {
	secrets := map[string]string{}
	wd, err := e.workdir()
	if err != nil {
		return nil, secrets, ExitOK
	}
	file, err := project.Find(wd)
	if err != nil {
		return nil, nil, e.usage("%v", err)
	}
	if file != nil {
		for _, ident := range file.ExpandIdentities() {
			if ident.SecretEnv != "" {
				if v := e.Getenv(ident.SecretEnv); v != "" {
					secrets[ident.Name] = v
				}
			}
		}
	}
	return file, secrets, ExitOK
}
