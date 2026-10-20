// Package docs holds the CLI's user-facing guides. They are linked from
// cli/README.md and built into the binary, so `aidetector mcp` serves a coding
// agent the guide that matches the validator it ships with.
package docs

import "embed"

// FS holds every guide, keyed by file name (setup.md, project-file.md, ...).
//
//go:embed *.md
var FS embed.FS
