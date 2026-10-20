// Package api is a small hand-written client for the aidetector server.
//
// It is hand-written rather than generated: FastAPI publishes OpenAPI 3.1,
// which the Go generators only partly support, and the CLI needs about twenty
// routes. What keeps it honest is internal/api/contract_test.go, which reads a
// snapshot of the server's OpenAPI document and fails if a route used here is
// missing or a run flag the server accepts cannot be sent.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// The API returns bounded pages. A pipeline gate that reads one page can pass
// a scan whose only active high finding sits past the first thousand dismissed
// rows, so every list read here exhausts its pages.
const (
	findingsPageSize = 1000
	scansPageSize    = 1000
	maxListPages     = 1000
)

// Route is one server endpoint, in OpenAPI path-template form.
type Route struct {
	Method string
	Path   string
}

// Every route this client calls. UsedRoutes is what the contract test checks,
// so a call that bypasses these constants would escape the check — don't.
var (
	RouteHealthReady    = Route{"GET", "/health/ready"}
	RouteCapabilities   = Route{"GET", "/capabilities"}
	RouteListScans      = Route{"GET", "/scans"}
	RouteCreateScan     = Route{"POST", "/scans"}
	RouteGetScan        = Route{"GET", "/scans/{scan_id}"}
	RouteDeleteScan     = Route{"DELETE", "/scans/{scan_id}"}
	RouteUpdateScan     = Route{"PATCH", "/scans/{scan_id}"}
	RouteUploadSpec     = Route{"POST", "/scans/{scan_id}/spec"}
	RouteAddCredential  = Route{"POST", "/scans/{scan_id}/credentials"}
	RouteUpdateCred     = Route{"PATCH", "/scans/{scan_id}/credentials/{cred_id}"}
	RouteDeleteCred     = Route{"DELETE", "/scans/{scan_id}/credentials/{cred_id}"}
	RouteAuthHints      = Route{"POST", "/specs/auth-hints"}
	RouteManagedConfig  = Route{"PUT", "/scans/{scan_id}/managed-config"}
	RouteCancel         = Route{"POST", "/scans/{scan_id}/cancel"}
	RouteEvents         = Route{"GET", "/scans/{scan_id}/events"}
	RouteListRuns       = Route{"GET", "/scans/{scan_id}/runs"}
	RouteRunTrace       = Route{"GET", "/scans/{scan_id}/runs/{run_number}/trace"}
	RouteFindings       = Route{"GET", "/scans/{scan_id}/findings"}
	RouteSetVerdict     = Route{"PATCH", "/scans/{scan_id}/findings/{finding_id}"}
	RouteFindingSummary = Route{"GET", "/scans/{scan_id}/findings/summary"}
	RouteCoverage       = Route{"GET", "/scans/{scan_id}/coverage"}
	RouteCost           = Route{"GET", "/scans/{scan_id}/cost"}
	RouteDiff           = Route{"GET", "/scans/{scan_id}/diff"}
	RouteReportPDF      = Route{"GET", "/scans/{scan_id}/report.pdf"}
	RouteReportHTML     = Route{"GET", "/scans/{scan_id}/report.html"}
	RouteReportPentest  = Route{"GET", "/scans/{scan_id}/report.pentest"}
	RouteSARIF          = Route{"GET", "/scans/{scan_id}/sarif"}
	RouteExport         = Route{"GET", "/scans/{scan_id}/export"}
	// The local runner: the claim is authenticated by the API key; the fail
	// route by the per-run token the claim returned, never the API key.
	RouteClaimLocalRun = Route{"POST", "/scans/{scan_id}/local-runs"}
	RouteRunnerFail    = Route{"POST", "/runner/runs/{run_id}/fail"}
)

// UsedRoutes lists every route above, for the contract test.
var UsedRoutes = []Route{
	RouteHealthReady, RouteCapabilities, RouteListScans, RouteCreateScan, RouteGetScan, RouteDeleteScan,
	RouteUpdateScan, RouteUploadSpec, RouteAddCredential, RouteUpdateCred, RouteDeleteCred,
	RouteAuthHints, RouteManagedConfig,
	RouteCancel, RouteEvents, RouteListRuns, RouteRunTrace,
	RouteFindings, RouteSetVerdict, RouteFindingSummary, RouteCoverage, RouteCost,
	RouteDiff, RouteReportPDF, RouteReportHTML, RouteReportPentest,
	RouteSARIF, RouteExport, RouteClaimLocalRun, RouteRunnerFail,
}

// ReportFormats maps a --format value to its route.
var ReportFormats = map[string]Route{
	"pdf":     RouteReportPDF,
	"html":    RouteReportHTML,
	"pentest": RouteReportPentest,
	"sarif":   RouteSARIF,
	"json":    RouteExport,
}

const maxResponse = 64 << 20 // a report is megabytes, never more than this

// APIError is a non-2xx answer from the server.
type APIError struct {
	Status int
	Detail string
}

func (e *APIError) Error() string {
	if e.Detail == "" {
		return fmt.Sprintf("server answered %d", e.Status)
	}
	return fmt.Sprintf("server answered %d: %s", e.Status, e.Detail)
}

// UserAgent identifies the CLI on every request. On aidetector.com the API
// shares an origin with the web app, and this prefix is what routes a request
// for /scans to the API instead of the page (deploy/caddy/Caddyfile).
var UserAgent = "aidetector-cli"

// Client talks to one server with one API key.
type Client struct {
	base string
	key  string
	http *http.Client
}

// New builds a client. key may be empty when the server runs with auth off.
func New(base, key string) *Client {
	return &Client{
		base: strings.TrimRight(base, "/"),
		key:  key,
		http: &http.Client{Timeout: 120 * time.Second},
	}
}

func expand(path, scanID string) string {
	return strings.ReplaceAll(path, "{scan_id}", url.PathEscape(scanID))
}

// Base is the server URL this client talks to.
func (c *Client) Base() string { return c.base }

// do performs one API-key-authenticated request. in, when non-nil, is sent as
// JSON; out, when non-nil, receives the decoded JSON body. The raw body is
// always returned.
func (c *Client) do(ctx context.Context, r Route, scanID string, query url.Values, in, out any) ([]byte, error) {
	u := c.base + expand(r.Path, scanID)
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	headers := map[string]string{}
	if c.key != "" {
		headers["X-API-Key"] = c.key
	}
	return c.send(ctx, r, u, headers, in, out)
}

// send performs one request with exactly the headers given.
func (c *Client) send(ctx context.Context, r Route, u string, headers map[string]string, in, out any) ([]byte, error) {
	var body io.Reader
	if in != nil {
		data, err := json.Marshal(in)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, r.Method, u, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", UserAgent)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return raw, &APIError{Status: resp.StatusCode, Detail: detail(raw)}
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return raw, fmt.Errorf("unexpected response from %s %s: %w", r.Method, r.Path, err)
		}
	}
	return raw, nil
}

// detail extracts FastAPI's {"detail": ...} message, however it is shaped.
func detail(raw []byte) string {
	var env struct {
		Detail any `json:"detail"`
	}
	if json.Unmarshal(raw, &env) != nil || env.Detail == nil {
		return ""
	}
	if s, ok := env.Detail.(string); ok {
		return s
	}
	b, _ := json.Marshal(env.Detail)
	return string(b)
}

// --- types -----------------------------------------------------------------

// FindingCounts is the per-severity tally on a scan summary.
type FindingCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// ScanSummary is one row of the scan list.
type ScanSummary struct {
	ID            string        `json:"id"`
	TargetBaseURL string        `json:"target_base_url"`
	Status        string        `json:"status"`
	Progress      int           `json:"progress"`
	FindingCounts FindingCounts `json:"finding_counts"`
	LastRunAt     *string       `json:"last_run_at"`
}

// Operation is one spec operation on a scan.
type Operation struct {
	ID      string `json:"id"`
	Method  string `json:"method"`
	Path    string `json:"path"`
	Enabled bool   `json:"enabled"`
}

// CredentialProfile is a stored identity as the server shows it: no secret.
type CredentialProfile struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	Role       string  `json:"role"`
	AuthType   string  `json:"auth_type"`
	HeaderName *string `json:"header_name"`
	// Privilege is null when the server infers it from the role name.
	Privilege *int `json:"privilege"`
	// Tenant is the workspace the identity belongs to; null when undeclared.
	Tenant      *string        `json:"tenant"`
	GrantType   string         `json:"grant_type"`
	TokenURL    *string        `json:"token_url"`
	GrantParams map[string]any `json:"grant_params"`
	// LocalOnly identities have no secret on the server: only a local run can use them.
	LocalOnly bool `json:"local_only"`
}

// Scan is the full scan record.
type Scan struct {
	ID                 string              `json:"id"`
	TargetBaseURL      string              `json:"target_base_url"`
	Status             string              `json:"status"`
	Progress           int                 `json:"progress"`
	FailureReason      *string             `json:"failure_reason"`
	Operations         []Operation         `json:"operations"`
	SpecText           *string             `json:"spec_text"`
	CredentialProfiles []CredentialProfile `json:"credential_profiles"`
	ManagedConfig      map[string]any      `json:"managed_config"`
	// A schedule is a standing run request set in the web: its interval and the
	// options every scheduled run uses. The CLI has no schedules of its own, but
	// `scans show --json` prints this struct, so the fields stay.
	ScheduleMinutes *int           `json:"schedule_minutes"`
	NextRunAt       *string        `json:"next_run_at"`
	ScheduleOptions map[string]any `json:"schedule_options"`
	// CostUSD is what AI adjudication has spent on this scan so far.
	CostUSD float64 `json:"cost_usd"`
}

// Event is one line of a scan's progress log.
type Event struct {
	Stage     string `json:"stage"`
	Pct       int    `json:"pct"`
	Message   string `json:"message"`
	CreatedAt string `json:"created_at"`
}

// Finding is one finding on the scan's current run.
type Finding struct {
	ID          string         `json:"id"`
	OperationID *string        `json:"operation_id"`
	Check       string         `json:"check"`
	Fingerprint string         `json:"fingerprint"`
	OwaspID     *string        `json:"owasp_id"`
	Severity    string         `json:"severity"`
	Confidence  string         `json:"confidence"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Evidence    map[string]any `json:"evidence"`
	Remediation string         `json:"remediation"`
	References  []string       `json:"references"`
	Verdict     string         `json:"verdict"`
	AIRationale *string        `json:"ai_rationale"`
	// Raw is the FindingOut exactly as the server sent it, so `findings show
	// --json` prints every field, including ones this struct does not model.
	Raw map[string]any `json:"-"`
}

// UnmarshalJSON keeps the server's object alongside the typed fields.
func (f *Finding) UnmarshalJSON(data []byte) error {
	type typed Finding
	var t typed
	if err := json.Unmarshal(data, &t); err != nil {
		return err
	}
	*f = Finding(t)
	return json.Unmarshal(data, &f.Raw)
}

// FindingSummary is the counts over a scan's whole finding set, not one page.
type FindingSummary struct {
	Total            int            `json:"total"`
	Active           int            `json:"active"`
	Dismissed        int            `json:"dismissed"`
	VerifiedCritical int            `json:"verified_critical"`
	VerifiedHigh     int            `json:"verified_high"`
	Severity         map[string]int `json:"severity"`
}

// LedgerEntry is one AI call in the scan's token/cost ledger.
type LedgerEntry struct {
	Phase      string `json:"phase"`
	Model      string `json:"model"`
	TokensIn   int    `json:"tokens_in"`
	TokensOut  int    `json:"tokens_out"`
	CostMicros int64  `json:"cost_micros"`
}

// AiModelUsage is one model aggregated across the scan's calls.
type AiModelUsage struct {
	Model     string   `json:"model"`
	Phases    []string `json:"phases"`
	Calls     int      `json:"calls"`
	TokensIn  int      `json:"tokens_in"`
	TokensOut int      `json:"tokens_out"`
	CostUSD   float64  `json:"cost_usd"`
}

// Cost is a scan's AI spend: the total, the per-model rollup, the ledger.
type Cost struct {
	ScanID   string         `json:"scan_id"`
	TotalUSD float64        `json:"total_usd"`
	Entries  []LedgerEntry  `json:"entries"`
	Models   []AiModelUsage `json:"models"`
}

// CoverageRow is what the latest run did to one operation.
type CoverageRow struct {
	OperationID *string  `json:"operation_id"`
	Method      string   `json:"method"`
	Path        string   `json:"path"`
	Enabled     bool     `json:"enabled"`
	Requests    int      `json:"requests"`
	Checks      []string `json:"checks"`
	Findings    int      `json:"findings"`
}

// RunGaps is what a run was asked to do and did not.
type RunGaps struct {
	NotRun          []string `json:"not_run"`
	BudgetExhausted bool     `json:"budget_exhausted"`
	FailedChecks    []string `json:"failed_checks"`
}

// ScanRun is one past execution of a scan, as the run history lists it.
type ScanRun struct {
	RunNumber     int            `json:"run_number"`
	Status        string         `json:"status"`
	StartedAt     string         `json:"started_at"`
	FinishedAt    *string        `json:"finished_at"`
	FindingsCount int            `json:"findings_count"`
	Requests      int            `json:"requests"`
	Options       map[string]any `json:"options"`
	Executor      map[string]any `json:"executor"`
	Gaps          RunGaps        `json:"gaps"`
	TraceCount    int            `json:"trace_count"`
	// Raw is the ScanRunOut exactly as the server sent it (runs --json).
	Raw map[string]any `json:"-"`
}

// UnmarshalJSON keeps the server's object alongside the typed fields.
func (r *ScanRun) UnmarshalJSON(data []byte) error {
	type typed ScanRun
	var t typed
	if err := json.Unmarshal(data, &t); err != nil {
		return err
	}
	*r = ScanRun(t)
	return json.Unmarshal(data, &r.Raw)
}

// MutationRequestRow is the sanitized request half of one trace row. Fields
// arrived from the target are redacted server-side, not here.
type MutationRequestRow struct {
	Headers      map[string]string `json:"headers"`
	QueryFields  []string          `json:"query_fields"`
	JSONShape    any               `json:"json_shape"`
	JSONBody     string            `json:"json_body"`
	ContentBytes int               `json:"content_bytes"`
}

// MutationResponseRow is the sanitized response half of one trace row.
type MutationResponseRow struct {
	Status      *int              `json:"status"`
	Headers     map[string]string `json:"headers"`
	ContentType string            `json:"content_type"`
	BodyBytes   int               `json:"body_bytes"`
	Body        string            `json:"body"`
	Truncated   bool              `json:"truncated"`
	BodyOmitted bool              `json:"body_omitted"`
	JSONShape   any               `json:"json_shape"`
}

// MutationRow is one request/response the run sent.
type MutationRow struct {
	Sequence  int                 `json:"sequence"`
	Method    string              `json:"method"`
	Route     string              `json:"route"`
	Identity  string              `json:"identity"`
	Pass      string              `json:"pass"`
	ElapsedMS *float64            `json:"elapsed_ms"`
	Error     *string             `json:"error"`
	Check     string              `json:"check"`
	Request   MutationRequestRow  `json:"request"`
	Response  MutationResponseRow `json:"response"`
	// Raw is the MutationRow exactly as the server sent it (runs trace --json).
	Raw map[string]any `json:"-"`
}

// UnmarshalJSON keeps the server's object alongside the typed fields.
func (m *MutationRow) UnmarshalJSON(data []byte) error {
	type typed MutationRow
	var t typed
	if err := json.Unmarshal(data, &t); err != nil {
		return err
	}
	*m = MutationRow(t)
	return json.Unmarshal(data, &m.Raw)
}

// RunTracePage is one page of a run's request log.
type RunTracePage struct {
	RunNumber int           `json:"run_number"`
	Total     int           `json:"total"`
	Offset    int           `json:"offset"`
	Rows      []MutationRow `json:"rows"`
}

// RunFinding is a finding as archived in a run snapshot / diff.
type RunFinding struct {
	Check       string `json:"check"`
	Severity    string `json:"severity"`
	Confidence  string `json:"confidence"`
	Fingerprint string `json:"fingerprint"`
	Title       string `json:"title"`
	Verdict     string `json:"verdict"`
}

// Diff is what changed between two runs.
type Diff struct {
	FromRun         int          `json:"from_run"`
	ToRun           int          `json:"to_run"`
	Added           []RunFinding `json:"added"`
	Resolved        []RunFinding `json:"resolved"`
	NotRetested     []RunFinding `json:"not_retested"`
	Unchanged       []RunFinding `json:"unchanged"`
	OptionsChanged  bool         `json:"options_changed"`
	ExecutorChanged bool         `json:"executor_changed"`
	Unmatchable     int          `json:"unmatchable"`
}

// Credential is what `cred add` sends. The secret is write-only on the server.
type Credential struct {
	Name       string  `json:"name"`
	Role       string  `json:"role"`
	AuthType   string  `json:"auth_type"`
	HeaderName *string `json:"header_name,omitempty"`
	// Omitted for a local-only identity: the server refuses one there.
	Secret    string `json:"secret,omitempty"`
	LocalOnly bool   `json:"local_only,omitempty"`
	// Privilege is explicit when set; otherwise the server infers it from role.
	Privilege *int `json:"privilege,omitempty"`
	// Tenant is the workspace the identity belongs to.
	Tenant *string `json:"tenant,omitempty"`
	// A non-static grant mints the token: Secret is its sensitive half.
	GrantType   string         `json:"grant_type,omitempty"`
	TokenURL    *string        `json:"token_url,omitempty"`
	GrantParams map[string]any `json:"grant_params,omitempty"`
}

// CredentialUpdate replaces an identity's shape. Secret is optional: nil keeps
// the stored one, which is how a local run updates a shape without sending it.
type CredentialUpdate struct {
	Name        string         `json:"name"`
	Role        string         `json:"role"`
	AuthType    string         `json:"auth_type"`
	HeaderName  *string        `json:"header_name,omitempty"`
	Secret      *string        `json:"secret,omitempty"`
	Privilege   *int           `json:"privilege,omitempty"`
	Tenant      *string        `json:"tenant,omitempty"`
	GrantType   string         `json:"grant_type,omitempty"`
	TokenURL    *string        `json:"token_url,omitempty"`
	GrantParams map[string]any `json:"grant_params,omitempty"`
}

// AuthHintScheme is one security scheme the server found in a spec, with the
// identity shape it maps to.
type AuthHintScheme struct {
	Name        string   `json:"name"`
	Kind        string   `json:"kind"`
	AuthType    string   `json:"auth_type"`
	HeaderName  *string  `json:"header_name"`
	GrantType   string   `json:"grant_type"`
	TokenURL    *string  `json:"token_url"`
	Scopes      []string `json:"scopes"`
	Description *string  `json:"description"`
}

// AuthHintRole is one role the spec implies, with the privilege its name
// suggests.
type AuthHintRole struct {
	Name      string `json:"name"`
	Privilege int    `json:"privilege"`
}

// AuthHints is POST /specs/auth-hints: what the spec says about authentication,
// so `init` can suggest a project file instead of asking from nothing.
type AuthHints struct {
	Suggested           string           `json:"suggested"` // public | single | roles
	Reason              string           `json:"reason"`
	Operations          int              `json:"operations"`
	ProtectedOperations int              `json:"protected_operations"`
	Schemes             []AuthHintScheme `json:"schemes"`
	Roles               []AuthHintRole   `json:"roles"`
}

// ManagedConfig tells the server which settings a project file owns.
type ManagedConfig struct {
	Path       string   `json:"path"`
	Digest     string   `json:"digest"`
	Commit     *string  `json:"commit,omitempty"`
	Fields     []string `json:"fields"`
	Identities []string `json:"identities"`
}

// PassCapability is what the server says about one opt-in pass. Available may
// be true with a non-null reason: the pass runs, but partially (for example one
// of its tools is missing).
type PassCapability struct {
	Available bool    `json:"available"`
	Reason    *string `json:"reason"`
}

// PremiumCapability is the calling tenant's entitlement.
type PremiumCapability struct {
	Available bool    `json:"available"`
	Plan      string  `json:"plan"`
	Reason    *string `json:"reason"`
}

// Capabilities is GET /capabilities. Passes is keyed by RunRequest field name
// (security_review, genai_payloads, ...), so a key this struct does not know
// is simply absent — an older server may report fewer passes.
type Capabilities struct {
	Passes  map[string]PassCapability `json:"passes"`
	Premium PremiumCapability         `json:"premium"`
}

// --- calls -----------------------------------------------------------------

// Ready checks the server is up and its database reachable.
func (c *Client) Ready(ctx context.Context) error {
	_, err := c.do(ctx, RouteHealthReady, "", nil, nil, nil)
	return err
}

// Capabilities asks what this deployment can run and what the tenant may run.
// It is advisory and may 404 on a server older than the route.
func (c *Client) Capabilities(ctx context.Context) (Capabilities, error) {
	var out Capabilities
	_, err := c.do(ctx, RouteCapabilities, "", nil, nil, &out)
	return out, err
}

// ListScans returns the tenant's scans, newest first, across every page.
func (c *Client) ListScans(ctx context.Context) ([]ScanSummary, error) {
	out := make([]ScanSummary, 0, scansPageSize)
	for page := 0; page < maxListPages; page++ {
		query := url.Values{}
		query.Set("limit", strconv.Itoa(scansPageSize))
		query.Set("offset", strconv.Itoa(len(out)))
		var batch []ScanSummary
		if _, err := c.do(ctx, RouteListScans, "", query, nil, &batch); err != nil {
			return nil, err
		}
		out = append(out, batch...)
		if len(batch) < scansPageSize {
			return out, nil
		}
	}
	return nil, fmt.Errorf("scan list pagination exceeded %d pages", maxListPages)
}

// CreateScan creates an empty scan for a target.
func (c *Client) CreateScan(ctx context.Context, target string) (Scan, error) {
	var out Scan
	_, err := c.do(ctx, RouteCreateScan, "", nil, map[string]string{"target_base_url": target}, &out)
	return out, err
}

// GetScan returns one scan.
func (c *Client) GetScan(ctx context.Context, id string) (Scan, error) {
	var out Scan
	_, err := c.do(ctx, RouteGetScan, id, nil, nil, &out)
	return out, err
}

// DeleteScan deletes a scan and its data.
func (c *Client) DeleteScan(ctx context.Context, id string) error {
	_, err := c.do(ctx, RouteDeleteScan, id, nil, nil, nil)
	return err
}

// UploadSpec ingests an OpenAPI/Swagger/HAR/Postman document as text.
func (c *Client) UploadSpec(ctx context.Context, id, content string) (Scan, error) {
	var out Scan
	_, err := c.do(ctx, RouteUploadSpec, id, nil, map[string]string{"content": content}, &out)
	return out, err
}

// UpdateTarget changes a scan's target base URL.
func (c *Client) UpdateTarget(ctx context.Context, id, target string) (Scan, error) {
	var out Scan
	_, err := c.do(ctx, RouteUpdateScan, id, nil, map[string]string{"target_base_url": target}, &out)
	return out, err
}

// UpdateCredential replaces one identity's shape (and its secret, when given).
func (c *Client) UpdateCredential(ctx context.Context, scanID, credID string, cred CredentialUpdate) error {
	u := c.base + strings.ReplaceAll(expand(RouteUpdateCred.Path, scanID), "{cred_id}", url.PathEscape(credID))
	headers := map[string]string{}
	if c.key != "" {
		headers["X-API-Key"] = c.key
	}
	_, err := c.send(ctx, RouteUpdateCred, u, headers, cred, nil)
	return err
}

// DeleteCredential removes one identity from a scan.
func (c *Client) DeleteCredential(ctx context.Context, scanID, credID string) error {
	u := c.base + strings.ReplaceAll(expand(RouteDeleteCred.Path, scanID), "{cred_id}", url.PathEscape(credID))
	headers := map[string]string{}
	if c.key != "" {
		headers["X-API-Key"] = c.key
	}
	_, err := c.send(ctx, RouteDeleteCred, u, headers, nil, nil)
	return err
}

// SetManagedConfig records which settings a project file owns on a scan.
func (c *Client) SetManagedConfig(ctx context.Context, id string, mc ManagedConfig) error {
	_, err := c.do(ctx, RouteManagedConfig, id, nil, mc, nil)
	return err
}

// AddCredential attaches an identity to a scan.
func (c *Client) AddCredential(ctx context.Context, id string, cred Credential) error {
	_, err := c.do(ctx, RouteAddCredential, id, nil, cred, nil)
	return err
}

// AuthHints asks what a spec says about authentication, without a scan: the
// server parses the text and maps its security schemes to identity shapes.
func (c *Client) AuthHints(ctx context.Context, specText string) (AuthHints, error) {
	var out AuthHints
	_, err := c.do(ctx, RouteAuthHints, "", nil, map[string]string{"spec": specText}, &out)
	return out, err
}

// Cancel asks a running scan to stop at the next check boundary.
func (c *Client) Cancel(ctx context.Context, id string) error {
	_, err := c.do(ctx, RouteCancel, id, nil, nil, nil)
	return err
}

// Events returns the scan's progress log.
func (c *Client) Events(ctx context.Context, id string) ([]Event, error) {
	var out []Event
	_, err := c.do(ctx, RouteEvents, id, nil, nil, &out)
	return out, err
}

// Runs returns the scan's run history, newest first, up to limit runs.
func (c *Client) Runs(ctx context.Context, id string, limit int) ([]ScanRun, error) {
	query := url.Values{}
	query.Set("limit", strconv.Itoa(limit))
	var out []ScanRun
	_, err := c.do(ctx, RouteListRuns, id, query, nil, &out)
	return out, err
}

// RunTrace returns one page of a run's request/response log.
func (c *Client) RunTrace(ctx context.Context, id string, run, offset, limit int) (RunTracePage, error) {
	u := c.base + strings.ReplaceAll(expand(RouteRunTrace.Path, id), "{run_number}", strconv.Itoa(run))
	q := url.Values{}
	q.Set("offset", strconv.Itoa(offset))
	q.Set("limit", strconv.Itoa(limit))
	headers := map[string]string{}
	if c.key != "" {
		headers["X-API-Key"] = c.key
	}
	var out RunTracePage
	_, err := c.send(ctx, RouteRunTrace, u+"?"+q.Encode(), headers, nil, &out)
	return out, err
}

// Findings returns the scan's current findings, across every page.
//
// The gate this feeds must see the whole result set: reading one page lets a
// scan pass `--fail-on` when its only active high finding is behind a page of
// dismissed criticals.
func (c *Client) Findings(ctx context.Context, id string) ([]Finding, error) {
	out := make([]Finding, 0, findingsPageSize)
	for page := 0; page < maxListPages; page++ {
		query := url.Values{}
		query.Set("limit", strconv.Itoa(findingsPageSize))
		query.Set("offset", strconv.Itoa(len(out)))
		var batch []Finding
		if _, err := c.do(ctx, RouteFindings, id, query, nil, &batch); err != nil {
			return nil, err
		}
		out = append(out, batch...)
		if len(batch) < findingsPageSize {
			return out, nil
		}
	}
	return nil, fmt.Errorf("findings pagination exceeded %d pages", maxListPages)
}

// SetVerdict marks one finding unreviewed, confirmed or dismissed. The server
// remembers the verdict against the finding's fingerprint, so it carries to
// later runs.
func (c *Client) SetVerdict(ctx context.Context, scanID, findingID, verdict string) (Finding, error) {
	u := c.base + strings.ReplaceAll(expand(RouteSetVerdict.Path, scanID),
		"{finding_id}", url.PathEscape(findingID))
	headers := map[string]string{}
	if c.key != "" {
		headers["X-API-Key"] = c.key
	}
	var out Finding
	_, err := c.send(ctx, RouteSetVerdict, u, headers, map[string]string{"verdict": verdict}, &out)
	return out, err
}

// FindingSummary returns the counts over every finding on the scan.
func (c *Client) FindingSummary(ctx context.Context, id string) (FindingSummary, error) {
	var out FindingSummary
	_, err := c.do(ctx, RouteFindingSummary, id, nil, nil, &out)
	return out, err
}

// Coverage returns what the latest run did to each operation.
func (c *Client) Coverage(ctx context.Context, id string) ([]CoverageRow, error) {
	out := make([]CoverageRow, 0)
	_, err := c.do(ctx, RouteCoverage, id, nil, nil, &out)
	return out, err
}

// Cost returns the scan's AI ledger and totals.
func (c *Client) Cost(ctx context.Context, id string) (Cost, error) {
	var out Cost
	_, err := c.do(ctx, RouteCost, id, nil, nil, &out)
	return out, err
}

// Diff compares the two most recent runs. A scan with one run answers 409.
func (c *Client) Diff(ctx context.Context, id string) (Diff, error) {
	var out Diff
	_, err := c.do(ctx, RouteDiff, id, nil, nil, &out)
	return out, err
}

// Report downloads a report in the named format (see ReportFormats).
func (c *Client) Report(ctx context.Context, id, format string) ([]byte, error) {
	route, ok := ReportFormats[format]
	if !ok {
		return nil, fmt.Errorf("unknown report format %q", format)
	}
	return c.do(ctx, route, id, nil, nil, nil)
}

// LocalClaim is the answer to a local-run claim, kept as the server sent it:
// the runner is handed the same document, so nothing is lost in translation.
type LocalClaim map[string]any

// Str reads a string field ("" when absent).
func (l LocalClaim) Str(key string) string {
	s, _ := l[key].(string)
	return s
}

// Credentials lists the credential shapes (role, name, auth_type, ...).
func (l LocalClaim) Credentials() []map[string]any {
	var out []map[string]any
	raw, _ := l["credentials"].([]any)
	for _, item := range raw {
		if m, ok := item.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// ClaimLocalRun claims a scan to run on this machine. The server answers the
// authorization gate and the target guard, issues the request budget, and
// returns a per-run token (once). body is the RunRequest JSON.
func (c *Client) ClaimLocalRun(ctx context.Context, id string, body map[string]any) (LocalClaim, error) {
	var out LocalClaim
	_, err := c.do(ctx, RouteClaimLocalRun, id, nil, body, &out)
	return out, err
}

// FailLocalRun ends a claimed run without results, authenticated by the run's
// own token. It is the CLI's safety net when the runner container dies before
// it could say so itself.
func (c *Client) FailLocalRun(ctx context.Context, runID, token, reason string, cancelled bool) error {
	u := c.base + strings.ReplaceAll(RouteRunnerFail.Path, "{run_id}", url.PathEscape(runID))
	_, err := c.send(ctx, RouteRunnerFail, u, map[string]string{"X-Run-Token": token},
		map[string]any{"reason": reason, "cancelled": cancelled}, nil)
	return err
}
