// Package mcp is a minimal Model Context Protocol server over stdio: tools,
// resources and prompts, one JSON-RPC message per line.
//
// It is hand-written for the same reason the API client is: the CLI is one
// static binary with two dependencies, and the part of the protocol a
// setup helper needs is small. Messages are handled one at a time, in order.
// Nothing but protocol messages is written to the output; a caller that wants
// to log uses stderr.
package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Protocol versions this server speaks, newest first. A client asking for one
// of them gets it back; any other request is answered with the newest.
var Versions = []string{"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}

// maxMessageBytes bounds one incoming line. The largest legitimate argument is
// a draft project file, which the project loader caps far below this.
const maxMessageBytes = 1 << 20

// JSON-RPC and MCP error codes.
const (
	codeParse            = -32700
	codeInvalidRequest   = -32600
	codeMethodNotFound   = -32601
	codeInvalidParams    = -32602
	codeInternal         = -32603
	codeResourceNotFound = -32002
)

// Tool is one callable tool. Call returns the result as a value to encode as
// JSON text, or an error the agent sees as a failed call (isError), not a
// protocol error: the agent can read it and try again.
type Tool struct {
	Name        string
	Title       string
	Description string
	// InputSchema is a JSON Schema object for the arguments.
	InputSchema map[string]any
	// ReadOnly and OpenWorld become the tool's annotations: whether it changes
	// anything, and whether it talks to something outside this machine.
	ReadOnly  bool
	OpenWorld bool
	Call      func(ctx context.Context, args json.RawMessage) (any, error)
}

// Resource is one readable document.
type Resource struct {
	URI         string
	Name        string
	Title       string
	Description string
	MimeType    string
	Text        string
}

// PromptArgument is one argument a prompt accepts.
type PromptArgument struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
}

// Prompt is one prompt template. Render builds the user message from the
// arguments the client passed.
type Prompt struct {
	Name        string
	Title       string
	Description string
	Arguments   []PromptArgument
	Render      func(args map[string]string) (string, error)
}

// Server is the set of things one MCP session can use.
type Server struct {
	Name         string
	Version      string
	Instructions string
	Tools        []Tool
	Resources    []Resource
	Prompts      []Prompt
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	// A response from the client carries one of these instead of a method.
	Result json.RawMessage `json:"result,omitempty"`
	Error  json.RawMessage `json:"error,omitempty"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Serve reads messages from in and writes answers to out until in ends or ctx
// is cancelled. Only a failure to read or write ends it with an error.
//
// Reading happens on its own goroutine so a cancelled context (Ctrl-C) ends the
// session at once instead of waiting for the next line on stdin.
func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	type read struct {
		line []byte
		err  error
	}
	lines := make(chan read)
	go func() {
		r := bufio.NewReaderSize(in, 64<<10)
		for {
			line, err := readLine(r)
			select {
			case lines <- read{line, err}:
			case <-ctx.Done():
				return
			}
			if err != nil && !errors.Is(err, errTooLong) {
				return
			}
		}
	}()
	w := bufio.NewWriter(out)
	send := func(resp *response) error {
		data, err := json.Marshal(resp)
		if err != nil {
			data, _ = json.Marshal(errorResponse(resp.ID, codeInternal, "cannot encode the answer"))
		}
		if _, err := w.Write(append(data, '\n')); err != nil {
			return err
		}
		return w.Flush()
	}
	for {
		var next read
		select {
		case <-ctx.Done():
			return nil
		case next = <-lines:
		}
		if errors.Is(next.err, errTooLong) {
			if err := send(errorResponse(nil, codeInvalidRequest, "message too large")); err != nil {
				return err
			}
			continue
		}
		if len(bytes.TrimSpace(next.line)) > 0 {
			if resp := s.handle(ctx, next.line); resp != nil {
				if err := send(resp); err != nil {
					return err
				}
			}
		}
		if errors.Is(next.err, io.EOF) {
			return nil
		}
		if next.err != nil {
			return next.err
		}
	}
}

var errTooLong = errors.New("message too large")

// readLine reads one newline-terminated message, discarding the rest of a line
// longer than maxMessageBytes so one bad message cannot end the session.
func readLine(r *bufio.Reader) ([]byte, error) {
	var buf []byte
	for {
		chunk, err := r.ReadSlice('\n')
		if len(buf)+len(chunk) > maxMessageBytes {
			for errors.Is(err, bufio.ErrBufferFull) {
				_, err = r.ReadSlice('\n')
			}
			if err != nil && !errors.Is(err, io.EOF) {
				return nil, err
			}
			return nil, errTooLong
		}
		buf = append(buf, chunk...)
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return buf, err
	}
}

func errorResponse(id json.RawMessage, code int, msg string) *response {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	return &response{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}}
}

// handle answers one message. A notification (no id) gets no answer.
func (s *Server) handle(ctx context.Context, line []byte) *response {
	trimmed := bytes.TrimSpace(line)
	if trimmed[0] == '[' {
		return errorResponse(nil, codeInvalidRequest, "batches are not supported")
	}
	var req request
	if err := json.Unmarshal(trimmed, &req); err != nil {
		return errorResponse(nil, codeParse, "not valid JSON")
	}
	if req.Method == "" && (len(req.Result) > 0 || len(req.Error) > 0) {
		return nil // a response is never answered; this server sends no requests
	}
	if req.JSONRPC != "2.0" || req.Method == "" {
		if len(req.ID) == 0 {
			return nil
		}
		return errorResponse(req.ID, codeInvalidRequest, "not a JSON-RPC 2.0 request")
	}
	if len(req.ID) == 0 || bytes.Equal(req.ID, []byte("null")) {
		return nil // notifications/initialized, notifications/cancelled, ...
	}
	result, rerr := s.dispatch(ctx, req)
	if rerr != nil {
		return errorResponse(req.ID, rerr.Code, rerr.Message)
	}
	return &response{JSONRPC: "2.0", ID: req.ID, Result: result}
}

func (s *Server) dispatch(ctx context.Context, req request) (any, *rpcError) {
	switch req.Method {
	case "initialize":
		return s.initialize(req.Params)
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		return s.listTools(), nil
	case "tools/call":
		return s.callTool(ctx, req.Params)
	case "resources/list":
		return s.listResources(), nil
	case "resources/templates/list":
		return map[string]any{"resourceTemplates": []any{}}, nil
	case "resources/read":
		return s.readResource(req.Params)
	case "prompts/list":
		return s.listPrompts(), nil
	case "prompts/get":
		return s.getPrompt(req.Params)
	}
	return nil, &rpcError{codeMethodNotFound, fmt.Sprintf("method %q is not supported", req.Method)}
}

func (s *Server) initialize(params json.RawMessage) (any, *rpcError) {
	var p struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, &rpcError{codeInvalidParams, "initialize: bad params"}
		}
	}
	version := Versions[0]
	for _, v := range Versions {
		if v == p.ProtocolVersion {
			version = v
		}
	}
	out := map[string]any{
		"protocolVersion": version,
		"capabilities": map[string]any{
			"tools":     map[string]any{},
			"resources": map[string]any{},
			"prompts":   map[string]any{},
		},
		"serverInfo": map[string]any{"name": s.Name, "version": s.Version},
	}
	if s.Instructions != "" {
		out["instructions"] = s.Instructions
	}
	return out, nil
}

func (s *Server) listTools() any {
	tools := make([]map[string]any, 0, len(s.Tools))
	for _, t := range s.Tools {
		schema := t.InputSchema
		if schema == nil {
			schema = map[string]any{"type": "object", "properties": map[string]any{}}
		}
		entry := map[string]any{
			"name":        t.Name,
			"description": t.Description,
			"inputSchema": schema,
			"annotations": map[string]any{
				"title":           t.Title,
				"readOnlyHint":    t.ReadOnly,
				"destructiveHint": false,
				"idempotentHint":  t.ReadOnly,
				"openWorldHint":   t.OpenWorld,
			},
		}
		if t.Title != "" {
			entry["title"] = t.Title
		}
		tools = append(tools, entry)
	}
	return map[string]any{"tools": tools}
}

func (s *Server) callTool(ctx context.Context, params json.RawMessage) (any, *rpcError) {
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &rpcError{codeInvalidParams, "tools/call: bad params"}
	}
	for _, t := range s.Tools {
		if t.Name != p.Name {
			continue
		}
		args := p.Arguments
		if len(args) == 0 || bytes.Equal(args, []byte("null")) {
			args = json.RawMessage("{}")
		}
		value, err := t.Call(ctx, args)
		if err != nil {
			return toolResult(err.Error(), true), nil
		}
		data, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			return toolResult("cannot encode the result", true), nil
		}
		return toolResult(string(data), false), nil
	}
	return nil, &rpcError{codeInvalidParams, fmt.Sprintf("unknown tool %q", p.Name)}
}

func toolResult(text string, isError bool) map[string]any {
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
		"isError": isError,
	}
}

func (s *Server) listResources() any {
	out := make([]map[string]any, 0, len(s.Resources))
	for _, r := range s.Resources {
		entry := map[string]any{
			"uri":         r.URI,
			"name":        r.Name,
			"description": r.Description,
			"mimeType":    r.MimeType,
		}
		if r.Title != "" {
			entry["title"] = r.Title
		}
		out = append(out, entry)
	}
	return map[string]any{"resources": out}
}

func (s *Server) readResource(params json.RawMessage) (any, *rpcError) {
	var p struct {
		URI string `json:"uri"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &rpcError{codeInvalidParams, "resources/read: bad params"}
	}
	for _, r := range s.Resources {
		if r.URI == p.URI {
			return map[string]any{"contents": []map[string]any{{
				"uri": r.URI, "mimeType": r.MimeType, "text": r.Text,
			}}}, nil
		}
	}
	return nil, &rpcError{codeResourceNotFound, fmt.Sprintf("resource %q not found", p.URI)}
}

func (s *Server) listPrompts() any {
	out := make([]map[string]any, 0, len(s.Prompts))
	for _, p := range s.Prompts {
		args := p.Arguments
		if args == nil {
			args = []PromptArgument{}
		}
		entry := map[string]any{"name": p.Name, "description": p.Description, "arguments": args}
		if p.Title != "" {
			entry["title"] = p.Title
		}
		out = append(out, entry)
	}
	return map[string]any{"prompts": out}
}

func (s *Server) getPrompt(params json.RawMessage) (any, *rpcError) {
	var p struct {
		Name      string            `json:"name"`
		Arguments map[string]string `json:"arguments"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &rpcError{codeInvalidParams, "prompts/get: bad params"}
	}
	for _, pr := range s.Prompts {
		if pr.Name != p.Name {
			continue
		}
		for _, a := range pr.Arguments {
			if a.Required && p.Arguments[a.Name] == "" {
				return nil, &rpcError{codeInvalidParams, fmt.Sprintf("prompt %q needs argument %q", pr.Name, a.Name)}
			}
		}
		text, err := pr.Render(p.Arguments)
		if err != nil {
			return nil, &rpcError{codeInvalidParams, err.Error()}
		}
		return map[string]any{
			"description": pr.Description,
			"messages": []map[string]any{{
				"role":    "user",
				"content": map[string]any{"type": "text", "text": text},
			}},
		}, nil
	}
	return nil, &rpcError{codeInvalidParams, fmt.Sprintf("unknown prompt %q", p.Name)}
}
