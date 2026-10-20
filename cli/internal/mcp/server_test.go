package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func testServer() *Server {
	return &Server{
		Name: "t", Version: "1",
		Tools: []Tool{
			{Name: "ok", Title: "Ok", ReadOnly: true, Call: func(context.Context, json.RawMessage) (any, error) {
				return map[string]string{"a": "b"}, nil
			}},
			{Name: "fails", Title: "Fails", Call: func(context.Context, json.RawMessage) (any, error) {
				return nil, errors.New("it broke")
			}},
		},
		Resources: []Resource{{URI: "x://doc", Name: "doc", MimeType: "text/markdown", Text: "hello"}},
	}
}

// serve runs the server over lines and returns its answers in order.
func serve(t *testing.T, s *Server, lines ...string) []map[string]any {
	t.Helper()
	var out bytes.Buffer
	if err := s.Serve(context.Background(), strings.NewReader(strings.Join(lines, "\n")), &out); err != nil {
		t.Fatal(err)
	}
	var answers []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("not one JSON message per line: %q", line)
		}
		answers = append(answers, m)
	}
	return answers
}

func errCode(m map[string]any) int {
	e, ok := m["error"].(map[string]any)
	if !ok {
		return 0
	}
	return int(e["code"].(float64))
}

func TestInitializeNegotiatesTheVersion(t *testing.T) {
	got := serve(t, testServer(),
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}`,
		`{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"1999-01-01"}}`,
	)
	if v := got[0]["result"].(map[string]any)["protocolVersion"]; v != "2024-11-05" {
		t.Errorf("a supported version should be echoed, got %v", v)
	}
	if v := got[1]["result"].(map[string]any)["protocolVersion"]; v != Versions[0] {
		t.Errorf("an unknown version should get the newest, got %v", v)
	}
}

func TestNotificationsGetNoAnswerAndErrorsKeepTheSessionGoing(t *testing.T) {
	got := serve(t, testServer(),
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":9,"result":{}}`,
		`not json`,
		`[{"jsonrpc":"2.0","id":1,"method":"ping"}]`,
		`{"jsonrpc":"2.0","id":2,"method":"nope"}`,
		`{"jsonrpc":"2.0","id":3,"method":"resources/read","params":{"uri":"x://missing"}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"missing"}}`,
		`{"jsonrpc":"2.0","id":5,"method":"ping"}`,
	)
	want := []int{codeParse, codeInvalidRequest, codeMethodNotFound, codeResourceNotFound, codeInvalidParams, 0}
	if len(got) != len(want) {
		t.Fatalf("want %d answers, got %d: %v", len(want), len(got), got)
	}
	for i, code := range want {
		if c := errCode(got[i]); c != code {
			t.Errorf("answer %d: code %d, want %d (%v)", i, c, code, got[i])
		}
	}
}

func TestAToolErrorIsAResultTheAgentCanRead(t *testing.T) {
	got := serve(t, testServer(),
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"ok"}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"fails","arguments":{}}}`,
	)
	ok := got[0]["result"].(map[string]any)
	if ok["isError"] != false || !strings.Contains(ok["content"].([]any)[0].(map[string]any)["text"].(string), `"a": "b"`) {
		t.Errorf("want the value as JSON text, got %v", ok)
	}
	failed := got[1]["result"].(map[string]any)
	if failed["isError"] != true || failed["content"].([]any)[0].(map[string]any)["text"] != "it broke" {
		t.Errorf("want isError with the message, got %v", failed)
	}
}

func TestAnOversizeMessageIsRefusedAndTheNextOneAnswered(t *testing.T) {
	huge := `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"pad":"` + strings.Repeat("x", maxMessageBytes) + `"}}`
	got := serve(t, testServer(), huge, `{"jsonrpc":"2.0","id":2,"method":"ping"}`)
	if len(got) != 2 || errCode(got[0]) != codeInvalidRequest || errCode(got[1]) != 0 {
		t.Fatalf("want a refusal then a pong, got %v", got)
	}
}

func TestCancellingTheContextEndsAServerWaitingForInput(t *testing.T) {
	pr, pw := io.Pipe()
	defer pw.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- testServer().Serve(ctx, pr, io.Discard) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("a cancelled session should end cleanly, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve kept blocking on stdin after the context was cancelled (Ctrl-C would hang)")
	}
}
