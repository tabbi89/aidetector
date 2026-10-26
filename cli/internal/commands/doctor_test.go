package commands

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
)

// doctorHarness gives the harness a Docker that answers as told.
func doctorHarness(t *testing.T, f *fake, daemon error, images, networks map[string]bool) *harness {
	t.Helper()
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	h := newHarness(t, srv, "", false)
	h.env.DockerVersion = func(context.Context) (string, error) {
		if daemon != nil {
			return "", daemon
		}
		return "27.1.0", nil
	}
	h.env.ImageExists = func(_ context.Context, image string) (bool, error) { return images[image], nil }
	h.env.NetworkExists = func(_ context.Context, name string) (bool, error) { return networks[name], nil }
	return h
}

func allPasses() map[string]any {
	return map[string]any{"passes": map[string]any{"zap": map[string]any{"available": true, "reason": nil}},
		"premium": map[string]any{"available": false, "plan": "free", "reason": "free plan"},
		"levels":  map[string]any{}}
}

func TestDoctorPassesOnAReadyMachineAndTouchesNothing(t *testing.T) {
	f := &fake{capabilities: allPasses()}
	h := doctorHarness(t, f, nil, map[string]bool{runnerImageDefault: true}, map[string]bool{"scan-net": true})
	if got := h.run("doctor", "--docker-network", "scan-net", "--json"); got != ExitOK {
		t.Fatalf("exit = %d\n%s", got, h.out.String())
	}
	var doc struct {
		Ready  bool             `json:"ready"`
		Checks []readinessCheck `json:"checks"`
	}
	if err := json.Unmarshal(h.out.Bytes(), &doc); err != nil || !doc.Ready {
		t.Fatalf("doc = %+v, err = %v\n%s", doc, err, h.out.String())
	}
	for _, r := range f.requests {
		if !strings.HasPrefix(r, "GET ") {
			t.Fatalf("doctor must only read: %v", f.requests)
		}
	}
	h.assertNoSecretPrinted(t)
}

func TestDoctorNamesTheFixForEachBlocker(t *testing.T) {
	cases := []struct {
		name     string
		daemon   error
		images   map[string]bool
		networks map[string]bool
		args     []string
		want     string
	}{
		{"docker down", errors.New("the Docker daemon did not answer"), nil, nil, nil, "install Docker and start it"},
		{"no runner image", nil, map[string]bool{}, nil, nil, "make runner-image"},
		{"missing network", nil, map[string]bool{runnerImageDefault: true}, map[string]bool{},
			[]string{"--docker-network", "scan-net"}, "docker network create scan-net"},
		{"zap without a network", nil, map[string]bool{runnerImageDefault: true, zapImageDefault: true}, nil,
			[]string{"--zap"}, "docker network create runpentests"},
		{"zap image missing", nil, map[string]bool{runnerImageDefault: true}, map[string]bool{"n": true},
			[]string{"--zap", "--docker-network", "n"}, "docker pull " + zapImageDefault},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := doctorHarness(t, &fake{capabilities: allPasses()}, c.daemon, c.images, c.networks)
			if got := h.run(append([]string{"doctor"}, c.args...)...); got != ExitUsage {
				t.Fatalf("exit = %d, want %d\n%s", got, ExitUsage, h.out.String())
			}
			if !strings.Contains(h.out.String(), "fix: "+c.want) {
				t.Fatalf("want fix %q:\n%s", c.want, h.out.String())
			}
		})
	}
}

func TestDoctorReportsARejectedKeyAndAnOlderServer(t *testing.T) {
	f := &fake{apiKey: "a-different-key", capabilities: allPasses()}
	h := doctorHarness(t, f, nil, map[string]bool{runnerImageDefault: true}, nil)
	if got := h.run("doctor"); got != ExitUsage || !strings.Contains(h.out.String(), "missing or rejected") {
		t.Fatalf("exit = %d\n%s", got, h.out.String())
	}
	h.assertNoSecretPrinted(t)

	// No /capabilities: the key is proven another way and the passes are unknown.
	h = doctorHarness(t, &fake{}, nil, map[string]bool{runnerImageDefault: true}, nil)
	if got := h.run("doctor"); got != ExitOK {
		t.Fatalf("an older server is a warning, not a blocker: exit = %d\n%s", got, h.out.String())
	}
	if !strings.Contains(h.out.String(), "older than this CLI") {
		t.Fatalf("out = %s", h.out.String())
	}
}

func TestDeepLevelStartsZapFromTheServersExpansion(t *testing.T) {
	caps := allPasses()
	caps["levels"] = map[string]any{"deep": map[string]any{"passes": []any{"fuzz", "zap"}, "ai": []any{}, "ai_with_writes": []any{}}}
	f := &fake{capabilities: caps}
	h, calls := localHarness(t, f, "completed", nil, nil)
	// No network: refused before the claim, because the level implies ZAP.
	if got := h.run("run", fakeScanID, "--authorized", "--level", "deep"); got != ExitUsage {
		t.Fatalf("exit = %d\n%s", got, h.errOut.String())
	}
	if f.sawRequest("POST "+fakeScanPath+"/local-runs") || len(*calls) != 0 {
		t.Fatal("a missing prerequisite must stop before the claim")
	}

	// With a network, the sibling starts from what the level turned on.
	f2 := &fake{capabilities: caps, claimOptions: map[string]any{"fuzz": true, "zap": true}}
	h, _ = localHarness(t, f2, "completed", nil, nil)
	var started []string
	h.env.StartContainer = func(_ context.Context, name string, _ []string) error {
		started = append(started, name)
		return nil
	}
	h.env.StopContainer = func(string) {}
	if got := h.run("run", fakeScanID, "--authorized", "--level", "deep", "--docker-network", "n"); got != ExitOK {
		t.Fatalf("exit = %d\n%s", got, h.errOut.String())
	}
	if len(started) != 1 || !strings.HasPrefix(started[0], "runpentests-zap-") {
		t.Fatalf("started = %v", started)
	}
}
