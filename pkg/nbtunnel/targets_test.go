package nbtunnel

import (
	"net/netip"
	"testing"
	"time"
)

func TestLiveTargetReusesARememberedTargetWithALiveMaster(t *testing.T) {
	dir := t.TempDir()
	ws := Target{Name: "gpu dev 1", ID: "ws_123", Alias: "gpu dev 1", Addr: netip.MustParseAddr("100.73.41.7"), Port: 22, Workspace: true}
	node := Target{Name: "My Spark", ID: "unode_9", Alias: "my-spark", Addr: netip.MustParseAddr("100.73.9.9"), Port: 22022, Host: true}
	for _, target := range []Target{ws, node} {
		if err := RememberTarget(dir, target); err != nil {
			t.Fatalf("RememberTarget: %v", err)
		}
	}
	alive := func(alias string) bool { return alias == "gpu dev 1" }

	// Every spelling of the instance finds its live master, with the address
	// and port the ProxyCommand would have used and the instance flag.
	for _, spellings := range [][]string{{"gpu dev 1", "gpu-dev-1"}, {"ws_123", "ws_123"}} {
		got, ok := LiveTarget(dir, spellings, alive)
		if !ok {
			t.Fatalf("LiveTarget(%q) should find the live master", spellings)
		}
		if got.Alias != "gpu dev 1" || got.Addr != ws.Addr || got.Port != 22 || got.Host || !got.Workspace {
			t.Errorf("LiveTarget(%q) = %+v", spellings, got)
		}
	}
	// The machine is remembered but its master is gone: back to the cold path.
	if _, ok := LiveTarget(dir, []string{"My Spark", "my-spark"}, alive); ok {
		t.Error("a remembered target without a live master must not be reused")
	}
	if _, ok := LiveTarget(dir, []string{"unknown", "unknown"}, alive); ok {
		t.Error("an unknown name must not be reused")
	}
}

func TestRememberTargetReplacesAndForgets(t *testing.T) {
	dir := t.TempDir()
	ws := Target{Name: "gpu dev 1", ID: "ws_123", Alias: "gpu dev 1", Addr: netip.MustParseAddr("100.73.41.7"), Port: 22, Workspace: true}
	if err := RememberTarget(dir, ws); err != nil {
		t.Fatalf("RememberTarget: %v", err)
	}
	alive := func(string) bool { return true }
	// Re-resolving the same alias replaces the entry rather than adding one.
	ws.Addr = netip.MustParseAddr("100.73.41.8")
	if err := RememberTarget(dir, ws); err != nil {
		t.Fatalf("RememberTarget again: %v", err)
	}
	targets, err := ReadTargets(dir)
	if err != nil {
		t.Fatalf("ReadTargets: %v", err)
	}
	if len(targets) != 1 || targets["gpu dev 1"].Addr != ws.Addr {
		t.Errorf("targets after re-resolve = %+v", targets)
	}
	if err := ForgetTarget(dir, "gpu dev 1"); err != nil {
		t.Fatalf("ForgetTarget: %v", err)
	}
	if _, ok := LiveTarget(dir, []string{"gpu dev 1"}, alive); ok {
		t.Error("a forgotten target must not be reused")
	}
}

func TestLiveTargetPrefersTheIDThenTheInstance(t *testing.T) {
	dir := t.TempDir()
	// An instance and a machine with the same display name: the instance's
	// alias is the raw name, the machine's the sanitized one.
	ws := Target{Name: "My Spark", ID: "ws_1", Alias: "My Spark", Addr: netip.MustParseAddr("100.73.1.1"), Port: 22, Workspace: true}
	node := Target{Name: "My Spark", ID: "unode_1", Alias: "my-spark", Addr: netip.MustParseAddr("100.73.2.2"), Port: 22022, Host: true}
	for _, target := range []Target{node, ws} {
		if err := RememberTarget(dir, target); err != nil {
			t.Fatalf("RememberTarget: %v", err)
		}
	}
	always := func(string) bool { return true }
	for i := 0; i < 20; i++ {
		got, ok := LiveTarget(dir, []string{"My Spark", "my-spark"}, always)
		if !ok || got.ID != "ws_1" {
			t.Fatalf("by name the instance must win every time, got %+v", got)
		}
		got, ok = LiveTarget(dir, []string{"unode_1", "unode_1"}, always)
		if !ok || got.ID != "unode_1" {
			t.Fatalf("by id the machine must win, got %+v", got)
		}
	}
}

func TestLiveTargetExpiresAfterTheReuseWindow(t *testing.T) {
	dir := t.TempDir()
	stale := Target{Name: "old", Alias: "old", Addr: netip.MustParseAddr("100.73.3.3"), Port: 22}
	if err := RememberTarget(dir, stale); err != nil {
		t.Fatalf("RememberTarget: %v", err)
	}
	targets, err := ReadTargets(dir)
	if err != nil {
		t.Fatalf("ReadTargets: %v", err)
	}
	entry := targets["old"]
	entry.UpdatedAt = time.Now().Add(-ReuseWindow - time.Minute)
	targets["old"] = entry
	if err := writeTargets(dir, targets); err != nil {
		t.Fatalf("writeTargets: %v", err)
	}
	if _, ok := LiveTarget(dir, []string{"old"}, func(string) bool { return true }); ok {
		t.Error("a target resolved before the reuse window must go through Brev again")
	}
}

func TestLiveTargetWithoutCache(t *testing.T) {
	if _, ok := LiveTarget(t.TempDir(), []string{"anything"}, func(string) bool { return true }); ok {
		t.Error("no cache means no live target")
	}
}
