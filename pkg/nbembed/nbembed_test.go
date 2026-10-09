//go:build linux || darwin

package nbembed

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testTargetID = "environment-123"
const testTargetAddress = "100.73.1.2:22"

type fakeEngine struct {
	dial       func(context.Context, string, string) (net.Conn, error)
	startCalls atomic.Int32
	stopCalls  atomic.Int32
	dialCalls  atomic.Int32
}

func (f *fakeEngine) Start(context.Context) error {
	f.startCalls.Add(1)
	return nil
}

func (f *fakeEngine) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	f.dialCalls.Add(1)
	if f.dial == nil {
		return nil, errors.New("unexpected dial")
	}
	return f.dial(ctx, network, address)
}

func (f *fakeEngine) Stop(context.Context) error {
	f.stopCalls.Add(1)
	return nil
}

type testServer struct {
	dir          string
	cancel       context.CancelFunc
	done         chan struct{}
	err          error
	factoryCalls atomic.Int32
}

func newTestProfile(t *testing.T) string {
	t.Helper()
	// Unix socket paths are limited to about 100 bytes on supported systems.
	dir, err := os.MkdirTemp("", "nb-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := writePrivateJSON(filepath.Join(dir, "profile.json"), profileInfo{
		ManagementURL: "https://management.example.invalid",
		DeviceName:    "test-laptop",
	}); err != nil {
		t.Fatal(err)
	}
	writeTestManifest(t, dir, `{"version":1,"targets":[{"id":"`+testTargetID+`","address":"`+testTargetAddress+`","name":"extra manifest fields are allowed"}]}`)
	return dir
}

func writeTestManifest(t *testing.T, dir, manifest string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "targets.json"), []byte(manifest), 0600); err != nil {
		t.Fatal(err)
	}
}

func startTestServer(t *testing.T, eng *fakeEngine) *testServer {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	s := &testServer{dir: newTestProfile(t), cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(s.done)
		s.err = serve(ctx, s.dir, func(_ string, _ profileInfo, setupKey string) (engine, error) {
			s.factoryCalls.Add(1)
			if setupKey != "" {
				return nil, errors.New("serving a saved identity must not require a setup key")
			}
			return eng, nil
		})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-s.done:
		case <-time.After(5 * time.Second):
			t.Error("helper did not stop after cancellation")
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("unix", filepath.Join(s.dir, "agent.sock"), 50*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return s
		}
		select {
		case <-s.done:
			t.Fatalf("helper exited before listening: %v", s.err)
		case <-time.After(5 * time.Millisecond):
		}
	}
	t.Fatal("helper never opened its socket")
	return nil
}

type wireConn struct {
	*net.UnixConn
	reader *bufio.Reader
}

func (c *wireConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func openTestWire(dir string, req request) (*wireConn, response, error) {
	var reply response
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: filepath.Join(dir, "agent.sock"), Net: "unix"})
	if err != nil {
		return nil, reply, err
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	c := &wireConn{UnixConn: conn, reader: bufio.NewReader(conn)}
	if err := json.NewEncoder(c).Encode(req); err != nil {
		_ = c.Close()
		return nil, reply, err
	}
	line, err := c.reader.ReadBytes('\n')
	if err == nil {
		err = json.Unmarshal(line, &reply)
	}
	if err != nil {
		_ = c.Close()
		return nil, reply, err
	}
	return c, reply, nil
}

func TestServeRejectsTargetsOutsideManifest(t *testing.T) {
	eng := &fakeEngine{}
	s := startTestServer(t, eng)
	for _, targetID := range []string{"", "unknown-environment", testTargetAddress, "../profile.json"} {
		t.Run(targetID, func(t *testing.T) {
			conn, reply, err := openTestWire(s.dir, request{Operation: "dial", TargetID: targetID})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if reply.OK || reply.Error == "" {
				t.Fatalf("unconfigured target was not rejected: %+v", reply)
			}
		})
	}
	if got := eng.dialCalls.Load(); got != 0 {
		t.Fatalf("unconfigured targets reached the network engine %d times", got)
	}
}

func TestServeConcurrentStreamsPreserveBinaryAndHalfClose(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	const streams = 4
	remoteErrors := make(chan error, streams)
	go func() {
		for i := 0; i < streams; i++ {
			conn, err := listener.Accept()
			if err != nil {
				remoteErrors <- err
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				body, err := io.ReadAll(conn)
				if err == nil {
					// The response starts only after receiving EOF. Closing the entire
					// outbound connection instead of half-closing loses this response.
					_, err = conn.Write(append([]byte{255, 0, 13, 10}, body...))
				}
				remoteErrors <- err
			}()
		}
	}()
	eng := &fakeEngine{dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != testTargetAddress {
			return nil, fmt.Errorf("unexpected network destination %s %s", network, address)
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
	}}
	s := startTestServer(t, eng)
	clientErrors := make(chan error, streams)
	var clients sync.WaitGroup
	for i := 0; i < streams; i++ {
		clients.Add(1)
		go func(stream int) {
			defer clients.Done()
			conn, reply, err := openTestWire(s.dir, request{Operation: "dial", TargetID: testTargetID})
			if err != nil {
				clientErrors <- err
				return
			}
			defer conn.Close()
			if !reply.OK {
				clientErrors <- fmt.Errorf("dial was rejected: %s", reply.Error)
				return
			}
			payload := make([]byte, 32<<10)
			for j := range payload {
				payload[j] = byte(j + stream)
			}
			if _, err := conn.Write(payload); err != nil {
				clientErrors <- err
				return
			}
			if err := conn.CloseWrite(); err != nil {
				clientErrors <- err
				return
			}
			got, err := io.ReadAll(conn)
			if err == nil && !bytes.Equal(got, append([]byte{255, 0, 13, 10}, payload...)) {
				err = fmt.Errorf("stream %d response was truncated or modified: got %d bytes", stream, len(got))
			}
			clientErrors <- err
		}(i)
	}
	clients.Wait()
	for i := 0; i < streams; i++ {
		if err := <-clientErrors; err != nil {
			t.Error(err)
		}
		select {
		case err := <-remoteErrors:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("remote stream did not finish")
		}
	}
	if eng.startCalls.Load() != 1 || eng.dialCalls.Load() != streams || s.factoryCalls.Load() != 1 {
		t.Fatalf("streams did not share one engine: starts=%d dials=%d factories=%d", eng.startCalls.Load(), eng.dialCalls.Load(), s.factoryCalls.Load())
	}
}

func TestServeDoesNotStartSecondEngineForLockedIdentity(t *testing.T) {
	eng := &fakeEngine{}
	s := startTestServer(t, eng)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var duplicateFactories atomic.Int32
	err := serve(ctx, s.dir, func(string, profileInfo, string) (engine, error) {
		duplicateFactories.Add(1)
		return &fakeEngine{}, nil
	})
	if err == nil {
		t.Fatal("a second helper acquired an active identity")
	}
	if duplicateFactories.Load() != 0 {
		t.Fatal("a second network engine was constructed before acquiring the identity lock")
	}
	conn, reply, err := openTestWire(s.dir, request{Operation: "status"})
	if err != nil {
		t.Fatalf("duplicate startup disrupted the existing helper: %v", err)
	}
	defer conn.Close()
	if !reply.OK {
		t.Fatalf("existing helper no longer answers requests: %+v", reply)
	}
}

func TestTargetAddressRejectsInvalidManifestEntries(t *testing.T) {
	for _, tc := range []struct {
		name     string
		manifest string
	}{
		{"unsupported version", `{"version":2,"targets":[{"id":"environment-123","address":"100.73.1.2:22"}]}`},
		{"duplicate target", `{"version":1,"targets":[{"id":"environment-123","address":"100.73.1.2:22"},{"id":"environment-123","address":"100.73.1.3:22"}]}`},
		{"hostname", `{"version":1,"targets":[{"id":"environment-123","address":"attacker.invalid:22"}]}`},
		{"zero port", `{"version":1,"targets":[{"id":"environment-123","address":"100.73.1.2:0"}]}`},
		{"unspecified IP", `{"version":1,"targets":[{"id":"environment-123","address":"0.0.0.0:22"}]}`},
		{"multicast IP", `{"version":1,"targets":[{"id":"environment-123","address":"224.0.0.1:22"}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := newTestProfile(t)
			writeTestManifest(t, dir, tc.manifest)
			if address, err := targetAddress(dir, testTargetID); err == nil {
				t.Fatalf("invalid target resolved to %q", address)
			}
		})
	}
}
