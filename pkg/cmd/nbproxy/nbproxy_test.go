package nbproxy

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

func TestProxyIsBinaryCleanAndSkipsParentHooks(t *testing.T) {
	t.Setenv("BREV_EXPERIMENTAL_NETBIRD", "")
	client, server := net.Pipe()
	defer server.Close()
	request := []byte{0, 1, 2, 3, '\n'}
	response := []byte("SSH-2.0-test\r\n")
	peerDone := make(chan error, 1)
	go func() {
		defer server.Close()
		got := make([]byte, len(request))
		if _, err := io.ReadFull(server, got); err != nil {
			peerDone <- err
			return
		}
		if !bytes.Equal(got, request) {
			peerDone <- io.ErrUnexpectedEOF
			return
		}
		_, err := server.Write(response)
		peerDone <- err
	}()
	proxy := newCmdNBProxy(proxyDeps{dial: func(_ context.Context, dir, id string) (net.Conn, error) {
		if dir != "/state" || id != "gpu" {
			t.Fatal("wrong target")
		}
		return client, nil
	}})
	parent := &cobra.Command{Use: "brev", PersistentPreRunE: func(*cobra.Command, []string) error { t.Fatal("parent hook invoked"); return nil }, PersistentPostRunE: func(*cobra.Command, []string) error { t.Fatal("parent hook invoked"); return nil }}
	parent.AddCommand(proxy)
	parent.SetArgs([]string{"nb-proxy", "gpu", "--state-dir", "/state"})
	parent.SetIn(bytes.NewReader(request))
	var out, diagnostics bytes.Buffer
	parent.SetOut(&out)
	parent.SetErr(&diagnostics)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := parent.ExecuteContext(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-peerDone; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), response) || diagnostics.Len() != 0 {
		t.Fatalf("protocol polluted: %q diagnostics %q", out.String(), diagnostics.String())
	}
}

func TestProxyReturnsOnCancellation(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := forward(ctx, client, strings.NewReader(""), io.Discard); err != context.Canceled {
		t.Fatalf("got %v", err)
	}
}
