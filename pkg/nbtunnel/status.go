package nbtunnel

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	netbird "github.com/netbirdio/netbird/client/embed"
)

// Status is a snapshot of the embedded peer, for display and for deciding
// whether it has joined the network.
type Status struct {
	DeviceName          string
	ManagementURL       string
	ManagementConnected bool
	ManagementError     string
	SignalConnected     bool
	IP                  string
	FQDN                string
	PubKey              string
	Peers               []PeerStatus
}

// PeerStatus is one entry of the network map as the embedded peer sees it.
type PeerStatus struct {
	FQDN          string
	IP            string
	PubKey        string
	Status        string
	Connected     bool
	Relayed       bool
	Latency       time.Duration
	LastHandshake time.Time
}

// Joined reports whether management accepted the peer and handed it an address.
func (s Status) Joined() bool {
	return s.ManagementConnected && s.IP != ""
}

// Status returns the current snapshot of the running tunnel.
func (t *Tunnel) Status() (Status, error) {
	return statusOf(t.client, t.id.DeviceName)
}

// WaitForIP polls until the peer has logged in and holds a NetBird address, or
// ctx expires. The last snapshot is returned either way.
func (t *Tunnel) WaitForIP(ctx context.Context) (Status, error) {
	return waitForIP(ctx, t.Status)
}

func statusOf(client *netbird.Client, deviceName string) (Status, error) {
	full, err := client.Status()
	if err != nil {
		return Status{}, fmt.Errorf("embedded netbird status: %w", err)
	}
	st := Status{
		DeviceName:          deviceName,
		ManagementURL:       full.ManagementState.URL,
		ManagementConnected: full.ManagementState.Connected,
		SignalConnected:     full.SignalState.Connected,
		IP:                  full.LocalPeerState.IP,
		FQDN:                full.LocalPeerState.FQDN,
		PubKey:              full.LocalPeerState.PubKey,
	}
	if full.ManagementState.Error != nil {
		st.ManagementError = full.ManagementState.Error.Error()
	}
	for _, p := range full.Peers {
		st.Peers = append(st.Peers, PeerStatus{
			FQDN:          p.FQDN,
			IP:            p.IP,
			PubKey:        p.PubKey,
			Status:        p.ConnStatus.String(),
			Connected:     p.ConnStatus == netbird.PeerStatusConnected,
			Relayed:       p.Relayed,
			Latency:       p.Latency,
			LastHandshake: p.LastWireguardHandshake,
		})
	}
	sort.Slice(st.Peers, func(i, j int) bool { return st.Peers[i].FQDN < st.Peers[j].FQDN })
	return st, nil
}

func waitForIP(ctx context.Context, status func() (Status, error)) (Status, error) {
	ticker := time.NewTicker(peerPoll)
	defer ticker.Stop()
	for {
		st, err := status()
		if err != nil {
			return st, err
		}
		if st.Joined() {
			return st, nil
		}
		select {
		case <-ctx.Done():
			reason := "management did not accept the peer"
			if st.ManagementError != "" {
				reason = st.ManagementError
			} else if st.ManagementConnected {
				reason = "management accepted the peer but assigned no address"
			}
			return st, fmt.Errorf("no NetBird address: %s: %w", reason, ctx.Err())
		case <-ticker.C:
		}
	}
}

// Format renders the snapshot for a terminal.
func (s Status) Format(now time.Time) string {
	var b strings.Builder
	b.WriteString("Embedded Brev tunnel\n")
	fmt.Fprintf(&b, "  Device:      %s\n", orDash(s.DeviceName))
	fmt.Fprintf(&b, "  Management:  %s (%s)\n", orDash(s.ManagementURL), connectedWord(s.ManagementConnected, s.ManagementError))
	fmt.Fprintf(&b, "  Signal:      %s\n", connectedWord(s.SignalConnected, ""))
	fmt.Fprintf(&b, "  NetBird IP:  %s\n", orDash(s.IP))
	fmt.Fprintf(&b, "  FQDN:        %s\n", orDash(s.FQDN))
	fmt.Fprintf(&b, "  Public key:  %s\n", orDash(s.PubKey))
	b.WriteString("\n")
	b.WriteString(s.FormatPeers(now))
	return b.String()
}

// FormatPeers renders only the peer table.
func (s Status) FormatPeers(now time.Time) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Peers in the network map: %d\n", len(s.Peers))
	if len(s.Peers) == 0 {
		return b.String()
	}
	w := tabwriter.NewWriter(&b, 2, 0, 2, ' ', 0)
	fmt.Fprintln(w, "  NAME\tIP\tSTATUS\tVIA\tLATENCY\tLAST HANDSHAKE")
	for _, p := range s.Peers {
		via := "-"
		if p.Connected {
			via = "direct"
			if p.Relayed {
				via = "relay"
			}
		}
		latency := "-"
		if p.Connected && p.Latency > 0 {
			latency = p.Latency.Round(time.Millisecond).String()
		}
		handshake := "-"
		if !p.LastHandshake.IsZero() {
			handshake = now.Sub(p.LastHandshake).Round(time.Second).String() + " ago"
		}
		fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s\t%s\n", orDash(p.FQDN), orDash(p.IP), p.Status, via, latency, handshake)
	}
	_ = w.Flush()
	return b.String()
}

func connectedWord(connected bool, errText string) string {
	if connected {
		return "connected"
	}
	if errText != "" {
		return "disconnected: " + errText
	}
	return "disconnected"
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
