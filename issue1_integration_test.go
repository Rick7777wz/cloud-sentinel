//go:build integration

package main

import (
	"bufio"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestIssue1RelayTLSFailure is deliberately red for Issue #1: the Go probe
// emits correct individual observations but does not correlate two paths yet.
func TestIssue1RelayTLSFailure(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	// Trust only this local test fixture's CA/certificate, not arbitrary hosts.
	certFile := filepath.Join(t.TempDir(), "test-server.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", certFile)

	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxyListener.Close()
	go func() {
		conn, acceptErr := proxyListener.Accept()
		if acceptErr != nil { return }
		defer conn.Close()
		reader := bufio.NewReader(conn)
		for {
			line, readErr := reader.ReadString('\n')
			if readErr != nil { return }
			if strings.TrimSpace(line) == "" { break }
		}
		// CONNECT succeeds, but tunnel is reset before TLS negotiation.
		_, _ = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		// Deliberately close the connection, simulating a relay path drop.
	}()

	target := server.Listener.Addr().String()
	direct := runProbe(target, "", 3*time.Second)
	viaRelay := runProbe(target, proxyListener.Addr().String(), 3*time.Second)

	if direct.Outcome != "healthy" {
		t.Fatalf("fixture setup error: direct path must be healthy, got %s (%+v)", direct.Outcome, direct.Stages)
	}
	if viaRelay.Stages["http_connect"].State != "pass" {
		t.Fatalf("fixture setup error: CONNECT must return 200, got %+v", viaRelay.Stages["http_connect"])
	}
	if viaRelay.Outcome != "tls_handshake_failure" {
		t.Fatalf("fixture setup error: TLS must fail on relay, got %s", viaRelay.Outcome)
	}
	if direct.LLMCalls != 0 || viaRelay.LLMCalls != 0 {
		t.Fatal("routine checks must use zero LLM calls")
	}
	if got := classifyIncident(direct, viaRelay); got != "relay_path_tls_failure" {
		t.Fatalf("Issue #1 RED: want relay_path_tls_failure after comparing both paths, got %q", got)
	}
}
