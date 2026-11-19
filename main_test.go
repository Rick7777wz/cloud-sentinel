package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTLSErrorIsClassified(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Test server uses a self-signed certificate; production probes must reject it.
	target := server.Listener.Addr().String()
	report := runProbe(target, "", 2*time.Second)
	if report.Outcome != "tls_handshake_failure" {
		t.Fatalf("expected tls_handshake_failure, got %s (%+v)", report.Outcome, report.Stages)
	}
	if report.LLMCalls != 0 {
		t.Fatalf("expected zero LLM calls, got %d", report.LLMCalls)
	}
}

func TestTCPFailureIsClassified(t *testing.T) {
	// Get a local ephemeral port, then release it so no process is listening.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	target := listener.Addr().String()
	_ = listener.Close()

	report := runProbe(target, "", 200*time.Millisecond)
	if report.Outcome != "tcp_failure" {
		t.Fatalf("expected tcp_failure, got %s", report.Outcome)
	}
}
