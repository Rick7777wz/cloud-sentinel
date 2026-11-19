package main

import (
	"testing"
	"time"
)

func stageMap(states map[string]string) map[string]Stage {
	out := map[string]Stage{}
	for k, v := range states {
		out[k] = Stage{State: v}
	}
	return out
}

func rep(target, outcome string, stages map[string]string) Report {
	return Report{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Target:    target,
		Stages:    stageMap(stages),
		Outcome:   outcome,
		LLMCalls:  0,
	}
}

func TestClassifyRelayTLSOnlyWhenDirectHealthy(t *testing.T) {
	direct := rep("h:443", "healthy", map[string]string{"tls": "pass", "http": "pass"})
	relay := rep("h:443", "tls_handshake_failure", map[string]string{"http_connect": "pass", "tls": "fail"})
	if got := classifyIncident(direct, relay); got != "relay_path_tls_failure" {
		t.Fatalf("got %q", got)
	}
}

func TestClassifyBothFailUnclassified(t *testing.T) {
	direct := rep("h:443", "tls_handshake_failure", map[string]string{"tls": "fail"})
	relay := rep("h:443", "tls_handshake_failure", map[string]string{"http_connect": "pass", "tls": "fail"})
	if got := classifyIncident(direct, relay); got != "unclassified" {
		t.Fatalf("both-fail must stay unclassified, got %q", got)
	}
}

func TestClassifyConnectFailUnclassified(t *testing.T) {
	direct := rep("h:443", "healthy", map[string]string{"tls": "pass"})
	relay := rep("h:443", "connect_failure", map[string]string{"http_connect": "fail", "tls": "skipped"})
	if got := classifyIncident(direct, relay); got != "unclassified" {
		t.Fatalf("connect-fail must stay unclassified, got %q", got)
	}
}

func TestClassifyDirectCertFailUnclassified(t *testing.T) {
	direct := rep("h:443", "tls_handshake_failure", map[string]string{"tls": "fail"})
	relay := rep("h:443", "healthy", map[string]string{"http_connect": "pass", "tls": "pass"})
	if got := classifyIncident(direct, relay); got != "unclassified" {
		t.Fatalf("direct cert failure must stay unclassified, got %q", got)
	}
}

func TestClassifyDifferentTargetsUnclassified(t *testing.T) {
	direct := rep("a.example:443", "healthy", map[string]string{"tls": "pass"})
	relay := rep("b.example:443", "tls_handshake_failure", map[string]string{"http_connect": "pass", "tls": "fail"})
	if got := classifyIncident(direct, relay); got != "unclassified" {
		t.Fatalf("unrelated targets must stay unclassified, got %q", got)
	}
}
