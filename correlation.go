package main

import "time"

// Observation window for pairing a direct report with a relay report.
// Reports further apart are not treated as one incident.
const correlateWindow = 30 * time.Second

// classifyIncident compares a direct probe with an HTTP CONNECT relay probe
// of the same target. It names a relay-specific TLS failure only when the
// direct path is healthy, CONNECT succeeded, and TLS failed on the relay.
// Anything else stays unclassified: both-fail, CONNECT failure, a direct TLS
// failure, or two different targets must not be blamed on the relay.
func classifyIncident(direct, relay Report) string {
	if direct.Target == "" || direct.Target != relay.Target {
		return "unclassified"
	}
	if !withinWindow(direct, relay) {
		return "unclassified"
	}
	if direct.LLMCalls != 0 || relay.LLMCalls != 0 {
		return "unclassified"
	}
	if direct.Outcome == "healthy" &&
		stageState(relay, "http_connect") == "pass" &&
		(relay.Outcome == "tls_handshake_failure" || stageState(relay, "tls") == "fail") {
		return "relay_path_tls_failure"
	}
	return "unclassified"
}

func stageState(r Report, name string) string {
	if r.Stages == nil {
		return ""
	}
	return r.Stages[name].State
}

func withinWindow(a, b Report) bool {
	ta, ea := time.Parse(time.RFC3339, a.Timestamp)
	tb, eb := time.Parse(time.RFC3339, b.Timestamp)
	if ea != nil || eb != nil {
		// Tests build reports in-process; missing timestamps still pair.
		return a.Timestamp == "" || b.Timestamp == "" || a.Timestamp == b.Timestamp
	}
	d := ta.Sub(tb)
	if d < 0 {
		d = -d
	}
	return d <= correlateWindow
}
