package main

// classifyIncident is intentionally incomplete in the Issue #1 baseline.
// The probe can identify stage failures separately, but cannot yet correlate
// a healthy direct path with a broken relayed path.
func classifyIncident(direct, relay Report) string {
	return "unclassified"
}
