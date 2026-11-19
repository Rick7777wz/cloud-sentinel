package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// Stage is a single deterministic network check (no LLM calls).
type Stage struct {
	State     string  `json:"state"`
	LatencyMS float64 `json:"latency_ms,omitempty"`
	Error     string  `json:"error,omitempty"`
}

// Report matches the first version of Cloud Sentinel's probe schema.
type Report struct {
	Timestamp string           `json:"timestamp"`
	Target    string           `json:"target"`
	Route     string           `json:"route"`
	Stages    map[string]Stage `json:"stages"`
	Outcome   string           `json:"outcome"`
	LLMCalls  int              `json:"llm_calls"`
}

func newReport(target, proxy string) Report {
	route := "direct"
	if proxy != "" {
		route = "http_connect_relay"
	}
	stages := make(map[string]Stage)
	for _, name := range []string{"dns", "tcp", "http_connect", "tls", "http"} {
		stages[name] = Stage{State: "skipped"}
	}
	return Report{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Target:    target,
		Route:     route,
		Stages:    stages,
		Outcome:   "inconclusive",
		LLMCalls:  0,
	}
}

func result(start time.Time, err error) Stage {
	stage := Stage{State: "pass", LatencyMS: float64(time.Since(start).Microseconds()) / 1000}
	if err != nil {
		stage.State = "fail"
		stage.Error = err.Error()
	}
	return stage
}

// bufferedConn preserves any bytes buffered while reading the proxy's CONNECT response.
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func runProbe(target, proxy string, timeout time.Duration) Report {
	report := newReport(target, proxy)
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		report.Stages["dns"] = Stage{State: "fail", Error: "target must be host:port"}
		report.Outcome = "dns_failure"
		return report
	}

	// Local DNS is a reference signal; HTTP CONNECT proxies may resolve hosts remotely.
	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	_, dnsErr := net.DefaultResolver.LookupIPAddr(ctx, host)
	cancel()
	report.Stages["dns"] = result(started, dnsErr)
	if dnsErr != nil && proxy == "" {
		report.Outcome = "dns_failure"
		return report
	}

	dialTarget := target
	if proxy != "" {
		dialTarget = proxy
	}
	started = time.Now()
	conn, err := net.DialTimeout("tcp", dialTarget, timeout)
	report.Stages["tcp"] = result(started, err)
	if err != nil {
		report.Outcome = "tcp_failure"
		return report
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if proxy != "" {
		started = time.Now()
		// This is deliberately an unauthenticated HTTP CONNECT proof of concept.
		_, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
		if err != nil {
			report.Stages["http_connect"] = result(started, err)
			report.Outcome = "connect_failure"
			return report
		}
		reader := bufio.NewReader(conn)
		req, _ := http.NewRequest(http.MethodConnect, "http://"+target, nil)
		response, readErr := http.ReadResponse(reader, req)
		if readErr == nil && response.StatusCode != http.StatusOK {
			readErr = fmt.Errorf("proxy returned %s", response.Status)
		}
		report.Stages["http_connect"] = result(started, readErr)
		if readErr != nil {
			report.Outcome = "connect_failure"
			return report
		}
		conn = &bufferedConn{Conn: conn, reader: reader}
	}

	started = time.Now()
	secure := tls.Client(conn, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	err = secure.Handshake()
	report.Stages["tls"] = result(started, err)
	if err != nil {
		report.Outcome = "tls_handshake_failure"
		return report
	}
	defer secure.Close()

	started = time.Now()
	request, err := http.NewRequest(http.MethodGet, "https://"+target+"/", nil)
	if err == nil {
		request.Header.Set("User-Agent", "CloudSentinel-Probe/0.1")
		request.Header.Set("Connection", "close")
		err = request.Write(secure)
	}
	if err == nil {
		response, readErr := http.ReadResponse(bufio.NewReader(secure), request)
		err = readErr
		if response != nil {
			defer response.Body.Close()
			if response.StatusCode >= 500 {
				err = fmt.Errorf("upstream returned HTTP %d", response.StatusCode)
			}
		}
	}
	report.Stages["http"] = result(started, err)
	if err != nil {
		report.Outcome = "http_failure"
	} else {
		report.Outcome = "healthy"
	}
	return report
}

func main() {
	target := flag.String("target", "example.com:443", "HTTPS destination as host:port")
	proxy := flag.String("proxy", "", "Optional HTTP CONNECT proxy as host:port")
	timeout := flag.Duration("timeout", 8*time.Second, "Timeout for each connection/check")
	flag.Parse()

	if strings.TrimSpace(*target) == "" || *timeout <= 0 {
		fmt.Fprintln(os.Stderr, "invalid -target or -timeout")
		os.Exit(2)
	}
	report := runProbe(*target, *proxy, *timeout)
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if report.Outcome != "healthy" {
		os.Exit(1)
	}
}
