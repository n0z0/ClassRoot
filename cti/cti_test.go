package cti

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestClassRootCTIEnrichmentAndLogging(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "test_classroot_cti.jsonl")

	logger, err := Init(logFile, "test-sensor", "")
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer logger.Close()

	// Test LogHTTPProbe with Path Traversal (SQLi/LFI)
	LogHTTPProbe("198.51.100.25", 44321, "GET", "/etc/passwd", "", "curl/7.68.0", map[string]string{"User-Agent": "curl"}, 404, "")

	// Test LogRoomAuth
	clientAddr, _ := net.ResolveTCPAddr("tcp", "198.51.100.25:55123")
	LogRoomAuth(clientAddr, "Mozilla/5.0", nil, "room-admin", "admin", "123456", "jwt.token", "failed", "invalid_password")

	// Allow goroutines to process
	time.Sleep(200 * time.Millisecond)

	// Verify file content
	f, err := os.Open(logFile)
	if err != nil {
		t.Fatalf("Failed to open log file: %v", err)
	}
	defer f.Close()

	content, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) < 2 {
		t.Fatalf("Expected at least 2 events in JSONL, got %d. Content:\n%s", len(lines), string(content))
	}

	var evt1, evt2 ClassRootCTIEvent
	if err := json.Unmarshal([]byte(lines[0]), &evt1); err != nil {
		t.Fatalf("Unmarshal evt1 failed: %v", err)
	}
	if err := json.Unmarshal([]byte(lines[1]), &evt2); err != nil {
		t.Fatalf("Unmarshal evt2 failed: %v", err)
	}

	// Verify SOC fields
	if evt1.AttackPattern != "PATH_TRAVERSAL" {
		t.Errorf("Expected PATH_TRAVERSAL, got %s", evt1.AttackPattern)
	}
	if evt1.ThreatScore < 80 {
		t.Errorf("Expected high threat score, got %d", evt1.ThreatScore)
	}
	if evt1.Severity != "HIGH" && evt1.Severity != "CRITICAL" {
		t.Errorf("Expected HIGH or CRITICAL severity, got %s", evt1.Severity)
	}
	if evt1.SessionID == "" {
		t.Errorf("Expected non-empty SessionID")
	}
}
