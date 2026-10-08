package cti

import (
	"testing"
)

func TestDetectAttackPatterns(t *testing.T) {
	tests := []struct {
		name        string
		method      string
		urlPath     string
		query       string
		payload     string
		expectedPat string
		expectedID  string
	}{
		{
			name:        "Path Traversal",
			method:      "GET",
			urlPath:     "/static/../../etc/passwd",
			query:       "",
			payload:     "",
			expectedPat: "PATH_TRAVERSAL",
			expectedID:  "T1190",
		},
		{
			name:        "SQL Injection",
			method:      "GET",
			urlPath:     "/api/data",
			query:       "id=1' UNION SELECT 1,2,3-- -",
			payload:     "",
			expectedPat: "SQL_INJECTION",
			expectedID:  "T1190",
		},
		{
			name:        "XSS Payload",
			method:      "GET",
			urlPath:     "/search",
			query:       "q=<script>alert(1)</script>",
			payload:     "",
			expectedPat: "CROSS_SITE_SCRIPTING",
			expectedID:  "T1189",
		},
		{
			name:        "WebShell Probe",
			method:      "GET",
			urlPath:     "/upload/shell.php",
			query:       "",
			payload:     "",
			expectedPat: "COMMAND_INJECTION_OR_WEBSHELL",
			expectedID:  "T1059",
		},
		{
			name:        "Sensitive Env File",
			method:      "GET",
			urlPath:     "/.env",
			query:       "",
			payload:     "",
			expectedPat: "SENSITIVE_FILE_SCANNING",
			expectedID:  "T1083",
		},
		{
			name:        "Unexpected Method",
			method:      "PUT",
			urlPath:     "/some-endpoint",
			query:       "",
			payload:     "",
			expectedPat: "UNEXPECTED_HTTP_METHOD",
			expectedID:  "T1190",
		},
		{
			name:        "Reconnaissance Scanner",
			method:      "GET",
			urlPath:     "/random-non-existent-path",
			query:       "",
			payload:     "",
			expectedPat: "ENDPOINT_RECONNAISSANCE",
			expectedID:  "T1595.002",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pattern, _, _, id := DetectAttackPatterns(tc.method, tc.urlPath, tc.query, tc.payload)
			if pattern != tc.expectedPat {
				t.Errorf("expected pattern %s, got %s", tc.expectedPat, pattern)
			}
			if id != tc.expectedID {
				t.Errorf("expected MITRE ID %s, got %s", tc.expectedID, id)
			}
		})
	}
}
