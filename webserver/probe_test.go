package webserver

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/n0z0/ClassRoot/cti"
)

func TestURLProbeHandling(t *testing.T) {
	dir := t.TempDir()
	datadir := t.TempDir()
	err := setupTest(dir, datadir)
	if err != nil {
		t.Fatalf("setupTest: %v", err)
	}

	// Inisialisasi CTI logger untuk test
	logger, _ := cti.Init(t.TempDir()+"/cti_test.log", "test-sensor", "")
	defer logger.Close()

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	testCases := []struct {
		name           string
		method         string
		urlPath        string
		body           string
		expectedStatus int
		checkBody      string
	}{
		{
			name:           "Salah Path Biasa (404 Not Found)",
			method:         "GET",
			urlPath:        "/halaman-tidak-ada-12345",
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "Path Traversal Attempt",
			method:         "GET",
			urlPath:        "/static/../../etc/passwd",
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "SQL Injection Probe di Query String",
			method:         "GET",
			urlPath:        "/cari?id=1'%20UNION%20SELECT%201,2,3--%20-",
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "XSS Probe di Query String",
			method:         "GET",
			urlPath:        "/search?q=<script>alert('xss')</script>",
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "Sensitive File Probing (.env)",
			method:         "GET",
			urlPath:        "/.env",
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "Webshell Scanning (.php)",
			method:         "GET",
			urlPath:        "/upload/shell.php",
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "Method Tampering (POST ke static file)",
			method:         "POST",
			urlPath:        "/index.html",
			body:           "malicious_post_data=1",
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{
			name:           "Method Tampering (PUT ke sembarang file)",
			method:         "PUT",
			urlPath:        "/test.txt",
			body:           "malicious_upload_data",
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{
			name:           "Client 404 Telemetry Beacon",
			method:         "POST",
			urlPath:        "/api/telemetry",
			body:           `{"event":"HTTP_404_PROBE","url_path":"/percobaan-path","query":"?id=1","screen_resolution":"1920x1080","platform":"Win32"}`,
			expectedStatus: http.StatusOK,
			checkBody:      "ok",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			url := "http://localhost:1234" + tc.urlPath
			var bodyReader io.Reader
			if tc.body != "" {
				bodyReader = strings.NewReader(tc.body)
			}

			req, err := http.NewRequest(tc.method, url, bodyReader)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Threat-Simulator/1.0")
			req.Header.Set("X-Forwarded-For", "198.51.100.42")
			if tc.method == "POST" && tc.urlPath == "/api/telemetry" {
				req.Header.Set("Content-Type", "application/json")
			}

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("client.Do: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tc.expectedStatus {
				t.Errorf("[%s] Expected status %d, got %d", tc.name, tc.expectedStatus, resp.StatusCode)
			}

			if tc.checkBody != "" {
				bodyBytes, _ := io.ReadAll(resp.Body)
				if !bytes.Contains(bodyBytes, []byte(tc.checkBody)) {
					t.Errorf("[%s] Expected body to contain %q, got %q", tc.name, tc.checkBody, string(bodyBytes))
				}
			}
		})
	}
}
