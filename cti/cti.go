package cti

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/n0z0/cachedb/cdc"
	"github.com/n0z0/cachedb/proto/cachepb"
	"google.golang.org/grpc"
)

// ReconProfileInfo menyimpan korelasi intelijen L4 dari synwatcher via cacheDB
type ReconProfileInfo struct {
	SYNFingerprintHash string `json:"syn_hash,omitempty"`
	RiskScore          string `json:"risk_score,omitempty"`
	Severity           string `json:"severity,omitempty"`
	TargetService      string `json:"target_service,omitempty"`
	IntentCategory     string `json:"intent_category,omitempty"`
	ScanVelocity       string `json:"scan_velocity,omitempty"`
	EstimatedOS        string `json:"estimated_os,omitempty"`
	ScannerTool        string `json:"scanner_tool,omitempty"`
	ScanHits           string `json:"scan_hits,omitempty"`
	LastScan           string `json:"last_scan,omitempty"`
}

// ClassRootCTIEvent mencatat data telemetri intelijen dari interaksi Web & WebRTC
type ClassRootCTIEvent struct {
	Timestamp      string              `json:"timestamp"` // ISO 8601 UTC
	SensorID       string              `json:"sensor_id"`
	SessionID      string              `json:"session_id,omitempty"` // Correlation ID
	EventType      string              `json:"event_type"`           // WEBRTC_ICE_CANDIDATE_LEAK, ROOM_AUTH_ATTEMPT, ROOM_JOIN_SUCCESS, HTTP_ATTACK_ATTEMPT, dll.
	Status         string              `json:"status,omitempty"`     // success, failed, captured, rejected_404
	ThreatScore    int                 `json:"threat_score,omitempty"`
	Severity       string              `json:"severity,omitempty"`        // INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL
	KillChainPhase string              `json:"kill_chain_phase,omitempty"` // Reconnaissance, Initial Access, Discovery, Collection, Credential Access
	RemoteIP       string              `json:"remote_ip"`
	RemotePort     int                 `json:"remote_port,omitempty"`
	ReverseDNS     string              `json:"reverse_dns,omitempty"` // Hostname hasil PTR lookup via Goroutine
	Group          string              `json:"group,omitempty"`
	Username       string              `json:"username,omitempty"`
	Password       string              `json:"password,omitempty"`
	Token          string              `json:"token,omitempty"`
	Method         string              `json:"method,omitempty"`
	URLPath        string              `json:"url_path,omitempty"`
	Query          string              `json:"query,omitempty"`
	PayloadSnippet string              `json:"payload_snippet,omitempty"`
	AttackPattern  string              `json:"attack_pattern,omitempty"`
	UserAgent      string              `json:"user_agent,omitempty"`
	Headers        map[string]string   `json:"headers,omitempty"`
	Fingerprint    *BrowserFingerprint `json:"fingerprint,omitempty"`
	Candidate      *ICECandidateInfo   `json:"ice_candidate,omitempty"`
	ReconProfile   *ReconProfileInfo   `json:"recon_profile,omitempty"`
	FailureDesc    string              `json:"failure_reason,omitempty"`
	Mitre          MitreAttackInfo     `json:"mitre_attack"`
}

type MediaDeviceInfo struct {
	Kind     string `json:"kind"`                // audioinput, videoinput, audiooutput
	Label    string `json:"label"`               // e.g. "Logitech HD Pro Webcam C920", "Realtek Audio"
	DeviceID string `json:"device_id,omitempty"` // Device ID / hash
}

type NetworkInfo struct {
	ConnectionType string  `json:"connection_type,omitempty"` // wifi, cellular, ethernet
	EffectiveType  string  `json:"effective_type,omitempty"`  // 4g, 3g
	DownlinkMbps   float64 `json:"downlink_mbps,omitempty"`
	RTTMs          int     `json:"rtt_ms,omitempty"`
}

type BrowserFingerprint struct {
	ScreenResolution   string            `json:"screen_resolution,omitempty"` // Contoh: 1920x1080
	ColorDepth         int               `json:"color_depth,omitempty"`
	PixelRatio         float64           `json:"pixel_ratio,omitempty"`
	Platform           string            `json:"platform,omitempty"`          // Contoh: Win32, Linux x86_64
	Languages          string            `json:"languages,omitempty"`         // Contoh: id-ID,en-US
	Timezone           string            `json:"timezone,omitempty"`          // Contoh: Asia/Jakarta
	TimezoneOffset     int               `json:"timezone_offset,omitempty"`
	HardwareCores      int               `json:"hardware_cores,omitempty"`
	DeviceMemory       float64           `json:"device_memory,omitempty"`     // dalam GB
	GPUVendor          string            `json:"gpu_vendor,omitempty"`
	GPURenderer        string            `json:"gpu_renderer,omitempty"`      // Contoh: NVIDIA GeForce RTX 4070 Laptop GPU
	CanvasHash         string            `json:"canvas_hash,omitempty"`
	AudioHash          string            `json:"audio_hash,omitempty"`
	MediaDevices       []MediaDeviceInfo `json:"media_devices,omitempty"`     // Kamera & Microphone terdeteksi
	NetworkInfo        *NetworkInfo      `json:"network_info,omitempty"`      // WiFi/Cellular & Latensi
	BluetoothSupported bool              `json:"bluetooth_supported,omitempty"`
}

type ICECandidateInfo struct {
	Raw          string `json:"raw"`
	CandidateTyp string `json:"type"` // host (Local IP), srflx (STUN Public IP), relay (TURN)
	IP           string `json:"ip"`
	Port         int    `json:"port"`
	Protocol     string `json:"protocol"`
	RelatedIP    string `json:"related_ip,omitempty"`
	RelatedPort  int    `json:"related_port,omitempty"`
}

type MitreAttackInfo struct {
	Tactic    string `json:"tactic"`
	Technique string `json:"technique"`
	ID        string `json:"technique_id"`
}

type Logger struct {
	file        *os.File
	mu          sync.Mutex
	sensorID    string
	cacheClient cachepb.CacheClient
	grpcConn    *grpc.ClientConn
	eventChan   chan *ClassRootCTIEvent
	quit        chan struct{}
	wg          sync.WaitGroup
}

var globalLogger *Logger

// Init menginisialisasi CTI Logger dan koneksi opsional ke cacheDB
func Init(logPath, sensorID, cacheDBAddr string) (*Logger, error) {
	if sensorID == "" {
		host, _ := os.Hostname()
		if host == "" {
			sensorID = "classroot-webrtc"
		} else {
			sensorID = host
		}
	}

	var f *os.File
	if logPath != "" {
		var err error
		f, err = os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return nil, fmt.Errorf("gagal membuka log CTI %s: %w", logPath, err)
		}
	}

	logger := &Logger{
		file:      f,
		sensorID:  sensorID,
		eventChan: make(chan *ClassRootCTIEvent, 4096),
		quit:      make(chan struct{}),
	}

	if cacheDBAddr != "" {
		client, conn, err := cdc.Connect(cacheDBAddr)
		if err != nil {
			log.Printf("[CTI] Peringatan: Tidak dapat terhubung ke cacheDB di %s: %v", cacheDBAddr, err)
		} else {
			logger.cacheClient = client
			logger.grpcConn = conn
			log.Printf("[CTI] Terhubung ke cacheDB di %s", cacheDBAddr)
		}
	}

	// Worker goroutine untuk penulisan file dan push ke CacheDB secara asinkron
	logger.wg.Add(1)
	go func() {
		defer logger.wg.Done()
		for {
			select {
			case event, ok := <-logger.eventChan:
				if !ok {
					return
				}
				logger.processEvent(event)
			case <-logger.quit:
				for {
					select {
					case event := <-logger.eventChan:
						logger.processEvent(event)
					default:
						return
					}
				}
			}
		}
	}()

	globalLogger = logger
	return globalLogger, nil
}

var rdnsCache sync.Map

// resolveReverseDNS melakukan DNS PTR lookup dengan in-memory deduplication cache
func resolveReverseDNS(ipStr string) string {
	if val, ok := rdnsCache.Load(ipStr); ok {
		return val.(string)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 350*time.Millisecond)
	defer cancel()

	var r net.Resolver
	var host string
	names, err := r.LookupAddr(ctx, ipStr)
	if err == nil && len(names) > 0 {
		host = strings.TrimSuffix(names[0], ".")
	}
	rdnsCache.Store(ipStr, host)
	return host
}

// generateSessionID membuat correlation identifier konsisten berdasarkan IP dan tanggal UTC
func generateSessionID(ip string) string {
	h := sha256.New()
	h.Write([]byte(ip + ":" + time.Now().UTC().Format("2006-01-02")))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// evaluateThreatScore mengevaluasi risk score komposit & severity event CTI
func evaluateThreatScore(evt *ClassRootCTIEvent) {
	if evt.ThreatScore == 0 {
		switch evt.AttackPattern {
		case "SQL_INJECTION", "COMMAND_INJECTION_OR_WEBSHELL":
			evt.ThreatScore = 95
			evt.Severity = "CRITICAL"
			evt.KillChainPhase = "Exploitation"
		case "PATH_TRAVERSAL":
			evt.ThreatScore = 88
			evt.Severity = "HIGH"
			evt.KillChainPhase = "Exploitation"
		case "CROSS_SITE_SCRIPTING", "SENSITIVE_FILE_SCANNING":
			evt.ThreatScore = 80
			evt.Severity = "HIGH"
			evt.KillChainPhase = "Discovery"
		case "UNEXPECTED_HTTP_METHOD":
			evt.ThreatScore = 60
			evt.Severity = "MEDIUM"
			evt.KillChainPhase = "Initial Access"
		default:
			if evt.EventType == "HTTP_ATTACK_ATTEMPT" {
				evt.ThreatScore = 75
				evt.Severity = "HIGH"
				evt.KillChainPhase = "Initial Access"
			} else if evt.EventType == "ROOM_AUTH_FAILED" {
				evt.ThreatScore = 65
				evt.Severity = "MEDIUM"
				evt.KillChainPhase = "Credential Access"
			} else if evt.EventType == "WEBRTC_ICE_CANDIDATE_LEAK" {
				evt.ThreatScore = 50
				evt.Severity = "MEDIUM"
				evt.KillChainPhase = "Discovery"
			} else if evt.EventType == "ROOM_JOIN_SUCCESS" {
				evt.ThreatScore = 40
				evt.Severity = "LOW"
				evt.KillChainPhase = "Initial Access"
			} else {
				evt.ThreatScore = 30
				evt.Severity = "LOW"
				if evt.KillChainPhase == "" {
					evt.KillChainPhase = "Reconnaissance"
				}
			}
		}
	}

	// Korelasi Unified Kill Chain: jika penyerang memiliki riwayat L4 Recon scan di cachedb
	if evt.ReconProfile != nil && evt.ReconProfile.RiskScore != "" {
		if l4Score, err := strconv.Atoi(evt.ReconProfile.RiskScore); err == nil {
			if l4Score > evt.ThreatScore {
				evt.ThreatScore = l4Score
			}
		}
		// Attacker yang sudah scan L4 dan sekarang probe exploit L7 adalah ancaman kritis
		if evt.AttackPattern != "" && evt.AttackPattern != "ENDPOINT_RECONNAISSANCE" {
			evt.ThreatScore = 98
			evt.Severity = "CRITICAL"
			evt.KillChainPhase = "Exploitation"
		}
	}

	if evt.Severity == "" {
		if evt.ThreatScore >= 90 {
			evt.Severity = "CRITICAL"
		} else if evt.ThreatScore >= 70 {
			evt.Severity = "HIGH"
		} else if evt.ThreatScore >= 40 {
			evt.Severity = "MEDIUM"
		} else {
			evt.Severity = "LOW"
		}
	}
}

// asyncEnrichAndLog mengeksekusi korelasi L4 dari cacheDB dan rDNS menggunakan Goroutine asinkron
func (l *Logger) asyncEnrichAndLog(event *ClassRootCTIEvent) {
	if l == nil || event == nil {
		return
	}

	// Goroutine terisolasi: zero latency impact pada loop request/koneksi utama
	go func(evt *ClassRootCTIEvent) {
		if evt.SessionID == "" && evt.RemoteIP != "" {
			evt.SessionID = generateSessionID(evt.RemoteIP)
		}

		// Asynchronous Reverse DNS lookup jika bukan loopback
		if evt.RemoteIP != "" && evt.RemoteIP != "127.0.0.1" && evt.RemoteIP != "::1" && evt.ReverseDNS == "" {
			evt.ReverseDNS = resolveReverseDNS(evt.RemoteIP)
		}

		// Korelasi L4 Reconnaissance Profile dari CacheDB
		if l.cacheClient != nil && evt.RemoteIP != "" {
			if dossier, found, err := cdc.GetActor(evt.RemoteIP, l.cacheClient); err == nil && found && dossier != nil {
				evt.ReconProfile = &ReconProfileInfo{
					SYNFingerprintHash: dossier.SynHash,
					RiskScore:          dossier.RiskScore,
					Severity:           dossier.Severity,
					TargetService:      dossier.TargetService,
					IntentCategory:     dossier.IntentCategory,
					ScanVelocity:       dossier.ScanVelocity,
					EstimatedOS:        dossier.EstimatedOs,
					ScannerTool:        dossier.ScannerTool,
					ScanHits:           dossier.ScanHits,
					LastScan:           dossier.LastActivity,
				}
				if evt.AttackPattern != "" && evt.AttackPattern != "ENDPOINT_RECONNAISSANCE" {
					log.Printf("[SOC ALERT] Korelasi Terdeteksi: IP %s (L4 Tool: %s, SYN Hash: %s) mencoba exploit L7: %s pada %s",
						evt.RemoteIP, evt.ReconProfile.ScannerTool, evt.ReconProfile.SYNFingerprintHash, evt.AttackPattern, evt.URLPath)
				}
			}
		}

		evaluateThreatScore(evt)
		l.LogEvent(evt)
	}(event)
}

func (l *Logger) processEvent(event *ClassRootCTIEvent) {
	if event.SensorID == "" {
		event.SensorID = l.sensorID
	}
	if event.Timestamp == "" {
		event.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}

	data, err := json.Marshal(event)
	if err != nil {
		log.Printf("[CTI] Gagal serialize JSON event: %v", err)
		return
	}

	if l.file != nil {
		l.mu.Lock()
		l.file.Write(append(data, '\n'))
		l.mu.Unlock()
	}

	if l.cacheClient != nil {
		// Simpan riwayat ancaman ke cacheDB
		key := fmt.Sprintf("webrtc:%s", event.RemoteIP)
		if event.Candidate != nil && event.Candidate.IP != "" {
			key = fmt.Sprintf("webrtc:local_ip:%s", event.Candidate.IP)
		}
		_ = cdc.Set(key, string(data), l.cacheClient)

		// Simpan korelasi ancaman kredensial & hardware
		if event.Username != "" {
			_ = cdc.Set(fmt.Sprintf("actor:classroot:user:%s", event.RemoteIP), event.Username, l.cacheClient)
		}
		if event.Password != "" {
			_ = cdc.Set(fmt.Sprintf("actor:classroot:pass:%s", event.RemoteIP), event.Password, l.cacheClient)
		}
		if event.Fingerprint != nil && event.Fingerprint.GPURenderer != "" {
			_ = cdc.Set(fmt.Sprintf("actor:gpu:%s", event.RemoteIP), event.Fingerprint.GPURenderer, l.cacheClient)
		}
		if event.URLPath != "" {
			_ = cdc.Set(fmt.Sprintf("actor:probe:%s:%s", event.RemoteIP, event.URLPath), string(data), l.cacheClient)
		}
		if event.ReverseDNS != "" {
			_ = cdc.Set(fmt.Sprintf("actor:rdns:%s", event.RemoteIP), event.ReverseDNS, l.cacheClient)
		}
		if event.AttackPattern != "" && event.AttackPattern != "ENDPOINT_RECONNAISSANCE" {
			_ = cdc.Set(fmt.Sprintf("actor:risk:%s", event.RemoteIP), strconv.Itoa(event.ThreatScore), l.cacheClient)
			_ = cdc.Set(fmt.Sprintf("actor:severity:%s", event.RemoteIP), event.Severity, l.cacheClient)
			_ = cdc.Set(fmt.Sprintf("actor:intent:%s", event.RemoteIP), "EXPLOITATION_WEB:"+event.AttackPattern, l.cacheClient)
		}
	}

	if event.Method != "" || event.URLPath != "" {
		log.Printf("[CTI PROBE] [%s] %s %s %s from IP: %s (Pattern: %s, Score: %d [%s], Status: %s)",
			event.EventType, event.Mitre.ID, event.Method, event.URLPath, event.RemoteIP, event.AttackPattern, event.ThreatScore, event.Severity, event.Status)
	} else {
		log.Printf("[CTI ALERT] [%s] %s IP: %s (User: %s, Room: %s, Score: %d [%s])",
			event.EventType, event.Mitre.ID, event.RemoteIP, event.Username, event.Group, event.ThreatScore, event.Severity)
	}
}

func (l *Logger) Close() {
	if l != nil {
		close(l.quit)
		l.wg.Wait()
		if l.file != nil {
			l.file.Close()
		}
		if l.grpcConn != nil {
			l.grpcConn.Close()
		}
	}
}

func Get() *Logger {
	return globalLogger
}

func (l *Logger) LogEvent(event *ClassRootCTIEvent) {
	if l == nil {
		return
	}
	select {
	case l.eventChan <- event:
	default:
		go l.processEvent(event)
	}
}

// LogRoomAuth mencatat percobaan join atau otentikasi group/room beserta identitas client & agent
func LogRoomAuth(remoteAddr net.Addr, userAgent string, headers map[string]string, groupName string, username, password, tokenStr, status, reason string) {
	if globalLogger == nil {
		return
	}

	ip, port := splitAddr(remoteAddr)
	eventType := "ROOM_AUTH_FAILED"
	technique := "Brute Force: Password Guessing / Room Probing"
	techniqueID := "T1110"

	if status == "success" {
		eventType = "ROOM_JOIN_SUCCESS"
		technique = "Valid Accounts: Default / Known Accounts"
		techniqueID = "T1078"
	}

	event := &ClassRootCTIEvent{
		EventType:   eventType,
		Status:      status,
		RemoteIP:    ip,
		RemotePort:  port,
		Group:       groupName,
		Username:    username,
		Password:    password,
		Token:       tokenStr,
		UserAgent:   userAgent,
		Headers:     headers,
		FailureDesc: reason,
		Mitre: MitreAttackInfo{
			Tactic:    "Initial Access",
			Technique: technique,
			ID:        techniqueID,
		},
	}

	globalLogger.asyncEnrichAndLog(event)
}

// LogICECandidate mencatat kandidat alamat IP (WebRTC IP Leak)
func LogICECandidate(remoteAddr net.Addr, userAgent string, headers map[string]string, groupName, username, candStr string) {
	if globalLogger == nil || candStr == "" {
		return
	}

	ip, port := splitAddr(remoteAddr)
	info := parseCandidate(candStr)

	tactic := "Discovery"
	technique := "System Network Configuration Discovery (WebRTC Local IP Leak)"
	techniqueID := "T1016"

	event := &ClassRootCTIEvent{
		EventType:  "WEBRTC_ICE_CANDIDATE_LEAK",
		Status:     "success",
		RemoteIP:   ip,
		RemotePort: port,
		Group:      groupName,
		Username:   username,
		UserAgent:  userAgent,
		Headers:    headers,
		Candidate:  info,
		Mitre: MitreAttackInfo{
			Tactic:    tactic,
			Technique: technique,
			ID:        techniqueID,
		},
	}

	globalLogger.asyncEnrichAndLog(event)
}

// DetectAttackPatterns mengidentifikasi pola serangan web seperti LFI/Path Traversal, SQLi, XSS, Command Injection, atau Sensitive File Scanning
func DetectAttackPatterns(method, urlPath, query, payload string) (attackPattern, tactic, technique, techniqueID string) {
	combined := strings.ToLower(urlPath + " " + query + " " + payload)

	// Path Traversal / Directory Traversal / LFI
	if strings.Contains(combined, "..") || strings.Contains(combined, "%2e%2e") ||
		strings.Contains(combined, "/etc/passwd") || strings.Contains(combined, "win.ini") ||
		strings.Contains(combined, "boot.ini") || strings.Contains(combined, "/proc/self") {
		return "PATH_TRAVERSAL", "Initial Access", "Exploit Public-Facing Application: Path Traversal", "T1190"
	}

	// SQL Injection
	if strings.Contains(combined, "union select") || strings.Contains(combined, "' or '") ||
		strings.Contains(combined, "' or 1=1") || strings.Contains(combined, "\" or \"") ||
		strings.Contains(combined, "sleep(") || strings.Contains(combined, "benchmark(") ||
		strings.Contains(combined, "-- -") || strings.Contains(combined, "information_schema") ||
		strings.Contains(combined, "' union") || strings.Contains(combined, "\" union") {
		return "SQL_INJECTION", "Initial Access", "Exploit Public-Facing Application: SQL Injection", "T1190"
	}

	// Cross-Site Scripting (XSS)
	if strings.Contains(combined, "<script") || strings.Contains(combined, "javascript:") ||
		strings.Contains(combined, "onerror=") || strings.Contains(combined, "onload=") ||
		strings.Contains(combined, "<svg") || strings.Contains(combined, "alert(") ||
		strings.Contains(combined, "%3cscript") {
		return "CROSS_SITE_SCRIPTING", "Initial Access", "Exploit Public-Facing Application: Cross-Site Scripting", "T1189"
	}

	// Command Injection / Web Shell scanning
	if strings.Contains(combined, ";cmd") || strings.Contains(combined, "|cmd") ||
		strings.Contains(combined, ";powershell") || strings.Contains(combined, "|powershell") ||
		strings.Contains(combined, ";/bin/sh") || strings.Contains(combined, "|/bin/sh") ||
		strings.Contains(combined, ";/bin/bash") || strings.Contains(combined, "|/bin/bash") ||
		strings.Contains(combined, "wget http") || strings.Contains(combined, "curl http") ||
		strings.HasSuffix(urlPath, ".php") || strings.HasSuffix(urlPath, ".asp") ||
		strings.HasSuffix(urlPath, ".aspx") || strings.HasSuffix(urlPath, ".jsp") ||
		strings.HasSuffix(urlPath, ".sh") || strings.HasSuffix(urlPath, ".cgi") {
		return "COMMAND_INJECTION_OR_WEBSHELL", "Initial Access", "Exploit Public-Facing Application: Command Injection", "T1059"
	}

	// Sensitive File / Credential Enumeration
	if strings.Contains(combined, ".env") || strings.Contains(combined, ".git") ||
		strings.Contains(combined, "wp-config") || strings.Contains(combined, "config.json") ||
		strings.Contains(combined, "id_rsa") || strings.Contains(combined, ".aws") ||
		strings.Contains(combined, "actuator/health") || strings.Contains(combined, "phpmyadmin") ||
		strings.Contains(combined, "telescope") || strings.Contains(combined, "swagger") {
		return "SENSITIVE_FILE_SCANNING", "Discovery", "File and Directory Discovery: Sensitive Information", "T1083"
	}

	// HTTP Method Tampering
	if method != "" && method != "GET" && method != "HEAD" && method != "OPTIONS" {
		return "UNEXPECTED_HTTP_METHOD", "Initial Access", "Exploit Public-Facing Application: HTTP Method Tampering", "T1190"
	}

	// Default: Vulnerability Scanning & Path Reconnaissance
	return "ENDPOINT_RECONNAISSANCE", "Reconnaissance", "Active Scanning: Vulnerability Scanning / Path Recon", "T1595.002"
}

// LogHTTPProbe mencatat percobaan akses ke endpoint tak dikenal, salah path, method tidak diizinkan, atau percobaan injection
func LogHTTPProbe(remoteIP string, remotePort int, method, urlPath, query, userAgent string, headers map[string]string, status int, payloadSnippet string) {
	if globalLogger == nil {
		return
	}

	attackPattern, tactic, technique, techniqueID := DetectAttackPatterns(method, urlPath, query, payloadSnippet)

	eventType := "HTTP_ENDPOINT_PROBE"
	if attackPattern != "ENDPOINT_RECONNAISSANCE" {
		eventType = "HTTP_ATTACK_ATTEMPT"
	}

	statusStr := "rejected_404"
	if status == 405 {
		statusStr = "rejected_405"
	} else if status != 0 && status != 404 {
		statusStr = fmt.Sprintf("rejected_%d", status)
	}

	event := &ClassRootCTIEvent{
		EventType:      eventType,
		Status:         statusStr,
		RemoteIP:       remoteIP,
		RemotePort:     remotePort,
		Method:         method,
		URLPath:        urlPath,
		Query:          query,
		PayloadSnippet: payloadSnippet,
		AttackPattern:  attackPattern,
		UserAgent:      userAgent,
		Headers:        headers,
		Mitre: MitreAttackInfo{
			Tactic:    tactic,
			Technique: technique,
			ID:        techniqueID,
		},
	}

	globalLogger.asyncEnrichAndLog(event)
}

// LogWebTelemetry mencatat telemetri browser mendalam, pelacakan 404 client, & credential harvesting dari form login
func LogWebTelemetry(remoteIP string, remotePort int, userAgent string, headers map[string]string, groupName, username, password, eventType string, fp *BrowserFingerprint, extraPaths ...string) {
	if globalLogger == nil {
		return
	}

	var urlPath, query string
	if len(extraPaths) > 0 {
		urlPath = extraPaths[0]
	}
	if len(extraPaths) > 1 {
		query = extraPaths[1]
	}

	tactic := "Discovery"
	technique := "System Information Discovery: Hardware & Network"
	techniqueID := "T1082"
	var attackPattern string

	if eventType == "HTTP_404_PROBE" || strings.Contains(eventType, "404") {
		tactic = "Reconnaissance"
		technique = "Active Scanning: Vulnerability Scanning / Path Recon"
		techniqueID = "T1595.002"
		attackPattern, tactic, technique, techniqueID = DetectAttackPatterns("GET", urlPath, query, "")
		if attackPattern != "ENDPOINT_RECONNAISSANCE" {
			eventType = "HTTP_CLIENT_ATTACK_TELEMETRY"
		} else {
			eventType = "HTTP_404_CLIENT_TELEMETRY"
		}
	} else if eventType == "MEDIA_DEVICES_ACCESSED" || (fp != nil && len(fp.MediaDevices) > 0) {
		tactic = "Collection"
		technique = "Peripheral Device Discovery: Camera & Microphone Enumeration"
		techniqueID = "T1125"
	}
	if username != "" || password != "" {
		tactic = "Credential Access"
		technique = "Input Capture: Credentials Harvested"
		techniqueID = "T1056.001"
	}

	event := &ClassRootCTIEvent{
		EventType:     eventType,
		Status:        "captured",
		RemoteIP:      remoteIP,
		RemotePort:    remotePort,
		Group:         groupName,
		Username:      username,
		Password:      password,
		URLPath:       urlPath,
		Query:         query,
		AttackPattern: attackPattern,
		UserAgent:     userAgent,
		Headers:       headers,
		Fingerprint:   fp,
		Mitre: MitreAttackInfo{
			Tactic:    tactic,
			Technique: technique,
			ID:        techniqueID,
		},
	}

	globalLogger.asyncEnrichAndLog(event)
}

func splitAddr(addr net.Addr) (string, int) {
	if addr == nil {
		return "", 0
	}
	s := addr.String()
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return s, 0
	}
	p, _ := strconv.Atoi(portStr)
	return host, p
}

// parseCandidate mem-parsing string kandidat WebRTC SDP
func parseCandidate(c string) *ICECandidateInfo {
	info := &ICECandidateInfo{
		Raw: c,
	}

	fields := strings.Fields(c)
	if len(fields) >= 8 {
		info.Protocol = strings.ToUpper(fields[2])
		info.IP = fields[4]
		info.Port, _ = strconv.Atoi(fields[5])

		// Cari field "typ <type>"
		for i := 6; i < len(fields)-1; i++ {
			if fields[i] == "typ" {
				info.CandidateTyp = fields[i+1]
			}
			if fields[i] == "raddr" {
				info.RelatedIP = fields[i+1]
			}
			if fields[i] == "rport" {
				info.RelatedPort, _ = strconv.Atoi(fields[i+1])
			}
		}
	}
	return info
}
