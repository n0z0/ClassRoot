package cti

import (
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

// ClassRootCTIEvent mencatat data telemetri intelijen dari interaksi WebRTC
type ClassRootCTIEvent struct {
	Timestamp   string            `json:"timestamp"` // ISO 8601 UTC
	SensorID    string            `json:"sensor_id"`
	EventType   string            `json:"event_type"` // WEBRTC_ICE_CANDIDATE_LEAK, ROOM_AUTH_ATTEMPT, ROOM_JOIN_SUCCESS
	Status      string            `json:"status,omitempty"` // success, failed
	RemoteIP    string            `json:"remote_ip"`
	RemotePort  int               `json:"remote_port,omitempty"`
	Group       string            `json:"group,omitempty"`
	Username    string            `json:"username,omitempty"`
	Password    string            `json:"password,omitempty"`
	Token       string            `json:"token,omitempty"`
	UserAgent   string            `json:"user_agent,omitempty"`
	Candidate   *ICECandidateInfo `json:"ice_candidate,omitempty"`
	FailureDesc string            `json:"failure_reason,omitempty"`
	Mitre       MitreAttackInfo   `json:"mitre_attack"`
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
}

var globalLogger *Logger
var once sync.Once

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
		file:     f,
		sensorID: sensorID,
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

	globalLogger = logger
	return globalLogger, nil
}

func (l *Logger) Close() {
	if l != nil {
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
	}

	log.Printf("[CTI ALERT] [%s] %s IP: %s (User: %s, Room: %s)",
		event.EventType, event.Mitre.ID, event.RemoteIP, event.Username, event.Group)
}

// LogRoomAuth mencatat percobaan join atau otentikasi group/room
func LogRoomAuth(remoteAddr net.Addr, groupName string, username, password, tokenStr, status, reason string) {
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
		FailureDesc: reason,
		Mitre: MitreAttackInfo{
			Tactic:    "Initial Access",
			Technique: technique,
			ID:        techniqueID,
		},
	}

	globalLogger.LogEvent(event)
}

// LogICECandidate mencatat kandidat alamat IP (WebRTC IP Leak)
func LogICECandidate(remoteAddr net.Addr, groupName, username, candStr string) {
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
		Candidate:  info,
		Mitre: MitreAttackInfo{
			Tactic:    tactic,
			Technique: technique,
			ID:        techniqueID,
		},
	}

	globalLogger.LogEvent(event)
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
// Contoh: candidate:842163049 1 udp 1677729535 192.168.1.15 54321 typ host generation 0
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
