package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/n0z0/ClassRoot/cti"
	"github.com/n0z0/ClassRoot/diskwriter"
	"github.com/n0z0/ClassRoot/group"
	"github.com/n0z0/ClassRoot/ice"
	"github.com/n0z0/ClassRoot/limit"
	"github.com/n0z0/ClassRoot/token"
	"github.com/n0z0/ClassRoot/turnserver"
	"github.com/n0z0/ClassRoot/webserver"
)

var appVersion = "0.1.0"

func main() {
	var cpuprofile, memprofile, mutexprofile, httpAddr string
	var udpRange string
	var ctiLog, sensorID, cacheDB string
	var versionFlag bool

	flag.StringVar(&httpAddr, "http", ":8443", "web server `address`")
	flag.StringVar(&webserver.StaticRoot, "static", "./static/",
		"web server root `directory`")
	flag.BoolVar(&webserver.Insecure, "insecure", false,
		"act as an HTTP server rather than HTTPS")
	flag.StringVar(&group.DataDirectory, "data", "./data/",
		"data `directory`")
	flag.StringVar(&group.Directory, "groups", "./groups/",
		"group description `directory`")
	flag.StringVar(&diskwriter.Directory, "recordings", "./recordings/",
		"recordings `directory`")
	flag.StringVar(&cpuprofile, "cpuprofile", "",
		"store CPU profile in `file`")
	flag.StringVar(&memprofile, "memprofile", "",
		"store memory profile in `file`")
	flag.StringVar(&mutexprofile, "mutexprofile", "",
		"store mutex profile in `file`")
	flag.StringVar(&udpRange, "udp-range", "",
		"UDP `port` (multiplexing) or port1-port2 (range)")
	flag.BoolVar(&group.UseMDNS, "mdns", false, "gather mDNS addresses")
	flag.BoolVar(&ice.ICERelayOnly, "relay-only", false,
		"require use of TURN relays for all media traffic")
	flag.StringVar(&turnserver.Address, "turn", "auto",
		"built-in TURN server `address` (\"\" to disable)")
	flag.StringVar(&ctiLog, "ctilog", "classroot_cti.jsonl", "file output log CTI (format JSON Lines)")
	flag.StringVar(&sensorID, "sensor-id", "", "ID sensor node (default: hostname)")
	flag.StringVar(&cacheDB, "cachedb", "", "alamat gRPC cacheDB opsional (contoh: 127.0.0.1:50051)")
	flag.BoolVar(&versionFlag, "version", false, "tampilkan versi aplikasi")
	flag.Parse()

	if versionFlag {
		fmt.Printf("ClassRoot v%s\n", appVersion)
		return
	}

	ctiLogger, err := cti.Init(ctiLog, sensorID, cacheDB)
	if err != nil {
		log.Printf("[CTI] Peringatan: gagal inisialisasi logger CTI: %v", err)
	} else {
		defer ctiLogger.Close()
	}

	// Fallback lokasi groups jika ./groups/ tidak ada di working dir tetapi ada di lokasi executable
	if group.Directory == "./groups/" || group.Directory == "./groups" {
		if _, err := os.Stat(group.Directory); os.IsNotExist(err) {
			if exePath, err := os.Executable(); err == nil {
				exeDir := filepath.Dir(exePath)
				exeGroups := filepath.Join(exeDir, "groups")
				if _, err := os.Stat(exeGroups); err == nil {
					group.Directory = exeGroups
				}
			}
		}
	}

	// Fallback lokasi data jika ./data/ tidak ada di working dir tetapi ada di lokasi executable
	if group.DataDirectory == "./data/" || group.DataDirectory == "./data" {
		if _, err := os.Stat(group.DataDirectory); os.IsNotExist(err) {
			if exePath, err := os.Executable(); err == nil {
				exeDir := filepath.Dir(exePath)
				exeData := filepath.Join(exeDir, "data")
				if _, err := os.Stat(exeData); err == nil {
					group.DataDirectory = exeData
				}
			}
		}
	}

	// Pastikan direktori groups dan data otomatis dibuat jika belum ada
	if err := os.MkdirAll(group.Directory, 0755); err == nil {
		defaultGroup := filepath.Join(group.Directory, "public.json")
		// Buat baru atau perbarui jika public.json lama belum memiliki wildcard-user
		if data, err := os.ReadFile(defaultGroup); os.IsNotExist(err) || (err == nil && !strings.Contains(string(data), "wildcard-user")) {
			_ = os.WriteFile(defaultGroup, []byte("{\"public\": true, \"wildcard-user\": {\"password\": {\"type\": \"wildcard\"}, \"permissions\": \"present\"}}\n"), 0644)
		}
		briefingGroup := filepath.Join(group.Directory, "it-briefing.json")
		if _, err := os.Stat(briefingGroup); os.IsNotExist(err) {
			_ = os.WriteFile(briefingGroup, []byte("{\"public\": true, \"users\": {\"admin\": {\"password\": \"admin123\", \"permissions\": \"op\"}}}\n"), 0644)
		}
	}
	_ = os.MkdirAll(group.DataDirectory, 0755)
	_ = os.MkdirAll(diskwriter.Directory, 0755)

	// Fallback lokasi static jika ./static/ tidak ditemukan di working dir
	if webserver.StaticRoot == "./static/" || webserver.StaticRoot == "./static" {
		if _, err := os.Stat(webserver.StaticRoot); os.IsNotExist(err) {
			if exePath, err := os.Executable(); err == nil {
				exeDir := filepath.Dir(exePath)
				exeStatic := filepath.Join(exeDir, "static")
				if _, err := os.Stat(exeStatic); err == nil {
					webserver.StaticRoot = exeStatic
				}
			}
		}
	}

	if udpRange != "" {
		if strings.ContainsRune(udpRange, '-') {
			var min, max uint16
			n, err := fmt.Sscanf(udpRange, "%v-%v", &min, &max)
			if err != nil || n != 2 {
				log.Fatalf("UDP range: %v", err)
			}
			if min <= 0 || max <= 0 || min > max {
				log.Fatalf("UDP range: bad range")
			}
			group.UDPMin = min
			group.UDPMax = max
		} else {
			port, err := strconv.Atoi(udpRange)
			if err != nil {
				log.Fatalf("UDP: %v", err)
			}
			err = group.SetUDPMux(port)
			if err != nil {
				log.Fatalf("UDP: %v", err)
			}
		}
	}

	if cpuprofile != "" {
		f, err := os.Create(cpuprofile)
		if err != nil {
			log.Printf("Create(cpuprofile): %v", err)
			return
		}
		pprof.StartCPUProfile(f)
		defer func() {
			pprof.StopCPUProfile()
			f.Close()
		}()
	}

	if memprofile != "" {
		defer func() {
			f, err := os.Create(memprofile)
			if err != nil {
				log.Printf("Create(memprofile): %v", err)
				return
			}
			pprof.WriteHeapProfile(f)
			f.Close()
		}()
	}

	if mutexprofile != "" {
		runtime.SetMutexProfileFraction(1)
		defer func() {
			f, err := os.Create(mutexprofile)
			if err != nil {
				log.Printf("Create(mutexprofile): %v", err)
				return
			}
			pprof.Lookup("mutex").WriteTo(f, 0)
			f.Close()
		}()
	}

	n, err := limit.Nofile()
	if err != nil {
		log.Printf("Couldn't get file descriptor limit: %v", err)
	} else if n < 0xFFFF {
		log.Printf("File descriptor limit is %v, please increase it!", n)
	}

	ice.ICEFilename = filepath.Join(group.DataDirectory, "ice-servers.json")
	token.SetStatefulFilename(
		filepath.Join(
			filepath.Join(group.DataDirectory, "var"),
			"tokens.jsonl",
		),
	)

	// make sure the list of public groups is updated early
	go group.Update()

	// causes the built-in server to start if required
	ice.Update()
	defer turnserver.Stop()

	err = webserver.Serve(httpAddr, group.DataDirectory)
	if err != nil {
		log.Fatalf("Server: %v", err)
	}

	terminate := make(chan os.Signal, 1)
	signal.Notify(terminate, syscall.SIGINT, syscall.SIGTERM)

	go relayTest()

	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()

	slowTicker := time.NewTicker(12 * time.Hour)
	defer slowTicker.Stop()

	for {
		select {
		case <-ticker.C:
			go func() {
				group.Update()
				token.Expire()
			}()
		case <-slowTicker.C:
			go relayTest()
		case <-terminate:
			webserver.Shutdown()
			return
		}
	}
}

func relayTest() {
	now := time.Now()
	d, err := ice.RelayTest(20 * time.Second)
	if err != nil {
		log.Printf("Relay test failed: %v", err)
		log.Printf("Perhaps you didn't configure a TURN server?")
		return
	}
	log.Printf("Relay test successful in %v, RTT = %v", time.Since(now), d)
}
