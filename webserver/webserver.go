package webserver

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"

	"github.com/jech/cert"
	"github.com/n0z0/ClassRoot/cti"
	"github.com/n0z0/ClassRoot/diskwriter"
	"github.com/n0z0/ClassRoot/group"
	"github.com/n0z0/ClassRoot/rtpconn"
)

var server *http.Server

var StaticRoot string
var staticRoot *os.Root

var Insecure bool

func Serve(address string, dataDir string) error {
	var err error
	staticRoot, err = os.OpenRoot(StaticRoot)
	if err != nil {
		return err
	}
	http.Handle("/", &fileHandler{staticRoot})
	http.HandleFunc("/group/", groupHandler)
	http.HandleFunc("/recordings",
		func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r,
				"/recordings/", http.StatusPermanentRedirect)
		})
	http.HandleFunc("/recordings/", recordingsHandler)
	http.HandleFunc("/ws", wsHandler)
	http.HandleFunc("/public-groups.json", publicHandler)
	http.HandleFunc("/galene-api/", apiHandler)
	http.HandleFunc("/api/telemetry", telemetryHandler)
	http.HandleFunc("/cti/telemetry", telemetryHandler)

	s := &http.Server{
		Addr:              address,
		ReadHeaderTimeout: 60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	if !Insecure {
		if err := EnsureTLSCertificates(dataDir); err != nil {
			log.Printf("[TLS] Peringatan: gagal memastikan sertifikat TLS: %v", err)
		}
		certificate := cert.New(
			filepath.Join(dataDir, "cert.pem"),
			filepath.Join(dataDir, "key.pem"),
		)
		s.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				return certificate.Get()
			},
		}
	}
	s.RegisterOnShutdown(func() {
		group.Shutdown("server is shutting down")
	})

	server = s

	proto := "tcp"
	if strings.HasPrefix(address, "/") {
		proto = "unix"
	}

	listener, err := net.Listen(proto, address)
	if err != nil {
		return err
	}
	go func() {
		defer listener.Close()
		if !Insecure {
			err = s.ServeTLS(listener, "", "")
		} else {
			err = s.Serve(listener)
		}
	}()
	return nil
}

func cspHeader(w http.ResponseWriter, connect string) {
	c := "connect-src ws: wss: 'self'; "
	if connect != "" {
		c = "connect-src " + connect + " ws: wss: 'self'; "
	}
	w.Header().Add("Content-Security-Policy",
		c+"img-src 'self'; media-src blob: 'self'; script-src 'unsafe-eval' 'self'; default-src 'self'")

	// Make browser stop sending referrer information
	w.Header().Add("Referrer-Policy", "no-referrer")

	// Require correct MIME type to load CSS and JS
	w.Header().Add("X-Content-Type-Options", "nosniff")
}

func extractRequestBodySnippet(r *http.Request) string {
	if r == nil || r.Body == nil {
		return ""
	}
	bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, 2048))
	if err != nil || len(bodyBytes) == 0 {
		return ""
	}
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	return string(bodyBytes)
}

func notFound(w http.ResponseWriter, r ...*http.Request) {
	var req *http.Request
	if len(r) > 0 {
		req = r[0]
	}
	if req != nil {
		clientIP, clientPort := extractClientIP(req)
		userAgent := req.UserAgent()
		headers := extractKeyHeaders(req)
		payloadSnippet := extractRequestBodySnippet(req)
		cti.LogHTTPProbe(clientIP, clientPort, req.Method, req.URL.Path, req.URL.RawQuery, userAgent, headers, http.StatusNotFound, payloadSnippet)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)

	f, err := staticRoot.Open("404.html")
	if err != nil {
		fmt.Fprintln(w, "<p>Not found</p>")
		return
	}
	defer f.Close()

	io.Copy(w, f)
}

func internalError(w http.ResponseWriter, format string, args ...any) {
	log.Printf(format, args...)
	http.Error(w, "Internal server error", http.StatusInternalServerError)
}

var ErrIsDirectory = errors.New("is a directory")

func httpError(w http.ResponseWriter, err error, r ...*http.Request) {
	if errors.Is(err, os.ErrNotExist) {
		notFound(w, r...)
		return
	}
	if errors.Is(err, group.ErrUnknownPermission) {
		http.Error(w, "unknown permission", http.StatusBadRequest)
		return
	}
	var autherr *group.NotAuthorisedError
	if errors.As(err, &autherr) {
		log.Printf("HTTP server error: %v", err)
		http.Error(w, "not authorised", http.StatusUnauthorized)
		return
	}
	var mberr *http.MaxBytesError
	if errors.As(err, &mberr) {
		http.Error(w, "Request body too large",
			http.StatusRequestEntityTooLarge)
		return
	}
	internalError(w, "HTTP server error: %v", err)
}

func methodNotAllowed(w http.ResponseWriter, methods string, r ...*http.Request) {
	if len(r) > 0 && r[0] != nil {
		req := r[0]
		clientIP, clientPort := extractClientIP(req)
		userAgent := req.UserAgent()
		headers := extractKeyHeaders(req)
		payloadSnippet := extractRequestBodySnippet(req)
		cti.LogHTTPProbe(clientIP, clientPort, req.Method, req.URL.Path, req.URL.RawQuery, userAgent, headers, http.StatusMethodNotAllowed, payloadSnippet)
	}
	w.Header().Set("Allow", "OPTIONS, "+methods)
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

const (
	normalCacheControl       = "max-age=1800"
	veryCachableCacheControl = "max-age=86400"
)

func redirect(w http.ResponseWriter, r *http.Request) bool {
	conf, err := group.GetConfiguration()
	if err != nil || conf.CanonicalHost == "" {
		return false
	}

	if strings.EqualFold(r.Host, conf.CanonicalHost) {
		return false
	}

	u := url.URL{
		Scheme: "https",
		Host:   conf.CanonicalHost,
		Path:   r.URL.Path,
	}
	http.Redirect(w, r, u.String(), http.StatusMovedPermanently)
	return true
}

func makeCachable(w http.ResponseWriter, p string, fi os.FileInfo, cachable bool) {
	etag := fmt.Sprintf("\"%v-%v\"", fi.Size(), fi.ModTime().UnixNano())
	w.Header().Set("ETag", etag)
	if !cachable {
		w.Header().Set("cache-control", "no-cache")
		return
	}

	cc := normalCacheControl
	if strings.HasPrefix(p, "/third-party/") {
		cc = veryCachableCacheControl
	}

	w.Header().Set("Cache-Control", cc)
}

// fileHandler is our custom reimplementation of http.FileServer
type fileHandler struct {
	root *os.Root
}

func (fh *fileHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if redirect(w, r) {
		return
	}

	if r.Method != "GET" && r.Method != "HEAD" {
		methodNotAllowed(w, "GET, HEAD", r)
		return
	}

	cspHeader(w, "")
	if !strings.HasPrefix(r.URL.Path, "/") {
		http.Error(w,
			"internal server error", http.StatusInternalServerError)
		return
	}
	var p string
	if r.URL.Path == "/" {
		p = "."
	} else {
		p = r.URL.Path[1:]
	}

	f, err := fh.root.Open(p)
	if err != nil {
		httpError(w, err, r)
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		httpError(w, err, r)
		return
	}

	if fi.IsDir() {
		u := r.URL.Path
		if u[len(u)-1] != '/' {
			http.Redirect(w, r, u+"/", http.StatusPermanentRedirect)
			return
		}

		index := path.Join(p, "index.html")
		ff, err := fh.root.Open(index)
		if err != nil {
			// return 404 if index.html doesn't exist
			if errors.Is(err, os.ErrNotExist) {
				notFound(w, r)
				return
			}
			httpError(w, err, r)
			return
		}
		defer ff.Close()
		dd, err := ff.Stat()
		if err != nil {
			httpError(w, err, r)
			return
		}
		if dd.IsDir() {
			httpError(w, ErrIsDirectory, r)
			return
		}
		f, fi = ff, dd
		p = index
	}

	makeCachable(w, p, fi, true)
	http.ServeContent(w, r, fi.Name(), fi.ModTime(), f)
}

// serveFile is similar to http.ServeFile, except that it doesn't check
// for .. and adds cachability headers.
func serveFile(w http.ResponseWriter, r *http.Request, root *os.Root, p string) {
	f, err := root.Open(p)
	if err != nil {
		httpError(w, err, r)
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		httpError(w, err, r)
		return
	}

	if fi.IsDir() {
		httpError(w, ErrIsDirectory, r)
		return
	}

	makeCachable(w, p, fi, true)
	http.ServeContent(w, r, fi.Name(), fi.ModTime(), f)
}

func parseGroupName(prefix string, p string) string {
	if !strings.HasPrefix(p, prefix) {
		return ""
	}

	name := p[len(prefix):]
	if name == "" {
		return ""
	}

	if name[0] == '.' {
		return ""
	}

	if filepath.Separator != '/' &&
		strings.ContainsRune(name, filepath.Separator) {
		return ""
	}

	name = path.Clean("/" + name)
	return name[1:]
}

func splitPath(pth string) (string, string, string) {
	index := strings.Index(pth, "/.")
	if index < 0 {
		return pth, "", ""
	}

	index2 := strings.Index(pth[index+1:], "/")
	if index2 < 0 {
		return pth[:index], pth[index+1:], ""
	}
	return pth[:index], pth[index+1 : index+1+index2], pth[index+1+index2:]
}

func groupHandler(w http.ResponseWriter, r *http.Request) {
	if redirect(w, r) {
		return
	}

	dir, kind, rest := splitPath(r.URL.Path)
	if kind == ".status" && rest == "" {
		groupStatusHandler(w, r)
		return
	} else if kind == ".status.json" && rest == "" {
		http.Redirect(w, r, dir+"/"+".status",
			http.StatusPermanentRedirect)
		return
	} else if kind == ".whip" {
		if rest == "" {
			whipEndpointHandler(w, r)
		} else {
			whipResourceHandler(w, r)
		}
		return
	} else if kind != "" {
		notFound(w, r)
		return
	}

	name := parseGroupName("/group/", r.URL.Path)
	if name == "" {
		notFound(w, r)
		return
	}

	g, err := group.Add(name, nil)
	if err != nil {
		httpError(w, err, r)
		return
	}

	if r.URL.Path != "/group/"+name+"/" {
		http.Redirect(w, r, "/group/"+name+"/",
			http.StatusPermanentRedirect)
		return
	}

	if redirect := g.Description().Redirect; redirect != "" {
		http.Redirect(w, r, redirect, http.StatusPermanentRedirect)
		return
	}

	status := g.Status(false, nil)
	cspHeader(w, status.AuthServer)
	serveFile(w, r, staticRoot, "galene.html")
}

func baseURL(r *http.Request) (*url.URL, error) {
	conf, err := group.GetConfiguration()
	if err != nil {
		return nil, err
	}
	var pu *url.URL
	if conf.ProxyURL != "" {
		pu, err = url.Parse(conf.ProxyURL)
		if err != nil {
			return nil, err
		}
	}
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	host := r.Host
	path := ""
	if pu != nil {
		if pu.Scheme != "" {
			scheme = pu.Scheme
		}
		if pu.Host != "" {
			host = pu.Host
		}
		path = pu.Path
	}
	base := url.URL{
		Scheme: scheme,
		Host:   host,
		Path:   path,
	}
	return &base, nil
}

func groupStatusHandler(w http.ResponseWriter, r *http.Request) {
	pth, kind, rest := splitPath(r.URL.Path)
	if kind != ".status" || rest != "" {
		internalError(w, "groupStatusHandler: this shouldn't happen")
		return
	}
	name := parseGroupName("/group/", pth)
	if name == "" {
		notFound(w, r)
		return
	}

	g, err := group.Add(name, nil)
	if err != nil {
		httpError(w, err, r)
		return
	}

	base, err := baseURL(r)
	if err != nil {
		internalError(w, "Parse ProxyURL: %v", err)
		return
	}
	d := g.Status(false, base)
	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-cache")

	if r.Method == "HEAD" {
		return
	}

	e := json.NewEncoder(w)
	e.Encode(d)
}

func publicHandler(w http.ResponseWriter, r *http.Request) {
	base, err := baseURL(r)
	if err != nil {
		log.Printf("couldn't determine group base: %v", err)
		httpError(w, err)
		return
	}
	w.Header().Set("content-type", "application/json")
	w.Header().Set("cache-control", "no-cache")

	if r.Method == "HEAD" {
		return
	}

	g := group.GetPublic(base)
	e := json.NewEncoder(w)
	e.Encode(g)
}

// globalAdminMatch checks whether the given credentials match with an
// administrator entry in the global configuration file.
func globalAdminMatch(username, password string) (bool, error) {
	conf, err := group.GetConfiguration()
	if err != nil {
		return false, err
	}

	u, found := conf.Users[username]
	if found {
		ok, err := u.Password.Match(password)
		if err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
		perms := u.Permissions.Permissions(nil)
		for _, p := range perms {
			if p == "admin" {
				return true, nil
			}
		}
		return false, nil
	}

	return false, nil
}

func failAuthentication(w http.ResponseWriter, realm string) {
	w.Header().Set("www-authenticate",
		fmt.Sprintf("basic realm=\"%v\"", realm))
	http.Error(w, "Haha!", http.StatusUnauthorized)
}

// CheckOrigin adds the CORS header to the reply.
// It obeys the AllowOrigin or AllowAdminOrigin field of the global
// configuration, depending on the value of admin.
// It returns true if the header was added, false otherwise.
func CheckOrigin(w http.ResponseWriter, r *http.Request, admin bool) bool {
	if w != nil {
		w.Header().Add("Vary", "Origin")
	}

	origins := r.Header["Origin"]
	if len(origins) == 0 {
		return true
	}
	origin := origins[0]

	ok := false
	o, err := url.Parse(origin)
	if err == nil && strings.EqualFold(o.Host, r.Host) {
		ok = true
	} else {
		conf, err := group.GetConfiguration()
		if err != nil {
			return false
		}

		allow := conf.AllowOrigin
		if admin {
			allow = conf.AllowAdminOrigin
		}
		for _, a := range allow {
			if strings.EqualFold(origin, a) {
				ok = true
				break
			}
		}
	}

	if !ok {
		return false
	}

	if w != nil {
		w.Header().Add("Access-Control-Allow-Origin", origin)
	}
	return true
}

var wsUpgrader = websocket.Upgrader{
	HandshakeTimeout: 30 * time.Second,
	CheckOrigin: func(r *http.Request) bool {
		return CheckOrigin(nil, r, false)
	},
}

func wsHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Websocket upgrade: %v", err)
		return
	}

	userAgent := r.UserAgent()
	headers := extractKeyHeaders(r)

	var addr net.Addr
	tcpaddr, err := net.ResolveTCPAddr("tcp", r.RemoteAddr)
	if err != nil {
		log.Printf("ResolveTCPAddr: %v", err)
	} else {
		addr = tcpaddr
	}

	go func() {
		err := rtpconn.StartClient(conn, addr, userAgent, headers)
		if err != nil {
			log.Printf("client: %v", err)
		}
	}()
}

func extractClientIP(r *http.Request) (string, int) {
	ipStr := r.Header.Get("CF-Connecting-IP")
	if ipStr == "" {
		ipStr = r.Header.Get("X-Real-IP")
	}
	if ipStr == "" {
		xff := r.Header.Get("X-Forwarded-For")
		if xff != "" {
			parts := strings.Split(xff, ",")
			ipStr = strings.TrimSpace(parts[0])
		}
	}

	var port int
	remoteHost, remotePortStr, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		p, _ := strconv.Atoi(remotePortStr)
		port = p
		if ipStr == "" {
			ipStr = remoteHost
		}
	} else if ipStr == "" {
		ipStr = r.RemoteAddr
	}

	return ipStr, port
}

func extractKeyHeaders(r *http.Request) map[string]string {
	headers := make(map[string]string)
	keys := []string{
		"User-Agent", "Accept-Language", "Sec-Ch-Ua", "Sec-Ch-Ua-Platform",
		"Sec-Ch-Ua-Mobile", "Dnt", "Upgrade-Insecure-Requests",
		"CF-Connecting-IP", "X-Forwarded-For", "X-Real-IP",
	}
	for _, k := range keys {
		val := r.Header.Get(k)
		if val != "" {
			headers[k] = val
		}
	}
	return headers
}

type webTelemetryRequest struct {
	Event              string                `json:"event"`
	Username           string                `json:"username"`
	Password           string                `json:"password"`
	Group              string                `json:"group"`
	URLPath            string                `json:"url_path,omitempty"`
	Query              string                `json:"query,omitempty"`
	Referrer           string                `json:"referrer,omitempty"`
	Fingerprint        *cti.BrowserFingerprint `json:"fingerprint,omitempty"`
	ScreenResolution   string                `json:"screen_resolution,omitempty"`
	ColorDepth         int                   `json:"color_depth,omitempty"`
	PixelRatio         float64               `json:"pixel_ratio,omitempty"`
	Platform           string                `json:"platform,omitempty"`
	Languages          string                `json:"languages,omitempty"`
	Timezone           string                `json:"timezone,omitempty"`
	TimezoneOffset     int                   `json:"timezone_offset,omitempty"`
	HardwareCores      int                   `json:"hardware_cores,omitempty"`
	DeviceMemory       float64               `json:"device_memory,omitempty"`
	GPUVendor          string                `json:"gpu_vendor,omitempty"`
	GPURenderer        string                `json:"gpu_renderer,omitempty"`
	CanvasHash         string                `json:"canvas_hash,omitempty"`
	AudioHash          string                `json:"audio_hash,omitempty"`
	MediaDevices       []cti.MediaDeviceInfo `json:"media_devices,omitempty"`
	NetworkInfo        *cti.NetworkInfo      `json:"network_info,omitempty"`
	BluetoothSupported bool                  `json:"bluetooth_supported,omitempty"`
}

func telemetryHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clientIP, clientPort := extractClientIP(r)
	userAgent := r.UserAgent()
	headers := extractKeyHeaders(r)

	var req webTelemetryRequest
	body, err := io.ReadAll(io.LimitReader(r.Body, 1024*1024))
	if err == nil && len(body) > 0 {
		_ = json.Unmarshal(body, &req)
	}

	if req.Referrer != "" {
		headers["Referer"] = req.Referrer
	}

	fp := req.Fingerprint
	if fp == nil {
		fp = &cti.BrowserFingerprint{
			ScreenResolution:   req.ScreenResolution,
			ColorDepth:         req.ColorDepth,
			PixelRatio:         req.PixelRatio,
			Platform:           req.Platform,
			Languages:          req.Languages,
			Timezone:           req.Timezone,
			TimezoneOffset:     req.TimezoneOffset,
			HardwareCores:      req.HardwareCores,
			DeviceMemory:       req.DeviceMemory,
			GPUVendor:          req.GPUVendor,
			GPURenderer:        req.GPURenderer,
			CanvasHash:         req.CanvasHash,
			AudioHash:          req.AudioHash,
			MediaDevices:       req.MediaDevices,
			NetworkInfo:        req.NetworkInfo,
			BluetoothSupported: req.BluetoothSupported,
		}
	} else {
		if len(fp.MediaDevices) == 0 && len(req.MediaDevices) > 0 {
			fp.MediaDevices = req.MediaDevices
		}
		if fp.NetworkInfo == nil && req.NetworkInfo != nil {
			fp.NetworkInfo = req.NetworkInfo
		}
		if !fp.BluetoothSupported && req.BluetoothSupported {
			fp.BluetoothSupported = req.BluetoothSupported
		}
	}

	eventType := "WEB_TELEMETRY_CAPTURED"
	if req.Event != "" {
		eventType = req.Event
	}

	cti.LogWebTelemetry(clientIP, clientPort, userAgent, headers, req.Group, req.Username, req.Password, eventType, fp, req.URLPath, req.Query)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

func recordingsHandler(w http.ResponseWriter, r *http.Request) {
	if redirect(w, r) {
		return
	}

	if len(r.URL.Path) < 12 || r.URL.Path[:12] != "/recordings/" {
		internalError(w, "reconrdingsHandler: this shouldn't happen")
		return
	}

	p := r.URL.Path[12:]
	if p == "" {
		http.Error(w, "Bad group name", http.StatusBadRequest)
		return
	}

	if filepath.Separator != '/' &&
		strings.ContainsRune(p, filepath.Separator) {
		http.Error(w, "Bad character in filename",
			http.StatusBadRequest)
		return
	}

	root, err := os.OpenRoot(diskwriter.Directory)
	if err != nil {
		httpError(w, err)
		return
	}
	defer root.Close()

	f, err := root.Open(p)
	if err != nil {
		httpError(w, err)
		return
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		httpError(w, err)
		return
	}

	var group, filename string
	if fi.IsDir() {
		for len(p) > 0 && p[len(p)-1] == '/' {
			p = p[:len(p)-1]
		}
		group = parseGroupName("", p)
		if group == "" {
			http.Error(w, "Bad group name", http.StatusBadRequest)
			return
		}
	} else {
		group, filename = path.Split(p)
		group = parseGroupName("", group)
		if group == "" {
			http.Error(w, "Bad group name", http.StatusBadRequest)
			return
		}
	}

	u := "/recordings/" + group + "/" + filename
	if r.URL.Path != u {
		http.Redirect(w, r, u, http.StatusPermanentRedirect)
		return
	}

	ok := checkRecordPermission(w, r, group)
	if !ok {
		failAuthentication(w, "recordings/"+group)
		return
	}

	if filename == "" {
		if r.Method == "POST" {
			handleGroupAction(w, r, group)
		} else {
			serveGroupRecordings(w, r, f, group)
		}
		return
	}

	// Ensure the file is uncachable if it's still recording
	cachable := time.Since(fi.ModTime()) > time.Minute
	makeCachable(w, path.Join("/recordings/", p), fi, cachable)
	http.ServeContent(w, r, fi.Name(), fi.ModTime(), f)
}

func handleGroupAction(w http.ResponseWriter, r *http.Request, group string) {
	if r.Method != "POST" {
		methodNotAllowed(w, "POST")
		return
	}

	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Couldn't parse request", http.StatusBadRequest)
		return
	}

	q := r.Form.Get("q")

	switch q {
	case "delete":
		filename := r.Form.Get("filename")
		if group == "" || filename == "" {
			http.Error(w, "No filename provided",
				http.StatusBadRequest)
			return
		}
		if strings.ContainsRune(filename, '/') ||
			strings.ContainsRune(filename, filepath.Separator) {
			http.Error(w, "Bad character in filename",
				http.StatusBadRequest)
			return
		}
		root, err := os.OpenRoot(diskwriter.Directory)
		if err != nil {
			httpError(w, err)
			return
		}
		defer root.Close()

		err = root.Remove(
			filepath.Join(group, path.Clean("/"+filename)),
		)
		if err != nil {
			httpError(w, err)
			return
		}
		http.Redirect(w, r, "/recordings/"+group+"/",
			http.StatusSeeOther)
		return
	default:
		http.Error(w, "Unknown query", http.StatusBadRequest)
	}
}

func checkRecordPermission(w http.ResponseWriter, r *http.Request, groupname string) bool {
	user, pass, ok := r.BasicAuth()
	if !ok {
		return false
	}

	desc, err := group.GetDescription(groupname)
	if err != nil {
		return false
	}

	_, p, err := desc.GetPermission(
		groupname,
		group.ClientCredentials{
			Username: &user,
			Password: pass,
		},
	)
	record := false
	if err == nil {
		for _, v := range p {
			if v == "record" {
				record = true
				break
			}
		}
	}
	if err != nil || !record {
		var autherr *group.NotAuthorisedError
		if errors.As(err, &autherr) {
			time.Sleep(200 * time.Millisecond)
		}
		return false
	}

	return true
}

func serveGroupRecordings(w http.ResponseWriter, r *http.Request, f *os.File, group string) {
	if r.Method != "HEAD" && r.Method != "GET" {
		methodNotAllowed(w, "HEAD,GET")
		return
	}
	// read early, so we return permission errors to HEAD
	fis, err := f.Readdir(-1)
	if err != nil {
		httpError(w, err)
		return
	}

	sort.Slice(fis, func(i, j int) bool {
		return fis[i].Name() < fis[j].Name()
	})

	w.Header().Set("content-type", "text/html; charset=utf-8")
	w.Header().Set("cache-control", "no-cache")

	if r.Method == "HEAD" {
		return
	}

	fmt.Fprintf(w, "<!DOCTYPE html>\n<html><head>\n")
	fmt.Fprintf(w, "<title>Recordings for group %v</title>\n", group)
	fmt.Fprintf(w, "<link rel=\"stylesheet\" type=\"text/css\" href=\"/common.css\"/>")
	fmt.Fprintf(w, "</head><body>\n")

	fmt.Fprintf(w, "<table>\n")
	for _, fi := range fis {
		if fi.IsDir() {
			continue
		}
		fmt.Fprintf(w, "<tr><td><a href=\"./%v\">%v</a></td><td>%d</td>",
			html.EscapeString(fi.Name()),
			html.EscapeString(fi.Name()),
			fi.Size(),
		)
		fmt.Fprintf(w,
			"<td><form action=\"/recordings/%v/\" method=\"post\">"+
				"<input type=\"hidden\" name=\"filename\" value=\"%v\">"+
				"<button type=\"submit\" name=\"q\" value=\"delete\">Delete</button>"+
				"</form></td></tr>\n",
			url.PathEscape(group), html.EscapeString(fi.Name()))
	}
	fmt.Fprintf(w, "</table>\n")
	fmt.Fprintf(w, "</body></html>\n")
}

func Shutdown() {
	if server == nil {
		log.Printf("Shutting down nonexistent server")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	server.Shutdown(ctx)
	server = nil
}
