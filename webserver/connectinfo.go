package webserver

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"

	"rsc.io/qr"
)

// DefaultGroup is the room advertised on the main page and in QR codes.
const DefaultGroup = "main"

// listenPort is the TCP port the web server listens on.
var listenPort string

// NetworkAddress describes one active, non-loopback IPv4 interface.
type NetworkAddress struct {
	Interface string `json:"interface"`
	IP        string `json:"ip"`
}

// NetworkAddresses returns the active, non-loopback IPv4 addresses of
// this host.
func NetworkAddresses() ([]NetworkAddress, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []NetworkAddress
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			if ipv4 := ip.To4(); ipv4 != nil {
				out = append(out, NetworkAddress{iface.Name, ipv4.String()})
			}
		}
	}
	return out, nil
}

// PortFromAddress extracts the port of a listen address, falling back
// to the scheme's default port.
func PortFromAddress(address string, insecure bool) string {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		port = strings.TrimPrefix(address, ":")
	}
	if port == "" {
		if insecure {
			return "80"
		}
		return "443"
	}
	return port
}

func ipBaseURL(ip string) string {
	scheme := "https"
	if Insecure {
		scheme = "http"
	}
	return scheme + "://" + net.JoinHostPort(ip, listenPort) + "/"
}

const textRule = "=============================="

// ConnectText returns the connection details as plain text, formatted
// like the CLI banner, ready to be shared to a class chat group.
func ConnectText() (string, error) {
	addrs, err := NetworkAddresses()
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("ClassRoot - Info Koneksi Meet\n")
	b.WriteString(textRule + "\n")
	b.WriteString("[Akses Jaringan]\n")
	if len(addrs) == 0 {
		b.WriteString("(Tidak ada interface IPv4 yang aktif)\n")
	}
	for _, a := range addrs {
		base := ipBaseURL(a.IP)
		fmt.Fprintf(&b, "* %s (IP: %s)\n", a.Interface, a.IP)
		fmt.Fprintf(&b, "  URL Portal : %s\n", base)
		fmt.Fprintf(&b, "  Ruang Rapat: %sgroup/%s/\n", base, DefaultGroup)
	}
	b.WriteString(textRule + "\n")
	fmt.Fprintf(&b, "Grup Default: /group/%s/ | Rekaman: /recordings/\n", DefaultGroup)
	b.WriteString(textRule + "\n")
	fmt.Fprintf(&b, "[Login Room %s]\n", DefaultGroup)
	b.WriteString("Presenter: username (bebas)\n")
	b.WriteString("Password : (bebas, asal tidak kosong)\n")
	return b.String(), nil
}

func connectInfoHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	text, err := ConnectText()
	if err != nil {
		http.Error(w, "cannot list interfaces", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]string{
		"text": text,
		"qr":   "/connect-qr.png",
	})
}

// connectQRHandler serves a QR code whose content is ConnectText.
func connectQRHandler(w http.ResponseWriter, r *http.Request) {
	text, err := ConnectText()
	if err != nil {
		http.Error(w, "cannot list interfaces", http.StatusInternalServerError)
		return
	}
	code, err := qr.Encode(text, qr.L)
	if err != nil {
		http.Error(w, "cannot encode QR", http.StatusInternalServerError)
		return
	}
	code.Scale = 6
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(code.PNG())
}
