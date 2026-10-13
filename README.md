# ClassRoot

[![Release](https://github.com/n0z0/ClassRoot/actions/workflows/release.yml/badge.svg)](https://github.com/n0z0/ClassRoot/actions/workflows/release.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/n0z0/ClassRoot)](https://goreportcard.com/report/github.com/n0z0/ClassRoot)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**ClassRoot** adalah server media konferensi video interaktif WebRTC berkinerja tinggi yang dilengkapi kapabilitas **Threat Intelligence Telemetry & Security Observability (SOC-Grade)**.

ClassRoot memadukan fungsionalitas ruang pertemuan WebRTC mutakhir dengan mesin observabilitas telemetri keamanan aktif. Ketika terdapat upaya akses tidak terotorisasi, sistem secara otomatis merekam telemetri jaringan tingkat dalam—termasuk analisis kandidat WebRTC ICE (*Interactive Connectivity Establishment*) guna pemetaan topologi jaringan untuk kebutuhan Cyber Threat Intelligence (CTI).

---

## 🎯 Peran dalam Ekosistem Pertahanan Terpadu

Dalam arsitektur pemantauan ancaman multi-layer:
- **`synwatcher`**: Mengamati anomali probe transport level rendah (SYN scanning, port sweep).
- **`scpd`**: Mendokumentasikan dan menganalisis percobaan akses ilegal pada protokol transfer berkas & SSH.
- **`lemes`**: Memantau interaksi akses berkas dan canary token berbasis HTTP/dokumen umpan.
- **`ClassRoot`**: Menyediakan node layanan komunikasi kolaboratif (WebRTC) dengan pencatatan telemetri interface jaringan, ICE candidate profiling, dan audit akses L7.
- **`cachedb`**: In-memory correlation bus berbasis gRPC untuk agregasi indikator ancaman (IOC) secara real-time.

---

## ⚡ Fitur Utama & Telemetri Keamanan

### 1. WebRTC ICE Candidate & Network Topology Mapping (MITRE T1016)
Protokol WebRTC mengumpulkan interface lokal (*host candidates*) untuk konektivitas peer-to-peer:
- **Host Candidates (`typ host`)**: Mengidentifikasi interface jaringan lokal client, tipe protokol (UDP/TCP), port, dan subnet.
- **Server Reflexive Candidates (`typ srflx`)**: Menentukan IP publik dan pemetaan port NAT via STUN.
- **Relay Candidates (`typ relay`)**: Mendokumentasikan relay endpoint TURN yang digunakan client.

Telemetri dianalisis pada dua lapisan:
1. Pertukaran pesan Trickle ICE WebRTC (`candidate` via WebSocket).
2. Pemeriksaan parameter `a=candidate:` di dalam SDP (*Session Description Protocol*) Offer.

### 2. Audit Autentikasi & Access Tracking (MITRE T1110 & T1078)
- Memantau dan mencatat upaya otentikasi pada ruangan terproteksi (misal ruang `it-briefing`).
- Mendokumentasikan username, pola input otentikasi, target grup ruangan, dan status verifikasi ke log CTI.

### 3. Client Environment & Peripheral Diagnostics (`cti-telemetry.js`)
ClassRoot dilengkapi modul telemetri client-side (`static/cti-telemetry.js`) untuk memverifikasi integritas lingkungan browser yang mengakses sistem:
- **Pre-Auth Session Beacon:** Mengirim telemetri inisiasi saat halaman pertama kali dimuat (`/api/telemetry`).
- **Hardware & Environment Diagnostics:** Mencatat resolusi layar, color depth, logical CPU cores (`hardwareConcurrency`), estimasi RAM (`deviceMemory`), timezone sistem, preferensi bahasa OS, dan canvas hash.
- **Graphics Pipeline Telemetry:** Membaca informasi renderer WebGL untuk kebutuhan verifikasi hardware workstation.
- **Media Capability Diagnostics (MITRE T1125 & T1123):** Memeriksa profil kapabilitas kamera dan mikrofon yang tersedia via `navigator.mediaDevices.enumerateDevices()`.
- **Network Performance Telemetry:** Mengestimasi profil interface jaringan (`wifi`, `cellular`, `ethernet`), downlink bandwidth, dan estimasi RTT via Network Information API.
- **Behavioral Mouse Dynamics & User Presence (MITRE T1056.001):** Melacak dinamika pergerakan mouse (jarak pergerakan piksel, kecepatan, klik, dan durasi idle) untuk profiling interaksi pengguna vs otomasi bot, serta mendeteksi status kehadiran (*presence*):
  - 🟢 **Hijau (Aktif):** Interaksi mouse/keyboard aktif di dalam ruang pertemuan.
  - 🟡 **Kuning (Away):** Mouse tidak bergerak selama >30 detik saat jendela masih terbuka.
  - 🔴 **Merah (Inactive / Background):** Pengguna berpindah tab (`visibilityState === 'hidden'`) atau meminimalkan jendela.
- **Real-Time Signal Quality Bar (Top Navigation):** Widget indikator kualitas sinyal 4-bar di navbar bagian atas yang memantau latensi RTT (Round Trip Time) koneksi secara real-time (Hijau/Kuning/Merah) ke server.
- **Authentication Event Logger:** Mencatat interaksi form login ke dalam format CTI terstruktur untuk diteruskan ke `cachedb`.

### 4. Integrasi Real-Time dengan CacheDB
Dapat mengirimkan indikator telemetri ancaman (IOC) secara langsung ke server `cachedb` via gRPC untuk korelasi otomatis lintas sensor.

---

## 🚀 Panduan Instalasi

### Windows (PowerShell)
```powershell
Invoke-Expression (Invoke-WebRequest -Uri "https://raw.githubusercontent.com/n0z0/ClassRoot/main/install.ps1" -UseBasicParsing).Content
```

### Linux (Bash)
```bash
curl -fsSL https://raw.githubusercontent.com/n0z0/ClassRoot/main/install.sh | bash
```

### Kompilasi Mandiri (Go)
```bash
git clone https://github.com/n0z0/ClassRoot.git
cd ClassRoot
go build -o classroot.exe .
go build -o classrootctl.exe ./classrootctl
```

---

## 🛠️ Cara Penggunaan

### Menjalankan Server HTTPS (Default - Auto TLS)
Secara default, ClassRoot berjalan pada mode **HTTPS**. Jika sertifikat TLS belum ada di folder `data/`, ClassRoot secara otomatis menerbitkan sertifikat lokal:
```bash
classroot -http :8443
```
Akses melalui peramban: `https://<ip-komputer>:8443/group/main/`.  
*(Jika menggunakan peramban modern dengan sertifikat lokal, konfirmasi halaman peringatan TLS dengan memilih "Advanced" -> "Proceed to localhost" agar fitur media WebRTC kamera & mikrofon dapat berjalan).*

### Menjalankan Mode HTTP Standar
```bash
classroot -insecure -http :8443 -ctilog classroot_cti.jsonl
```

### Menjalankan dengan Integrasi CacheDB
```bash
classroot -http :8443 -ctilog classroot_cti.jsonl -cachedb 127.0.0.1:50051 -sensor-id "sensor-webrtc-dc1"
```

### Parameter Baris Perintah
| Flag | Default | Penjelasan |
|------|---------|------------|
| `-http` | `:8443` | Alamat & port web server ClassRoot |
| `-insecure` | `false` | Jalankan protokol HTTP biasa (tanpa enkripsi TLS) |
| `-static` | `./static/` | Direktori berkas UI web statis (HTML/JS/CSS) |
| `-groups` | `./groups/` | Direktori konfigurasi ruangan pertemuan |
| `-data` | `./data/` | Direktori data persistent |
| `-ctilog` | `classroot_cti.jsonl` | Lokasi berkas log telemetri CTI (JSON Lines) |
| `-sensor-id` | `hostname` | Identitas node sensor |
| `-cachedb` | `""` | Alamat endpoint gRPC server CacheDB (contoh: `127.0.0.1:50051`) |
| `-turn` | `auto` | Konfigurasi bawaan built-in TURN server |
| `-version` | `false` | Menampilkan versi ClassRoot |

---

## 📊 Skema Log Telemetri (JSON Lines)

Setiap peristiwa koneksi dan interaksi tercatat secara terstruktur ke berkas log (`-ctilog`):

### 1. Telemetri WebRTC ICE Candidate
```json
{
  "timestamp": "2026-10-08T10:45:12.124890+07:00",
  "sensor_id": "sensor-webrtc-dc1",
  "event_type": "WEBRTC_ICE_CANDIDATE_LEAK",
  "source_ip": "203.0.113.45",
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36...",
  "group": "it-briefing",
  "username": "client-operator",
  "candidate": {
    "ip": "192.168.1.15",
    "port": 54231,
    "type": "host",
    "protocol": "udp",
    "raw": "candidate:14563 1 udp 2122260223 192.168.1.15 54231 typ host generation 0"
  },
  "mitre_technique": "T1016",
  "details": "WebRTC Host candidate recorded client LAN interface (192.168.1.15:54231)"
}
```

### 2. Audit Upaya Autentikasi Ruangan
```json
{
  "timestamp": "2026-10-08T10:46:01.402115+07:00",
  "sensor_id": "sensor-webrtc-dc1",
  "event_type": "ROOM_AUTH_FAILED",
  "source_ip": "203.0.113.45",
  "user_agent": "Mozilla/5.0 ...",
  "group": "it-briefing",
  "username": "guest_user",
  "mitre_technique": "T1110",
  "details": "Authentication verification failed for room 'it-briefing'"
}
```

---

## 🛡️ Konfigurasi Ruangan Bawaan

ClassRoot menginisialisasi 2 ruang pertemuan default:
1. **`main`**: Ruangan kolaborasi terbuka dengan otorisasi wildcard. Pengguna dapat langsung bergabung tanpa kata sandi khusus.
2. **`it-briefing`**: Ruangan terproteksi sandi untuk pemantauan audit akses administratif.

Ruangan tambahan dapat ditambahkan secara dinamis dalam format JSON pada direktori `groups/` (misalnya `board-meeting.json`).

---

## 📄 Lisensi
Didistribusikan di bawah lisensi MIT. Lihat [LICENSE](LICENSE) untuk informasi lebih lanjut.
