# ClassRoot

[![Release](https://github.com/n0z0/ClassRoot/actions/workflows/release.yml/badge.svg)](https://github.com/n0z0/ClassRoot/actions/workflows/release.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/n0z0/ClassRoot)](https://goreportcard.com/report/github.com/n0z0/ClassRoot)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**ClassRoot** adalah server media konferensi video interaktif WebRTC berkinerja tinggi yang diinstrumentasi khusus sebagai **Decoy / Honeypot Sensor** untuk **Cyber Threat Intelligence (CTI)**.

ClassRoot memadukan fungsionalitas ruang pertemuan WebRTC sungguhan dengan mesin telemetri intelijen ancaman aktif. Ketika penyerang atau pengguna tanpa izin mencoba mengakses ruang pertemuan, ClassRoot secara otomatis mengekstrak detail jaringan tingkat dalam—termasuk alamat IP lokal/LAN penyerang di balik VPN melalui kebocoran kandidat WebRTC ICE (*Interactive Connectivity Establishment*).

---

## 🎯 Peran dalam Ekosistem n0z0 CTI

Dalam ekosistem pertahanan berlapis `n0z0`:
- **`synwatcher`**: Mengawasi probe port jaringan level rendah (SYN scanning, port sweeping).
- **`scp`**: Mendeteksi penyusup yang mencoba login SSH / mentransfer berkas ilegal.
- **`lemes`**: Menyediakan Honeybeacon & Lure HTTP/HTML canary untuk melacak pembukaan dokumen intelijen palsu.
- **`ClassRoot`**: Memancing pelaku yang mencari layanan komunikasi internal (WebRTC/Zoom-like meeting) dan **membongkar topologi jaringan privat (LAN IP) penyerang** melalui WebRTC ICE Candidate Leakage.
- **`cachedb`**: Pusat agregasi memori berbasis gRPC berkinerja tinggi yang menerima indikator ancaman secara real-time.

---

## ⚡ Fitur Utama & Intelijen WebRTC

### 1. WebRTC ICE Candidate IP De-anonymization (MITRE T1016)
Banyak penyerang menggunakan proxy HTTP atau VPN komersial untuk menyamarkan alamat IP publik mereka. Namun, standar WebRTC mengharuskan browser mengumpulkan alamat interface lokal (*host candidates*) untuk konektivitas peer-to-peer:
- **Host Candidates (`typ host`)**: Mengungkap alamat IP privat penyerang (misal `192.168.1.105`, `10.8.0.2`), tipe protokol (UDP/TCP), port, dan subnet lokal.
- **Server Reflexive Candidates (`typ srflx`)**: Mengungkap alamat IP publik dan port NAT yang dipetakan oleh STUN.
- **Relay Candidates (`typ relay`)**: Mengungkap server relay TURN penyerang.

ClassRoot mencegat kandidat ini pada dua lapisan:
1. Pesan pertukaran Trickle ICE WebRTC (`candidate` payload via WebSocket).
2. Parsing baris `a=candidate:` langsung di dalam SDP (*Session Description Protocol*) Offer.

### 2. Room Authentication & Credential Abuse Tracking (MITRE T1110 & T1078)
- Mendeteksi upaya brute-force kata sandi ruangan (misal ruang `it-briefing`).
- Mencatat username, password yang dimasukkan penyerang, grup target, dan status otentikasi.

### 3. Client-Side Sensor & Hardware Fingerprinting (`cti-telemetry.js`)
ClassRoot dilengkapi sensor JavaScript client-side (`static/cti-telemetry.js`) yang berjalan otomatis di browser penyerang saat membuka landing page maupun form login:
- **Pre-Auth Recon Beacon:** Mengirim beacon pengintaian instan saat halaman dimuat (`/api/telemetry`).
- **GPU Unmasking:** Menggunakan WebGL extension `WEBGL_debug_renderer_info` untuk mengungkap chipset grafis asli penyerang (misal `NVIDIA GeForce RTX 3070`) bahkan saat penyerang memakai VPN atau mode Incognito.
- **Hardware & Environment Fingerprinting:** Merekam resolusi layar, color depth, logical CPU cores (`hardwareConcurrency`), RAM (`deviceMemory`), timezone sistem, bahasa preferensi OS, canvas hash, dan audio context hash.
- **Credential Harvester:** Mencegat interaksi tombol *Connect* / login modal, merekam username dan password ke log CTI dan menyimpannya ke `cachedb`.

### 4. Integrasi Otomatis dengan CacheDB
Dapat mengirimkan IOC (*Indicators of Compromise*) secara langsung ke server `cachedb` via gRPC, memungkinkan pemblokiran atau korelasi otomatis oleh sensor lain.

---

## 🚀 Instalasi Cepat

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

### Menjalankan Server Decoy HTTPS (Default - Auto Self-Signed Cert)
Secara default, ClassRoot berjalan di mode **HTTPS**. Jika sertifikat TLS belum ada di folder `data/`, ClassRoot akan **secara otomatis men-generate sertifikat self-signed** dengan Subject Alternative Names (SAN) mencakup `localhost`, `127.0.0.1`, dan seluruh IP LAN lokal Anda:
```bash
classroot -http :8443
```
Buka di browser perangkat lain: `https://<ip-komputer>:8443/group/public/`. Klik *Advanced -> Proceed*, dan seluruh fitur WebRTC (**Share Screen**, Kamera, Mic) langsung aktif!

### Menjalankan Server Decoy HTTP Biasa (Insecure)
```bash
classroot -insecure -http :8443 -ctilog classroot_cti.jsonl
```

### Menjalankan Decoy dengan Integrasi CacheDB
```bash
classroot -http :8443 -ctilog classroot_cti.jsonl -cachedb 127.0.0.1:50051 -sensor-id "sensor-webrtc-dc1"
```

### Opsi Parameter Baris Perintah
| Flag | Default | Penjelasan |
|------|---------|------------|
| `-http` | `:8443` | Alamat & port web server ClassRoot |
| `-insecure` | `false` | Jalankan HTTP biasa (tanpa sertifikat TLS bawaan) |
| `-static` | `./static/` | Direktori berkas UI web statis (HTML/JS/CSS) |
| `-groups` | `./groups/` | Direktori konfigurasi ruangan pertemuan |
| `-data` | `./data/` | Direktori data persistent |
| `-ctilog` | `classroot_cti.jsonl` | Lokasi berkas output log telemetri CTI (JSON Lines) |
| `-sensor-id` | `hostname` | Identitas unik sensor node |
| `-cachedb` | `""` | Alamat target gRPC server CacheDB (contoh: `127.0.0.1:50051`) |
| `-turn` | `auto` | Konfigurasi bawaan built-in TURN server |
| `-version` | `false` | Menampilkan versi ClassRoot saat ini |

---

## 📊 Skema Log CTI (JSON Lines)

Setiap aktivitas interaksi dan kebocoran ICE candidate akan dicatat ke berkas JSONL (`-ctilog`):

### 1. Kebocoran WebRTC ICE Candidate (LAN IP Terungkap)
```json
{
  "timestamp": "2026-10-08T10:45:12.124890+07:00",
  "sensor_id": "sensor-webrtc-dc1",
  "event_type": "WEBRTC_ICE_CANDIDATE_LEAK",
  "source_ip": "203.0.113.45",
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36...",
  "group": "it-briefing",
  "username": "attacker99",
  "candidate": {
    "ip": "192.168.1.15",
    "port": 54231,
    "type": "host",
    "protocol": "udp",
    "raw": "candidate:14563 1 udp 2122260223 192.168.1.15 54231 typ host generation 0"
  },
  "mitre_technique": "T1016",
  "details": "WebRTC Host candidate leaked internal LAN IP (192.168.1.15:54231)"
}
```

### 2. Upaya Autentikasi Ruang Rahasia Gagal
```json
{
  "timestamp": "2026-10-08T10:46:01.402115+07:00",
  "sensor_id": "sensor-webrtc-dc1",
  "event_type": "ROOM_AUTH_FAILED",
  "source_ip": "203.0.113.45",
  "user_agent": "Mozilla/5.0 ...",
  "group": "it-briefing",
  "username": "admin",
  "mitre_technique": "T1110",
  "details": "User 'admin' failed authentication for room 'it-briefing'"
}
```

---

## 🛡️ Skenario Umpan (Decoy Strategy)

Secara otomatis, ClassRoot menginisialisasi 2 ruangan pancingan:
1. **`public`**: Ruangan terbuka umum. Siapa saja yang masuk akan segera menginisialisasi sesi WebRTC dan membocorkan ICE candidate perangkatnya.
2. **`it-briefing`**: Ruangan dengan proteksi sandi bertema teknis internal IT perusahaan. Penyerang yang mencoba mengakses ruangan ini akan memicu alarm brute force sekaligus membocorkan data interface perangkat lokalnya.

Anda dapat menambahkan ruang umpan khusus lainnya di dalam direktori `groups/` (misalnya `executive-board.json`, `financial-audit.json`).

---

## 📄 Lisensi
Didistribusikan di bawah lisensi MIT. Lihat [LICENSE](LICENSE) untuk informasi lebih lanjut.
