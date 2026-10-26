# VulnVault // CyberSec Threat & Vulnerability Tracker

Aplikasi pemantauan temuan celah keamanan (Vulnerability) dan indikator ancaman (Indicators of Compromise / IOC) berbasis Python Flask, MySQL, dan Docker Compose untuk praktikum Komputasi Awan.

---

## 🏗️ Arsitektur Layanan (Docker Compose)

Proyek ini memenuhi seluruh **Ketentuan Wajib Tugas Praktikum 2**:

1. **Multi-Stage Dockerfile**: Menggunakan 2 stage (`builder` untuk compile dependencies dan `runtime` berbasis `python:3.11-slim` non-root user `appuser`).
2. **Minimal 2 Service**:
   - `app`: Web frontend & backend API (Python 3.11 Flask + Gunicorn WSGI).
   - `database`: Relational Database Management System (MySQL 8.4).
3. **Network Isolation**:
   - `public_net`: Menghubungkan service `app` ke internet/host (Port 80 -> 5000).
   - `internal_net` (`internal: true`): Jaringan privat internal yang menghubungkan `app` dan `database`. **Port 3306 MySQL TIDAK diekspos ke publik**.
4. **Data Persistence**:
   - Menggunakan named volume `db_data` yang di-mount ke `/var/lib/mysql`.
5. **Healthcheck & Dependency Orchestration**:
   - Service `database` memiliki probe `mysqladmin ping`.
   - Service `app` menggunakan `depends_on: database: condition: service_healthy`.
6. **High Availability**:
   - Kedua service menggunakan parameter `restart: unless-stopped`.
7. **Zero Plaintext Secrets**:
   - Kredensial sensitif disimpan di file `.env` (diabaikan oleh Git via `.gitignore`).
   - Tersedia `.env.example` sebagai referensi konfigurasi.
8. **Cloud-Ready**:
   - Siap di-deploy pada Azure Virtual Machine dan diakses langsung melalui `http://<IP_PUBLIC_VM>`.

---

## 📁 Struktur Direktori

```text
python-app/
├── .env                  # Environment variable lokal/server (JANGAN di-push ke git)
├── .env.example          # Template konfigurasi variabel
├── .gitignore            # Mengabaikan .env dan cache
├── compose.yaml          # Orkestrasi Docker Compose (App + MySQL + Network + Volume)
├── Dockerfile            # Multi-stage build image aplikasi
├── requirements.txt      # Dependensi Python
├── app.py                # Kode backend Flask, koneksi DB, schema auto-migration
└── templates/
    └── index.html        # UI Dark Cyber Dashboard & SecOps Tools
```

---

## 🚀 Cara Menjalankan di Lokal / VM Azure

### 1. Salin Konfigurasi Environment
```bash
cp .env.example .env
```
*(Sesuaikan password jika diperlukan)*

### 2. Jalankan Docker Compose
```bash
docker compose up -d --build
```

### 3. Periksa Status Service & Healthcheck
```bash
docker compose ps
```
Pastikan `cybersec_db` berstatus `Up (healthy)` dan `cybersec_app` berstatus `Up`.

### 4. Akses Aplikasi
- Lokal: `http://localhost:80` (atau `http://localhost`)
- Azure VM: `http://<IP_PUBLIC_VM>`

---

## 🧪 7 Bukti Pengujian Wajib untuk Laporan

1. **Struktur Folder & Kode**: Tampilkan output `tree` / `ls -R` dan isi `Dockerfile` & `compose.yaml`.
2. **Status Container**: Jalankan `docker compose ps` (tunjukkan status `healthy` dan `running`).
3. **Akses Browser**: Buka `http://<IP_PUBLIC_VM>` di browser dengan URL bar terlihat jelas.
4. **Overview Azure Portal**: Tangkap layar halaman Overview VM di Azure Portal yang memperlihatkan nama VM dan IP publik yang sama.
5. **Uji Persistensi Data**:
   - Tambah 1 data temuan baru di web.
   - Jalankan `docker compose down`.
   - Jalankan `docker compose up -d`.
   - Refresh browser, tunjukkan data yang baru ditambahkan tetap tersimpan.
6. **Uji Keamanan Jaringan**:
   - Periksa `docker compose ps` atau jalankan `nmap -p 3306 <IP_PUBLIC_VM>`.
   - Tunjukkan bahwa port `3306` berstatus *closed/filtered* (tidak ada binding port `0.0.0.0:3306`).
7. **Uji Auto-Restart**:
   - Matikan container aplikasi paksa: `docker stop cybersec_app`.
   - Tunggu beberapa detik atau cek `docker ps`, container akan otomatis restart (`unless-stopped`).
