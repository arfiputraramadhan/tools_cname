Tentang Alat Ini

tools_cname.js adalah alat berbasis Node.js yang melakukan rekon pasif terhadap daftar subdomain. Cara kerjanya:

· Membaca rekaman CNAME dan mengikuti rantai alias hingga kedalaman tertentu.
· Mencocokkan target akhir dengan basis data sidik jari (fingerprint) penyedia cloud umum (AWS, GitHub, Heroku, Azure, dll.).
· Melakukan pemeriksaan HTTP opsional untuk memastikan apakah sumber daya terlihat tidak diklaim (misal NoSuchBucket, 404 Not Found).
· Mendeteksi wildcard DNS untuk menyaring positif palsu secara otomatis.
· Menerapkan konkurensi adaptif, pemutus sirkuit, checkpoint/penyimpanan status, dan pencatatan terstruktur – dirancang untuk pemindaian skala besar.

Semua temuan bersifat kandidat – Anda wajib memverifikasi secara manual sebelum melaporkan melalui program VDP/bug-bounty resmi.



Fitur Utama

· Resolusi rantai CNAME hingga kedalaman yang dapat diatur.
· Pencocokan sidik jari dengan daftar bawaan penyedia cloud populer; dapat diperluas dengan file JSON lokal atau umpan jarak jauh.
· Validasi HTTP memeriksa isi tanggapan dan kode status untuk pola "tidak diklaim" khas penyedia.
· Penyaringan wildcard DNS otomatis untuk menghindari positif palsu massal.
· Konkurensi adaptif menyesuaikan jumlah pekerja paralel secara dinamis berdasarkan tingkat kegagalan.
· Pemutus sirkuit melewati seluruh domain akar setelah sejumlah kegagalan berturut-turut yang dapat dikonfigurasi.
· Checkpoint dan lanjutkan: menyimpan kemajuan secara berkala; lanjutkan dengan --resume setelah interupsi.
· Resolver dan proksi kustom: gunakan resolver DNS dan proksi HTTP/HTTPS khusus (menghormati variabel lingkungan HTTP_PROXY/HTTPS_PROXY).
· Notifikasi webhook mengirimkan POST JSON untuk setiap temuan POTENTIAL_TAKEOVER (integrasi Slack/Teams/sistem tiket).
· Pencatatan terstruktur JSON Lines untuk konsumsi oleh SIEM atau pipa data.
· Beragam format laporan: CSV, JSON, Markdown, HTML, dan ringkasan teks biasa.
· Berkas konfigurasi: muat pengaturan dari JSON; opsi CLI selalu menimpa.

---

Prasyarat

Node.js versi 12 atau lebih baru (menggunakan dns.promises dan modul fs bawaan).



Cara Install Node.js di Berbagai Platform

Di Linux (Ubuntu/Debian)

Menggunakan NodeSource (disarankan untuk versi terbaru):

```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs
```

Untuk verifikasi:

```bash
node --version
npm --version
```

Alternatif dengan nvm (Node Version Manager) – cocok untuk multiple versi:

```bash
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash
# Restart terminal atau jalankan source ~/.bashrc
nvm install --lts
nvm use --lts
```

Di Termux (Android)

```bash
pkg update
pkg install nodejs-lts
```

Verifikasi:

```bash
node --version
```

Di Windows

· Unduh installer dari nodejs.org (pilih versi LTS), jalankan dan ikuti wizard.
· Atau menggunakan Chocolatey (sebagai administrator):
  ```bash
  choco install nodejs-lts
  ```
· Atau menggunakan winget:
  ```bash
  winget install OpenJS.NodeJS.LTS
  ```

Setelah instalasi, buka Command Prompt atau PowerShell, jalankan node --version untuk memastikan.

Di macOS

· Menggunakan Homebrew:
  ```bash
  brew install node
  ```
· Atau unduh installer dari nodejs.org.

Di terminal lain (misal WSL, Cygwin)

Ikuti cara Linux (gunakan nvm atau paket manager masing-masing). Pastikan node dan npm tersedia di PATH.



Instalasi Alat tools_cname

Clone repository dan beri izin eksekusi (opsional):

```bash
git clone https://github.com/arfiputraramadhan/tools_cname
cd tools_cname
chmod +x tools_cname.js   # opsional, jika ingin dijalankan langsung
```

Tidak diperlukan instalasi dependency karena hanya menggunakan modul bawaan Node.js.



Cara Penggunaan

Jalankan dengan:

```bash
node tools_cname.js -i daftar_subdomain.txt [opsi]
```

atau melalui pipa (stdin):

```bash
cat daftar_subdomain.txt | node tools_cname.js [opsi]
```

Metode Input

· Berkas (-i): node tools_cname.js -i domains.txt
· Daftar langsung (--targets): node tools_cname.js --targets sub1.example.com,sub2.example.com
· Stdin (atau -): cat domains.txt | node tools_cname.js atau node tools_cname.js -i -

Opsi Command Line (Ringkasan)

Opsi Umum:

· -i, --input <file> – Berkas masukan (satu subdomain per baris). Gunakan - untuk stdin.
· --targets <a,b,c> – Daftar subdomain dipisahkan koma.
· -o, --output <awalan> – Awalan nama berkas keluaran (baku: report).
· --markdown – Hasilkan laporan Markdown (.md).
· --html – Hasilkan laporan HTML mandiri (.html).
· --log-file <file> – Tulis log terstruktur JSON Lines ke berkas.
· --webhook <url> – Kirim notifikasi POST JSON untuk setiap POTENTIAL_TAKEOVER.

Kinerja dan Keandalan:

· -c, --concurrency <n> – Jumlah pekerja paralel maksimum (baku: 15).
· --no-adaptive-concurrency – Nonaktifkan penyesuaian konkurensi otomatis.
· -d, --delay <ms> – Jeda antar permintaan per pekerja (baku: 150).
· -t, --timeout <ms> – Batas waktu HTTP per permintaan (baku: 7000).
· --dns-retries <n> – Jumlah percobaan ulang DNS untuk galat sementara (baku: 2).
· --http-retries <n> – Jumlah percobaan ulang HTTP untuk galat 429/koneksi (baku: 1).
· --circuit-breaker-threshold <n> – Jumlah kegagalan berturut-turut sebelum melewati domain akar (baku: 8).
· --resume – Lanjutkan dari checkpoint terakhir jika pemindaian terinterupsi.
· --checkpoint-every <n> – Simpan checkpoint setiap n target selesai (baku: 20).

Deteksi:

· --no-http – Lewati pemeriksaan HTTP (hanya DNS).
· --resolve-a – Periksa rekaman A jika tidak ada CNAME.
· --no-wildcard-check – Nonaktifkan deteksi wildcard DNS.
· --internal-suffix <s> – Tandai akhiran domain sebagai internal (dapat diulang).
· --max-cname-depth <n> – Kedalaman maksimum rantai CNAME (baku: 8).
· --fingerprints <file> – Tambahkan sidik jari dari berkas JSON lokal.
· --fingerprints-url <url> – Ambil sidik jari tambahan dari umpan JSON jarak jauh.

Jaringan:

· --resolver <ip1,ip2> – Gunakan resolver DNS kustom (mis. 1.1.1.1,8.8.8.8).
· --proxy <url> – Proksi HTTP/HTTPS (mis. http://proxy:8080). Juga menghormati variabel lingkungan HTTP_PROXY/HTTPS_PROXY.

Lain-lain:

· --config <file.json> – Muat opsi dari berkas konfigurasi JSON (CLI menimpa konfigurasi).
· --timestamps – Tampilkan stempel waktu ISO-8601 pada setiap baris log.
· -v, --verbose – Tampilkan detail setiap subdomain saat diproses.
· -q, --quiet – Kurangi keluaran yang tidak penting.
· -h, --help – Tampilkan bantuan.



Contoh Penggunaan

· Pemindaian dasar (pemeriksaan HTTP aktif, penyaringan wildcard aktif):
  ```bash
  node tools_cname.js -i daftar/produksi.txt -o scan_produksi
  ```
· Pemindaian cepat dengan konkurensi tinggi dan tanpa jeda:
  ```bash
  node tools_cname.js -i daftar/semua.txt -c 50 -d 0 --no-adaptive-concurrency
  ```
· Pemindaian di belakang proksi perusahaan, dengan DNS kustom:
  ```bash
  node tools_cname.js -i domains.txt --proxy http://proxy.perusahaan:8080 --resolver 10.0.0.1,10.0.0.2
  ```
· Melanjutkan pemindaian yang terhenti:
  ```bash
  node tools_cname.js -i daftar_besar.txt --resume
  ```
· Menambahkan sidik jari eksternal dari umpan tim:
  ```bash
  node tools_cname.js -i domains.txt --fingerprints-url https://internal.example.com/fingerprints.json
  ```



Berkas Keluaran

Alat ini selalu menghasilkan:

· <awalan>.csv – hasil terperinci dalam format CSV.
· <awalan>.json – hasil terstruktur lengkap (JSON).
· <awalan>_summary.txt – ringkasan terbaca manusia dengan hitungan per kategori.
· <awalan>_takeover.txt – daftar semua kandidat potensial (untuk triase cepat).

Jika opsi --markdown atau --html digunakan, berkas tambahan akan dibuat.

Pada penyimpanan parsial (misalnya karena SIGINT), awalan menjadi <awalan>_PARTIAL.*.



Kode Keluar

· 0 – Pemindaian selesai, tidak ditemukan potensi takeover.
· 1 – Galat fatal (input tidak valid, berkas tidak ditemukan, dll.).
· 2 – Pemindaian selesai, setidaknya satu potensi takeover terdeteksi. Berguna untuk gerbang CI/CD.
· 130 – Proses dihentikan secara manual (SIGINT/SIGTERM); laporan parsial telah disimpan.



Berkas Konfigurasi

Anda dapat menyimpan opsi bawaan dalam berkas JSON (mis. config.json) dan memuatnya dengan --config:

```json
{
  "concurrency": 30,
  "timeout": 10000,
  "httpRetries": 2,
  "markdown": true,
  "html": true,
  "internalSuffixes": ["internal.local", "corp.net"]
}
```

Opsi CLI selalu menimpa opsi dari berkas konfigurasi.



Basis Data Sidik Jari

Daftar sidik jari bawaan mencakup penyedia cloud paling umum. Anda dapat menambahkannya:

· Berkas JSON lokal (mis. tambahan.json):
  ```json
  [
    { "provider": "CDN Internal", "cname": "\\.mycdn\\.com$", "body": "Situs ini tidak aktif" }
  ]
  ```
· Umpan JSON jarak jauh – format yang sama, diambil melalui HTTP/HTTPS.

Semua sidik jari ditambahkan ke daftar bawaan.



Lisensi

Proyek ini dilisensikan di bawah Creative Commons Attribution-NonCommercial 4.0 International License (CC BY-NC 4.0).
Anda diperbolehkan untuk berbagi dan mengadaptasi materi ini dengan ketentuan:

· Atribusi – mencantumkan kredit yang sesuai.
· NonKomersial – tidak digunakan untuk tujuan komersial tanpa izin tertulis.
  Untuk lisensi komersial, hubungi penulis.



Peringatan

· Alat ini ditujukan hanya untuk pengujian keamanan dan penelitian yang sah.
· Alat ini melakukan deteksi pasif; tidak melakukan eksploitasi apa pun.
· Selalu verifikasi secara manual setiap temuan sebelum melaporkan ke program VDP/bug-bounty.
· Penulis tidak bertanggung jawab atas penyalahgunaan atau kerusakan yang ditimbulkan oleh perangkat lunak ini.



Kontribusi dan Kontak

Kontribusi sangat diterima! Silakan buka isu atau kirim permintaan tarik untuk perbaikan, perbaikan galat, atau sidik jari baru. Untuk pertanyaan atau lisensi komersial, hubungi melalui GitHub.

Selamat memindai dengan penuh tanggung jawab!
