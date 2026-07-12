# GeoPass Vault — Panduan Instalasi (GitHub Pages, Gratis)

Aplikasi ini adalah Progressive Web App (PWA): sekumpulan file statis (HTML/JS/CSS)
yang berjalan sepenuhnya di perangkat Anda. Setelah di-host dan dibuka sekali,
aplikasi bekerja offline dan bisa "diinstal" ke Home Screen iPhone Anda seperti
aplikasi native.

Semua data (username, password, PIN, catatan) dienkripsi AES-256 dan disimpan
di penyimpanan lokal browser (IndexedDB) di perangkat Anda. Host hanya menyajikan
file kosong — tidak pernah menyimpan atau melihat isi vault Anda.

## Langkah 1 — Buat akun GitHub (jika belum punya)
Buka https://github.com/signup — gratis, cukup email dan password.

## Langkah 2 — Buat repository baru
1. Klik tombol **+** di kanan atas → **New repository**
2. Nama repo bebas, misalnya `geopass-vault`
3. Set ke **Public** (wajib untuk GitHub Pages gratis)
4. Klik **Create repository** (tidak perlu centang apapun yang lain)

## Langkah 3 — Upload semua file
Di halaman repo yang baru dibuat:
1. Klik **uploading an existing file** (atau **Add file → Upload files**)
2. Seret (drag & drop) SEMUA isi folder ini — termasuk isi folder `icons/` —
   pastikan struktur foldernya tetap sama persis:
   ```
   index.html
   styles.css
   app.js
   manifest.json
   sw.js
   icons/icon-192.png
   icons/icon-512.png
   icons/icon-192-maskable.png
   icons/icon-512-maskable.png
   ```
3. Scroll ke bawah, klik **Commit changes**

## Langkah 4 — Aktifkan GitHub Pages
1. Di repo, klik tab **Settings**
2. Klik **Pages** di sidebar kiri
3. Di bagian **Source**, pilih branch **main**, folder **/ (root)** → **Save**
4. Tunggu 1–2 menit. Muncul link hijau seperti:
   `https://<username-anda>.github.io/geopass-vault/`

## Langkah 5 — Buka di iPhone & Install
1. Buka link tersebut di **Safari** (harus Safari, bukan Chrome/lainnya, agar
   "Add to Home Screen" tersedia di iOS)
2. Tunggu halaman termuat penuh sekali (ini men-download & meng-cache aplikasi
   untuk pemakaian offline)
3. Tap tombol **Share** (ikon kotak dengan panah ke atas)
4. Tap **Add to Home Screen** → **Add**
5. Ikon GeoPass Vault akan muncul di Home Screen Anda

## Langkah 6 — Mulai pakai
Buka dari ikon Home Screen. Pertama kali akan diminta membuat **Master Password**.
Setelah itu aplikasi berjalan sepenuhnya offline — tidak perlu internet lagi
kecuali Anda menghapus data situs di Safari.

## Penting: Backup
Karena data tersimpan lokal di perangkat, **lakukan Export Backup secara berkala**
lewat menu Pengaturan → Backup & Restore, dan simpan file `.gpvault` tersebut di
tempat aman (iCloud Drive, komputer, dsb). Jika Anda menghapus Safari website
data/cache untuk domain ini, atau mengganti perangkat, vault akan kosong kembali
kecuali Anda melakukan Restore dari file backup tersebut.

## Update aplikasi di kemudian hari
Jika saya (atau Anda) mengubah kode aplikasi ini, cukup upload ulang file yang
berubah ke repo GitHub yang sama (Add file → Upload files, lalu commit). Buka
aplikasi dari Home Screen sambil online sekali agar service worker mengambil
versi terbaru; setelah itu offline seperti biasa.

## Keterbatasan versi PWA ini (dibanding aplikasi native)
- Face ID / Touch ID: belum tersedia (butuh akses OS native)
- Anti-screenshot / sembunyikan dari Recent Apps: belum tersedia (butuh akses OS native)
- Selebihnya (enkripsi AES-256, master password, decoy mode, mode stealth
  kalkulator, kategori, tag, pencarian, generator password, auto-lock,
  clipboard auto-clear, backup/restore) berfungsi penuh.

Done
