GeoPass Vault
Aplikasi ini adalah Progressive Web App (PWA): sekumpulan file statis (HTML/JS/CSS)
yang berjalan sepenuhnya di perangkat Anda. Setelah di-host dan dibuka sekali,
aplikasi bekerja offline dan bisa "diinstal" ke Home Screen iPhone Anda seperti
aplikasi native.

Semua data (username, password, PIN, catatan) dienkripsi AES-256 dan disimpan
di penyimpanan lokal browser (IndexedDB) di perangkat Anda. Host hanya menyajikan
file kosong — tidak pernah menyimpan atau melihat isi vault Anda.

## Buka di iPhone & Install
1. Buka link tersebut di **Safari** (harus Safari, bukan Chrome/lainnya, agar
   "Add to Home Screen" tersedia di iOS)
2. Tunggu halaman termuat penuh sekali (ini men-download & meng-cache aplikasi
   untuk pemakaian offline)
3. Tap tombol **Share** (ikon kotak dengan panah ke atas)
4. Tap **Add to Home Screen** → **Add**
5. Ikon GeoPass Vault akan muncul di Home Screen Anda

## Mulai pakai
Buka dari ikon Home Screen. Pertama kali akan diminta membuat **Master Password**.
Setelah itu aplikasi berjalan sepenuhnya offline — tidak perlu internet lagi
kecuali Anda menghapus data situs di Safari.

## Backup
Karena data tersimpan lokal di perangkat, **lakukan Export Backup secara berkala**
lewat menu Pengaturan → Backup & Restore, dan simpan file `.gpvault` tersebut di
tempat aman (iCloud Drive, komputer, dsb). Jika Anda menghapus Safari website
data/cache untuk domain ini, atau mengganti perangkat, vault akan kosong kembali
kecuali Anda melakukan Restore dari file backup tersebut.

Done
