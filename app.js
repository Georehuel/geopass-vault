'use strict';

/* ==================================================================
   Constants
   ================================================================== */
const DEFAULT_CATEGORIES = ["Sosial Media","Keuangan","Pekerjaan","Pribadi"];
const NO_CATEGORY = ""; // pseudo-category: entries with category === "" show under "Tanpa Kategori"
const SUGGESTED_TAGS = ["Penting","Kerja","Pribadi","2FA","Lama","Baru"];
const DEFAULT_SETTINGS = { theme:"dark", autoLockMin:5, clipboardSec:30, stealthEnabled:false, stealthPin:"", hasDecoy:false, lang:"id" };
const PBKDF2_ITER = 210000;
const VERIFY_TAG = "geopass-verify-v1";
const BUILTIN_FIELDS = [
  {key:"website", labelKey:"field_website", type:"text", secret:false, placeholder:"https://"},
  {key:"email", labelKey:"field_email", type:"text", secret:false},
  {key:"username", labelKey:"field_username", type:"text", secret:false},
  {key:"password", labelKey:"field_password", type:"text", secret:true, generator:true, mono:true},
  {key:"pin", labelKey:"field_pin", type:"text", secret:true, mono:true},
  {key:"notes", labelKey:"field_notes", type:"textarea", secret:false},
];
const DEFAULT_VISIBLE_FIELDS = ["email","username","password"];

/* ==================================================================
   Crypto helpers (Web Crypto API - AES-256-GCM + PBKDF2)
   ================================================================== */
function bufToBase64(buf){ const bytes=new Uint8Array(buf); let bin=""; for(let i=0;i<bytes.byteLength;i++) bin+=String.fromCharCode(bytes[i]); return btoa(bin); }
function base64ToBuf(b64){ const bin=atob(b64); const bytes=new Uint8Array(bin.length); for(let i=0;i<bin.length;i++) bytes[i]=bin.charCodeAt(i); return bytes.buffer; }
function randomSaltB64(){ return bufToBase64(crypto.getRandomValues(new Uint8Array(16)).buffer); }
async function deriveKey(password, saltB64, iterations){
  const enc = new TextEncoder();
  const salt = base64ToBuf(saltB64);
  const baseKey = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({name:"PBKDF2", salt, iterations, hash:"SHA-256"}, baseKey, {name:"AES-GCM", length:256}, false, ["encrypt","decrypt"]);
}
async function encryptJSON(key, obj){
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const data = enc.encode(JSON.stringify(obj));
  const cipherBuf = await crypto.subtle.encrypt({name:"AES-GCM", iv}, key, data);
  return {iv: bufToBase64(iv.buffer), data: bufToBase64(cipherBuf)};
}
async function decryptJSON(key, ivB64, dataB64){
  const iv = base64ToBuf(ivB64);
  const data = base64ToBuf(dataB64);
  const plainBuf = await crypto.subtle.decrypt({name:"AES-GCM", iv}, key, data);
  return JSON.parse(new TextDecoder().decode(plainBuf));
}

/* ==================================================================
   IndexedDB (local, on-device storage)
   ================================================================== */
const DB_NAME="geopass-db", STORE="kv";
function openDB(){
  return new Promise((resolve,reject)=>{
    const req = indexedDB.open(DB_NAME,1);
    req.onupgradeneeded = ()=>{ req.result.createObjectStore(STORE); };
    req.onsuccess = ()=>resolve(req.result);
    req.onerror = ()=>reject(req.error);
  });
}
async function idbGet(key){
  const db = await openDB();
  return new Promise((resolve,reject)=>{
    const tx = db.transaction(STORE,"readonly");
    const req = tx.objectStore(STORE).get(key);
    req.onsuccess=()=>resolve(req.result);
    req.onerror=()=>reject(req.error);
  });
}
async function idbSet(key,value){
  const db = await openDB();
  return new Promise((resolve,reject)=>{
    const tx = db.transaction(STORE,"readwrite");
    tx.objectStore(STORE).put(value,key);
    tx.oncomplete=()=>resolve(true);
    tx.onerror=()=>reject(tx.error);
  });
}
async function idbDelete(key){
  const db = await openDB();
  return new Promise((resolve,reject)=>{
    const tx = db.transaction(STORE,"readwrite");
    tx.objectStore(STORE).delete(key);
    tx.oncomplete=()=>resolve(true);
    tx.onerror=()=>reject(tx.error);
  });
}

/* ==================================================================
   Small utils
   ================================================================== */
function uid(){ return Date.now().toString(36)+Math.random().toString(36).slice(2,9); }
function esc(s){ if(s===undefined||s===null) return ""; return String(s).replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function maskValue(v){ return "•".repeat(Math.min(String(v||"").length,14)); }
function timeAgo(ts){
  if(!ts) return "-";
  const s = Math.floor((Date.now()-ts)/1000);
  if(s<60) return "Baru saja";
  if(s<3600) return Math.floor(s/60)+" menit lalu";
  if(s<86400) return Math.floor(s/3600)+" jam lalu";
  if(s<2592000) return Math.floor(s/86400)+" hari lalu";
  return new Date(ts).toLocaleDateString("id-ID");
}
function calcStrength(pw){
  if(!pw) return {label:"",score:0};
  let charsetSize=0;
  if(/[a-z]/.test(pw)) charsetSize+=26;
  if(/[A-Z]/.test(pw)) charsetSize+=26;
  if(/[0-9]/.test(pw)) charsetSize+=10;
  if(/[^a-zA-Z0-9]/.test(pw)) charsetSize+=32;
  const entropy = pw.length*Math.log2(charsetSize||1);
  if(entropy<28) return {label:t("strength_weak"),score:1};
  if(entropy<45) return {label:t("strength_medium"),score:2};
  if(entropy<65) return {label:t("strength_strong"),score:3};
  return {label:t("strength_very_strong"),score:4};
}
function generatePassword(opts){
  let chars="";
  if(opts.lower) chars+="abcdefghijklmnopqrstuvwxyz";
  if(opts.upper) chars+="ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  if(opts.numbers) chars+="0123456789";
  if(opts.symbols) chars+="!@#$%^&*()-_=+[]{}<>?";
  if(!chars) chars="abcdefghijklmnopqrstuvwxyz";
  const arr = new Uint32Array(opts.length);
  crypto.getRandomValues(arr);
  let out="";
  for(let i=0;i<opts.length;i++) out+=chars[arr[i]%chars.length];
  return out;
}
function strengthHTML(pw){
  if(!pw) return "";
  const {label,score} = calcStrength(pw);
  const colors = ["","var(--danger)","var(--warning)","var(--success)","var(--accent)"];
  let bars = "";
  for(let i=1;i<=4;i++) bars += `<div class="strength-bar" style="background:${i<=score?colors[score]:"var(--border)"}"></div>`;
  return `<div class="strength-bars">${bars}</div><div class="strength-label" style="color:${colors[score]||"var(--text-muted)"}">${label}</div>`;
}
function migrateEntry(e){
  if(!e.customFields) e.customFields = [];
  if(!e.visibleFields){
    const keys = ["website","email","username","password","pin","notes"];
    const present = keys.filter(k=>e[k]);
    e.visibleFields = Array.from(new Set(present.concat(DEFAULT_VISIBLE_FIELDS)));
  }
  if(e.category===undefined || e.category===null) e.category = "";
  return e;
}
function buildCopyAllText(entry){
  const visible = entry.visibleFields||DEFAULT_VISIBLE_FIELDS;
  const lines = [];
  const push = (label, val) => { if(val) lines.push(`${label}: ${val}`); };
  if(visible.indexOf("username")!==-1) push(t("field_username"), entry.username);
  if(visible.indexOf("password")!==-1) push(t("field_password"), entry.password);
  if(visible.indexOf("pin")!==-1) push(t("field_pin"), entry.pin);
  if(visible.indexOf("email")!==-1) push(t("field_email"), entry.email);
  if(visible.indexOf("website")!==-1) push(t("field_website"), entry.website);
  (entry.customFields||[]).forEach(f=>{ if(f.value) push(f.label||t("field_custom_default"), f.value); });
  if(visible.indexOf("notes")!==-1) push(t("field_notes"), entry.notes);
  return lines.join("\n");
}

/* ==================================================================
   Inline icons (no external font/icon dependency -> works offline)
   ================================================================== */
const ic = {
  star:(filled)=>`<svg width="15" height="15" viewBox="0 0 24 24" fill="${filled?'var(--accent)':'none'}" stroke="${filled?'var(--accent)':'var(--text-muted)'}" stroke-width="2"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>`,
  copy:()=>`<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>`,
  eye:()=>`<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`,
  eyeOff:()=>`<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.94 10.94 0 0 1 12 20c-7 0-11-8-11-8a21.8 21.8 0 0 1 5.06-6.06M9.9 4.24A10.94 10.94 0 0 1 12 4c7 0 11 8 11 8a21.8 21.8 0 0 1-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/></svg>`,
  close:()=>`<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>`,
  warn:()=>`<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
  trash:()=>`<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6M14 11v6"/></svg>`,
  edit:()=>`<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 20h9"/><path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg>`,
  folder:()=>`<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>`,
  clock:()=>`<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>`,
  download:()=>`<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>`,
  upload:()=>`<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>`,
  shieldCheck:()=>`<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2 3 6v6c0 5 4 8.5 9 10 5-1.5 9-5 9-10V6z"/><polyline points="9 12 11 14 15 10"/></svg>`,
  share:()=>`<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>`,
  mail:()=>`<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="4" width="20" height="16" rx="2"/><path d="M22 6 12 13 2 6"/></svg>`,
};

/* ==================================================================
   i18n (Bahasa Indonesia / English / 中文)
   ================================================================== */
const I18N = {
  id: {
    loading: "Memuat...",
    setup_subtitle: "Buat Master Password untuk mengamankan vault ini. Password ini tidak dapat dipulihkan jika lupa.",
    master_password_placeholder: "Master Password",
    confirm_master_password_placeholder: "Konfirmasi Master Password",
    create_vault_btn: "Buat Vault",
    creating_vault: "Membuat Vault...",
    restore_backup_btn: "Pulihkan dari Backup",
    setup_footer_note: "Semua data dienkripsi AES-256 dan hanya tersimpan di perangkat ini. Tidak ada server, tidak ada akun.",
    err_master_min: "Master Password minimal 8 karakter",
    err_confirm_mismatch: "Konfirmasi password tidak cocok",
    err_create_vault_failed: "Gagal membuat vault",
    vault_locked_title: "Vault Terkunci",
    vault_locked_subtitle: "Masukkan Master Password untuk membuka",
    unlock_vault_btn: "Buka Vault",
    unlocking: "Membuka...",
    err_wrong_password: "Master Password salah",
    lock_footer_note: "Tidak ada pemulihan password — jaga baik-baik.",
    app_name: "GeoPass Vault",
    decoy_mode_badge: "Mode Decoy",
    all_data: "Semua Data",
    favorites: "Favorit",
    recently_opened: "Terbaru Dibuka",
    category_heading: "Kategori",
    tag_heading: "Tag",
    no_category: "Tanpa Kategori",
    settings_menu: "Pengaturan",
    lock_now: "Kunci Sekarang",
    search_placeholder: "Cari judul, username, email, tag...",
    add_btn: "Tambah",
    empty_no_data: "Belum ada data tersimpan.<br>Tekan \"Tambah\" untuk menyimpan data pertama Anda.",
    empty_no_match: "Tidak ada data yang cocok.",
    add_data_title: "Tambah Data",
    edit_data_title: "Edit Data",
    title_label: "Judul *",
    title_placeholder: "mis. GitHub Kerja",
    category_label: "Kategori",
    add_field_btn: "+ Tambah Field",
    add_custom_field_btn: "+ Field Custom",
    field_website: "Website",
    field_email: "Email",
    field_username: "Username",
    field_password: "Password",
    field_pin: "PIN",
    field_notes: "Catatan",
    field_custom_default: "Field",
    generator_toggle: "⟳ Generator",
    remove_field_btn: "✕ Hapus",
    custom_field_name_placeholder: "Nama Field",
    sensitive_label: "Sensitif",
    custom_value_placeholder: "Nilai",
    tag_input_placeholder: "Tambah tag lalu Enter",
    mark_favorite_label: "Tandai sebagai favorit",
    cancel_btn: "Batal",
    save_btn: "Simpan",
    new_category_prompt: "Nama kategori baru:",
    new_category_option: "+ Tambah Kategori Baru",
    strength_weak: "Lemah",
    strength_medium: "Sedang",
    strength_strong: "Kuat",
    strength_very_strong: "Sangat Kuat",
    regenerate_btn: "↻ Acak Ulang",
    use_btn: "Gunakan",
    copy_all_btn: "Salin Semua",
    reuse_warning: "Password ini digunakan di lebih dari satu data",
    created_label: "Dibuat",
    updated_label: "Diubah",
    last_used_label: "Terakhir dibuka",
    used_count_label: "digunakan",
    delete_btn: "Hapus",
    edit_btn: "Edit",
    confirm_delete_entry: "Hapus data ini?",
    undo_btn: "Urungkan",
    toast_copied: "{label} disalin — akan dihapus dalam {sec}d",
    toast_copy_failed: "Gagal menyalin",
    toast_all_copied_label: "Semua data",
    notes_label: "Catatan",
    settings_title: "Pengaturan",
    theme_label: "Tema",
    theme_sub: "Terang / gelap",
    theme_dark: "Gelap",
    theme_light: "Terang",
    language_label: "Bahasa",
    language_sub: "Pilih bahasa aplikasi",
    autolock_label: "Auto Lock",
    autolock_sub: "Kunci otomatis saat tidak aktif",
    minute_suffix: "menit",
    clipboard_label: "Durasi Clipboard",
    clipboard_sub: "Hapus clipboard otomatis",
    second_suffix: "detik",
    manage_categories_heading: "Kelola Kategori",
    no_categories_yet: "Belum ada kategori.",
    change_master_password_heading: "Ubah Master Password",
    current_master_password_placeholder: "Master Password saat ini",
    new_master_password_placeholder: "Master Password baru",
    change_password_btn: "Ganti Password",
    err_new_password_min: "Password baru minimal 8 karakter",
    err_old_password_wrong: "Password lama salah",
    toast_password_changed: "Master Password diubah",
    decoy_mode_heading: "Decoy Mode",
    decoy_active_note: "Decoy vault aktif. Password kedua membuka vault kosong/palsu.",
    decoy_inactive_note: "Buat password kedua yang membuka vault kosong jika Anda dipaksa membuka aplikasi.",
    create_decoy_btn: "Buat Decoy Password",
    decoy_password_placeholder: "Decoy Master Password",
    save_decoy_btn: "Simpan Decoy",
    err_decoy_min: "Minimal 8 karakter",
    err_decoy_failed: "Gagal membuat decoy",
    toast_decoy_created: "Decoy password dibuat",
    stealth_mode_heading: "Mode Stealth",
    stealth_toggle_label: "Samarkan sebagai Kalkulator",
    stealth_toggle_sub: "Buka vault lewat PIN rahasia di kalkulator",
    stealth_pin_placeholder: "PIN rahasia (4-8 digit)",
    stealth_pin_note: "Ketik PIN ini di kalkulator lalu tekan \"=\" untuk membuka vault.",
    backup_restore_heading: "Backup & Restore",
    share_btn: "Bagikan",
    email_btn: "Kirim via Email",
    share_backup_text: "Backup GeoPass Vault (file terenkripsi)",
    toast_share_unsupported: "Berbagi langsung tidak didukung browser ini — file sudah diunduh",
    toast_share_failed: "Gagal membuka menu berbagi",
    email_subject: "Backup GeoPass Vault",
    email_body: "File backup terenkripsi sudah terunduh ke perangkat ini. Silakan lampirkan file .gpvault tersebut secara manual ke email ini sebelum mengirim (browser tidak mengizinkan lampiran otomatis demi keamanan).",
    export_btn: "Export",
    import_btn: "Import",
    backup_note: "File backup tetap terenkripsi. Import akan menggantikan seluruh isi vault ini.",
    native_note: "Sidik jari/Face ID memerlukan akses sistem operasi native dan belum tersedia pada versi PWA ini — kunci layar perangkat Anda tetap melindungi akses ke aplikasi ini.",
    toast_backup_downloaded: "Backup diunduh",
    toast_backup_failed: "Gagal membuat backup",
    toast_backup_restored: "Backup dipulihkan — silakan buka vault",
    toast_backup_invalid: "File backup tidak valid",
    delete_category_confirm: "Hapus kategori \"{name}\" ({count} data)?",
    move_category_btn: "Pindahkan data ke \"Tanpa Kategori\"",
    delete_category_with_data_btn: "Hapus kategori beserta semua datanya",
    confirm_delete_category_data: "Hapus kategori \"{name}\" beserta {count} data di dalamnya? Tindakan ini tidak bisa dibatalkan.",
    toast_category_deleted: "Kategori \"{name}\" dan datanya dihapus",
    toast_category_moved: "Kategori \"{name}\" dihapus, data dipindah ke Tanpa Kategori",
    copy_password_title: "Copy Password",
    favorite_title: "Favorit",
    toast_saved: "Data disimpan",
    toast_deleted: "Data dihapus",
    toast_vault_created: "Vault berhasil dibuat",
    toast_settings_save_failed: "Gagal menyimpan pengaturan",
    calculator_label: "Kalkulator",
    history_heading: "Riwayat",
    clear_history_btn: "Hapus",
    no_history_yet: "Belum ada riwayat perhitungan",
    native_features_heading: "Fitur Native",
    decoy_toggle_label: "Aktifkan Mode Decoy",
    decoy_toggle_sub: "Password kedua yang membuka vault kosong",
    change_decoy_btn: "Ganti Password Decoy",
    new_decoy_password_placeholder: "Password Decoy Baru",
    confirm_disable_decoy: "Menonaktifkan Mode Decoy akan menghapus vault decoy yang ada. Lanjutkan?",
    toast_decoy_changed: "Password decoy diubah",
    danger_zone_heading: "Zona Berbahaya",
    about_app_btn: "Tentang Aplikasi Ini",
    panic_reset_btn: "Reset Darurat (Panic Reset)",
    panic_title: "Reset Darurat",
    panic_warning_1: "⚠️ PERINGATAN: Tindakan ini akan MENGHAPUS SEMUA data secara PERMANEN \u2014 seluruh password, kategori, pengaturan, dan vault decoy (jika ada). Tidak dapat dibatalkan, tidak dapat dipulihkan. Pastikan Anda benar-benar ingin melakukan ini.",
    panic_enter_password: "Masukkan Master Password Anda untuk melanjutkan",
    panic_warning_2: "Ini adalah kesempatan terakhir. Setelah Anda menekan tombol di bawah, SEMUA DATA AKAN HILANG SELAMANYA \u2014 tidak ada cara untuk mengembalikannya, bahkan oleh kami.",
    panic_confirm_password: "Masukkan Master Password sekali lagi untuk konfirmasi final",
    panic_continue_btn: "Saya Mengerti, Lanjutkan",
    panic_execute_btn: "HAPUS SEMUA DATA SEKARANG",
    toast_panic_done: "Aplikasi telah direset. Silakan buat Master Password baru.",
  },
  en: {
    loading: "Loading...",
    setup_subtitle: "Create a Master Password to secure this vault. This password cannot be recovered if forgotten.",
    master_password_placeholder: "Master Password",
    confirm_master_password_placeholder: "Confirm Master Password",
    create_vault_btn: "Create Vault",
    creating_vault: "Creating Vault...",
    restore_backup_btn: "Restore from Backup",
    setup_footer_note: "All data is encrypted with AES-256 and stored only on this device. No server, no account.",
    err_master_min: "Master Password must be at least 8 characters",
    err_confirm_mismatch: "Password confirmation doesn't match",
    err_create_vault_failed: "Failed to create vault",
    vault_locked_title: "Vault Locked",
    vault_locked_subtitle: "Enter your Master Password to unlock",
    unlock_vault_btn: "Unlock Vault",
    unlocking: "Unlocking...",
    err_wrong_password: "Incorrect Master Password",
    lock_footer_note: "There is no password recovery — keep it safe.",
    app_name: "GeoPass Vault",
    decoy_mode_badge: "Decoy Mode",
    all_data: "All Data",
    favorites: "Favorites",
    recently_opened: "Recently Opened",
    category_heading: "Categories",
    tag_heading: "Tags",
    no_category: "Uncategorized",
    settings_menu: "Settings",
    lock_now: "Lock Now",
    search_placeholder: "Search title, username, email, tag...",
    add_btn: "Add",
    empty_no_data: "No data saved yet.<br>Tap \"Add\" to save your first entry.",
    empty_no_match: "No matching entries.",
    add_data_title: "Add Entry",
    edit_data_title: "Edit Entry",
    title_label: "Title *",
    title_placeholder: "e.g. Work GitHub",
    category_label: "Category",
    add_field_btn: "+ Add Field",
    add_custom_field_btn: "+ Custom Field",
    field_website: "Website",
    field_email: "Email",
    field_username: "Username",
    field_password: "Password",
    field_pin: "PIN",
    field_notes: "Notes",
    field_custom_default: "Field",
    generator_toggle: "⟳ Generator",
    remove_field_btn: "✕ Remove",
    custom_field_name_placeholder: "Field Name",
    sensitive_label: "Sensitive",
    custom_value_placeholder: "Value",
    tag_input_placeholder: "Add a tag, then Enter",
    mark_favorite_label: "Mark as favorite",
    cancel_btn: "Cancel",
    save_btn: "Save",
    new_category_prompt: "New category name:",
    new_category_option: "+ Add New Category",
    strength_weak: "Weak",
    strength_medium: "Medium",
    strength_strong: "Strong",
    strength_very_strong: "Very Strong",
    regenerate_btn: "↻ Regenerate",
    use_btn: "Use",
    copy_all_btn: "Copy All",
    reuse_warning: "This password is used in more than one entry",
    created_label: "Created",
    updated_label: "Updated",
    last_used_label: "Last opened",
    used_count_label: "used",
    delete_btn: "Delete",
    edit_btn: "Edit",
    confirm_delete_entry: "Delete this entry?",
    undo_btn: "Undo",
    toast_copied: "{label} copied — will clear in {sec}s",
    toast_copy_failed: "Failed to copy",
    toast_all_copied_label: "All data",
    notes_label: "Notes",
    settings_title: "Settings",
    theme_label: "Theme",
    theme_sub: "Light / dark",
    theme_dark: "Dark",
    theme_light: "Light",
    language_label: "Language",
    language_sub: "Choose app language",
    autolock_label: "Auto Lock",
    autolock_sub: "Lock automatically when inactive",
    minute_suffix: "min",
    clipboard_label: "Clipboard Duration",
    clipboard_sub: "Clear clipboard automatically",
    second_suffix: "sec",
    manage_categories_heading: "Manage Categories",
    no_categories_yet: "No categories yet.",
    change_master_password_heading: "Change Master Password",
    current_master_password_placeholder: "Current Master Password",
    new_master_password_placeholder: "New Master Password",
    change_password_btn: "Change Password",
    err_new_password_min: "New password must be at least 8 characters",
    err_old_password_wrong: "Current password is incorrect",
    toast_password_changed: "Master Password changed",
    decoy_mode_heading: "Decoy Mode",
    decoy_active_note: "Decoy vault active. The second password opens an empty/fake vault.",
    decoy_inactive_note: "Create a second password that opens an empty vault if you're ever forced to open the app.",
    create_decoy_btn: "Create Decoy Password",
    decoy_password_placeholder: "Decoy Master Password",
    save_decoy_btn: "Save Decoy",
    err_decoy_min: "At least 8 characters",
    err_decoy_failed: "Failed to create decoy",
    toast_decoy_created: "Decoy password created",
    stealth_mode_heading: "Stealth Mode",
    stealth_toggle_label: "Disguise as Calculator",
    stealth_toggle_sub: "Unlock the vault via a secret PIN on the calculator",
    stealth_pin_placeholder: "Secret PIN (4-8 digits)",
    stealth_pin_note: "Type this PIN on the calculator, then press \"=\" to unlock the vault.",
    backup_restore_heading: "Backup & Restore",
    share_btn: "Share",
    email_btn: "Send via Email",
    share_backup_text: "GeoPass Vault backup (encrypted file)",
    toast_share_unsupported: "Direct sharing isn't supported in this browser — the file was downloaded instead",
    toast_share_failed: "Failed to open the share menu",
    email_subject: "GeoPass Vault Backup",
    email_body: "The encrypted backup file has been downloaded to this device. Please manually attach the .gpvault file to this email before sending (browsers don't allow automatic attachments for security reasons).",
    export_btn: "Export",
    import_btn: "Import",
    backup_note: "Backup files remain encrypted. Importing will replace this vault's entire contents.",
    native_note: "Fingerprint/Face ID requires native OS access and isn't available in this PWA version yet — your device's lock screen still protects access to this app.",
    toast_backup_downloaded: "Backup downloaded",
    toast_backup_failed: "Failed to create backup",
    toast_backup_restored: "Backup restored — please unlock the vault",
    toast_backup_invalid: "Invalid backup file",
    delete_category_confirm: "Delete category \"{name}\" ({count} entries)?",
    move_category_btn: "Move entries to \"Uncategorized\"",
    delete_category_with_data_btn: "Delete category and all its entries",
    confirm_delete_category_data: "Delete category \"{name}\" along with {count} entries inside it? This cannot be undone.",
    toast_category_deleted: "Category \"{name}\" and its entries were deleted",
    toast_category_moved: "Category \"{name}\" deleted, entries moved to Uncategorized",
    copy_password_title: "Copy Password",
    favorite_title: "Favorite",
    toast_saved: "Entry saved",
    toast_deleted: "Entry deleted",
    toast_vault_created: "Vault created successfully",
    toast_settings_save_failed: "Failed to save settings",
    calculator_label: "Calculator",
    history_heading: "History",
    clear_history_btn: "Clear",
    no_history_yet: "No calculations yet",
    native_features_heading: "Native Features",
    decoy_toggle_label: "Enable Decoy Mode",
    decoy_toggle_sub: "A second password that opens an empty vault",
    change_decoy_btn: "Change Decoy Password",
    new_decoy_password_placeholder: "New Decoy Password",
    confirm_disable_decoy: "Disabling Decoy Mode will delete the existing decoy vault. Continue?",
    toast_decoy_changed: "Decoy password changed",
    danger_zone_heading: "Danger Zone",
    about_app_btn: "About This App",
    panic_reset_btn: "Panic Reset",
    panic_title: "Panic Reset",
    panic_warning_1: "\u26a0\ufe0f WARNING: This will PERMANENTLY DELETE ALL data \u2014 every password, category, setting, and the decoy vault (if any). This cannot be undone or recovered. Make sure you truly want to do this.",
    panic_enter_password: "Enter your Master Password to continue",
    panic_warning_2: "This is your last chance. Once you press the button below, ALL DATA WILL BE GONE FOREVER \u2014 there is no way to get it back, not even by us.",
    panic_confirm_password: "Enter your Master Password once more for final confirmation",
    panic_continue_btn: "I Understand, Continue",
    panic_execute_btn: "DELETE ALL DATA NOW",
    toast_panic_done: "The app has been reset. Please create a new Master Password.",
  },
  zh: {
    loading: "加载中...",
    setup_subtitle: "创建主密码以保护此密码库。忘记密码后将无法找回。",
    master_password_placeholder: "主密码",
    confirm_master_password_placeholder: "确认主密码",
    create_vault_btn: "创建密码库",
    creating_vault: "正在创建...",
    restore_backup_btn: "从备份恢复",
    setup_footer_note: "所有数据均使用 AES-256 加密，仅保存在本设备上。没有服务器，没有账户。",
    err_master_min: "主密码至少需要 8 个字符",
    err_confirm_mismatch: "两次输入的密码不一致",
    err_create_vault_failed: "创建密码库失败",
    vault_locked_title: "密码库已锁定",
    vault_locked_subtitle: "输入主密码以解锁",
    unlock_vault_btn: "解锁密码库",
    unlocking: "正在解锁...",
    err_wrong_password: "主密码错误",
    lock_footer_note: "密码无法找回——请务必妥善保管。",
    app_name: "GeoPass Vault",
    decoy_mode_badge: "伪装模式",
    all_data: "全部数据",
    favorites: "收藏",
    recently_opened: "最近打开",
    category_heading: "分类",
    tag_heading: "标签",
    no_category: "未分类",
    settings_menu: "设置",
    lock_now: "立即锁定",
    search_placeholder: "搜索标题、用户名、邮箱、标签...",
    add_btn: "添加",
    empty_no_data: "还没有保存任何数据。<br>点击“添加”保存第一条数据。",
    empty_no_match: "没有匹配的数据。",
    add_data_title: "添加数据",
    edit_data_title: "编辑数据",
    title_label: "标题 *",
    title_placeholder: "例如：工作用 GitHub",
    category_label: "分类",
    add_field_btn: "+ 添加字段",
    add_custom_field_btn: "+ 自定义字段",
    field_website: "网站",
    field_email: "邮箱",
    field_username: "用户名",
    field_password: "密码",
    field_pin: "PIN 码",
    field_notes: "备注",
    field_custom_default: "字段",
    generator_toggle: "⟳ 生成器",
    remove_field_btn: "✕ 移除",
    custom_field_name_placeholder: "字段名称",
    sensitive_label: "敏感信息",
    custom_value_placeholder: "内容",
    tag_input_placeholder: "输入标签后按 Enter",
    mark_favorite_label: "标记为收藏",
    cancel_btn: "取消",
    save_btn: "保存",
    new_category_prompt: "新分类名称：",
    new_category_option: "+ 添加新分类",
    strength_weak: "弱",
    strength_medium: "中等",
    strength_strong: "强",
    strength_very_strong: "非常强",
    regenerate_btn: "↻ 重新生成",
    use_btn: "使用",
    copy_all_btn: "复制全部",
    reuse_warning: "此密码已在多条数据中重复使用",
    created_label: "创建于",
    updated_label: "更新于",
    last_used_label: "最近打开",
    used_count_label: "已使用",
    delete_btn: "删除",
    edit_btn: "编辑",
    confirm_delete_entry: "删除这条数据？",
    undo_btn: "撤销",
    toast_copied: "{label} 已复制 —— 将在 {sec} 秒后清除",
    toast_copy_failed: "复制失败",
    toast_all_copied_label: "全部数据",
    notes_label: "备注",
    settings_title: "设置",
    theme_label: "主题",
    theme_sub: "浅色 / 深色",
    theme_dark: "深色",
    theme_light: "浅色",
    language_label: "语言",
    language_sub: "选择应用语言",
    autolock_label: "自动锁定",
    autolock_sub: "闲置时自动锁定",
    minute_suffix: "分钟",
    clipboard_label: "剪贴板保留时长",
    clipboard_sub: "自动清除剪贴板",
    second_suffix: "秒",
    manage_categories_heading: "管理分类",
    no_categories_yet: "还没有分类。",
    change_master_password_heading: "更改主密码",
    current_master_password_placeholder: "当前主密码",
    new_master_password_placeholder: "新主密码",
    change_password_btn: "更改密码",
    err_new_password_min: "新密码至少需要 8 个字符",
    err_old_password_wrong: "当前密码错误",
    toast_password_changed: "主密码已更改",
    decoy_mode_heading: "伪装密码库",
    decoy_active_note: "伪装密码库已启用。第二组密码将打开一个空的（伪装）密码库。",
    decoy_inactive_note: "创建第二组密码，如果被迫打开应用时，可用它打开一个空密码库。",
    create_decoy_btn: "创建伪装密码",
    decoy_password_placeholder: "伪装主密码",
    save_decoy_btn: "保存伪装密码",
    err_decoy_min: "至少需要 8 个字符",
    err_decoy_failed: "创建伪装密码库失败",
    toast_decoy_created: "伪装密码已创建",
    stealth_mode_heading: "隐藏模式",
    stealth_toggle_label: "伪装成计算器",
    stealth_toggle_sub: "在计算器界面输入密PIN码以解锁密码库",
    stealth_pin_placeholder: "密PIN码（4-8位数字）",
    stealth_pin_note: "在计算器中输入此 PIN 码后按“=”即可解锁密码库。",
    backup_restore_heading: "备份与恢复",
    share_btn: "分享",
    email_btn: "通过邮件发送",
    share_backup_text: "GeoPass Vault 备份（加密文件）",
    toast_share_unsupported: "此浏览器不支持直接分享——文件已改为下载",
    toast_share_failed: "打开分享菜单失败",
    email_subject: "GeoPass Vault 备份",
    email_body: "加密备份文件已下载到此设备。发送前请手动将 .gpvault 文件添加为附件（出于安全原因，浏览器不允许自动添加附件）。",
    export_btn: "导出",
    import_btn: "导入",
    backup_note: "备份文件仍为加密状态。导入将替换此密码库的全部内容。",
    native_note: "指纹/面容 ID 需要系统原生权限，此 PWA 版本暂不支持——您设备本身的锁屏仍会保护此应用的访问。",
    toast_backup_downloaded: "备份已下载",
    toast_backup_failed: "创建备份失败",
    toast_backup_restored: "备份已恢复——请解锁密码库",
    toast_backup_invalid: "备份文件无效",
    delete_category_confirm: "删除分类“{name}”（{count} 条数据）？",
    move_category_btn: "将数据移动到“未分类”",
    delete_category_with_data_btn: "删除分类及其全部数据",
    confirm_delete_category_data: "删除分类“{name}”及其中 {count} 条数据？此操作无法撤销。",
    toast_category_deleted: "分类“{name}”及其数据已删除",
    toast_category_moved: "分类“{name}”已删除，数据已移至未分类",
    copy_password_title: "复制密码",
    favorite_title: "收藏",
    toast_saved: "数据已保存",
    toast_deleted: "数据已删除",
    toast_vault_created: "密码库创建成功",
    toast_settings_save_failed: "保存设置失败",
    calculator_label: "计算器",
    history_heading: "历史记录",
    clear_history_btn: "清除",
    no_history_yet: "还没有计算记录",
    native_features_heading: "\u539f\u751f\u529f\u80fd",
    decoy_toggle_label: "\u542f\u7528\u4f2a\u88c5\u6a21\u5f0f",
    decoy_toggle_sub: "\u7b2c\u4e8c\u7ec4\u5bc6\u7801\u5c06\u6253\u5f00\u4e00\u4e2a\u7a7a\u7684\u5bc6\u7801\u5e93",
    change_decoy_btn: "\u66f4\u6539\u4f2a\u88c5\u5bc6\u7801",
    new_decoy_password_placeholder: "\u65b0\u7684\u4f2a\u88c5\u5bc6\u7801",
    confirm_disable_decoy: "\u7981\u7528\u4f2a\u88c5\u6a21\u5f0f\u5c06\u5220\u9664\u73b0\u6709\u7684\u4f2a\u88c5\u5bc6\u7801\u5e93\u3002\u662f\u5426\u7ee7\u7eed\uff1f",
    toast_decoy_changed: "\u4f2a\u88c5\u5bc6\u7801\u5df2\u66f4\u6539",
    danger_zone_heading: "\u5371\u9669\u533a\u57df",
    about_app_btn: "\u5173\u4e8e\u6b64\u5e94\u7528",
    panic_reset_btn: "\u7d27\u6025\u91cd\u7f6e\uff08Panic Reset\uff09",
    panic_title: "\u7d27\u6025\u91cd\u7f6e",
    panic_warning_1: "\u26a0\ufe0f \u8b66\u544a\uff1a\u6b64\u64cd\u4f5c\u5c06\u6c38\u4e45\u5220\u9664\u6240\u6709\u6570\u636e\u2014\u2014\u6240\u6709\u5bc6\u7801\u3001\u5206\u7c7b\u3001\u8bbe\u7f6e\u4ee5\u53ca\u4f2a\u88c5\u5bc6\u7801\u5e93\uff08\u5982\u679c\u5b58\u5728\uff09\u3002\u6b64\u64cd\u4f5c\u65e0\u6cd5\u64a4\u9500\uff0c\u4e5f\u65e0\u6cd5\u6062\u590d\u3002\u8bf7\u786e\u8ba4\u60a8\u771f\u7684\u8981\u8fd9\u6837\u505a\u3002",
    panic_enter_password: "\u8bf7\u8f93\u5165\u60a8\u7684\u4e3b\u5bc6\u7801\u4ee5\u7ee7\u7eed",
    panic_warning_2: "\u8fd9\u662f\u6700\u540e\u7684\u673a\u4f1a\u3002\u4e00\u65e6\u60a8\u70b9\u51fb\u4e0b\u65b9\u6309\u94ae\uff0c\u6240\u6709\u6570\u636e\u5c06\u6c38\u4e45\u4e22\u5931\u2014\u2014\u6ca1\u6709\u4efb\u4f55\u65b9\u6cd5\u53ef\u4ee5\u6062\u590d\uff0c\u5305\u62ec\u6211\u4eec\u4e5f\u65e0\u6cd5\u5e2e\u60a8\u627e\u56de\u3002",
    panic_confirm_password: "\u8bf7\u518d\u6b21\u8f93\u5165\u4e3b\u5bc6\u7801\u4ee5\u8fdb\u884c\u6700\u7ec8\u786e\u8ba4",
    panic_continue_btn: "\u6211\u660e\u767d\uff0c\u7ee7\u7eed",
    panic_execute_btn: "\u7acb\u5373\u5220\u9664\u6240\u6709\u6570\u636e",
    toast_panic_done: "\u5e94\u7528\u5df2\u91cd\u7f6e\u3002\u8bf7\u521b\u5efa\u65b0\u7684\u4e3b\u5bc6\u7801\u3002",
  },
};
function t(key, vars){
  const lang = (State.settings && State.settings.lang) || "id";
  let str = (I18N[lang] && I18N[lang][key]) || I18N.id[key] || key;
  if(vars){ Object.keys(vars).forEach(k=>{ str = str.replace(`{${k}}`, vars[k]); }); }
  return str;
}

/* ==================================================================
   App state
   ================================================================== */
const State = {
  stage: "loading",
  settings: Object.assign({}, DEFAULT_SETTINGS),
  session: null,               // { slot, key, vault }
  view: { searchQ:"", filterCat:null, filterTag:null, filterFav:false, filterRecent:false },
  detailEntryId: null,
  formDraft: null,
  calc: { display:"0", pinBuffer:"", acc:null, op:null, expr:"", history:[], justEvaluated:false },
  panicStep: null,
};
let toastTimer=null, clipboardTimer=null, idleTimer=null, saveTimer=null, autoLockBound=false;

/* ==================================================================
   Screen management
   ================================================================== */
function goStage(stage){
  State.stage = stage;
  clearTimeout(toastTimer);
  const toastEl = document.getElementById("toast");
  toastEl.classList.add("hidden");
  toastEl.classList.remove("hiding");
  toastEl.textContent = "";
  ["loading","stealth","setup","locked","unlocked"].forEach(s=>{
    const el = document.getElementById("screen-"+s);
    el.classList.toggle("hidden", s!==stage);
    if(s===stage){
      el.classList.remove("screen-enter");
      void el.offsetWidth; // force reflow so the animation re-triggers every time
      el.classList.add("screen-enter");
    }
  });
  if(stage==="unlocked"){
    openSidebarPanel();
    renderSidebar();
    renderEntryList();
    setupAutoLock();
  } else {
    clearTimeout(idleTimer);
  }
  if(stage==="stealth"){
    resetCalc();
    document.getElementById("app-favicon").href = "icons/icon-calc.png";
    document.title = t("calculator_label");
  } else {
    document.getElementById("app-favicon").href = "icons/icon-192.png";
    document.title = t("app_name");
  }
}

function applyTheme(){
  const appEl = document.getElementById("app");
  appEl.classList.remove("dark","light");
  appEl.classList.add(State.settings.theme);
}

function showToast(msg){
  const toastEl = document.getElementById("toast");
  toastEl.classList.remove("hiding");
  toastEl.textContent = msg;
  toastEl.classList.remove("hidden");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(()=>dismissToast(), 2200);
}
function dismissToast(){
  const toastEl = document.getElementById("toast");
  if(toastEl.classList.contains("hidden")) return;
  toastEl.classList.add("hiding");
  setTimeout(()=>{ toastEl.classList.add("hidden"); toastEl.classList.remove("hiding"); }, 160);
}
function showUndoToast(msg, onUndo){
  const toastEl = document.getElementById("toast");
  toastEl.classList.remove("hiding");
  toastEl.innerHTML = `<span>${esc(msg)}</span><button id="toast-undo-btn" class="toast-undo-btn">${t("undo_btn")}</button>`;
  toastEl.classList.remove("hidden");
  document.getElementById("toast-undo-btn").onclick = ()=>{
    clearTimeout(toastTimer);
    dismissToast();
    onUndo();
  };
  clearTimeout(toastTimer);
  toastTimer = setTimeout(()=>dismissToast(), 5000);
}

/* ==================================================================
   Settings persistence
   ================================================================== */
async function persistSettings(next){
  State.settings = next;
  try{ await idbSet("geopass-settings", next); }catch(e){ showToast(t("toast_settings_save_failed")); }
}

/* ==================================================================
   Setup / Unlock / Lock
   ================================================================== */
async function handleSetup(password){
  const salt = randomSaltB64();
  const key = await deriveKey(password, salt, PBKDF2_ITER);
  const verify = await encryptJSON(key, {check:VERIFY_TAG});
  const vault = { entries:[], categories: DEFAULT_CATEGORIES.slice(), createdAt: Date.now() };
  const dataEnc = await encryptJSON(key, vault);
  const meta = { salt, iterations: PBKDF2_ITER, verify, vault: dataEnc };
  await idbSet("geopass-real", meta);
  State.session = { slot:"real", key, vault };
  goStage("unlocked");
  showToast(t("toast_vault_created"));
}

async function trySlot(slot, password){
  let meta;
  try{ meta = await idbGet(`geopass-${slot}`); } catch(e){ return null; }
  if(!meta) return null;
  try{
    const key = await deriveKey(password, meta.salt, meta.iterations);
    const check = await decryptJSON(key, meta.verify.iv, meta.verify.data);
    if(check && check.check===VERIFY_TAG){
      const vault = await decryptJSON(key, meta.vault.iv, meta.vault.data);
      vault.entries = (vault.entries||[]).map(migrateEntry);
      return {slot,key,vault};
    }
    return null;
  }catch(e){ return null; }
}

async function handleUnlock(password){
  let result = await trySlot("real", password);
  if(!result) result = await trySlot("decoy", password);
  if(result){ State.session = result; goStage("unlocked"); return true; }
  return false;
}

function lockVault(){
  State.session = null;
  document.getElementById("modal-detail").classList.add("hidden");
  document.getElementById("modal-form").classList.add("hidden");
  document.getElementById("modal-settings").classList.add("hidden");
  clearTimeout(idleTimer);
  goStage(State.settings.stealthEnabled ? "stealth" : "locked");
}

async function changeMasterPassword(oldPw, newPw){
  const check = await trySlot(State.session.slot, oldPw);
  if(!check) return false;
  const salt = randomSaltB64();
  const key = await deriveKey(newPw, salt, PBKDF2_ITER);
  const verify = await encryptJSON(key, {check:VERIFY_TAG});
  const dataEnc = await encryptJSON(key, State.session.vault);
  const meta = { salt, iterations: PBKDF2_ITER, verify, vault: dataEnc };
  await idbSet(`geopass-${State.session.slot}`, meta);
  State.session.key = key;
  return true;
}

async function setupDecoy(pw){
  const salt = randomSaltB64();
  const key = await deriveKey(pw, salt, PBKDF2_ITER);
  const verify = await encryptJSON(key, {check:VERIFY_TAG});
  const vault = { entries:[], categories: DEFAULT_CATEGORIES.slice(), createdAt: Date.now() };
  const dataEnc = await encryptJSON(key, vault);
  const meta = { salt, iterations: PBKDF2_ITER, verify, vault: dataEnc };
  await idbSet("geopass-decoy", meta);
  await persistSettings(Object.assign({}, State.settings, {hasDecoy:true}));
}
async function disableDecoy(){
  try{ await idbDelete("geopass-decoy"); }catch(e){ /* ignore */ }
  await persistSettings(Object.assign({}, State.settings, {hasDecoy:false}));
}

/* ==================================================================
   Backup / Restore
   ================================================================== */
async function exportBackup(){
  if(!State.session) return;
  try{
    const meta = await idbGet(`geopass-${State.session.slot}`);
    const blob = new Blob([JSON.stringify(meta)], {type:"application/json"});
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `geopass-backup-${State.session.slot}-${Date.now()}.gpvault`;
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast(t("toast_backup_downloaded"));
  }catch(e){ showToast(t("toast_backup_failed")); }
}
async function makeBackupFile(){
  const meta = await idbGet(`geopass-${State.session.slot}`);
  const filename = `geopass-backup-${State.session.slot}-${Date.now()}.gpvault`;
  const blob = new Blob([JSON.stringify(meta)], {type:"application/json"});
  return new File([blob], filename, {type:"application/json"});
}
async function shareBackup(){
  if(!State.session) return;
  try{
    const file = await makeBackupFile();
    if(navigator.canShare && navigator.canShare({files:[file]})){
      await navigator.share({ files:[file], title: t("app_name"), text: t("share_backup_text") });
    } else {
      await exportBackup();
      showToast(t("toast_share_unsupported"));
    }
  }catch(e){
    if(e && e.name==="AbortError") return; // user cancelled the native share sheet
    showToast(t("toast_share_failed"));
  }
}
async function emailBackup(){
  if(!State.session) return;
  try{
    await exportBackup();
    const subject = encodeURIComponent(t("email_subject"));
    const body = encodeURIComponent(t("email_body"));
    window.location.href = `mailto:?subject=${subject}&body=${body}`;
  }catch(e){ showToast(t("toast_backup_failed")); }
}
function importBackup(file, slot){
  const reader = new FileReader();
  reader.onload = async ()=>{
    try{
      const parsed = JSON.parse(reader.result);
      if(!parsed.salt || !parsed.verify || !parsed.vault) throw new Error("invalid");
      await idbSet(`geopass-${slot||"real"}`, parsed);
      showToast(t("toast_backup_restored"));
      if(State.stage!=="unlocked") goStage("locked");
    }catch(e){ showToast(t("toast_backup_invalid")); }
  };
  reader.readAsText(file);
}

/* ==================================================================
   Vault mutations
   ================================================================== */
function scheduleSave(){
  clearTimeout(saveTimer);
  saveTimer = setTimeout(async ()=>{
    if(!State.session) return;
    try{
      const meta = await idbGet(`geopass-${State.session.slot}`);
      if(!meta) return;
      const enc = await encryptJSON(State.session.key, State.session.vault);
      meta.vault = enc;
      await idbSet(`geopass-${State.session.slot}`, meta);
    }catch(e){ /* silent - retried on next change */ }
  }, 450);
}
function saveEntry(entry){
  const entries = State.session.vault.entries;
  const exists = entries.some(e=>e.id===entry.id);
  State.session.vault.entries = exists ? entries.map(e=>e.id===entry.id?entry:e) : entries.concat([entry]);
  scheduleSave(); renderEntryList(); renderSidebar();
  showToast(t("toast_saved"));
}
function deleteEntry(id){
  State.session.vault.entries = State.session.vault.entries.filter(e=>e.id!==id);
  scheduleSave(); renderEntryList(); renderSidebar();
}
function deleteEntryWithUndo(id){
  const entry = State.session.vault.entries.find(e=>e.id===id);
  if(!entry) return;
  const cardEl = document.querySelector(`.card[data-id="${id}"]`);
  const commit = ()=>{
    deleteEntry(id);
    showUndoToast(t("toast_deleted"), ()=>{
      State.session.vault.entries = State.session.vault.entries.concat([entry]);
      scheduleSave(); renderEntryList(); renderSidebar();
    });
  };
  if(cardEl){
    cardEl.classList.add("removing");
    setTimeout(commit, 260);
  } else {
    commit();
  }
}
function toggleFavorite(id){
  State.session.vault.entries = State.session.vault.entries.map(e=>e.id===id?Object.assign({},e,{favorite:!e.favorite}):e);
  scheduleSave(); renderEntryList();
}
function recordUse(id){
  State.session.vault.entries = State.session.vault.entries.map(e=>e.id===id?Object.assign({},e,{lastUsedAt:Date.now(),useCount:(e.useCount||0)+1}):e);
  scheduleSave();
}
function addCategory(name){
  if(State.session.vault.categories.indexOf(name)===-1){
    State.session.vault.categories = State.session.vault.categories.concat([name]);
    scheduleSave();
  }
}
function computePasswordCounts(entries){
  const m={}; entries.forEach(e=>{ if(e.password) m[e.password]=(m[e.password]||0)+1; }); return m;
}

/* ==================================================================
   Clipboard
   ================================================================== */
function copyToClipboard(value, label){
  if(!value) return;
  navigator.clipboard.writeText(value).then(()=>{
    showToast(t("toast_copied", {label: label||t("notes_label"), sec: State.settings.clipboardSec}));
  }).catch(()=>showToast(t("toast_copy_failed")));
  clearTimeout(clipboardTimer);
  clipboardTimer = setTimeout(()=>{ navigator.clipboard.writeText("").catch(()=>{}); }, State.settings.clipboardSec*1000);
}
function quickCopy(id){
  const entry = State.session.vault.entries.find(e=>e.id===id);
  if(!entry) return;
  copyToClipboard(entry.password, t("field_password"));
  recordUse(id);
}

/* ==================================================================
   Sidebar
   ================================================================== */
function renderSidebar(){
  const s = State.settings, session = State.session, v = State.view;
  document.getElementById("sb-quick").innerHTML = `
    <button class="sb-item ${v.filterCat===null&&!v.filterTag&&!v.filterFav&&!v.filterRecent?'active':''}" data-quick="all">${ic.folder()} ${t("all_data")}</button>
    <button class="sb-item ${v.filterFav?'active':''}" data-quick="fav">${ic.star(v.filterFav)} ${t("favorites")}</button>
    <button class="sb-item ${v.filterRecent?'active':''}" data-quick="recent">${ic.clock()} ${t("recently_opened")}</button>
  `;
  document.getElementById("sb-categories").innerHTML = session.vault.categories.map(c=>
    `<button class="sb-item ${v.filterCat===c?'active':''}" data-cat="${esc(c)}"><span class="sb-dot"></span> ${esc(c)}</button>`
  ).join("") + `<button class="sb-item ${v.filterCat===''?'active':''}" data-cat=""><span class="sb-dot" style="opacity:.4;"></span> ${t("no_category")}</button>`;
  const allTags = Array.from(new Set(session.vault.entries.reduce((a,e)=>a.concat(e.tags||[]),[])));
  document.getElementById("sb-tags-heading").classList.toggle("hidden", allTags.length===0);
  document.getElementById("sb-tags").innerHTML = allTags.map(t=>
    `<span class="chip ${v.filterTag===t?'active':''}" data-tag="${esc(t)}">${esc(t)}</span>`
  ).join("");
}

/* ==================================================================
   Entry list
   ================================================================== */
function getFilteredEntries(){
  const entries = State.session.vault.entries;
  const v = State.view;
  let list = entries;
  if(v.filterFav) list = list.filter(e=>e.favorite);
  if(v.filterCat!==null) list = list.filter(e=>(e.category||"")===v.filterCat);
  if(v.filterTag) list = list.filter(e=>e.tags && e.tags.indexOf(v.filterTag)!==-1);
  if(v.searchQ.trim()){
    const q = v.searchQ.toLowerCase();
    list = list.filter(e=>{
      const hay = [e.title,e.username,e.email,e.website,e.notes].concat(e.tags||[]).concat((e.customFields||[]).map(f=>f.value));
      return hay.filter(Boolean).some(f=>String(f).toLowerCase().indexOf(q)!==-1);
    });
  }
  if(v.filterRecent){
    list = list.filter(e=>e.lastUsedAt).slice().sort((a,b)=>(b.lastUsedAt||0)-(a.lastUsedAt||0)).slice(0,20);
  } else {
    list = list.slice().sort((a,b)=>(b.favorite-a.favorite)||(b.updatedAt-a.updatedAt));
  }
  return list;
}
function renderEntryList(){
  const container = document.getElementById("entry-list");
  const entries = State.session.vault.entries;
  const list = getFilteredEntries();
  const counts = computePasswordCounts(entries);
  if(list.length===0){
    container.innerHTML = `<div class="empty-state">${entries.length===0 ? t("empty_no_data") : t("empty_no_match")}</div>`;
    return;
  }
  container.innerHTML = list.map(e=>{
    const dup = e.password && counts[e.password]>1;
    const sub = e.username || e.email || e.website || "—";
    const tagsHtml = (e.tags&&e.tags.length) ? `<div class="card-tags">${e.tags.slice(0,3).map(tg=>`<span class="chip static">${esc(tg)}</span>`).join("")}</div>` : "";
    const visible = e.visibleFields||DEFAULT_VISIBLE_FIELDS;
    const canQuickCopy = e.password && visible.indexOf("password")!==-1;
    return `<div class="card" data-id="${e.id}" data-action="open-detail">
      <div class="card-row">
        <div style="min-width:0;flex:1;">
          <div class="card-title-row"><div class="card-title">${esc(e.title)}</div>${dup?ic.warn().replace('width="14"','width="12"').replace('height="14"','height="12"').replace('currentColor','var(--danger)'):''}</div>
          <div class="card-sub">${esc(sub)}</div>
          ${tagsHtml}
        </div>
        <div class="card-actions">
          <button class="icon-btn" data-action="toggle-fav" data-id="${e.id}" title="${t("favorite_title")}">${ic.star(e.favorite)}</button>
          ${canQuickCopy?`<button class="icon-btn" data-action="quick-copy" data-id="${e.id}" title="${t("copy_password_title")}">${ic.copy()}</button>`:''}
        </div>
      </div>
    </div>`;
  }).join("");
}
document.getElementById("entry-list").addEventListener("click",(e)=>{
  const btn = e.target.closest("[data-action]");
  if(!btn) return;
  const id = btn.getAttribute("data-id");
  const action = btn.getAttribute("data-action");
  if(action==="toggle-fav"){
    const entry = State.session.vault.entries.find(en=>en.id===id);
    const nowFav = entry ? !entry.favorite : false;
    btn.innerHTML = ic.star(nowFav);
    pulseIcon(btn);
    setTimeout(()=>toggleFavorite(id), 260);
  }
  else if(action==="quick-copy") quickCopy(id);
  else if(action==="open-detail") openDetail(id);
});
function pulseIcon(el){
  el.classList.remove("pulse");
  void el.offsetWidth;
  el.classList.add("pulse");
}

/* ==================================================================
   Entry detail modal
   ================================================================== */
function openDetail(id){
  const entry = State.session.vault.entries.find(e=>e.id===id);
  if(!entry) return;
  recordUse(id);
  State.detailEntryId = id;
  renderDetail();
  document.getElementById("modal-detail").classList.remove("hidden");
}
function closeDetail(){ document.getElementById("modal-detail").classList.add("hidden"); State.detailEntryId=null; }

function copyFieldHTML(label, field, value, secret){
  if(!value) return "";
  const displayVal = secret ? maskValue(value) : esc(value);
  return `<div class="copy-field">
    <div class="copy-field-label">${esc(label)}</div>
    <div class="copy-field-row">
      <div class="copy-field-val" data-shown="${secret?'0':'1'}">${displayVal}</div>
      ${secret?`<button class="copy-field-btn" data-toggle-secret data-field="${field}">${ic.eye()}</button>`:''}
      <button class="copy-field-btn" data-copy data-field="${field}">${ic.copy()}</button>
    </div>
  </div>`;
}
function getFieldValue(entry, fieldKey){
  if(fieldKey.indexOf("custom:")===0){
    const cf = (entry.customFields||[]).find(c=>c.id===fieldKey.slice(7));
    return cf ? cf.value : "";
  }
  return entry[fieldKey];
}
function getFieldLabel(entry, fieldKey){
  if(fieldKey.indexOf("custom:")===0){
    const cf = (entry.customFields||[]).find(c=>c.id===fieldKey.slice(7));
    return cf ? (cf.label||t("field_custom_default")) : t("field_custom_default");
  }
  const keyMap = {website:"field_website",email:"field_email",username:"field_username",password:"field_password",pin:"field_pin"};
  return keyMap[fieldKey] ? t(keyMap[fieldKey]) : fieldKey;
}

function renderDetail(){
  const entry = State.session.vault.entries.find(e=>e.id===State.detailEntryId);
  if(!entry){ closeDetail(); return; }
  const counts = computePasswordCounts(State.session.vault.entries);
  const dup = entry.password && counts[entry.password]>1;
  const el = document.getElementById("detail-content");
  const visible = entry.visibleFields||DEFAULT_VISIBLE_FIELDS;
  let fieldsHtml = "";
  BUILTIN_FIELDS.forEach(f=>{
    if(visible.indexOf(f.key)===-1) return;
    if(f.key==="notes"){
      if(entry.notes) fieldsHtml += `<div class="copy-field"><div class="copy-field-label">${t("field_notes")}</div><div class="note-box">${esc(entry.notes)}</div></div>`;
      return;
    }
    fieldsHtml += copyFieldHTML(t(f.labelKey), f.key, entry[f.key], f.secret);
  });
  (entry.customFields||[]).forEach(cf=>{
    fieldsHtml += copyFieldHTML(cf.label||t("field_custom_default"), "custom:"+cf.id, cf.value, cf.secret);
  });
  el.innerHTML = `
    <div class="modal-head">
      <div>
        <div class="display-title small-title">${esc(entry.title)}</div>
        <div class="muted tiny" style="margin-top:4px;">${esc(entry.category)||t("no_category")}</div>
      </div>
      <div style="display:flex;gap:4px;">
        <button class="icon-btn" id="detail-fav">${ic.star(entry.favorite)}</button>
        <button class="icon-btn" id="detail-close">${ic.close()}</button>
      </div>
    </div>
    <div class="modal-body">
      ${dup?`<div class="warn-box">${ic.warn()} ${t("reuse_warning")}</div>`:""}
      <button class="btn full" id="detail-copy-all" style="display:flex;align-items:center;justify-content:center;gap:6px;margin-top:0;margin-bottom:14px;">${ic.copy()} ${t("copy_all_btn")}</button>
      ${fieldsHtml}
      ${entry.tags&&entry.tags.length? `<div class="chips" style="margin-top:12px;">${entry.tags.map(tg=>`<span class="chip static">${esc(tg)}</span>`).join("")}</div>`:""}
      <div class="meta-lines">
        <span>${t("created_label")} ${timeAgo(entry.createdAt)}</span>
        <span>${t("updated_label")} ${timeAgo(entry.updatedAt)}</span>
        <span>${t("last_used_label")} ${timeAgo(entry.lastUsedAt)} &middot; ${t("used_count_label")} ${entry.useCount||0}x</span>
      </div>
    </div>
    <div class="modal-foot">
      <button class="btn btn-danger" id="detail-delete" style="display:flex;align-items:center;gap:6px;">${ic.trash()} ${t("delete_btn")}</button>
      <button class="btn btn-primary full" id="detail-edit" style="display:flex;align-items:center;justify-content:center;gap:6px;">${ic.edit()} ${t("edit_btn")}</button>
    </div>
  `;
  document.getElementById("detail-fav").onclick = (e)=>{
    const btn = e.currentTarget;
    btn.innerHTML = ic.star(!entry.favorite);
    pulseIcon(btn);
    setTimeout(()=>{ toggleFavorite(entry.id); renderDetail(); }, 260);
  };
  document.getElementById("detail-close").onclick = closeDetail;
  document.getElementById("detail-delete").onclick = ()=>{ closeDetail(); deleteEntryWithUndo(entry.id); };
  document.getElementById("detail-edit").onclick = ()=>{ closeDetail(); openForm(entry); };
  document.getElementById("detail-copy-all").onclick = ()=>{ copyToClipboard(buildCopyAllText(entry), t("toast_all_copied_label")); };
  el.querySelectorAll("[data-toggle-secret]").forEach(btn=>{
    btn.onclick = ()=>{
      const field = btn.getAttribute("data-field");
      const row = btn.closest(".copy-field-row");
      const valEl = row.querySelector(".copy-field-val");
      const shown = valEl.getAttribute("data-shown")==="1";
      const val = getFieldValue(entry, field);
      if(shown){ valEl.textContent = maskValue(val); valEl.setAttribute("data-shown","0"); btn.innerHTML = ic.eye(); }
      else { valEl.textContent = val; valEl.setAttribute("data-shown","1"); btn.innerHTML = ic.eyeOff(); }
    };
  });
  el.querySelectorAll("[data-copy]").forEach(btn=>{
    btn.onclick = ()=>{
      const field = btn.getAttribute("data-field");
      copyToClipboard(getFieldValue(entry, field), getFieldLabel(entry, field));
    };
  });
}

/* ==================================================================
   Entry form modal (add / edit)
   ================================================================== */
function buildCategoryOptions(selected){
  return State.session.vault.categories.map(c=>`<option value="${esc(c)}" ${c===selected?'selected':''}>${esc(c)}</option>`).join("")
    + `<option value="" ${selected===""?'selected':''}>${t("no_category")}</option>`
    + `<option value="__new__">${t("new_category_option")}</option>`;
}
function openForm(entry){
  const isNew = !entry;
  const draft = entry ? Object.assign({}, entry, {
    tags:(entry.tags||[]).slice(),
    visibleFields:(entry.visibleFields||DEFAULT_VISIBLE_FIELDS).slice(),
    customFields:(entry.customFields||[]).map(cf=>Object.assign({},cf)),
  }) : {
    id: uid(), category: State.session.vault.categories[0]||"",
    title:"", website:"", email:"", username:"", password:"", pin:"", notes:"",
    tags: [], favorite:false, createdAt: Date.now(), updatedAt: Date.now(), lastUsedAt:null, useCount:0,
    visibleFields: DEFAULT_VISIBLE_FIELDS.slice(), customFields: [],
  };
  State.formDraft = draft;
  document.getElementById("form-title").textContent = isNew? t("add_data_title") : t("edit_data_title");
  document.getElementById("form-category").innerHTML = buildCategoryOptions(draft.category);
  document.getElementById("form-titlefield").value = draft.title;
  document.getElementById("form-favorite").checked = !!draft.favorite;
  renderFormFields();
  document.getElementById("add-field-menu").classList.add("hidden");
  renderFormTags();
  document.getElementById("modal-form").classList.remove("hidden");
  setTimeout(()=>document.getElementById("form-titlefield").focus(), 50);
}
function closeForm(){ document.getElementById("modal-form").classList.add("hidden"); State.formDraft=null; }

/* ---- dynamic field rows (builtin: removable / custom: free-form) ---- */
function builtinFieldRowHTML(f, value){
  const genBtn = f.generator ? `<button class="link-btn" id="form-gen-toggle" type="button">${t("generator_toggle")}</button>` : "";
  const eyeBtn = f.secret ? `<button class="link-btn" data-toggle-form-secret="${f.key}" type="button">${ic.eye()}</button>` : "";
  const inputHtml = f.type==="textarea"
    ? `<textarea class="input" data-field-input="${f.key}" rows="3">${esc(value)}</textarea>`
    : `<input class="input ${f.mono?'mono':''}" data-field-input="${f.key}" value="${esc(value)}" placeholder="${esc(f.placeholder||'')}" ${f.secret?'type="password" autocomplete="new-password"':''}>`;
  const strengthDiv = f.generator ? `<div id="form-strength" class="strength">${strengthHTML(value)}</div><div id="form-generator" class="generator hidden"></div>` : "";
  return `<div class="field" data-builtin-field="${f.key}">
    <div class="field-label-row">
      <div class="field-label">${t(f.labelKey)}</div>
      <div style="display:flex;gap:10px;align-items:center;">${genBtn}${eyeBtn}<button class="link-btn" data-remove-builtin="${f.key}" style="color:var(--danger);" type="button">${t("remove_field_btn")}</button></div>
    </div>
    ${inputHtml}
    ${strengthDiv}
  </div>`;
}
function customFieldRowHTML(cf){
  const eyeBtn = cf.secret ? `<button class="link-btn" data-toggle-custom-secret="${cf.id}" type="button">${ic.eye()}</button>` : "";
  return `<div class="field" data-custom-field="${cf.id}">
    <div class="field-label-row">
      <input class="input" data-custom-label="${cf.id}" value="${esc(cf.label)}" placeholder="${t("custom_field_name_placeholder")}" style="max-width:52%;font-size:12px;padding:6px 8px;">
      <div style="display:flex;gap:10px;align-items:center;">
        <label style="font-size:11px;display:flex;gap:4px;align-items:center;white-space:nowrap;"><input type="checkbox" data-custom-secret="${cf.id}" ${cf.secret?'checked':''}> ${t("sensitive_label")}</label>
        ${eyeBtn}
        <button class="link-btn" data-remove-custom="${cf.id}" style="color:var(--danger);" type="button">✕</button>
      </div>
    </div>
    <input class="input ${cf.secret?'mono':''}" type="${cf.secret?'password':'text'}" autocomplete="new-password" data-custom-value="${cf.id}" value="${esc(cf.value)}" placeholder="${t("custom_value_placeholder")}">
  </div>`;
}
function renderFormFields(){
  const draft = State.formDraft;
  const container = document.getElementById("form-fields-container");
  let html = "";
  BUILTIN_FIELDS.forEach(f=>{
    if(draft.visibleFields.indexOf(f.key)===-1) return;
    html += builtinFieldRowHTML(f, draft[f.key]||"");
  });
  draft.customFields.forEach(cf=>{ html += customFieldRowHTML(cf); });
  container.innerHTML = html;
  container.querySelectorAll("[data-field-input]").forEach(el=>{
    el.addEventListener("input",(e)=>{
      const key = el.getAttribute("data-field-input");
      draft[key] = e.target.value;
      if(key==="password"){
        const sEl = document.getElementById("form-strength");
        if(sEl) sEl.innerHTML = strengthHTML(e.target.value);
      }
    });
  });
  container.querySelectorAll("[data-remove-builtin]").forEach(btn=>{
    btn.addEventListener("click",()=>{
      const key = btn.getAttribute("data-remove-builtin");
      draft.visibleFields = draft.visibleFields.filter(k=>k!==key);
      renderFormFields();
    });
  });
  const genToggle = document.getElementById("form-gen-toggle");
  if(genToggle){
    genToggle.addEventListener("click",()=>{
      const panel = document.getElementById("form-generator");
      const willShow = panel.classList.contains("hidden");
      panel.classList.toggle("hidden");
      if(willShow){
        renderGenerator(panel, (val)=>{
          draft.password = val;
          const inputEl = container.querySelector('[data-field-input="password"]');
          if(inputEl) inputEl.value = val;
          const sEl = document.getElementById("form-strength");
          if(sEl) sEl.innerHTML = strengthHTML(val);
          panel.classList.add("hidden");
        });
      }
    });
  }
  container.querySelectorAll("[data-custom-label]").forEach(el=>{
    el.addEventListener("input",(e)=>{
      const cf = draft.customFields.find(c=>c.id===el.getAttribute("data-custom-label"));
      if(cf) cf.label = e.target.value;
    });
  });
  container.querySelectorAll("[data-custom-value]").forEach(el=>{
    el.addEventListener("input",(e)=>{
      const cf = draft.customFields.find(c=>c.id===el.getAttribute("data-custom-value"));
      if(cf) cf.value = e.target.value;
    });
  });
  container.querySelectorAll("[data-custom-secret]").forEach(el=>{
    el.addEventListener("change",(e)=>{
      const cf = draft.customFields.find(c=>c.id===el.getAttribute("data-custom-secret"));
      if(cf){ cf.secret = e.target.checked; renderFormFields(); }
    });
  });
  container.querySelectorAll("[data-remove-custom]").forEach(btn=>{
    btn.addEventListener("click",()=>{
      const id = btn.getAttribute("data-remove-custom");
      draft.customFields = draft.customFields.filter(c=>c.id!==id);
      renderFormFields();
    });
  });
  container.querySelectorAll("[data-toggle-form-secret]").forEach(btn=>{
    btn.addEventListener("click",()=>{
      const key = btn.getAttribute("data-toggle-form-secret");
      const input = container.querySelector(`[data-field-input="${key}"]`);
      if(!input) return;
      if(input.type==="password"){ input.type="text"; btn.innerHTML = ic.eyeOff(); }
      else { input.type="password"; btn.innerHTML = ic.eye(); }
    });
  });
  container.querySelectorAll("[data-toggle-custom-secret]").forEach(btn=>{
    btn.addEventListener("click",()=>{
      const id = btn.getAttribute("data-toggle-custom-secret");
      const input = container.querySelector(`[data-custom-value="${id}"]`);
      if(!input) return;
      if(input.type==="password"){ input.type="text"; btn.innerHTML = ic.eyeOff(); }
      else { input.type="password"; btn.innerHTML = ic.eye(); }
    });
  });
}
function renderAddFieldMenu(){
  const draft = State.formDraft;
  const hidden = BUILTIN_FIELDS.filter(f=>draft.visibleFields.indexOf(f.key)===-1);
  const menu = document.getElementById("add-field-menu");
  let html = "";
  if(hidden.length){
    html += `<div class="chips">${hidden.map(f=>`<span class="chip" data-add-builtin="${f.key}" style="cursor:pointer;">+ ${t(f.labelKey)}</span>`).join("")}</div>`;
  }
  html += `<button class="btn btn-primary full" id="add-custom-field-btn" style="font-size:13px;">${t("add_custom_field_btn")}</button>`;
  menu.innerHTML = html;
  menu.querySelectorAll("[data-add-builtin]").forEach(chip=>{
    chip.addEventListener("click",()=>{
      draft.visibleFields.push(chip.getAttribute("data-add-builtin"));
      renderFormFields();
      menu.classList.add("hidden");
    });
  });
  document.getElementById("add-custom-field-btn").addEventListener("click",()=>{
    draft.customFields.push({id:uid(), label:"", value:"", secret:false});
    renderFormFields();
    menu.classList.add("hidden");
  });
}
document.getElementById("add-field-btn").addEventListener("click",()=>{
  const menu = document.getElementById("add-field-menu");
  const willShow = menu.classList.contains("hidden");
  if(willShow) renderAddFieldMenu();
  menu.classList.toggle("hidden");
});

function renderFormTags(){
  const draft = State.formDraft;
  document.getElementById("form-tags-chips").innerHTML = draft.tags.map(tg=>
    `<span class="chip active">${esc(tg)} <span class="x" data-remove-tag="${esc(tg)}">✕</span></span>`
  ).join("");
  const suggestions = SUGGESTED_TAGS.filter(tg=>draft.tags.indexOf(tg)===-1);
  document.getElementById("form-tag-suggest").innerHTML = suggestions.map(tg=>
    `<span class="chip" data-add-tag="${esc(tg)}">+ ${esc(tg)}</span>`
  ).join("");
}
function addFormTag(tg){
  tg = (tg||"").trim();
  if(!tg || State.formDraft.tags.indexOf(tg)!==-1) return;
  State.formDraft.tags.push(tg);
  renderFormTags();
}
function renderGenerator(panel, onPick){
  const opts = {length:16, upper:true, lower:true, numbers:true, symbols:true};
  let val = generatePassword(opts);
  function draw(){
    panel.innerHTML = `
      <div class="gen-value">${esc(val)}</div>
      <div class="gen-slider-row"><input type="range" min="8" max="32" value="${opts.length}" id="gen-len-slider"><span class="gen-len">${opts.length}</span></div>
      <div class="gen-checks">
        <label><input type="checkbox" id="gen-upper" ${opts.upper?'checked':''}> A-Z</label>
        <label><input type="checkbox" id="gen-lower" ${opts.lower?'checked':''}> a-z</label>
        <label><input type="checkbox" id="gen-numbers" ${opts.numbers?'checked':''}> 0-9</label>
        <label><input type="checkbox" id="gen-symbols" ${opts.symbols?'checked':''}> !@#</label>
      </div>
      <div class="gen-actions">
        <button class="btn" id="gen-regen">${t("regenerate_btn")}</button>
        <button class="btn btn-primary" id="gen-use">${t("use_btn")}</button>
      </div>`;
    panel.querySelector("#gen-len-slider").addEventListener("input",(e)=>{ opts.length=+e.target.value; val=generatePassword(opts); draw(); });
    panel.querySelector("#gen-upper").addEventListener("change",(e)=>{ opts.upper=e.target.checked; val=generatePassword(opts); draw(); });
    panel.querySelector("#gen-lower").addEventListener("change",(e)=>{ opts.lower=e.target.checked; val=generatePassword(opts); draw(); });
    panel.querySelector("#gen-numbers").addEventListener("change",(e)=>{ opts.numbers=e.target.checked; val=generatePassword(opts); draw(); });
    panel.querySelector("#gen-symbols").addEventListener("change",(e)=>{ opts.symbols=e.target.checked; val=generatePassword(opts); draw(); });
    panel.querySelector("#gen-regen").addEventListener("click",()=>{ val=generatePassword(opts); draw(); });
    panel.querySelector("#gen-use").addEventListener("click",()=>{ onPick(val); });
  }
  draw();
}

document.getElementById("form-category").addEventListener("change",(e)=>{
  if(!State.formDraft) return;
  if(e.target.value==="__new__"){
    const name = window.prompt(t("new_category_prompt"));
    if(name && name.trim()){
      addCategory(name.trim());
      e.target.innerHTML = buildCategoryOptions(name.trim());
      State.formDraft.category = name.trim();
    } else {
      e.target.value = State.formDraft.category;
    }
  } else {
    State.formDraft.category = e.target.value;
  }
});
document.getElementById("form-tag-input").addEventListener("keydown",(e)=>{
  if(e.key==="Enter"){ e.preventDefault(); addFormTag(e.target.value); e.target.value=""; }
});
document.getElementById("form-tags-chips").addEventListener("click",(e)=>{
  const rem = e.target.closest("[data-remove-tag]");
  if(rem){ const t = rem.getAttribute("data-remove-tag"); State.formDraft.tags = State.formDraft.tags.filter(x=>x!==t); renderFormTags(); }
});
document.getElementById("form-tag-suggest").addEventListener("click",(e)=>{
  const add = e.target.closest("[data-add-tag]");
  if(add) addFormTag(add.getAttribute("data-add-tag"));
});
document.getElementById("form-close").addEventListener("click", closeForm);
document.getElementById("form-cancel").addEventListener("click", closeForm);
document.getElementById("form-save").addEventListener("click", ()=>{
  const d = State.formDraft;
  if(!d) return;
  d.title = document.getElementById("form-titlefield").value.trim();
  if(!d.title){ document.getElementById("form-titlefield").focus(); return; }
  d.category = document.getElementById("form-category").value;
  if(d.category==="__new__") d.category = State.session.vault.categories[0]||"";
  d.favorite = document.getElementById("form-favorite").checked;
  d.customFields = d.customFields.filter(cf=>cf.label.trim() || cf.value.trim());
  d.updatedAt = Date.now();
  saveEntry(d);
  closeForm();
});

/* ==================================================================
   Settings modal
   ================================================================== */
function openSettings(){ renderSettings(); document.getElementById("modal-settings").classList.remove("hidden"); }
function closeSettings(){ document.getElementById("modal-settings").classList.add("hidden"); }

function renderSettings(){
  const s = State.settings;
  const slot = State.session.slot;
  const el = document.getElementById("settings-content");
  el.innerHTML = `
    <div class="modal-head"><div class="display-title small-title">${t("settings_title")}</div><button class="icon-btn" id="settings-close">${ic.close()}</button></div>
    <div class="modal-body">
      <div class="settings-row"><div><div class="settings-row-label">${t("theme_label")}</div><div class="settings-row-sub">${t("theme_sub")}</div></div><button class="btn settings-toggle-btn" id="settings-theme">${s.theme==="dark"?t("theme_dark"):t("theme_light")}</button></div>
      <div class="settings-row"><div><div class="settings-row-label">${t("language_label")}</div><div class="settings-row-sub">${t("language_sub")}</div></div>
        <select class="input settings-select" id="settings-lang">
          <option value="id" ${s.lang==="id"?'selected':''}>Bahasa Indonesia</option>
          <option value="en" ${s.lang==="en"?'selected':''}>English</option>
          <option value="zh" ${s.lang==="zh"?'selected':''}>中文</option>
        </select></div>
      <div class="settings-row"><div><div class="settings-row-label">${t("autolock_label")}</div><div class="settings-row-sub">${t("autolock_sub")}</div></div>
        <select class="input settings-select" id="settings-autolock">${[1,2,5,10,15,30].map(m=>`<option value="${m}" ${s.autoLockMin===m?'selected':''}>${m} ${t("minute_suffix")}</option>`).join("")}</select></div>
      <div class="settings-row"><div><div class="settings-row-label">${t("clipboard_label")}</div><div class="settings-row-sub">${t("clipboard_sub")}</div></div>
        <select class="input settings-select" id="settings-clipboard">${[15,30,45,60].map(sec=>`<option value="${sec}" ${s.clipboardSec===sec?'selected':''}>${sec} ${t("second_suffix")}</option>`).join("")}</select></div>

      <div class="settings-heading">${t("manage_categories_heading")}</div>
      <div id="category-manage-list"></div>

      <div class="settings-heading">${t("change_master_password_heading")}</div>
      <input class="input" type="password" placeholder="${t("current_master_password_placeholder")}" id="mp-old" style="margin-bottom:8px;">
      <input class="input" type="password" placeholder="${t("new_master_password_placeholder")}" id="mp-new">
      <div class="err" id="mp-err"></div>
      <button class="btn full" id="mp-submit">${t("change_password_btn")}</button>

      ${slot!=="decoy" ? `
      <div class="settings-heading">${t("decoy_mode_heading")}</div>
      <div class="settings-row"><div><div class="settings-row-label">${t("decoy_toggle_label")}</div><div class="settings-row-sub">${t("decoy_toggle_sub")}</div></div>
        <input type="checkbox" id="settings-decoy-toggle" ${s.hasDecoy?'checked':''}></div>
      <div id="decoy-area" style="margin-bottom:14px;">${s.hasDecoy ? `<button class="btn full" id="decoy-change-btn">${t("change_decoy_btn")}</button>` : ""}</div>
      ` : ""}

      <div class="settings-heading">${t("stealth_mode_heading")}</div>
      <div class="settings-row"><div><div class="settings-row-label">${t("stealth_toggle_label")}</div><div class="settings-row-sub">${t("stealth_toggle_sub")}</div></div>
        <input type="checkbox" id="settings-stealth" ${s.stealthEnabled?'checked':''}></div>
      <div id="stealth-pin-area" class="${s.stealthEnabled?'':'hidden'}" style="margin-bottom:14px;">
        <input class="input mono" placeholder="${t("stealth_pin_placeholder")}" id="settings-stealth-pin" value="${esc(s.stealthPin)}">
        <div class="settings-row-sub">${t("stealth_pin_note")}</div>
      </div>

      <div class="settings-heading">${t("backup_restore_heading")}</div>
      <div style="display:flex;gap:8px;margin-bottom:8px;">
        <button class="btn" id="settings-export" style="flex:1;display:flex;align-items:center;justify-content:center;gap:6px;">${ic.download()} ${t("export_btn")}</button>
        <button class="btn" id="settings-import-btn" style="flex:1;display:flex;align-items:center;justify-content:center;gap:6px;">${ic.upload()} ${t("import_btn")}</button>
      </div>
      <div style="display:flex;gap:8px;margin-bottom:4px;">
        <button class="btn" id="settings-share" style="flex:1;display:flex;align-items:center;justify-content:center;gap:6px;">${ic.share()} ${t("share_btn")}</button>
        <button class="btn" id="settings-email" style="flex:1;display:flex;align-items:center;justify-content:center;gap:6px;">${ic.mail()} ${t("email_btn")}</button>
      </div>
      <div class="settings-row-sub" style="margin-bottom:14px;">${t("backup_note")}</div>
      <input type="file" id="settings-import-file" accept=".gpvault,application/json" class="hidden">

      <div class="settings-note">${ic.shieldCheck()} <span>${t("native_note")}</span></div>

      <div class="settings-heading">${t("danger_zone_heading")}</div>
      <button class="btn full" id="settings-open-landing" style="margin-bottom:8px;">${ic.share()} ${t("about_app_btn")}</button>
      <button class="btn full btn-danger" id="settings-panic-reset" style="border-color:var(--danger);">${ic.warn()} ${t("panic_reset_btn")}</button>
    </div>`;
  document.getElementById("settings-close").onclick = closeSettings;
  renderCategoryManageList();
  document.getElementById("settings-theme").onclick = ()=>{ persistSettings(Object.assign({},State.settings,{theme:State.settings.theme==="dark"?"light":"dark"})); applyTheme(); renderSettings(); };
  document.getElementById("settings-lang").onchange = (e)=>{ persistSettings(Object.assign({},State.settings,{lang:e.target.value})); refreshUILanguage(); };
  document.getElementById("settings-autolock").onchange = (e)=>{ persistSettings(Object.assign({},State.settings,{autoLockMin:+e.target.value})); };
  document.getElementById("settings-clipboard").onchange = (e)=>{ persistSettings(Object.assign({},State.settings,{clipboardSec:+e.target.value})); };
  document.getElementById("mp-submit").onclick = async ()=>{
    const oldPw = document.getElementById("mp-old").value;
    const newPw = document.getElementById("mp-new").value;
    const errEl = document.getElementById("mp-err");
    errEl.textContent="";
    if(newPw.length<8){ errEl.textContent=t("err_new_password_min"); return; }
    const ok = await changeMasterPassword(oldPw,newPw);
    if(!ok) errEl.textContent=t("err_old_password_wrong");
    else { document.getElementById("mp-old").value=""; document.getElementById("mp-new").value=""; showToast(t("toast_password_changed")); }
  };
  const decoyToggle = document.getElementById("settings-decoy-toggle");
  if(decoyToggle){
    decoyToggle.onchange = async (e)=>{
      if(e.target.checked){
        document.getElementById("decoy-area").innerHTML = `
          <input class="input" type="password" placeholder="${t("decoy_password_placeholder")}" id="decoy-pw">
          <div class="err" id="decoy-err"></div>
          <button class="btn btn-primary full" id="decoy-submit">${t("save_decoy_btn")}</button>`;
        document.getElementById("decoy-submit").onclick = async ()=>{
          const pw = document.getElementById("decoy-pw").value;
          const errEl = document.getElementById("decoy-err");
          if(pw.length<8){ errEl.textContent=t("err_decoy_min"); return; }
          try{ await setupDecoy(pw); renderSettings(); showToast(t("toast_decoy_created")); }
          catch(e2){ errEl.textContent=t("err_decoy_failed"); }
        };
      } else {
        if(confirm(t("confirm_disable_decoy"))){
          await disableDecoy();
          renderSettings();
        } else {
          e.target.checked = true;
        }
      }
    };
  }
  const decoyChangeBtn = document.getElementById("decoy-change-btn");
  if(decoyChangeBtn){
    decoyChangeBtn.onclick = ()=>{
      document.getElementById("decoy-area").innerHTML = `
        <input class="input" type="password" placeholder="${t("new_decoy_password_placeholder")}" id="decoy-pw-change">
        <div class="err" id="decoy-change-err"></div>
        <button class="btn btn-primary full" id="decoy-change-submit">${t("save_decoy_btn")}</button>`;
      document.getElementById("decoy-change-submit").onclick = async ()=>{
        const pw = document.getElementById("decoy-pw-change").value;
        const errEl = document.getElementById("decoy-change-err");
        if(pw.length<8){ errEl.textContent=t("err_decoy_min"); return; }
        try{ await setupDecoy(pw); renderSettings(); showToast(t("toast_decoy_changed")); }
        catch(e2){ errEl.textContent=t("err_decoy_failed"); }
      };
    };
  }
  document.getElementById("settings-open-landing").onclick = ()=>{ window.location.href = "landing.html"; };
  document.getElementById("settings-panic-reset").onclick = openPanicReset;
  document.getElementById("settings-stealth").onchange = (e)=>{
    persistSettings(Object.assign({},State.settings,{stealthEnabled:e.target.checked}));
    document.getElementById("stealth-pin-area").classList.toggle("hidden", !e.target.checked);
  };
  document.getElementById("settings-stealth-pin").oninput = (e)=>{ e.target.value = e.target.value.replace(/\D/g,"").slice(0,8); };
  document.getElementById("settings-stealth-pin").onblur = (e)=>{ persistSettings(Object.assign({},State.settings,{stealthPin:e.target.value})); };
  document.getElementById("settings-export").onclick = exportBackup;
  document.getElementById("settings-import-btn").onclick = ()=>document.getElementById("settings-import-file").click();
  document.getElementById("settings-import-file").onchange = (e)=>{ const f=e.target.files[0]; if(f) importBackup(f, State.session.slot); };
  document.getElementById("settings-share").onclick = shareBackup;
  document.getElementById("settings-email").onclick = emailBackup;
}

function countEntriesInCategory(name){
  return State.session.vault.entries.filter(e=>e.category===name).length;
}
function deleteCategoryEntries(name){
  State.session.vault.entries = State.session.vault.entries.filter(e=>e.category!==name);
  State.session.vault.categories = State.session.vault.categories.filter(c=>c!==name);
  scheduleSave(); renderEntryList(); renderSidebar(); renderCategoryManageList();
  showToast(t("toast_category_deleted", {name}));
}
function moveCategoryEntriesToNone(name){
  State.session.vault.entries = State.session.vault.entries.map(e=> e.category===name ? Object.assign({},e,{category:""}) : e);
  State.session.vault.categories = State.session.vault.categories.filter(c=>c!==name);
  scheduleSave(); renderEntryList(); renderSidebar(); renderCategoryManageList();
  showToast(t("toast_category_moved", {name}));
}
function renderCategoryManageList(){
  const list = document.getElementById("category-manage-list");
  if(!list) return;
  const cats = State.session.vault.categories;
  if(cats.length===0){ list.innerHTML = `<div class="settings-row-sub">${t("no_categories_yet")}</div>`; return; }
  list.innerHTML = cats.map(c=>{
    const count = countEntriesInCategory(c);
    return `<div class="cat-manage-row" data-cat-row="${esc(c)}">
      <div class="cat-manage-info"><span class="sb-dot"></span> ${esc(c)} <span class="muted tiny">(${count})</span></div>
      <button class="icon-btn" data-delete-cat="${esc(c)}" style="color:var(--danger);">${ic.trash()}</button>
    </div>`;
  }).join("");
  list.querySelectorAll("[data-delete-cat]").forEach(btn=>{
    btn.addEventListener("click",()=>{
      const name = btn.getAttribute("data-delete-cat");
      const count = countEntriesInCategory(name);
      const row = list.querySelector(`[data-cat-row="${CSS.escape(name)}"]`);
      if(count===0){
        deleteCategoryEntries(name);
        return;
      }
      row.innerHTML = `
        <div style="width:100%;">
          <div class="settings-row-sub" style="margin-bottom:8px;">${t("delete_category_confirm",{name,count})}</div>
          <div style="display:flex;flex-direction:column;gap:6px;">
            <button class="btn" data-move-cat="${esc(name)}" style="font-size:12px;">${t("move_category_btn")}</button>
            <button class="btn btn-danger" data-remove-cat="${esc(name)}" style="font-size:12px;">${t("delete_category_with_data_btn")}</button>
            <button class="btn" data-cancel-cat style="font-size:12px;background:none;">${t("cancel_btn")}</button>
          </div>
        </div>`;
      row.querySelector("[data-move-cat]").onclick = ()=>moveCategoryEntriesToNone(name);
      row.querySelector("[data-remove-cat]").onclick = ()=>{ if(confirm(t("confirm_delete_category_data",{name,count}))) deleteCategoryEntries(name); };
      row.querySelector("[data-cancel-cat]").onclick = ()=>renderCategoryManageList();
    });
  });
}

/* ==================================================================
   Panic Reset — wipes everything (real vault, decoy vault, settings)
   and returns the app to a fresh Setup state. Requires the current
   Master Password entered twice, with a stark warning each time.
   ================================================================== */
function openPanicReset(){
  State.panicStep = 1;
  renderPanicReset();
  document.getElementById("modal-panic").classList.remove("hidden");
}
function closePanicReset(){
  document.getElementById("modal-panic").classList.add("hidden");
  State.panicStep = null;
}
function renderPanicReset(){
  const el = document.getElementById("panic-content");
  if(State.panicStep === 1){
    el.innerHTML = `
      <div class="modal-head">
        <div class="display-title small-title" style="color:var(--danger);">${ic.warn()} ${t("panic_title")}</div>
        <button class="icon-btn" id="panic-close">${ic.close()}</button>
      </div>
      <div class="modal-body">
        <div class="warn-box" style="margin-bottom:16px;line-height:1.6;">${ic.warn()} ${t("panic_warning_1")}</div>
        <div class="field">
          <div class="field-label">${t("panic_enter_password")}</div>
          <input class="input" type="password" id="panic-pw-1" autocomplete="current-password">
        </div>
        <div class="err" id="panic-err-1"></div>
      </div>
      <div class="modal-foot">
        <button class="btn full" id="panic-cancel-1">${t("cancel_btn")}</button>
        <button class="btn btn-danger full" id="panic-next">${t("panic_continue_btn")}</button>
      </div>`;
    document.getElementById("panic-close").onclick = closePanicReset;
    document.getElementById("panic-cancel-1").onclick = closePanicReset;
    document.getElementById("panic-next").onclick = async ()=>{
      const pw = document.getElementById("panic-pw-1").value;
      const errEl = document.getElementById("panic-err-1");
      const check = await trySlot(State.session.slot, pw);
      if(!check){ errEl.textContent = t("err_wrong_password"); return; }
      State.panicStep = 2;
      renderPanicReset();
    };
  } else if(State.panicStep === 2){
    el.innerHTML = `
      <div class="modal-head">
        <div class="display-title small-title" style="color:var(--danger);">${ic.warn()} ${t("panic_title")}</div>
        <button class="icon-btn" id="panic-close">${ic.close()}</button>
      </div>
      <div class="modal-body">
        <div class="warn-box" style="margin-bottom:16px;line-height:1.6;">${ic.warn()} ${t("panic_warning_2")}</div>
        <div class="field">
          <div class="field-label">${t("panic_confirm_password")}</div>
          <input class="input" type="password" id="panic-pw-2" autocomplete="current-password">
        </div>
        <div class="err" id="panic-err-2"></div>
      </div>
      <div class="modal-foot">
        <button class="btn full" id="panic-cancel-2">${t("cancel_btn")}</button>
        <button class="btn btn-danger full" id="panic-execute">${t("panic_execute_btn")}</button>
      </div>`;
    document.getElementById("panic-close").onclick = closePanicReset;
    document.getElementById("panic-cancel-2").onclick = closePanicReset;
    document.getElementById("panic-execute").onclick = async ()=>{
      const pw = document.getElementById("panic-pw-2").value;
      const errEl = document.getElementById("panic-err-2");
      const check = await trySlot(State.session.slot, pw);
      if(!check){ errEl.textContent = t("err_wrong_password"); return; }
      await executePanicReset();
    };
  }
}
async function executePanicReset(){
  try{ await idbDelete("geopass-real"); }catch(e){ /* ignore */ }
  try{ await idbDelete("geopass-decoy"); }catch(e){ /* ignore */ }
  try{ await idbDelete("geopass-settings"); }catch(e){ /* ignore */ }
  clearTimeout(idleTimer); clearTimeout(saveTimer); clearTimeout(clipboardTimer); clearTimeout(toastTimer);
  State.session = null;
  State.settings = Object.assign({}, DEFAULT_SETTINGS);
  State.view = { searchQ:"", filterCat:null, filterTag:null, filterFav:false, filterRecent:false };
  State.detailEntryId = null;
  State.formDraft = null;
  closePanicReset();
  applyTheme();
  applyStaticI18n();
  goStage("setup");
  showToast(t("toast_panic_done"));
}

/* ==================================================================
   Auto-lock (idle + tab hidden) & panic shortcut
   ================================================================== */
const AUTO_LOCK_EVENTS = ["mousemove","keydown","click","touchstart","scroll"];
function resetIdleTimer(){
  if(State.stage!=="unlocked") return;
  clearTimeout(idleTimer);
  idleTimer = setTimeout(()=>{ lockVault(); }, State.settings.autoLockMin*60*1000);
}
function onVisibilityChange(){ if(document.hidden && State.stage==="unlocked") lockVault(); }
function setupAutoLock(){
  resetIdleTimer();
  if(!autoLockBound){
    AUTO_LOCK_EVENTS.forEach(ev=>window.addEventListener(ev, resetIdleTimer));
    document.addEventListener("visibilitychange", onVisibilityChange);
    autoLockBound = true;
  }
}
window.addEventListener("keydown",(e)=>{
  if((e.ctrlKey||e.metaKey) && e.shiftKey && e.key.toLowerCase()==="l"){
    if(State.stage==="unlocked") lockVault();
  }
});

/* ==================================================================
   Stealth calculator
   ================================================================== */
function fmtNum(n){
  if(!isFinite(n)) return "Error";
  const rounded = Math.round(n*1e10)/1e10;
  return String(rounded);
}
function opSymbol(op){ return {"+":"+","-":"−","*":"×","/":"÷"}[op] || op; }
function resetCalc(){
  State.calc.display = "0"; State.calc.pinBuffer=""; State.calc.acc=null; State.calc.op=null; State.calc.expr=""; State.calc.justEvaluated=false;
  const d = document.getElementById("calc-display"); if(d) d.textContent = "0";
  const ex = document.getElementById("calc-expr"); if(ex) ex.textContent = "";
  const panel = document.getElementById("calc-history-panel"); if(panel) panel.classList.add("hidden");
}
function exitStealth(){ goStage(State.session ? "unlocked" : "locked"); }
function renderCalcHistory(){
  const list = document.getElementById("calc-history-list");
  if(!list) return;
  if(!State.calc.history.length){ list.innerHTML = `<div class="muted tiny" style="padding:20px 4px;text-align:center;">${t("no_history_yet")}</div>`; return; }
  list.innerHTML = State.calc.history.map(h=>`<div class="calc-history-item">${esc(h)}</div>`).join("");
}
function handleCalcKey(k){
  const c = State.calc;
  const disp = document.getElementById("calc-display");
  const exprEl = document.getElementById("calc-expr");
  if(k==="C"){ resetCalc(); return; }
  if(k==="DEL"){
    c.display = c.display.length>1 ? c.display.slice(0,-1) : "0";
    c.pinBuffer = c.pinBuffer.slice(0,-1);
    disp.textContent = c.display;
    return;
  }
  if(k==="="){
    if(c.pinBuffer && State.settings.stealthPin && c.pinBuffer.indexOf(State.settings.stealthPin)!==-1){
      resetCalc(); exitStealth(); return;
    }
    if(c.acc!==null && c.op){
      const cur = parseFloat(c.display);
      let res = cur;
      if(c.op==="+") res = c.acc+cur;
      if(c.op==="-") res = c.acc-cur;
      if(c.op==="*") res = c.acc*cur;
      if(c.op==="/") res = cur!==0? c.acc/cur : NaN;
      const resStr = fmtNum(res);
      c.history.unshift(`${fmtNum(c.acc)} ${opSymbol(c.op)} ${fmtNum(cur)} = ${resStr}`);
      if(c.history.length>50) c.history.pop();
      c.display = resStr;
      exprEl.textContent = "";
    }
    c.acc=null; c.op=null; c.pinBuffer=""; c.justEvaluated=true;
    disp.textContent = c.display;
    return;
  }
  if(k==="+"||k==="-"||k==="*"||k==="/"){
    if(c.display==="Error"){ resetCalc(); }
    c.justEvaluated=false;
    if(c.acc!==null && c.op){
      const cur = parseFloat(c.display);
      let res = cur;
      if(c.op==="+") res=c.acc+cur;
      if(c.op==="-") res=c.acc-cur;
      if(c.op==="*") res=c.acc*cur;
      if(c.op==="/") res=cur!==0?c.acc/cur:NaN;
      c.acc = res;
    } else {
      c.acc = parseFloat(c.display);
    }
    c.op = k;
    c.display = "0";
    exprEl.textContent = `${fmtNum(c.acc)} ${opSymbol(k)}`;
    disp.textContent = c.display;
    return;
  }
  if(k==="."){
    if(c.justEvaluated){ c.display="0"; c.justEvaluated=false; }
    if(c.display.indexOf(".")===-1) c.display += ".";
    disp.textContent = c.display;
    return;
  }
  if(c.justEvaluated){ c.display="0"; c.justEvaluated=false; }
  c.pinBuffer = (c.pinBuffer + k).slice(-12);
  c.display = (c.display==="0"||c.display==="Error") ? k : c.display+k;
  disp.textContent = c.display;
}
document.querySelectorAll("[data-calc]").forEach(btn=>{
  btn.addEventListener("click", ()=>handleCalcKey(btn.getAttribute("data-calc")));
});
document.getElementById("calc-history-btn").addEventListener("click", ()=>{
  renderCalcHistory();
  document.getElementById("calc-history-panel").classList.remove("hidden");
});
document.getElementById("calc-history-close").addEventListener("click", ()=>{
  document.getElementById("calc-history-panel").classList.add("hidden");
});
document.getElementById("calc-history-clear").addEventListener("click", ()=>{
  State.calc.history = [];
  renderCalcHistory();
});

/* ==================================================================
   Sidebar / topbar static bindings
   ================================================================== */
function openSidebarPanel(){
  document.getElementById("sidebar").classList.remove("hidden");
  if(window.innerWidth<=680) document.getElementById("sidebar-backdrop").classList.remove("hidden");
}
function closeSidebarPanel(){
  document.getElementById("sidebar").classList.add("hidden");
  document.getElementById("sidebar-backdrop").classList.add("hidden");
}
document.getElementById("sidebar").addEventListener("click",(e)=>{
  const quickBtn = e.target.closest("[data-quick]");
  const catBtn = e.target.closest("[data-cat]");
  const tagEl = e.target.closest("[data-tag]");
  if(quickBtn){
    const q = quickBtn.getAttribute("data-quick");
    State.view.filterFav = q==="fav"; State.view.filterRecent = q==="recent";
    State.view.filterCat=null; State.view.filterTag=null;
    renderSidebar(); renderEntryList();
  } else if(catBtn){
    const c = catBtn.getAttribute("data-cat");
    State.view.filterCat = State.view.filterCat===c? null : c;
    State.view.filterFav=false; State.view.filterTag=null; State.view.filterRecent=false;
    renderSidebar(); renderEntryList();
  } else if(tagEl){
    const t = tagEl.getAttribute("data-tag");
    State.view.filterTag = State.view.filterTag===t? null : t;
    State.view.filterCat=null; State.view.filterFav=false; State.view.filterRecent=false;
    renderSidebar(); renderEntryList();
  } else {
    return;
  }
  if(window.innerWidth<=680) closeSidebarPanel();
});
document.getElementById("sb-settings-btn").addEventListener("click", openSettings);
document.getElementById("sb-lock-btn").addEventListener("click", lockVault);
document.getElementById("sidebar-close-btn").addEventListener("click", closeSidebarPanel);
document.getElementById("sidebar-backdrop").addEventListener("click", closeSidebarPanel);
document.getElementById("menu-btn").addEventListener("click", ()=>{
  const isHidden = document.getElementById("sidebar").classList.contains("hidden");
  if(isHidden) openSidebarPanel(); else closeSidebarPanel();
});
document.getElementById("search-input").addEventListener("input",(e)=>{ State.view.searchQ = e.target.value; renderEntryList(); });
document.getElementById("add-btn").addEventListener("click", ()=>openForm(null));

/* ==================================================================
   Modal backdrop click-to-close
   ================================================================== */
document.getElementById("modal-detail").addEventListener("mousedown",(e)=>{ if(e.target===e.currentTarget) closeDetail(); });
document.getElementById("modal-form").addEventListener("mousedown",(e)=>{ if(e.target===e.currentTarget) closeForm(); });
document.getElementById("modal-settings").addEventListener("mousedown",(e)=>{ if(e.target===e.currentTarget) closeSettings(); });
document.getElementById("modal-panic").addEventListener("mousedown",(e)=>{ if(e.target===e.currentTarget) closePanicReset(); });

/* ==================================================================
   Setup screen bindings
   ================================================================== */
document.getElementById("setup-pw").addEventListener("input",(e)=>{
  document.getElementById("setup-strength").innerHTML = strengthHTML(e.target.value);
});
document.getElementById("setup-submit").addEventListener("click", async ()=>{
  const pw = document.getElementById("setup-pw").value;
  const confirmPw = document.getElementById("setup-confirm").value;
  const errEl = document.getElementById("setup-err");
  errEl.textContent="";
  if(pw.length<8){ errEl.textContent=t("err_master_min"); return; }
  if(pw!==confirmPw){ errEl.textContent=t("err_confirm_mismatch"); return; }
  const btn = document.getElementById("setup-submit");
  btn.disabled=true; btn.textContent=t("creating_vault");
  try{ await handleSetup(pw); }
  catch(e){ errEl.textContent=t("err_create_vault_failed"); btn.disabled=false; btn.textContent=t("create_vault_btn"); }
});
document.getElementById("setup-import-btn").addEventListener("click", ()=>document.getElementById("setup-import-file").click());
document.getElementById("setup-import-file").addEventListener("change",(e)=>{ const f=e.target.files[0]; if(f) importBackup(f,"real"); });

/* ==================================================================
   Lock screen bindings
   ================================================================== */
async function doUnlock(){
  const pw = document.getElementById("lock-pw").value;
  const errEl = document.getElementById("lock-err");
  const btn = document.getElementById("lock-submit");
  errEl.textContent=""; btn.disabled=true;
  const ok = await handleUnlock(pw);
  btn.disabled=false;
  document.getElementById("lock-pw").value="";
  if(!ok) errEl.textContent=t("err_wrong_password");
}
document.getElementById("lock-submit").addEventListener("click", doUnlock);
document.getElementById("lock-pw").addEventListener("keydown",(e)=>{ if(e.key==="Enter") doUnlock(); });
document.getElementById("lock-import-btn").addEventListener("click", ()=>document.getElementById("lock-import-file").click());
document.getElementById("lock-import-file").addEventListener("change",(e)=>{ const f=e.target.files[0]; if(f) importBackup(f,"real"); });

/* ==================================================================
   Lock-screen dial decoration
   ================================================================== */
function drawDial(){
  const svg = document.querySelector(".dial");
  if(!svg) return;
  let html = `<circle cx="75" cy="75" r="68" fill="none" stroke="var(--border)" stroke-width="1.5"/>`;
  for(let i=0;i<24;i++){
    const a = (i/24)*Math.PI*2;
    const r1=68, r2 = i%6===0?58:63;
    const x1=(75+r1*Math.cos(a)).toFixed(2), y1=(75+r1*Math.sin(a)).toFixed(2);
    const x2=(75+r2*Math.cos(a)).toFixed(2), y2=(75+r2*Math.sin(a)).toFixed(2);
    html += `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="var(--accent)" stroke-width="1.5" opacity="0.6"/>`;
  }
  svg.innerHTML = html;
}

/* ==================================================================
   i18n application (static HTML text + live re-render of dynamic views)
   ================================================================== */
function applyStaticI18n(){
  document.querySelectorAll("[data-i18n]").forEach(el=>{
    const key = el.getAttribute("data-i18n");
    el.innerHTML = t(key);
  });
  document.querySelectorAll("[data-i18n-placeholder]").forEach(el=>{
    const key = el.getAttribute("data-i18n-placeholder");
    el.placeholder = t(key);
  });
  document.title = State.stage==="stealth" ? t("calculator_label") : t("app_name");
}
function refreshUILanguage(){
  applyStaticI18n();
  if(State.stage==="unlocked" && State.session){
    renderSidebar();
    renderEntryList();
    if(State.detailEntryId) renderDetail();
    if(!document.getElementById("modal-form").classList.contains("hidden") && State.formDraft){
      renderFormFields();
    }
    if(!document.getElementById("modal-settings").classList.contains("hidden")){
      renderSettings();
    }
  }
}

/* ==================================================================
   Bootstrap
   ================================================================== */
async function init(){
  drawDial();
  let loaded = Object.assign({}, DEFAULT_SETTINGS);
  try{ const s = await idbGet("geopass-settings"); if(s) loaded = Object.assign({}, DEFAULT_SETTINGS, s); }catch(e){ /* first run */ }
  State.settings = loaded;
  applyTheme();
  applyStaticI18n();
  let hasReal=false;
  try{ const r = await idbGet("geopass-real"); hasReal=!!r; }catch(e){ hasReal=false; }
  if(loaded.stealthEnabled) goStage("stealth");
  else if(!hasReal) goStage("setup");
  else goStage("locked");

  if("serviceWorker" in navigator){
    navigator.serviceWorker.register("sw.js").catch(()=>{});
  }
}
init();
