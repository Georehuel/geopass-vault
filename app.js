'use strict';

/* ==================================================================
   Constants
   ================================================================== */
const DEFAULT_CATEGORIES = ["Website","Sosial Media","Bank","Keuangan","Server","Pekerjaan","Pribadi","Lisensi","API","WiFi"];
const SUGGESTED_TAGS = ["Penting","Kerja","Pribadi","2FA","Lama","Baru"];
const TEMPLATES = [
  {id:"website",label:"Website",category:"Website"},
  {id:"email",label:"Email",category:"Pribadi"},
  {id:"social",label:"Media Sosial",category:"Sosial Media"},
  {id:"banking",label:"Internet Banking",category:"Bank"},
  {id:"ewallet",label:"E-Wallet",category:"Keuangan"},
  {id:"vps",label:"Server VPS",category:"Server"},
  {id:"apikey",label:"API Key",category:"API"},
  {id:"license",label:"Lisensi Software",category:"Lisensi"},
  {id:"wifi",label:"WiFi",category:"WiFi"},
  {id:"document",label:"Dokumen",category:"Pekerjaan"},
  {id:"note",label:"Catatan Bebas",category:"Pribadi"},
];
const DEFAULT_SETTINGS = { theme:"dark", autoLockMin:5, clipboardSec:30, stealthEnabled:false, stealthPin:"", hasDecoy:false };
const PBKDF2_ITER = 210000;
const VERIFY_TAG = "geopass-verify-v1";

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
  if(entropy<28) return {label:"Lemah",score:1};
  if(entropy<45) return {label:"Sedang",score:2};
  if(entropy<65) return {label:"Kuat",score:3};
  return {label:"Sangat Kuat",score:4};
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
};

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
  calc: { display:"0", pinBuffer:"", acc:null, op:null },
};
let toastTimer=null, clipboardTimer=null, idleTimer=null, saveTimer=null, autoLockBound=false;

/* ==================================================================
   Screen management
   ================================================================== */
function goStage(stage){
  State.stage = stage;
  ["loading","stealth","setup","locked","unlocked"].forEach(s=>{
    document.getElementById("screen-"+s).classList.toggle("hidden", s!==stage);
  });
  if(stage==="unlocked"){
    document.getElementById("sidebar").classList.remove("hidden");
    renderSidebar();
    renderEntryList();
    setupAutoLock();
  } else {
    clearTimeout(idleTimer);
  }
  if(stage==="stealth") resetCalc();
}

function applyTheme(){
  const appEl = document.getElementById("app");
  appEl.classList.remove("dark","light");
  appEl.classList.add(State.settings.theme);
}

function showToast(msg){
  const t = document.getElementById("toast");
  t.textContent = msg;
  t.classList.remove("hidden");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(()=>t.classList.add("hidden"), 2200);
}

/* ==================================================================
   Settings persistence
   ================================================================== */
async function persistSettings(next){
  State.settings = next;
  try{ await idbSet("geopass-settings", next); }catch(e){ showToast("Gagal menyimpan pengaturan"); }
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
  showToast("Vault berhasil dibuat");
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
    showToast("Backup diunduh");
  }catch(e){ showToast("Gagal membuat backup"); }
}
function importBackup(file, slot){
  const reader = new FileReader();
  reader.onload = async ()=>{
    try{
      const parsed = JSON.parse(reader.result);
      if(!parsed.salt || !parsed.verify || !parsed.vault) throw new Error("invalid");
      await idbSet(`geopass-${slot||"real"}`, parsed);
      showToast("Backup dipulihkan — silakan buka vault");
      if(State.stage!=="unlocked") goStage("locked");
    }catch(e){ showToast("File backup tidak valid"); }
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
  showToast("Data disimpan");
}
function deleteEntry(id){
  State.session.vault.entries = State.session.vault.entries.filter(e=>e.id!==id);
  scheduleSave(); renderEntryList(); renderSidebar();
  showToast("Data dihapus");
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
    showToast(`${label||"Teks"} disalin — akan dihapus dalam ${State.settings.clipboardSec}d`);
  }).catch(()=>showToast("Gagal menyalin"));
  clearTimeout(clipboardTimer);
  clipboardTimer = setTimeout(()=>{ navigator.clipboard.writeText("").catch(()=>{}); }, State.settings.clipboardSec*1000);
}
function quickCopy(id){
  const entry = State.session.vault.entries.find(e=>e.id===id);
  if(!entry) return;
  copyToClipboard(entry.password, "Password");
  recordUse(id);
}

/* ==================================================================
   Sidebar
   ================================================================== */
function renderSidebar(){
  const s = State.settings, session = State.session, v = State.view;
  document.getElementById("sb-decoy-badge").classList.toggle("hidden", session.slot!=="decoy");
  document.getElementById("sb-quick").innerHTML = `
    <button class="sb-item ${!v.filterCat&&!v.filterTag&&!v.filterFav&&!v.filterRecent?'active':''}" data-quick="all">${ic.folder()} Semua Data</button>
    <button class="sb-item ${v.filterFav?'active':''}" data-quick="fav">${ic.star(v.filterFav)} Favorit</button>
    <button class="sb-item ${v.filterRecent?'active':''}" data-quick="recent">${ic.clock()} Terbaru Dibuka</button>
  `;
  document.getElementById("sb-categories").innerHTML = session.vault.categories.map(c=>
    `<button class="sb-item ${v.filterCat===c?'active':''}" data-cat="${esc(c)}"><span class="sb-dot"></span> ${esc(c)}</button>`
  ).join("");
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
  if(v.filterCat) list = list.filter(e=>e.category===v.filterCat);
  if(v.filterTag) list = list.filter(e=>e.tags && e.tags.indexOf(v.filterTag)!==-1);
  if(v.searchQ.trim()){
    const q = v.searchQ.toLowerCase();
    list = list.filter(e=>[e.title,e.username,e.email,e.website,e.notes].concat(e.tags||[]).filter(Boolean).some(f=>f.toLowerCase().indexOf(q)!==-1));
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
    container.innerHTML = `<div class="empty-state">${entries.length===0 ? 'Belum ada data tersimpan.<br>Tekan "Tambah" untuk menyimpan data pertama Anda.' : "Tidak ada data yang cocok."}</div>`;
    return;
  }
  container.innerHTML = list.map(e=>{
    const dup = e.password && counts[e.password]>1;
    const sub = e.username || e.email || e.website || "—";
    const tagsHtml = (e.tags&&e.tags.length) ? `<div class="card-tags">${e.tags.slice(0,3).map(t=>`<span class="chip static">${esc(t)}</span>`).join("")}</div>` : "";
    return `<div class="card" data-id="${e.id}" data-action="open-detail">
      <div class="card-row">
        <div style="min-width:0;flex:1;">
          <div class="card-title-row"><div class="card-title">${esc(e.title)}</div>${dup?ic.warn().replace('width="14"','width="12"').replace('height="14"','height="12"').replace('currentColor','var(--danger)'):''}</div>
          <div class="card-sub">${esc(sub)}</div>
          ${tagsHtml}
        </div>
        <div class="card-actions">
          <button class="icon-btn" data-action="toggle-fav" data-id="${e.id}" title="Favorit">${ic.star(e.favorite)}</button>
          ${e.password?`<button class="icon-btn" data-action="quick-copy" data-id="${e.id}" title="Copy Password">${ic.copy()}</button>`:''}
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
  if(action==="toggle-fav") toggleFavorite(id);
  else if(action==="quick-copy") quickCopy(id);
  else if(action==="open-detail") openDetail(id);
});

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
    <div class="copy-field-label">${label}</div>
    <div class="copy-field-row">
      <div class="copy-field-val" data-shown="${secret?'0':'1'}">${displayVal}</div>
      ${secret?`<button class="copy-field-btn" data-toggle-secret data-field="${field}">${ic.eye()}</button>`:''}
      <button class="copy-field-btn" data-copy data-field="${field}">${ic.copy()}</button>
    </div>
  </div>`;
}

function renderDetail(){
  const entry = State.session.vault.entries.find(e=>e.id===State.detailEntryId);
  if(!entry){ closeDetail(); return; }
  const counts = computePasswordCounts(State.session.vault.entries);
  const dup = entry.password && counts[entry.password]>1;
  const el = document.getElementById("detail-content");
  el.innerHTML = `
    <div class="modal-head">
      <div>
        <div class="display-title small-title">${esc(entry.title)}</div>
        <div class="muted tiny" style="margin-top:4px;">${esc(entry.category)}</div>
      </div>
      <div style="display:flex;gap:4px;">
        <button class="icon-btn" id="detail-fav">${ic.star(entry.favorite)}</button>
        <button class="icon-btn" id="detail-close">${ic.close()}</button>
      </div>
    </div>
    <div class="modal-body">
      ${dup?`<div class="warn-box">${ic.warn()} Password ini digunakan di lebih dari satu data</div>`:""}
      ${copyFieldHTML("Website","website",entry.website,false)}
      ${copyFieldHTML("Email","email",entry.email,false)}
      ${copyFieldHTML("Username","username",entry.username,false)}
      ${copyFieldHTML("Password","password",entry.password,true)}
      ${copyFieldHTML("PIN","pin",entry.pin,true)}
      ${entry.notes? `<div class="copy-field"><div class="copy-field-label">Catatan</div><div class="note-box">${esc(entry.notes)}</div></div>` : ""}
      ${entry.tags&&entry.tags.length? `<div class="chips" style="margin-top:12px;">${entry.tags.map(t=>`<span class="chip static">${esc(t)}</span>`).join("")}</div>`:""}
      <div class="meta-lines">
        <span>Dibuat ${timeAgo(entry.createdAt)}</span>
        <span>Diubah ${timeAgo(entry.updatedAt)}</span>
        <span>Terakhir dibuka ${timeAgo(entry.lastUsedAt)} &middot; digunakan ${entry.useCount||0}x</span>
      </div>
    </div>
    <div class="modal-foot">
      <button class="btn btn-danger" id="detail-delete" style="display:flex;align-items:center;gap:6px;">${ic.trash()} Hapus</button>
      <button class="btn btn-primary full" id="detail-edit" style="display:flex;align-items:center;justify-content:center;gap:6px;">${ic.edit()} Edit</button>
    </div>
  `;
  document.getElementById("detail-fav").onclick = ()=>{ toggleFavorite(entry.id); renderDetail(); };
  document.getElementById("detail-close").onclick = closeDetail;
  document.getElementById("detail-delete").onclick = ()=>{ if(confirm("Hapus data ini?")){ deleteEntry(entry.id); closeDetail(); } };
  document.getElementById("detail-edit").onclick = ()=>{ closeDetail(); openForm(entry); };
  el.querySelectorAll("[data-toggle-secret]").forEach(btn=>{
    btn.onclick = ()=>{
      const field = btn.getAttribute("data-field");
      const row = btn.closest(".copy-field-row");
      const valEl = row.querySelector(".copy-field-val");
      const shown = valEl.getAttribute("data-shown")==="1";
      if(shown){ valEl.textContent = maskValue(entry[field]); valEl.setAttribute("data-shown","0"); btn.innerHTML = ic.eye(); }
      else { valEl.textContent = entry[field]; valEl.setAttribute("data-shown","1"); btn.innerHTML = ic.eyeOff(); }
    };
  });
  el.querySelectorAll("[data-copy]").forEach(btn=>{
    btn.onclick = ()=>{
      const field = btn.getAttribute("data-field");
      const labelMap = {website:"Website",email:"Email",username:"Username",password:"Password",pin:"PIN"};
      copyToClipboard(entry[field], labelMap[field]||field);
    };
  });
}

/* ==================================================================
   Entry form modal (add / edit)
   ================================================================== */
function buildCategoryOptions(selected){
  return State.session.vault.categories.map(c=>`<option value="${esc(c)}" ${c===selected?'selected':''}>${esc(c)}</option>`).join("")
    + `<option value="__new__">+ Tambah Kategori Baru</option>`;
}
function openForm(entry){
  const isNew = !entry;
  const draft = entry ? Object.assign({}, entry, {tags:(entry.tags||[]).slice()}) : {
    id: uid(), template:"website", category: State.session.vault.categories[0]||"Website",
    title:"", website:"", email:"", username:"", password:"", pin:"", notes:"",
    tags: [], favorite:false, createdAt: Date.now(), updatedAt: Date.now(), lastUsedAt:null, useCount:0,
  };
  State.formDraft = draft;
  document.getElementById("form-title").textContent = isNew? "Tambah Data" : "Edit Data";
  document.getElementById("field-template-wrap").classList.toggle("hidden", !isNew);
  const templateSel = document.getElementById("form-template");
  templateSel.innerHTML = TEMPLATES.map(t=>`<option value="${t.id}">${t.label}</option>`).join("");
  templateSel.value = draft.template || "website";
  document.getElementById("form-category").innerHTML = buildCategoryOptions(draft.category);
  document.getElementById("form-titlefield").value = draft.title;
  document.getElementById("form-website").value = draft.website||"";
  document.getElementById("form-email").value = draft.email||"";
  document.getElementById("form-username").value = draft.username||"";
  document.getElementById("form-password").value = draft.password||"";
  document.getElementById("form-pin").value = draft.pin||"";
  document.getElementById("form-notes").value = draft.notes||"";
  document.getElementById("form-favorite").checked = !!draft.favorite;
  document.getElementById("form-strength").innerHTML = strengthHTML(draft.password);
  document.getElementById("form-generator").classList.add("hidden");
  document.getElementById("form-generator").innerHTML = "";
  renderFormTags();
  document.getElementById("modal-form").classList.remove("hidden");
  setTimeout(()=>document.getElementById("form-titlefield").focus(), 50);
}
function closeForm(){ document.getElementById("modal-form").classList.add("hidden"); State.formDraft=null; }
function renderFormTags(){
  const draft = State.formDraft;
  document.getElementById("form-tags-chips").innerHTML = draft.tags.map(t=>
    `<span class="chip active">${esc(t)} <span class="x" data-remove-tag="${esc(t)}">✕</span></span>`
  ).join("");
  const suggestions = SUGGESTED_TAGS.filter(t=>draft.tags.indexOf(t)===-1);
  document.getElementById("form-tag-suggest").innerHTML = suggestions.map(t=>
    `<span class="chip" data-add-tag="${esc(t)}">+ ${esc(t)}</span>`
  ).join("");
}
function addFormTag(t){
  t = (t||"").trim();
  if(!t || State.formDraft.tags.indexOf(t)!==-1) return;
  State.formDraft.tags.push(t);
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
        <button class="btn" id="gen-regen">↻ Acak Ulang</button>
        <button class="btn btn-primary" id="gen-use">Gunakan</button>
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

document.getElementById("form-template").addEventListener("change",(e)=>{
  const t = TEMPLATES.find(x=>x.id===e.target.value);
  if(t && State.formDraft){
    State.formDraft.template = t.id;
    document.getElementById("form-category").value = t.category;
    State.formDraft.category = t.category;
  }
});
document.getElementById("form-category").addEventListener("change",(e)=>{
  if(!State.formDraft) return;
  if(e.target.value==="__new__"){
    const name = window.prompt("Nama kategori baru:");
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
document.getElementById("form-password").addEventListener("input",(e)=>{
  document.getElementById("form-strength").innerHTML = strengthHTML(e.target.value);
});
document.getElementById("form-gen-toggle").addEventListener("click",()=>{
  const panel = document.getElementById("form-generator");
  const willShow = panel.classList.contains("hidden");
  panel.classList.toggle("hidden");
  if(willShow){
    renderGenerator(panel, (val)=>{
      document.getElementById("form-password").value = val;
      document.getElementById("form-strength").innerHTML = strengthHTML(val);
      panel.classList.add("hidden");
    });
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
  if(d.category==="__new__") d.category = State.session.vault.categories[0]||"Website";
  d.website = document.getElementById("form-website").value.trim();
  d.email = document.getElementById("form-email").value.trim();
  d.username = document.getElementById("form-username").value.trim();
  d.password = document.getElementById("form-password").value;
  d.pin = document.getElementById("form-pin").value.trim();
  d.notes = document.getElementById("form-notes").value;
  d.favorite = document.getElementById("form-favorite").checked;
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
    <div class="modal-head"><div class="display-title small-title">Pengaturan</div><button class="icon-btn" id="settings-close">${ic.close()}</button></div>
    <div class="modal-body">
      <div class="settings-row"><div><div class="settings-row-label">Tema</div><div class="settings-row-sub">Terang / gelap</div></div><button class="btn settings-toggle-btn" id="settings-theme">${s.theme==="dark"?"Gelap":"Terang"}</button></div>
      <div class="settings-row"><div><div class="settings-row-label">Auto Lock</div><div class="settings-row-sub">Kunci otomatis saat tidak aktif</div></div>
        <select class="input settings-select" id="settings-autolock">${[1,2,5,10,15,30].map(m=>`<option value="${m}" ${s.autoLockMin===m?'selected':''}>${m} menit</option>`).join("")}</select></div>
      <div class="settings-row"><div><div class="settings-row-label">Durasi Clipboard</div><div class="settings-row-sub">Hapus clipboard otomatis</div></div>
        <select class="input settings-select" id="settings-clipboard">${[15,30,45,60].map(sec=>`<option value="${sec}" ${s.clipboardSec===sec?'selected':''}>${sec} detik</option>`).join("")}</select></div>

      <div class="settings-heading">Ubah Master Password</div>
      <input class="input" type="password" placeholder="Master Password saat ini" id="mp-old" style="margin-bottom:8px;">
      <input class="input" type="password" placeholder="Master Password baru" id="mp-new">
      <div class="err" id="mp-err"></div>
      <button class="btn full" id="mp-submit">Ganti Password</button>

      <div class="settings-heading">Decoy Mode</div>
      <div class="settings-row-sub" style="margin-bottom:10px;">${(s.hasDecoy||slot==="decoy") ? "Decoy vault aktif. Password kedua membuka vault kosong/palsu." : "Buat password kedua yang membuka vault kosong jika Anda dipaksa membuka aplikasi."}</div>
      <div id="decoy-area">${(slot!=="decoy" && !s.hasDecoy) ? `<button class="btn full" id="decoy-open-btn">Buat Decoy Password</button>` : ""}</div>

      <div class="settings-heading">Mode Stealth</div>
      <div class="settings-row"><div><div class="settings-row-label">Samarkan sebagai Kalkulator</div><div class="settings-row-sub">Buka vault lewat PIN rahasia di kalkulator</div></div>
        <input type="checkbox" id="settings-stealth" ${s.stealthEnabled?'checked':''}></div>
      <div id="stealth-pin-area" class="${s.stealthEnabled?'':'hidden'}" style="margin-bottom:14px;">
        <input class="input mono" placeholder="PIN rahasia (4-8 digit)" id="settings-stealth-pin" value="${esc(s.stealthPin)}">
        <div class="settings-row-sub">Ketik PIN ini di kalkulator lalu tekan &quot;=&quot; untuk membuka vault.</div>
      </div>

      <div class="settings-heading">Backup &amp; Restore</div>
      <div style="display:flex;gap:8px;margin-bottom:4px;">
        <button class="btn" id="settings-export" style="flex:1;display:flex;align-items:center;justify-content:center;gap:6px;">${ic.download()} Export</button>
        <button class="btn" id="settings-import-btn" style="flex:1;display:flex;align-items:center;justify-content:center;gap:6px;">${ic.upload()} Import</button>
      </div>
      <div class="settings-row-sub" style="margin-bottom:14px;">File backup tetap terenkripsi. Import akan menggantikan seluruh isi vault ini.</div>
      <input type="file" id="settings-import-file" accept=".gpvault,application/json" class="hidden">

      <div class="settings-note">${ic.shieldCheck()} <span>Sidik jari/Face ID memerlukan akses sistem operasi native dan belum tersedia pada versi PWA ini &mdash; kunci layar perangkat Anda tetap melindungi akses ke aplikasi ini.</span></div>
    </div>`;
  document.getElementById("settings-close").onclick = closeSettings;
  document.getElementById("settings-theme").onclick = ()=>{ persistSettings(Object.assign({},State.settings,{theme:State.settings.theme==="dark"?"light":"dark"})); applyTheme(); renderSettings(); };
  document.getElementById("settings-autolock").onchange = (e)=>{ persistSettings(Object.assign({},State.settings,{autoLockMin:+e.target.value})); };
  document.getElementById("settings-clipboard").onchange = (e)=>{ persistSettings(Object.assign({},State.settings,{clipboardSec:+e.target.value})); };
  document.getElementById("mp-submit").onclick = async ()=>{
    const oldPw = document.getElementById("mp-old").value;
    const newPw = document.getElementById("mp-new").value;
    const errEl = document.getElementById("mp-err");
    errEl.textContent="";
    if(newPw.length<8){ errEl.textContent="Password baru minimal 8 karakter"; return; }
    const ok = await changeMasterPassword(oldPw,newPw);
    if(!ok) errEl.textContent="Password lama salah";
    else { document.getElementById("mp-old").value=""; document.getElementById("mp-new").value=""; showToast("Master Password diubah"); }
  };
  const decoyOpenBtn = document.getElementById("decoy-open-btn");
  if(decoyOpenBtn){
    decoyOpenBtn.onclick = ()=>{
      document.getElementById("decoy-area").innerHTML = `
        <input class="input" type="password" placeholder="Decoy Master Password" id="decoy-pw">
        <div class="err" id="decoy-err"></div>
        <button class="btn btn-primary full" id="decoy-submit">Simpan Decoy</button>`;
      document.getElementById("decoy-submit").onclick = async ()=>{
        const pw = document.getElementById("decoy-pw").value;
        const errEl = document.getElementById("decoy-err");
        if(pw.length<8){ errEl.textContent="Minimal 8 karakter"; return; }
        try{ await setupDecoy(pw); renderSettings(); showToast("Decoy password dibuat"); }
        catch(e){ errEl.textContent="Gagal membuat decoy"; }
      };
    };
  }
  document.getElementById("settings-stealth").onchange = (e)=>{
    persistSettings(Object.assign({},State.settings,{stealthEnabled:e.target.checked}));
    document.getElementById("stealth-pin-area").classList.toggle("hidden", !e.target.checked);
  };
  document.getElementById("settings-stealth-pin").oninput = (e)=>{ e.target.value = e.target.value.replace(/\D/g,"").slice(0,8); };
  document.getElementById("settings-stealth-pin").onblur = (e)=>{ persistSettings(Object.assign({},State.settings,{stealthPin:e.target.value})); };
  document.getElementById("settings-export").onclick = exportBackup;
  document.getElementById("settings-import-btn").onclick = ()=>document.getElementById("settings-import-file").click();
  document.getElementById("settings-import-file").onchange = (e)=>{ const f=e.target.files[0]; if(f) importBackup(f, State.session.slot); };
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
function resetCalc(){
  State.calc = {display:"0", pinBuffer:"", acc:null, op:null};
  const d = document.getElementById("calc-display");
  if(d) d.textContent = "0";
}
function exitStealth(){ goStage(State.session ? "unlocked" : "locked"); }
function handleCalcKey(k){
  const c = State.calc;
  const disp = document.getElementById("calc-display");
  if(k==="C"){ resetCalc(); return; }
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
      if(c.op==="/") res = cur!==0? c.acc/cur : 0;
      c.display = String(res);
    }
    c.acc=null; c.op=null; c.pinBuffer="";
    disp.textContent = c.display;
    return;
  }
  if(k==="+"||k==="-"||k==="*"||k==="/"){
    c.acc = parseFloat(c.display); c.op = k; c.display = "0";
    disp.textContent = c.display;
    return;
  }
  if(k==="."){
    if(c.display.indexOf(".")===-1) c.display += ".";
    disp.textContent = c.display;
    return;
  }
  c.pinBuffer = (c.pinBuffer + k).slice(-12);
  c.display = c.display==="0" ? k : c.display+k;
  disp.textContent = c.display;
}
document.querySelectorAll("[data-calc]").forEach(btn=>{
  btn.addEventListener("click", ()=>handleCalcKey(btn.getAttribute("data-calc")));
});

/* ==================================================================
   Sidebar / topbar static bindings
   ================================================================== */
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
  }
});
document.getElementById("sb-settings-btn").addEventListener("click", openSettings);
document.getElementById("sb-lock-btn").addEventListener("click", lockVault);
document.getElementById("menu-btn").addEventListener("click", ()=>{
  document.getElementById("sidebar").classList.toggle("hidden");
});
document.getElementById("search-input").addEventListener("input",(e)=>{ State.view.searchQ = e.target.value; renderEntryList(); });
document.getElementById("add-btn").addEventListener("click", ()=>openForm(null));

/* ==================================================================
   Modal backdrop click-to-close
   ================================================================== */
document.getElementById("modal-detail").addEventListener("mousedown",(e)=>{ if(e.target===e.currentTarget) closeDetail(); });
document.getElementById("modal-form").addEventListener("mousedown",(e)=>{ if(e.target===e.currentTarget) closeForm(); });
document.getElementById("modal-settings").addEventListener("mousedown",(e)=>{ if(e.target===e.currentTarget) closeSettings(); });

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
  if(pw.length<8){ errEl.textContent="Master Password minimal 8 karakter"; return; }
  if(pw!==confirmPw){ errEl.textContent="Konfirmasi password tidak cocok"; return; }
  const btn = document.getElementById("setup-submit");
  btn.disabled=true; btn.textContent="Membuat Vault...";
  try{ await handleSetup(pw); }
  catch(e){ errEl.textContent="Gagal membuat vault"; btn.disabled=false; btn.textContent="Buat Vault"; }
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
  if(!ok) errEl.textContent="Master Password salah";
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
   Bootstrap
   ================================================================== */
async function init(){
  drawDial();
  let loaded = Object.assign({}, DEFAULT_SETTINGS);
  try{ const s = await idbGet("geopass-settings"); if(s) loaded = Object.assign({}, DEFAULT_SETTINGS, s); }catch(e){ /* first run */ }
  State.settings = loaded;
  applyTheme();
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
