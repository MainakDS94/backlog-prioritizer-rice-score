// ---------------------------
// Constants / Storage
// ---------------------------
const ITEMS_KEY = "bp_items_v1";
const PAIR_KEY  = "bp_pair_v1"; // { deviceLabel, saltB64, ivB64, ctB64 }  ct = encrypted PAT

let items = loadItems();
let sessionToken = null; // unlocked token kept only in memory (per tab)

// ---------------------------
// DOM
// ---------------------------
const elUrl = document.getElementById("issueUrl");
const elAdd = document.getElementById("addBtn");
const elRows = document.getElementById("rows");
const elAutoSort = document.getElementById("autoSort");
const elStatusLeft = document.getElementById("statusLeft");
const elCountPill = document.getElementById("countPill");
const elModePill = document.getElementById("modePill");
const elPairPill = document.getElementById("pairPill");
const elClear = document.getElementById("clearBtn");
const elRefresh = document.getElementById("refreshBtn");
const elResetPair = document.getElementById("resetPairBtn");
const elLockBtn = document.getElementById("lockBtn");

// Modal
const authBackdrop = document.getElementById("authBackdrop");
const closeAuthBtn = document.getElementById("closeAuthBtn");
const tabUnlock = document.getElementById("tabUnlock");
const tabPair = document.getElementById("tabPair");
const paneUnlock = document.getElementById("paneUnlock");
const panePair = document.getElementById("panePair");

const unlockDeviceLabel = document.getElementById("unlockDeviceLabel");
const unlockPass = document.getElementById("unlockPass");
const keepUnlocked = document.getElementById("keepUnlocked");
const unlockBtn = document.getElementById("unlockBtn");
const unlockNote = document.getElementById("unlockNote");

const pairDeviceLabel = document.getElementById("pairDeviceLabel");
const pairToken = document.getElementById("pairToken");
const pairPass = document.getElementById("pairPass");
const pairBtn = document.getElementById("pairBtn");
const pairNote = document.getElementById("pairNote");

// ---------------------------
// Utilities
// ---------------------------
function setStatus(msg){ elStatusLeft.textContent = msg; }

function uid(){
  return Math.random().toString(16).slice(2) + Date.now().toString(16);
}

function riceScore(it){
  const r = Number(it.reach || 1);
  const i = Number(it.impact || 1);
  const c = Number(it.confidence || 1);
  const e = Number(it.effort || 1);
  const val = (r * i * c) / e;
  return Math.round(val * 100) / 100;
}

function saveItems(){
  localStorage.setItem(ITEMS_KEY, JSON.stringify(items));
}
function loadItems(){
  try{
    const raw = localStorage.getItem(ITEMS_KEY);
    if(!raw) return [];
    const parsed = JSON.parse(raw);
    if(!Array.isArray(parsed)) return [];
    return parsed.map(x => ({
      reach: 1, impact: 1, confidence: 1, effort: 1,
      title: "", fetchStatus: "pending",
      createdAt: Date.now(),
      ...x
    }));
  } catch {
    return [];
  }
}

function getPairing(){
  try{
    const raw = localStorage.getItem(PAIR_KEY);
    if(!raw) return null;
    return JSON.parse(raw);
  } catch { return null; }
}
function setPairing(obj){
  localStorage.setItem(PAIR_KEY, JSON.stringify(obj));
}
function clearPairing(){
  localStorage.removeItem(PAIR_KEY);
  sessionToken = null;
}

function escapeHtml(s){
  return String(s ?? "")
    .replaceAll("&","&amp;")
    .replaceAll("<","&lt;")
    .replaceAll(">","&gt;")
    .replaceAll('"',"&quot;")
    .replaceAll("'","&#039;");
}
function escapeAttr(s){ return escapeHtml(s).replaceAll("`","&#096;"); }

function formatProjectSlug(projectPath){
  const parts = projectPath.split("/");
  if (parts.length <= 2) return projectPath;
  return "…/" + parts.slice(-2).join("/");
}

// ---------------------------
// Crypto (PBKDF2 + AES-GCM)
// ---------------------------
const enc = new TextEncoder();
const dec = new TextDecoder();

function b64FromBytes(bytes){
  let bin = "";
  bytes.forEach(b => bin += String.fromCharCode(b));
  return btoa(bin);
}
function bytesFromB64(b64){
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for(let i=0;i<bin.length;i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function deriveKey(passphrase, saltBytes){
  const baseKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: saltBytes,
      iterations: 150000,
      hash: "SHA-256"
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptToken(passphrase, token){
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(passphrase, salt);
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    enc.encode(token)
  );
  return {
    saltB64: b64FromBytes(salt),
    ivB64: b64FromBytes(iv),
    ctB64: b64FromBytes(new Uint8Array(ct))
  };
}

async function decryptToken(passphrase, { saltB64, ivB64, ctB64 }){
  const salt = bytesFromB64(saltB64);
  const iv = bytesFromB64(ivB64);
  const ct = bytesFromB64(ctB64);
  const key = await deriveKey(passphrase, salt);
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    ct
  );
  return dec.decode(pt);
}

// ---------------------------
// GitLab URL parsing + fetch
// ---------------------------
function parseGitLabIssueUrl(urlStr){
  let u;
  try { u = new URL(urlStr); }
  catch { throw new Error("Invalid URL."); }

  const host = u.origin;
  const path = u.pathname.replace(/\/+$/, "");
  const m = path.match(/^(\/.+?)\/-\/issues\/(\d+)$/);
  if(!m) throw new Error("URL must look like: https://host/<group>/<project>/-/issues/<iid>");

  const projectPath = m[1].replace(/^\//, "");
  const iid = m[2];
  return { host, projectPath, iid };
}

async function gitlabFetchIssueTitle({ host, projectPath, iid }, token){
  const encodedProject = encodeURIComponent(projectPath);
  const apiUrl = `${host}/api/v4/projects/${encodedProject}/issues/${encodeURIComponent(iid)}`;

  const res = await fetch(apiUrl, {
    method: "GET",
    headers: { "PRIVATE-TOKEN": token }
  });

  if(!res.ok){
    const t = await res.text().catch(() => "");
    throw new Error(`GitLab API ${res.status}: ${t || res.statusText}`);
  }
  const data = await res.json();
  return data.title || "(No title)";
}

// ---------------------------
// Render
// ---------------------------
function applyOrdering(){
  elModePill.textContent = `Mode: ${elAutoSort.checked ? "Auto" : "Manual"}`;
  if(elAutoSort.checked){
    items.sort((a,b) => {
      const d = riceScore(b) - riceScore(a);
      if(d !== 0) return d;
      return (a.createdAt || 0) - (b.createdAt || 0);
    });
  }
}

function updateCounts(){
  elCountPill.textContent = `${items.length} item${items.length === 1 ? "" : "s"}`;
}

function statusBadge(status){
  if(status === "ok") return `<span class="badge ok">Fetched</span>`;
  if(status === "err") return `<span class="badge err">Fetch failed</span>`;
  return `<span class="badge">Pending</span>`;
}

function scoreSelect(field, value, id){
  const v = Number(value || 1);
  return `
    <select data-field="${field}" data-id="${id}">
      <option value="1" ${v===1?"selected":""}>1</option>
      <option value="2" ${v===2?"selected":""}>2</option>
      <option value="3" ${v===3?"selected":""}>3</option>
    </select>
  `;
}

function render(){
  const paired = !!getPairing();
  elPairPill.textContent = paired ? "Paired" : "Unpaired";

  applyOrdering();
  updateCounts();
  saveItems();

  elRows.innerHTML = "";

  items.forEach((it, idx) => {
    const canMove = !elAutoSort.checked;

    const row = document.createElement("div");
    row.className = "grid row";
    row.innerHTML = `
      <div class="cell order">${idx+1}</div>

      <div class="cell issue">
        <div class="top">
          <div class="name" title="${escapeHtml(it.title || it.url)}">${escapeHtml(it.title || "Untitled")}</div>
          ${statusBadge(it.fetchStatus)}
        </div>
        <div class="meta">
          <span class="badge">${escapeHtml(it.host.replace(/^https?:\/\//,""))}</span>
          <span class="badge">${escapeHtml(formatProjectSlug(it.projectPath))}</span>
          <span class="badge">#${escapeHtml(it.iid)}</span>
          <span class="badge"><a href="${escapeAttr(it.url)}" target="_blank" rel="noreferrer">Open</a></span>
        </div>
      </div>

      <div class="cell">${scoreSelect("reach", it.reach, it.id)}</div>
      <div class="cell">${scoreSelect("impact", it.impact, it.id)}</div>
      <div class="cell">${scoreSelect("confidence", it.confidence, it.id)}</div>
      <div class="cell">${scoreSelect("effort", it.effort, it.id)}</div>

      <div class="cell rice">
        ${riceScore(it).toFixed(2)}
        <small>${it.reach}×${it.impact}×${it.confidence}÷${it.effort}</small>
      </div>

      <div class="cell actions">
        <button class="iconbtn" title="Move up" data-action="up" data-id="${it.id}" ${(!canMove || idx===0) ? "disabled" : ""}>↑</button>
        <button class="iconbtn" title="Move down" data-action="down" data-id="${it.id}" ${(!canMove || idx===items.length-1) ? "disabled" : ""}>↓</button>
      </div>
    `;
    elRows.appendChild(row);
  });
}

// ---------------------------
// Auth modal
// ---------------------------
function openAuth(mode = "unlock"){
  authBackdrop.classList.add("open");
  authBackdrop.setAttribute("aria-hidden", "false");

  const pairing = getPairing();
  unlockNote.textContent = "";
  pairNote.textContent = "";

  if(pairing){
    unlockDeviceLabel.value = pairing.deviceLabel || "";
  } else {
    unlockDeviceLabel.value = "";
  }

  if(mode === "pair"){
    setTab("pair");
  } else {
    setTab("unlock");
  }
}

function closeAuth(){
  authBackdrop.classList.remove("open");
  authBackdrop.setAttribute("aria-hidden", "true");
}

function setTab(which){
  if(which === "pair"){
    tabPair.classList.add("active");
    tabUnlock.classList.remove("active");
    panePair.classList.remove("hidden");
    paneUnlock.classList.add("hidden");
  } else {
    tabUnlock.classList.add("active");
    tabPair.classList.remove("active");
    paneUnlock.classList.remove("hidden");
    panePair.classList.add("hidden");
  }
}

function requireUnlocked(){
  if(sessionToken) return true;
  const pairing = getPairing();
  if(!pairing){
    setStatus("Unpaired. Please pair this PC/browser profile first.");
    openAuth("pair");
    return false;
  }
  setStatus("Locked. Please unlock to use GitLab fetching.");
  openAuth("unlock");
  return false;
}

// ---------------------------
// Backlog actions
// ---------------------------
async function addUrl(){
  if(!requireUnlocked()) return;

  const url = elUrl.value.trim();
  if(!url){ setStatus("Please paste a GitLab issue URL."); return; }

  let parsed;
  try { parsed = parseGitLabIssueUrl(url); }
  catch(e){ setStatus(e.message); return; }

  if(items.some(x => x.url === url)){
    setStatus("That URL is already in your list.");
    elUrl.value = "";
    return;
  }

  const it = {
    id: uid(),
    url,
    host: parsed.host,
    projectPath: parsed.projectPath,
    iid: parsed.iid,
    title: "Fetching…",
    fetchStatus: "pending",
    reach: 1, impact: 1, confidence: 1, effort: 1,
    createdAt: Date.now()
  };

  items.push(it);
  render();

  try{
    const title = await gitlabFetchIssueTitle(parsed, sessionToken);
    it.title = title;
    it.fetchStatus = "ok";
    setStatus(`Fetched: ${title}`);
  } catch(e){
    it.title = "Untitled";
    it.fetchStatus = "err";
    setStatus(String(e.message || e));
  }

  elUrl.value = "";
  render();
}

function moveItem(id, direction){
  const idx = items.findIndex(x => x.id === id);
  if(idx < 0) return;
  const newIdx = direction === "up" ? idx - 1 : idx + 1;
  if(newIdx < 0 || newIdx >= items.length) return;
  const [spliced] = items.splice(idx, 1);
  items.splice(newIdx, 0, spliced);
  render();
}

function updateField(id, field, value){
  const it = items.find(x => x.id === id);
  if(!it) return;
  it[field] = Number(value);
  render();
}

async function refreshAllTitles(){
  if(!requireUnlocked()) return;
  if(items.length === 0){ setStatus("No items to refresh."); return; }

  setStatus("Refreshing titles…");
  for(const it of items){
    it.fetchStatus = "pending";
    render();
    try{
      const title = await gitlabFetchIssueTitle(
        { host: it.host, projectPath: it.projectPath, iid: it.iid },
        sessionToken
      );
      it.title = title;
      it.fetchStatus = "ok";
    } catch {
      it.fetchStatus = "err";
    }
  }
  setStatus("Refresh completed.");
  render();
}

function clearAll(){
  if(!confirm("Clear all items? This cannot be undone.")) return;
  items = [];
  saveItems();
  render();
  setStatus("Cleared.");
}

// ---------------------------
// Pairing / Unlock / Reset
// ---------------------------
async function doPair(){
  const deviceLabel = pairDeviceLabel.value.trim();
  const token = pairToken.value.trim();
  const pass = pairPass.value;

  if(!deviceLabel){ pairNote.textContent = "Please set a device label."; return; }
  if(!token){ pairNote.textContent = "Please paste a GitLab PAT."; return; }
  if(!pass || pass.length < 8){ pairNote.textContent = "Passphrase must be at least 8 characters."; return; }

  try{
    const encObj = await encryptToken(pass, token);
    setPairing({ deviceLabel, ...encObj });

    // Immediately unlock into session (optional)
    sessionToken = token;

    // Clear sensitive inputs
    pairToken.value = "";
    pairPass.value = "";

    setStatus(`Paired & unlocked on this PC as "${deviceLabel}".`);
    pairNote.textContent = "Paired successfully. This pairing exists only on this browser profile.";
    render();
    closeAuth();
  } catch (e){
    pairNote.textContent = `Pairing failed: ${String(e.message || e)}`;
  }
}

async function doUnlock(){
  const pairing = getPairing();
  if(!pairing){
    unlockNote.textContent = "This PC/browser profile is not paired yet.";
    setTab("pair");
    return;
  }

  const pass = unlockPass.value;
  if(!pass){ unlockNote.textContent = "Enter your pairing passphrase."; return; }

  try{
    const token = await decryptToken(pass, pairing);
    sessionToken = token;

    // Clear pass field
    unlockPass.value = "";

    setStatus(`Unlocked (paired device: "${pairing.deviceLabel}").`);
    unlockNote.textContent = "Unlocked. Token is kept only in memory for this tab.";
    render();
    closeAuth();
  } catch {
    sessionToken = null;
    unlockNote.textContent = "Invalid passphrase (or pairing data was reset).";
  }
}

function doLock(){
  sessionToken = null;
  setStatus("Locked. Please unlock to fetch titles.");
  render();
  openAuth("unlock");
}

function doResetPairing(){
  if(!confirm("Reset pairing? This will forget the stored token on this PC/browser profile.")) return;
  clearPairing();
  setStatus("Pairing reset. You must pair again to fetch titles.");
  render();
  openAuth("pair");
}

// ---------------------------
// Event Wiring
// ---------------------------
elAdd.addEventListener("click", addUrl);
