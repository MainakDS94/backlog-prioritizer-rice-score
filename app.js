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
const elCountPill = document.getElementById("countPill");
const elModePill = document.getElementById("modePill");
const elPairPill = document.getElementById("pairPill");
const elClear = document.getElementById("clearBtn");

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
const keepUnlocked = document.getElementById("keepUnlocked"); // kept for compatibility (unused)
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
function setStatus(_){ /* intentionally silent */ }

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
      kind: "issues",               // "issues" or "work_items"
      issueState: "unknown",        // "opened" / "closed" / "unknown"
      timeEstimateHrs: 0,           // number (hours)
      velocitySelected: false,      // include checkbox
      velocityLoading: false,       // subtle loading state for refetch-on-select
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
    .replaceAll('"',"quot;")
    .replaceAll("'","&#039;");
}
function escapeAttr(s){ return escapeHtml(s).replaceAll("`","&#096;"); }

function formatProjectSlug(projectPath){
  const parts = projectPath.split("/");
  if (parts.length <= 2) return projectPath;
  return "…/" + parts.slice(-2).join("/");
}

// ---------------------------
// Estimate helpers (8h = 1d)
// ---------------------------
function estimateTotalHoursSelected(){
  // NOTE: we count selected items with estimate > 0 and not closed.
  return items
    .filter(it =>
      it.velocitySelected &&
      String(it.issueState || "unknown").toLowerCase() !== "closed" &&
      Number(it.timeEstimateHrs || 0) > 0
    )
    .reduce((sum, it) => sum + Number(it.timeEstimateHrs || 0), 0);
}

function formatDaysFromHours(hours){
  const days = hours / 8;
  const d = Math.round(days * 10) / 10; // 1 decimal
  return `${d}d`;
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

  // Accept both:
  // .../-/issues/<iid>
  // .../-/work_items/<iid>
  const m = path.match(/^(\/.+?)\/-\/(issues|work_items)\/(\d+)$/);
  if(!m) throw new Error("URL must look like: https://host/<group>/<project>/-/(issues|work_items)/<iid>");

  const projectPath = m[1].replace(/^\//, "");
  const kind = m[2];   // "issues" or "work_items"
  const iid = m[3];

  return { host, projectPath, kind, iid };
}

async function gitlabFetchIssueTitle({ host, projectPath, kind, iid }, token){
  const encodedProject = encodeURIComponent(projectPath);

  // Try endpoint based on kind
  const apiUrlPrimary = `${host}/api/v4/projects/${encodedProject}/${kind}/${encodeURIComponent(iid)}`;

  const headers = {
    "PRIVATE-TOKEN": token,
    "Authorization": `Bearer ${token}`
  };

  let res = await fetch(apiUrlPrimary, { method: "GET", headers });

  // Fallback: if work_items endpoint isn't supported, try issues
  if(!res.ok && kind === "work_items"){
    const apiUrlFallback = `${host}/api/v4/projects/${encodedProject}/issues/${encodeURIComponent(iid)}`;
    res = await fetch(apiUrlFallback, { method: "GET", headers });
  }

  if(!res.ok){
    // silent in UI; keep for debugging in console
    const t = await res.text().catch(() => "");
    throw new Error(`GitLab API ${res.status}: ${t || res.statusText}`);
  }

  const data = await res.json();

  const title = data.title || data.name || "(No title)";
  const state = (data.state || "unknown").toLowerCase(); // "opened" / "closed"
  const estimateSec = Number(data?.time_stats?.time_estimate || 0);
  const timeEstimateHrs = estimateSec > 0 ? (estimateSec / 3600) : 0;

  return { title, state, timeEstimateHrs };
}

// NEW: refetch meta when checkbox is selected
async function refetchIssueMeta(it){
  const parsed = {
    host: it.host,
    projectPath: it.projectPath,
    kind: it.kind || "issues",
    iid: it.iid
  };

  it.velocityLoading = true;
  it.fetchStatus = "pending";
  saveItems();
  render();

  try{
    const { title, state, timeEstimateHrs } = await gitlabFetchIssueTitle(parsed, sessionToken);
    it.title = title;
    it.issueState = state;
    it.timeEstimateHrs = Number(timeEstimateHrs || 0);
    it.fetchStatus = "ok";
  } catch(_e){
    // Keep whatever title we already have; allow re-try later
    it.fetchStatus = "err";
  } finally {
    it.velocityLoading = false;
    saveItems();
  }
}

// ---------------------------
// Render
// ---------------------------
function applyOrdering(){
  const totalDays = formatDaysFromHours(estimateTotalHoursSelected());

  if(elAutoSort.checked){
    elModePill.textContent = `Mode: Auto • ${totalDays}`;

    items.sort((a,b) => {
      const d = riceScore(b) - riceScore(a);
      if(d !== 0) return d;
      return (a.createdAt || 0) - (b.createdAt || 0);
    });
  } else {
    elModePill.textContent = `Mode: Manual • ${totalDays}`;
  }
}

function updateCounts(){
  elCountPill.textContent = `${items.length} item${items.length === 1 ? "" : "s"}`;
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

    const isClosed = String(it.issueState || "unknown").toLowerCase() === "closed";
    const hasEstimate = Number(it.timeEstimateHrs || 0) > 0;

    // Selectable means: counts toward totals if checked
    const selectable = hasEstimate && !isClosed;

    // Disable only when:
    // - explicitly closed, OR
    // - estimate confirmed missing (fetch ok + 0), OR
    // - currently loading (subtle loading state)
    const estimateConfirmedMissing = (it.fetchStatus === "ok") && !hasEstimate;
    const checkboxEnabled = !isClosed && !estimateConfirmedMissing && !it.velocityLoading;

    // If it truly can't be included, force unselect
    if(!selectable) it.velocitySelected = false;

    const perItemDays = hasEstimate ? formatDaysFromHours(Number(it.timeEstimateHrs || 0)) : "";

    const row = document.createElement("div");
    row.className = "grid row";
    row.innerHTML = `
      <div class="cell order">${idx+1}</div>

      <div class="cell includeCell">
        <input
          type="checkbox"
          data-include="1"
          data-id="${it.id}"
          ${it.velocitySelected ? "checked" : ""}
          ${checkboxEnabled ? "" : "disabled"}
          aria-busy="${it.velocityLoading ? "true" : "false"}"
          title="${
            it.velocityLoading
              ? "Fetching estimate…"
              : (isClosed
                  ? "Closed issues cannot be included."
                  : (hasEstimate
                      ? `Estimate: ${perItemDays}`
                      : (it.fetchStatus === "ok"
                          ? "No estimate set in GitLab."
                          : "Click to re-fetch estimate from GitLab.")
                    )
                )
          }"
        />
        <span class="includeHint">${escapeHtml(it.velocityLoading ? "…" : perItemDays)}</span>
      </div>

      <div class="cell issue">
        <div class="top">
          <div class="name" title="${escapeHtml(it.title || it.url)}">${escapeHtml(it.title || "Untitled")}</div>
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
      </div>

      <div class="cell actions">
        <button class="iconbtn trash" title="Remove" data-action="delete" data-id="${it.id}">🗑</button>
        <button class="iconbtn" title="Move up" data-action="up" data-id="${it.id}" ${(!canMove || idx===0) ? "disabled" : ""}>↑</button>
        <button class="iconbtn" title="Move down" data-action="down" data-id="${it.id}" ${(!canMove || idx===items.length-1) ? "disabled" : ""}>↓</button>
      </div>
    `;
    elRows.appendChild(row);
  });

  saveItems();
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
    openAuth("pair");
    return false;
  }
  openAuth("unlock");
  return false;
}

// ---------------------------
// Backlog actions
// ---------------------------
async function addUrl(){
  if(!requireUnlocked()) return;

  const url = elUrl.value.trim();
  if(!url) return;

  let parsed;
  try { parsed = parseGitLabIssueUrl(url); }
  catch(_e){ return; }

  if(items.some(x => x.url === url)){
    elUrl.value = "";
    return;
  }

  const it = {
    id: uid(),
    url,
    host: parsed.host,
    projectPath: parsed.projectPath,
    kind: parsed.kind,
    iid: parsed.iid,
    title: "Fetching…",
    fetchStatus: "pending",

    issueState: "unknown",
    timeEstimateHrs: 0,
    velocitySelected: false,
    velocityLoading: false,

    reach: 1, impact: 1, confidence: 1, effort: 1,
    createdAt: Date.now()
  };

  items.push(it);
  render();

  try{
    const { title, state, timeEstimateHrs } = await gitlabFetchIssueTitle(parsed, sessionToken);
    it.title = title;
    it.issueState = state;
    it.timeEstimateHrs = Number(timeEstimateHrs || 0);
    it.fetchStatus = "ok";

    // If estimate missing or closed, force unselected
    if(String(it.issueState || "unknown").toLowerCase() === "closed" || it.timeEstimateHrs <= 0){
      it.velocitySelected = false;
    }
  } catch(_e){
    it.title = "Untitled";
    it.issueState = "unknown";
    it.timeEstimateHrs = 0;
    it.velocitySelected = false;
    it.fetchStatus = "err";
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

function removeItem(id){
  const idx = items.findIndex(x => x.id === id);
  if(idx < 0) return;
  items.splice(idx, 1);
  render();
}

function updateField(id, field, value){
  const it = items.find(x => x.id === id);
  if(!it) return;
  it[field] = Number(value);
  render();
}

function clearAll(){
  if(!confirm("Clear all items? This cannot be undone.")) return;
  items = [];
  saveItems();
  render();
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

    sessionToken = token;

    pairToken.value = "";
    pairPass.value = "";

    pairNote.textContent = "";
    render();
    closeAuth();
  } catch (e){
    pairNote.textContent = `Pairing failed: ${String(e.message || e)}`;
  }
}

async function doUnlock(){
  const pairing = getPairing();
  if(!pairing){
    unlockNote.textContent = "This browser is not paired yet.";
    setTab("pair");
    return;
  }

  const pass = unlockPass.value;
  if(!pass){ unlockNote.textContent = "Enter your pairing passphrase."; return; }

  try{
    const token = await decryptToken(pass, pairing);
    sessionToken = token;

    unlockPass.value = "";

    unlockNote.textContent = "";
    render();
    closeAuth();
  } catch {
    sessionToken = null;
    unlockNote.textContent = "Invalid passphrase.";
  }
}

function doLock(){
  sessionToken = null;
  render();
  openAuth("unlock");
}

function doResetPairing(){
  if(!confirm("Reset pairing? This will forget the stored token on this PC/browser profile.")) return;
  clearPairing();
  render();
  openAuth("pair");
}

// ---------------------------
// Event Wiring + Startup (COPY-PASTE)
// ---------------------------
(function wireAndInit(){
  function must(el, name){
    if(!el) throw new Error(`[BP] Missing DOM element: ${name}`);
    return el;
  }

  must(pairBtn, "pairBtn");
  must(pairNote, "pairNote");
  must(pairDeviceLabel, "pairDeviceLabel");
  must(pairToken, "pairToken");
  must(pairPass, "pairPass");
  must(unlockBtn, "unlockBtn");
  must(unlockNote, "unlockNote");
  must(authBackdrop, "authBackdrop");

  // Main actions
  elAdd.addEventListener("click", addUrl);
  elUrl.addEventListener("keydown", (e) => { if(e.key === "Enter") addUrl(); });

  elRows.addEventListener("click", (e) => {
    const btn = e.target.closest("button[data-action]");
    if(!btn) return;

    const id = btn.getAttribute("data-id");
    const action = btn.getAttribute("data-action");

    if(action === "delete"){
      removeItem(id);
      return;
    }

    if(elAutoSort.checked) return;
    moveItem(id, action);
  });

  elRows.addEventListener("change", (e) => {
    // Estimate checkbox (refetch-on-select)
    const include = e.target.closest('input[type="checkbox"][data-include="1"]');
    if(include){
      const id = include.getAttribute("data-id");
      const it = items.find(x => x.id === id);
      if(!it) return;

      // If currently loading, ignore further toggles
      if(it.velocityLoading){
        include.checked = !!it.velocitySelected;
        return;
      }

      // Unchecking is immediate
      if(!include.checked){
        it.velocitySelected = false;
        saveItems();
        applyOrdering();
        return;
      }

      // Checking triggers refetch
      (async () => {
        if(!requireUnlocked()){
          include.checked = false;
          return;
        }

        await refetchIssueMeta(it);

        const isClosed = String(it.issueState || "unknown").toLowerCase() === "closed";
        const hasEstimate = Number(it.timeEstimateHrs || 0) > 0;
        it.velocitySelected = hasEstimate && !isClosed;

        saveItems();
        render();
      })();

      return;
    }

    // RICE selects
    const sel = e.target.closest("select[data-field]");
    if(!sel) return;
    updateField(sel.getAttribute("data-id"), sel.getAttribute("data-field"), sel.value);
  });

  elAutoSort.addEventListener("change", () => render());

  elClear.addEventListener("click", clearAll);
  elResetPair.addEventListener("click", doResetPairing);
  elLockBtn.addEventListener("click", doLock);

  // Modal actions
  closeAuthBtn.addEventListener("click", closeAuth);
  authBackdrop.addEventListener("click", (e) => { if(e.target === authBackdrop) closeAuth(); });

  tabUnlock.addEventListener("click", () => setTab("unlock"));
  tabPair.addEventListener("click", () => setTab("pair"));

  pairBtn.addEventListener("click", (e) => {
    e.preventDefault();
    e.stopPropagation();
    pairNote.textContent = "";
    doPair();
  });

  unlockBtn.addEventListener("click", (e) => {
    e.preventDefault();
    e.stopPropagation();
    unlockNote.textContent = "";
    doUnlock();
  });

  unlockPass.addEventListener("keydown", (e) => { if(e.key === "Enter") doUnlock(); });
  pairPass.addEventListener("keydown", (e) => { if(e.key === "Enter") doPair(); });

  // Startup
  render();

  const pairing = getPairing();
  if(!pairing){
    openAuth("pair");
  } else {
    openAuth("unlock");
  }
})();

// ---------------------------
// Cleanup on tab close / refresh (clears items + session token; keeps pairing)
// ---------------------------
function cleanupOnExit(){
  sessionToken = null;
}
window.addEventListener("pagehide", cleanupOnExit);
