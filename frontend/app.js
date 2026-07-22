/* Infiltr console — front-end controller.
 *
 * Talks to the FastAPI backend over fetch + SSE. When the API isn't reachable
 * (e.g. the file is opened directly via file://), it falls back to a local
 * simulation so the UI is still explorable.
 */
"use strict";

const API_BASE = ""; // same origin (served by the API at / and /ui)

const SEV_ORDER = ["info", "low", "medium", "high", "critical"];
const sevRank = (s) => Math.max(0, SEV_ORDER.indexOf(s || "info"));

const state = { results: {}, scanning: false, target: "", order: [], scanId: null, live: false };
const $ = (sel) => document.querySelector(sel);

// ---------------------------------------------------------------------
// Fallback data (simulation only)
// ---------------------------------------------------------------------
const MODULE_META = [
  { name: "nmap", category: "recon", desc: "Port scan + service/version detection" },
  { name: "theharvester", category: "recon", desc: "OSINT: emails, subdomains, hosts, IPs" },
  { name: "whatweb", category: "recon", desc: "Web technology fingerprinting" },
  { name: "feroxbuster", category: "web", desc: "Recursive directory / file brute force" },
  { name: "ffuf", category: "web", desc: "Fast web fuzzer" },
  { name: "gobuster", category: "web", desc: "Directory / file brute forcing" },
  { name: "nikto", category: "web", desc: "Web server / CGI scanner" },
  { name: "sqlmap", category: "web", desc: "SQL injection detection" },
  { name: "wfuzz", category: "web", desc: "Web application fuzzer" },
  { name: "xsstrike", category: "web", desc: "Reflected / DOM XSS detection" },
  { name: "hydra", category: "auth", desc: "Network login brute forcer" },
];

const PROFILE_MODULES = {
  full: MODULE_META.map((m) => m.name),
  quick: ["nmap", "whatweb"],
  "full-recon": ["nmap", "theharvester", "whatweb"],
  "web-audit": ["feroxbuster", "ffuf", "gobuster", "nikto", "sqlmap", "wfuzz", "xsstrike"],
  "auth-test": ["hydra"],
};

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------------
// Live API
// ---------------------------------------------------------------------
const LiveApi = {
  async getModules() {
    const r = await fetch(`${API_BASE}/modules`);
    const mods = await r.json();
    return mods.map((m) => ({ name: m.name, category: m.category, desc: m.description, installed: m.installed }));
  },

  async getScans() {
    const r = await fetch(`${API_BASE}/scans?limit=50`);
    return r.json();
  },

  async getProfiles() {
    const r = await fetch(`${API_BASE}/profiles`);
    return r.json();
  },

  async getExplanations() {
    try {
      const r = await fetch(`${API_BASE}/explanations`);
      return r.ok ? r.json() : { modules: {}, findings: {} };
    } catch (_) {
      return { modules: {}, findings: {} };
    }
  },

  async createProfile(body) {
    const r = await fetch(`${API_BASE}/profiles`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    return r.json();
  },

  async getScan(id) {
    const r = await fetch(`${API_BASE}/scan/${id}`);
    if (!r.ok) return null;
    return r.json();
  },

  async runScan(target, { modules, profile }, cb) {
    const body = { target };
    if (profile && profile !== "full") body.profile = profile;
    if (modules && modules.length) body.modules = modules;
    const r = await fetch(`${API_BASE}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!r.ok) throw new Error(`scan failed: ${r.status}`);
    const { scan_id, modules: selected } = await r.json();
    state.scanId = scan_id;
    cb.onStart(selected, scan_id);

    await new Promise((resolve) => {
      const es = new EventSource(`${API_BASE}/scan/${scan_id}/events`);
      es.addEventListener("module_start", (e) => {
        cb.onModuleStart(JSON.parse(e.data).module);
      });
      es.addEventListener("module", (e) => {
        const evt = JSON.parse(e.data);
        cb.onModule({ ...evt.result, phase: "done" });
      });
      es.addEventListener("done", () => { es.close(); resolve(); });
      es.addEventListener("close", () => { es.close(); resolve(); });
      es.onerror = () => { es.close(); resolve(); };
    });
    cb.onDone();
  },
};

// ---------------------------------------------------------------------
// Simulation API (fallback)
// ---------------------------------------------------------------------
const SIM_FINDINGS = {
  nmap: [
    { type: "open_port", name: "80/tcp", value: "http", detail: "Apache httpd 2.4.7", severity: "low" },
    { type: "open_port", name: "3306/tcp", value: "mysql", detail: "MySQL 5.5.44", severity: "medium" },
  ],
  whatweb: [{ type: "technology", name: "PHP", value: "5.5.9", severity: "low" }],
  sqlmap: [{ type: "sqli", name: "injectable parameter", value: "id", detail: "boolean-based blind", severity: "critical" }],
  hydra: [{ type: "credential", name: "admin:password", value: "127.0.0.1", severity: "critical" }],
  nikto: [{ type: "finding", name: "OSVDB-3268", value: "/config/ directory indexing", severity: "medium" }],
  xsstrike: [{ type: "xss", name: "reflected XSS", value: "<script>alert(1)</script>", severity: "high" }],
};

const SimApi = {
  async getModules() { return MODULE_META.map((m) => ({ ...m, installed: true })); },
  async getScans() { return []; },
  async getScan() { return null; },
  async getProfiles() {
    return Object.entries(PROFILE_MODULES).map(([name, mods]) => ({
      id: null, name, builtin: true, modules: name === "full" ? [] : mods, description: "",
    }));
  },
  async createProfile(body) { PROFILE_MODULES[body.name] = body.modules; return { ...body, id: null }; },
  async getExplanations() { return { modules: {}, findings: {} }; },
  async runScan(target, { modules, profile }, cb) {
    const names = modules && modules.length ? modules : PROFILE_MODULES[profile] || PROFILE_MODULES.full;
    cb.onStart(names, null);
    for (const name of names) {
      cb.onModuleStart(name);
      await sleep(300 + Math.random() * 700);
      const meta = MODULE_META.find((m) => m.name === name);
      const findings = (SIM_FINDINGS[name] || []).filter(() => Math.random() > 0.3);
      const severity = findings.reduce((t, f) => (sevRank(f.severity) > sevRank(t) ? f.severity : t), "info");
      cb.onModule({
        module: name, category: meta.category, status: "PASS", severity,
        duration: +(1 + Math.random() * 5).toFixed(1), findings,
        summary: findings.length ? `${findings.length} finding(s).` : "No findings.",
        raw_output: `$ ${name} ${target}\n[sim] ${findings.length} findings`, phase: "done",
      });
    }
    cb.onDone();
  },
};

let Api = SimApi;

// ---------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------
function renderSidebarModules(mods) {
  $("#module-list").innerHTML = mods
    .map((m) => `<li title="${m.installed ? "installed" : "not installed"}"><span class="m-dot ${m.installed ? "on" : "off"}"></span>${m.name}<span class="m-cat">${m.category}</span></li>`)
    .join("");
}

function renderModulesGrid(mods) {
  $("#modules-grid").innerHTML = mods
    .map((m) => `<div class="mod-card">
        <h3><span class="m-dot ${m.installed ? "on" : "off"}"></span>${m.name}</h3>
        <span class="mc-cat">${m.category} · ${m.installed ? "installed" : "missing"}</span>
        <p>${m.desc || ""}</p>
      </div>`)
    .join("");
}

function statusBadge(status, phase) {
  if (phase === "running") return `<span class="badge badge-run"><span class="spinner"></span> RUN</span>`;
  if (status === "PASS") return `<span class="badge badge-pass">PASS</span>`;
  if (status === "ERROR") return `<span class="badge badge-error">ERROR</span>`;
  return `<span class="badge badge-wait">WAIT</span>`;
}
const sevPill = (s) => `<span class="sev-pill ${s}">${s}</span>`;

function liveElapsed(r) {
  if (!r.startedAt) return "…";
  return ((Date.now() - r.startedAt) / 1000).toFixed(1) + "s";
}

function renderRow(r) {
  const running = r.phase === "running";
  const findings = r.findings ? r.findings.length : 0;
  const newCount = (r.findings || []).filter((f) => f.is_new).length;
  const newTag = newCount ? ` <span class="new-tag">◆ ${newCount} NEW</span>` : "";
  const timeCell = running ? liveElapsed(r) : r.duration ? r.duration + "s" : "—";
  const summaryCell = running
    ? `<div class="mod-bar" title="running"><div class="mod-bar-fill"></div></div>`
    : r.summary || "";
  return `<tr data-module="${r.module}">
    <td>${statusBadge(r.status, r.phase)}</td>
    <td class="mono">${r.module}${newTag}</td>
    <td>${r.category || ""}</td>
    <td>${sevPill(r.severity || "info")}</td>
    <td class="mono">${running ? "…" : findings}</td>
    <td class="mono">${timeCell}</td>
    <td>${summaryCell}</td>
  </tr>`;
}

function renderResults() {
  const body = $("#results-body");
  if (!state.order.length) {
    body.innerHTML = `<tr class="empty-row"><td colspan="7">No scan yet — set a target and hit <b>Run scan</b>.</td></tr>`;
    return;
  }
  body.innerHTML = state.order.map((n) => renderRow(state.results[n])).join("");
  body.querySelectorAll("tr[data-module]").forEach((tr) =>
    tr.addEventListener("click", () => openDrawer(tr.dataset.module)));
}

function updateStats() {
  const done = state.order.filter((n) => state.results[n].phase === "done").length;
  const pct = state.order.length ? Math.round((done / state.order.length) * 100) : 0;
  $("#stat-progress").innerHTML = `${pct}<span class="stat-unit">%</span>`;
  $("#progress-bar").style.width = pct + "%";
  const counts = { critical: 0, high: 0, medium: 0, low: 0, total: 0 };
  for (const n of state.order) {
    for (const f of state.results[n].findings || []) {
      counts.total++;
      if (counts[f.severity] !== undefined) counts[f.severity]++;
    }
  }
  $("#stat-critical").textContent = counts.critical;
  $("#stat-high").textContent = counts.high;
  $("#stat-medium").textContent = counts.medium;
  $("#stat-low").textContent = counts.low;
  $("#stat-findings").textContent = counts.total;
}

// ---------------------------------------------------------------------
// Drawer
// ---------------------------------------------------------------------
function openDrawer(moduleName) {
  const r = state.results[moduleName];
  if (!r || r.phase === "running") return;
  $("#drawer-title").textContent = r.module;
  $("#drawer-sub").textContent = `${r.category || ""} · ${r.status || ""} · ${r.severity || "info"} · ${r.duration || 0}s`;
  const explain = state.explain || { modules: {}, findings: {} };
  const findings = r.findings || [];
  const modBlurb = explain.modules?.[r.module]
    ? `<div class="mod-explain">${escapeHtml(explain.modules[r.module])}</div>` : "";
  const findingsHtml = findings.length
    ? findings.map((f) => {
        const expl = explain.findings?.[f.type];
        return `<div class="finding-item ${f.severity}">
          <div class="fi-top"><span class="fi-name">${escapeHtml(f.name)} ${escapeHtml(f.value || "")}</span>${sevPill(f.severity)}</div>
          ${f.detail ? `<div class="fi-detail">${escapeHtml(f.detail)}</div>` : ""}
          ${expl ? `<div class="fi-explain">${escapeHtml(expl)}</div>` : ""}
        </div>`;
      }).join("")
    : `<div class="fi-detail">No findings for this module.</div>`;
  $("#drawer-findings").innerHTML = modBlurb + findingsHtml;
  $("#drawer-raw").textContent = r.raw_output || (r.error ? `[error] ${r.error}` : "(no raw output)");
  $("#drawer").classList.remove("hidden");
}
const closeDrawer = () => $("#drawer").classList.add("hidden");

// ---------------------------------------------------------------------
// Scan flow
// ---------------------------------------------------------------------
async function runScan() {
  if (state.scanning) return;
  const target = $("#target").value.trim();
  if (!target) return;
  const profile = $("#profile").value;

  state.scanning = true;
  state.target = target;
  state.results = {};
  state.order = [];
  toggleRunning(true);

  // live-elapsed ticker: re-render running rows so their timers/bars animate
  clearInterval(state.tick);
  state.tick = setInterval(() => {
    if (state.order.some((n) => state.results[n].phase === "running")) renderResults();
  }, 400);

  try {
    await Api.runScan(target, { profile }, {
      onStart: (selected) => {
        state.order = selected.slice();
        selected.forEach((n) => {
          state.results[n] = { module: n, phase: "waiting", severity: "info", status: "WAIT" };
        });
        renderResults();
        updateStats();
      },
      onModuleStart: (name) => {
        const prev = state.results[name] || {};
        state.results[name] = { ...prev, module: name, phase: "running", status: "RUN", startedAt: Date.now() };
        renderResults();
      },
      onModule: (evt) => {
        state.results[evt.module] = { ...(state.results[evt.module] || {}), ...evt };
        renderResults();
        updateStats();
      },
      onDone: () => {
        $("#export-btn").disabled = false;
        $("#report-btn").disabled = !state.live;
        $("#analyze-btn").disabled = !state.live;
        if (state.live) loadHistory();
      },
    });
  } catch (err) {
    alert(`Scan error: ${err.message}`);
  } finally {
    state.scanning = false;
    clearInterval(state.tick);
    renderResults();
    toggleRunning(false);
  }
}

function toggleRunning(on) {
  $("#run-btn").disabled = on;
  $("#stop-btn").disabled = !on;
  $("#run-btn").innerHTML = on ? `<span class="spinner"></span> Scanning` : `<span class="btn-ico">▶</span> Run scan`;
}

async function exportJson() {
  let payload;
  if (state.live && state.scanId) {
    payload = await Api.getScan(state.scanId);
  } else {
    payload = { target: state.target, results: state.order.map((n) => state.results[n]) };
  }
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `infiltr-scan-${state.scanId || Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(a.href);
}

function openReport() {
  if (state.live && state.scanId) {
    window.open(`${API_BASE}/scan/${state.scanId}/report?format=html`, "_blank");
  }
}

async function analyzeScan() {
  if (!state.live || !state.scanId) return;
  $("#drawer-title").textContent = "✦ Flint analysis";
  $("#drawer-sub").textContent = "analyzing…";
  $("#drawer-findings").innerHTML = `<div class="fi-detail"><span class="spinner"></span> Contacting analysis layer…</div>`;
  $("#drawer-raw").textContent = "";
  $("#drawer").classList.remove("hidden");
  try {
    const r = await fetch(`${API_BASE}/scan/${state.scanId}/analyze`, { method: "POST" });
    const a = await r.json();
    $("#drawer-sub").textContent = `mode: ${a.mode}`;
    const paths = (a.attack_paths || []).map((p) => `<li>${escapeHtml(p)}</li>`).join("");
    $("#drawer-findings").innerHTML = `
      <div class="finding-item high"><div class="fi-name">Summary</div><div class="fi-detail">${escapeHtml(a.summary)}</div></div>
      <div class="finding-item critical"><div class="fi-name">Most critical</div><div class="fi-detail">${escapeHtml(a.most_critical)}</div></div>
      <div class="finding-item medium"><div class="fi-name">Suggested next steps</div><div class="fi-detail"><ol style="margin-left:16px">${paths}</ol></div></div>`;
  } catch (err) {
    $("#drawer-findings").innerHTML = `<div class="fi-detail">Analysis failed: ${escapeHtml(err.message)}</div>`;
  }
}

// ---------------------------------------------------------------------
// Profiles
// ---------------------------------------------------------------------
async function loadProfiles() {
  const profiles = await Api.getProfiles();
  const sel = $("#profile");
  const current = sel.value;
  sel.innerHTML = profiles
    .map((p) => {
      // name (left of the dash) uppercased for display; value stays the real name
      const label = p.description ? `${p.name.toUpperCase()} — ${p.description}` : p.name.toUpperCase();
      const tag = p.builtin ? "" : " ★";
      return `<option value="${escapeHtml(p.name)}">${escapeHtml(label)}${tag}</option>`;
    })
    .join("");
  // remember module sets so the sim path can resolve them
  profiles.forEach((p) => { if (p.modules && p.modules.length) PROFILE_MODULES[p.name] = p.modules; });
  if ([...sel.options].some((o) => o.value === current)) sel.value = current;
}

async function saveProfile() {
  const profile = $("#profile").value;
  const modules = profile === "full" ? MODULE_META.map((m) => m.name) : (PROFILE_MODULES[profile] || []);
  const name = prompt("New profile name:", `${profile}-copy`);
  if (!name) return;
  const description = prompt("Description (optional):", "") || "";
  await Api.createProfile({ name, modules, description });
  await loadProfiles();
  $("#profile").value = name;
}

// ---------------------------------------------------------------------
// History
// ---------------------------------------------------------------------
async function loadHistory() {
  const scans = await Api.getScans();
  const body = $("#history-body");
  if (!scans.length) {
    body.innerHTML = `<tr class="empty-row"><td colspan="6">No scans recorded yet.</td></tr>`;
    return;
  }
  body.innerHTML = scans.map((s) => `<tr data-scan="${s.id}">
      <td class="mono">#${s.id}</td>
      <td class="mono">${escapeHtml(s.target)}</td>
      <td class="mono">${(s.started_at || "").slice(0, 19).replace("T", " ")}</td>
      <td class="mono">${s.module_count}</td>
      <td class="mono">${s.finding_count}</td>
      <td>${sevPill(s.top_severity || "info")}</td>
    </tr>`).join("");
  body.querySelectorAll("tr[data-scan]").forEach((tr) =>
    tr.addEventListener("click", () => loadScan(+tr.dataset.scan)));
}

async function loadScan(id) {
  const scan = await Api.getScan(id);
  if (!scan) return;
  state.results = {};
  state.order = [];
  state.scanId = id;
  state.target = scan.target;
  $("#target").value = scan.target;
  for (const r of scan.results) {
    state.order.push(r.module);
    state.results[r.module] = { ...r, phase: "done" };
  }
  switchView("scan");
  renderResults();
  updateStats();
  $("#export-btn").disabled = false;
  $("#report-btn").disabled = !state.live;
  $("#analyze-btn").disabled = !state.live;
}

// ---------------------------------------------------------------------
// Nav + init
// ---------------------------------------------------------------------
function switchView(view) {
  document.querySelectorAll(".nav-item").forEach((b) => b.classList.toggle("active", b.dataset.view === view));
  document.querySelectorAll(".view").forEach((v) => v.classList.add("hidden"));
  $(`#view-${view}`).classList.remove("hidden");
  if (view === "history" && state.live) loadHistory();
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

async function detectApi() {
  try {
    const r = await fetch(`${API_BASE}/health`, { cache: "no-store" });
    if (r.ok) return true;
  } catch (_) { /* no API */ }
  return false;
}

async function init() {
  state.live = await detectApi();
  Api = state.live ? LiveApi : SimApi;

  $("#conn-dot").className = "dot " + (state.live ? "dot-live" : "dot-idle");
  $("#conn-text").textContent = state.live ? "connected" : "offline (sim)";

  state.explain = await Api.getExplanations();
  const mods = await Api.getModules();
  renderSidebarModules(mods);
  renderModulesGrid(mods);
  await loadProfiles();
  if (state.live) loadHistory();

  $("#run-btn").addEventListener("click", runScan);
  $("#save-profile-btn").addEventListener("click", saveProfile);
  $("#export-btn").addEventListener("click", exportJson);
  $("#report-btn").addEventListener("click", openReport);
  $("#analyze-btn").addEventListener("click", analyzeScan);
  $("#drawer-close").addEventListener("click", closeDrawer);
  document.querySelectorAll(".nav-item").forEach((b) => b.addEventListener("click", () => switchView(b.dataset.view)));
  $("#target").addEventListener("keydown", (e) => { if (e.key === "Enter") runScan(); });
}

document.addEventListener("DOMContentLoaded", init);
