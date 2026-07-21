/* Infiltr console — front-end controller.
 *
 * Phase 0/1: runs against a local simulation (SIM = true).
 * Phase 4 swaps `Api` for real fetch()/SSE against the FastAPI backend.
 */
"use strict";

const SIM = true; // Phase 4 flips this via config.js / API detection.

const MODULE_META = [
  { name: "nmap",         category: "recon", desc: "Port scan + service/version detection" },
  { name: "theharvester", category: "recon", desc: "OSINT: emails, subdomains, hosts, IPs" },
  { name: "whatweb",      category: "recon", desc: "Web technology fingerprinting" },
  { name: "feroxbuster",  category: "web",   desc: "Recursive directory / file brute force" },
  { name: "ffuf",         category: "web",   desc: "Fast web fuzzer" },
  { name: "gobuster",     category: "web",   desc: "Directory / file brute forcing" },
  { name: "nikto",        category: "web",   desc: "Web server / CGI scanner" },
  { name: "sqlmap",       category: "web",   desc: "SQL injection detection" },
  { name: "wfuzz",        category: "web",   desc: "Web application fuzzer" },
  { name: "xsstrike",     category: "web",   desc: "Reflected / DOM XSS detection" },
  { name: "hydra",        category: "auth",  desc: "Network login brute forcer" },
];

const PROFILES = {
  full: MODULE_META.map((m) => m.name),
  quick: ["nmap", "whatweb"],
  "full-recon": ["nmap", "theharvester", "whatweb"],
  "web-audit": ["feroxbuster", "ffuf", "gobuster", "nikto", "sqlmap", "wfuzz", "xsstrike"],
  "auth-test": ["hydra"],
};

const SEV_ORDER = ["info", "low", "medium", "high", "critical"];
const sevRank = (s) => Math.max(0, SEV_ORDER.indexOf(s || "info"));

// ---------------------------------------------------------------------
// State
// ---------------------------------------------------------------------
const state = { results: {}, scanning: false, target: "", order: [] };
const $ = (sel) => document.querySelector(sel);

// ---------------------------------------------------------------------
// Simulation "API" — replaced by real API layer in Phase 4.
// ---------------------------------------------------------------------
const SimApi = {
  async getModules() {
    return MODULE_META.map((m) => ({ ...m, installed: true }));
  },
  // Emits {module, status, ...result} events via onEvent as each module "runs".
  async runScan(target, modules, { onStart, onModule, onDone }) {
    onStart(modules);
    for (const name of modules) {
      onModule({ module: name, phase: "running" });
      await sleep(400 + Math.random() * 900);
      onModule(simResult(target, name));
    }
    onDone();
  },
};

function simResult(target, name) {
  const meta = MODULE_META.find((m) => m.name === name);
  const bank = SIM_FINDINGS[name] || [];
  // randomly include a subset
  const findings = bank.filter(() => Math.random() > 0.35);
  const severity = findings.reduce((top, f) => (sevRank(f.severity) > sevRank(top) ? f.severity : top), "info");
  return {
    module: name,
    category: meta.category,
    target,
    status: "PASS",
    severity,
    duration: +(1 + Math.random() * 6).toFixed(1),
    findings,
    summary: findings.length ? `${findings.length} finding(s).` : "No findings.",
    raw_output: `$ ${name} ${target}\n[sim] ${findings.length} findings parsed.\n` +
      findings.map((f) => `  - [${f.severity}] ${f.name} ${f.value}`).join("\n"),
    phase: "done",
  };
}

const SIM_FINDINGS = {
  nmap: [
    { type: "open_port", name: "80/tcp", value: "http", detail: "Apache httpd 2.4.7", severity: "low" },
    { type: "open_port", name: "22/tcp", value: "ssh", detail: "OpenSSH 6.6.1", severity: "low" },
    { type: "open_port", name: "3306/tcp", value: "mysql", detail: "MySQL 5.5.44", severity: "medium" },
  ],
  whatweb: [
    { type: "technology", name: "Apache", value: "2.4.7", severity: "low" },
    { type: "technology", name: "PHP", value: "5.5.9", severity: "low" },
  ],
  theharvester: [
    { type: "email", name: "email", value: "admin@target.local", severity: "low" },
    { type: "subdomain", name: "host", value: "dev.target.local", severity: "info" },
  ],
  nikto: [
    { type: "finding", name: "OSVDB-3268", value: "/config/ directory indexing found", severity: "medium" },
    { type: "finding", name: "nikto", value: "Server leaks inodes via ETags", severity: "low" },
  ],
  sqlmap: [
    { type: "sqli", name: "injectable parameter", value: "id", detail: "boolean-based blind; error-based", severity: "critical" },
  ],
  hydra: [
    { type: "credential", name: "admin:password", value: "127.0.0.1", detail: "valid login admin / password", severity: "critical" },
  ],
  feroxbuster: [
    { type: "path", name: "http://t/admin", value: "301", severity: "medium" },
    { type: "path", name: "http://t/login.php", value: "200", severity: "low" },
  ],
  ffuf: [{ type: "path", name: "http://t/config", value: "403", severity: "medium" }],
  gobuster: [{ type: "path", name: "/backup", value: "200", severity: "low" }],
  wfuzz: [{ type: "path", name: "phpinfo.php", value: "200", severity: "low" }],
  xsstrike: [{ type: "xss", name: "reflected XSS", value: "<script>alert(1)</script>", severity: "high" }],
};

const Api = SIM ? SimApi : null; // Phase 4: real API assigned here.
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------
function renderSidebarModules(mods) {
  const ul = $("#module-list");
  ul.innerHTML = mods
    .map(
      (m) => `<li><span class="m-dot ${m.installed ? "on" : "off"}"></span>${m.name}<span class="m-cat">${m.category}</span></li>`
    )
    .join("");
}

function renderModulesGrid(mods) {
  $("#modules-grid").innerHTML = mods
    .map(
      (m) => `<div class="mod-card">
        <h3><span class="m-dot ${m.installed ? "on" : "off"}"></span>${m.name}</h3>
        <span class="mc-cat">${m.category}</span>
        <p>${m.desc}</p>
      </div>`
    )
    .join("");
}

function statusBadge(status, phase) {
  if (phase === "running") return `<span class="badge badge-run"><span class="spinner"></span> RUN</span>`;
  if (status === "PASS") return `<span class="badge badge-pass">PASS</span>`;
  if (status === "ERROR") return `<span class="badge badge-error">ERROR</span>`;
  return `<span class="badge badge-wait">WAIT</span>`;
}

function sevPill(sev) {
  return `<span class="sev-pill ${sev}">${sev}</span>`;
}

function renderRow(r) {
  const findings = r.findings ? r.findings.length : 0;
  return `<tr data-module="${r.module}">
    <td>${statusBadge(r.status, r.phase)}</td>
    <td class="mono">${r.module}</td>
    <td>${r.category || ""}</td>
    <td>${sevPill(r.severity || "info")}</td>
    <td class="mono">${r.phase === "running" ? "…" : findings}</td>
    <td class="mono">${r.duration ? r.duration + "s" : "—"}</td>
    <td>${r.summary || (r.phase === "running" ? "scanning…" : "")}</td>
  </tr>`;
}

function renderResults() {
  const body = $("#results-body");
  if (!state.order.length) {
    body.innerHTML = `<tr class="empty-row"><td colspan="7">No scan yet — set a target and hit <b>Run scan</b>.</td></tr>`;
    return;
  }
  body.innerHTML = state.order.map((name) => renderRow(state.results[name])).join("");
  body.querySelectorAll("tr[data-module]").forEach((tr) => {
    tr.addEventListener("click", () => openDrawer(tr.dataset.module));
  });
}

function updateStats() {
  const done = state.order.filter((n) => state.results[n].phase === "done").length;
  const pct = state.order.length ? Math.round((done / state.order.length) * 100) : 0;
  $("#stat-progress").innerHTML = `${pct}<span class="stat-unit">%</span>`;
  $("#progress-bar").style.width = pct + "%";

  const counts = { critical: 0, high: 0, medium: 0, low: 0, total: 0 };
  for (const n of state.order) {
    const r = state.results[n];
    if (!r.findings) continue;
    for (const f of r.findings) {
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
  $("#drawer-sub").textContent = `${r.category} · ${r.status} · ${r.severity} · ${r.duration || 0}s`;
  const findings = r.findings || [];
  $("#drawer-findings").innerHTML = findings.length
    ? findings
        .map(
          (f) => `<div class="finding-item ${f.severity}">
            <div class="fi-top"><span class="fi-name">${escapeHtml(f.name)} ${escapeHtml(f.value || "")}</span>${sevPill(f.severity)}</div>
            ${f.detail ? `<div class="fi-detail">${escapeHtml(f.detail)}</div>` : ""}
          </div>`
        )
        .join("")
    : `<div class="fi-detail">No findings for this module.</div>`;
  $("#drawer-raw").textContent = r.raw_output || "(no raw output)";
  $("#drawer").classList.remove("hidden");
}
function closeDrawer() { $("#drawer").classList.add("hidden"); }

// ---------------------------------------------------------------------
// Scan flow
// ---------------------------------------------------------------------
async function runScan() {
  if (state.scanning) return;
  const target = $("#target").value.trim();
  if (!target) return;
  const profile = $("#profile").value;
  const modules = PROFILES[profile] || PROFILES.full;

  state.scanning = true;
  state.target = target;
  state.results = {};
  state.order = modules.slice();
  modules.forEach((n) => {
    const meta = MODULE_META.find((m) => m.name === n);
    state.results[n] = { module: n, category: meta.category, phase: "waiting", severity: "info", status: "WAIT" };
  });
  toggleRunning(true);
  renderResults();
  updateStats();

  await Api.runScan(target, modules, {
    onStart: () => {},
    onModule: (evt) => {
      const prev = state.results[evt.module] || {};
      state.results[evt.module] = { ...prev, ...evt };
      renderResults();
      updateStats();
    },
    onDone: () => {
      state.scanning = false;
      toggleRunning(false);
      $("#export-btn").disabled = false;
      $("#report-btn").disabled = false;
    },
  });
}

function toggleRunning(on) {
  $("#run-btn").disabled = on;
  $("#stop-btn").disabled = !on;
  $("#run-btn").innerHTML = on ? `<span class="spinner"></span> Scanning` : `<span class="btn-ico">▶</span> Run scan`;
}

function exportJson() {
  const payload = { target: state.target, results: state.order.map((n) => state.results[n]) };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `infiltr-scan-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(a.href);
}

// ---------------------------------------------------------------------
// Nav + wiring
// ---------------------------------------------------------------------
function switchView(view) {
  document.querySelectorAll(".nav-item").forEach((b) => b.classList.toggle("active", b.dataset.view === view));
  document.querySelectorAll(".view").forEach((v) => v.classList.add("hidden"));
  $(`#view-${view}`).classList.remove("hidden");
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

async function init() {
  const mods = await Api.getModules();
  renderSidebarModules(mods);
  renderModulesGrid(mods);

  $("#run-btn").addEventListener("click", runScan);
  $("#export-btn").addEventListener("click", exportJson);
  $("#drawer-close").addEventListener("click", closeDrawer);
  document.querySelectorAll(".nav-item").forEach((b) => b.addEventListener("click", () => switchView(b.dataset.view)));
  $("#target").addEventListener("keydown", (e) => { if (e.key === "Enter") runScan(); });

  if (!SIM) $("#conn-text").textContent = "connecting…";
}

document.addEventListener("DOMContentLoaded", init);
