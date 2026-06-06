/* LinShield GUI controller — vanilla JS, polls the same Engine the CLI drives.
   Auth is the httponly session cookie set on first load, sent automatically
   on same-origin fetches. */

"use strict";

const $ = (s) => document.querySelector(s);
const $$ = (s) => Array.from(document.querySelectorAll(s));

async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...opts,
  });
  if (!res.ok) {
    let msg = res.status + "";
    try { msg = (await res.json()).error || msg; } catch (_) {}
    throw new Error(msg);
  }
  const ct = res.headers.get("content-type") || "";
  return ct.includes("application/json") ? res.json() : res.text();
}

function toast(msg, kind = "") {
  const t = $("#toast");
  t.textContent = msg;
  t.className = "toast show " + kind;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => (t.className = "toast"), 2600);
}

const fmtTime = (epoch) => {
  if (!epoch) return "—";
  const d = new Date(epoch * 1000);
  return d.toLocaleString([], { dateStyle: "short", timeStyle: "short" });
};
const fmtAgo = (epoch) => {
  if (!epoch) return "—";
  const s = Date.now() / 1000 - epoch;
  if (s < 60) return Math.round(s) + "s ago";
  if (s < 3600) return Math.round(s / 60) + "m ago";
  if (s < 86400) return Math.round(s / 3600) + "h ago";
  return Math.round(s / 86400) + "d ago";
};
const esc = (s) =>
  String(s == null ? "" : s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
  );
const sevBadge = (s) => `<span class="sev ${esc(s)}">${esc(s)}</span>`;

/* ---------------- navigation ---------------- */
const CRUMBS = {
  dashboard: "DASHBOARD", scan: "THREAT SCAN", quarantine: "QUARANTINE VAULT",
  history: "ACTIVITY HISTORY", tools: "SECURITY TOOLS", settings: "CONFIGURATION",
};
function go(view) {
  $$(".nav-item").forEach((n) => n.classList.toggle("active", n.dataset.view === view));
  $$(".view").forEach((v) => (v.hidden = v.id !== "view-" + view));
  $("#crumb").textContent = CRUMBS[view] || view.toUpperCase();
  if (view === "dashboard") loadDashboard();
  if (view === "quarantine") loadQuarantine();
  if (view === "history") loadHistory();
  if (view === "tools") loadSignatures();
  if (view === "settings") loadSettings();
}
$$(".nav-item").forEach((n) => n.addEventListener("click", () => go(n.dataset.view)));

/* ---------------- dashboard ---------------- */
function shieldSVG(safe) {
  const c = safe ? "#b6f24a" : "#ff6b5e";
  const glyph = safe
    ? `<path d="M44 76 l18 18 l34 -38" stroke="${c}" stroke-width="7" stroke-linecap="round" stroke-linejoin="round" fill="none"/>`
    : `<path d="M70 44 v34 M70 92 v.5" stroke="${c}" stroke-width="8" stroke-linecap="round" fill="none"/>`;
  return `<svg viewBox="0 0 140 150" fill="none" xmlns="http://www.w3.org/2000/svg">
    <path class="ring" d="M70 6 L130 30 V72 C130 112 102 134 70 146 C38 134 10 112 10 72 V30 Z"
          stroke="${c}" stroke-width="2" fill="none" opacity="0.4"/>
    <path d="M70 16 L120 36 V72 C120 106 96 124 70 135 C44 124 20 106 20 72 V36 Z"
          stroke="${c}" stroke-width="3" fill="${safe ? "rgba(182,242,74,0.06)" : "rgba(255,107,94,0.06)"}"/>
    ${glyph}
  </svg>`;
}

async function loadDashboard() {
  let st;
  try { st = await api("/api/status"); } catch (e) { toast("Status failed: " + e.message, "err"); return; }
  $("#brand-ver").textContent = "v" + (st.version || "1.0.0");
  window._strict = !!(st.config && st.config.strict_mode);

  const c = st.counts || {};
  animateNum($("#s-scans"), c.scans || 0);
  animateNum($("#s-det"), c.detections || 0);
  animateNum($("#s-quar"), c.quarantine || 0);
  animateNum($("#s-base"), c.baseline || 0);

  const det = c.detections || 0;
  const quar = c.quarantine || 0;
  const last = st.last_scan;
  const lastBad = last && (last.infected > 0);
  const safe = !lastBad && quar === 0;

  const hero = $("#hero");
  hero.classList.toggle("risk", !safe);
  $("#hero-shield").innerHTML = shieldSVG(safe);
  $("#hero-state").textContent = safe ? "PROTECTED" : "ATTENTION NEEDED";
  $("#hero-desc").textContent = safe
    ? "No active threats. All enabled engines are operational and the vault is clear."
    : `${quar} item(s) in quarantine` + (lastBad ? ` · last scan flagged ${last.infected} infected file(s).` : ".");

  $("#hero-meta").innerHTML = [
    ["Last scan", last ? fmtAgo(last.started) : "never"],
    ["Files (last)", last ? last.files : "—"],
    ["Firewall", (st.firewall && st.firewall.backend) || "unknown"],
    ["Real-time", st.realtime && st.realtime.running ? "active" : "off"],
  ].map(([k, v]) => `<div><span>${esc(k)}</span><b>${esc(v)}</b></div>`).join("");

  // engines
  const e = st.engines || {};
  const eng = [];
  const chip = (on, label, extra = "") =>
    `<span class="chip ${on ? "on" : "off"}"><span class="led"></span>${esc(label)}${extra ? ` · ${esc(extra)}` : ""}</span>`;
  if (e.hashes) eng.push(chip(e.hashes.enabled, "Hashes", e.hashes.count + " sigs"));
  if (e.yara) eng.push(chip(e.yara.enabled && e.yara.available, "YARA", e.yara.available ? e.yara.rules + " rules" : "n/a"));
  if (e.clamav) eng.push(chip(e.clamav.enabled && e.clamav.available, "ClamAV", e.clamav.available ? e.clamav.engine : "absent"));
  if (e.heuristics) eng.push(chip(e.heuristics.enabled, "Heuristics"));
  $("#engines").innerHTML = eng.join("");

  // perimeter
  const fw = st.firewall || {};
  const rt = st.realtime || {};
  $("#perimeter").innerHTML =
    `<span class="chip ${fw.active ? "on" : "warn"}"><span class="led"></span>Firewall · ${esc(fw.backend || "none")}${fw.active ? " active" : " inactive"}</span>` +
    `<span class="chip ${rt.running ? "on" : "off"}"><span class="led"></span>Real-time · ${rt.running ? "running" : "stopped"}</span>`;

  renderRtp(rt);
  if (rt.running && !rtpPoll) {
    rtpPoll = setInterval(refreshRtpStats, 4000);
    refreshRtpStats();
  }
}

function renderRtp(rt) {
  const on = !!rt.running;
  $("#rtp-card").classList.toggle("on", on);
  const tog = $("#rtp-toggle");
  tog.checked = on;
  const stats = rt.stats || { scanned: 0, detected: 0, quarantined: 0 };
  $("#rtp-stats").hidden = !on;
  if (on) {
    $("#rtp-scanned").textContent = stats.scanned || 0;
    $("#rtp-detected").textContent = stats.detected || 0;
    $("#rtp-quar").textContent = stats.quarantined || 0;
    const paths = rt.paths || [];
    $("#rtp-paths").textContent = paths.length ? paths.length + " path(s)" : "none";
    $("#rtp-paths").title = paths.join("\n");
  }
  $("#rtp-desc").textContent = on
    ? "Active — files are scanned the moment they're written."
    : "Continuously scans files as they're written and isolates threats on contact.";
}

let rtpPoll = null;
async function setRtp(enable) {
  const tog = $("#rtp-toggle");
  tog.disabled = true;
  try {
    const r = await api(`/api/realtime/${enable ? "start" : "stop"}`, { method: "POST" });
    if (!r.ok) throw new Error(r.error || "failed");
    toast(enable ? "Real-time protection enabled" : "Real-time protection disabled", "ok");
    const rt = await api("/api/realtime");
    renderRtp(rt);
    clearInterval(rtpPoll);
    if (enable) rtpPoll = setInterval(refreshRtpStats, 4000);
  } catch (e) {
    toast("Could not change protection: " + e.message, "err");
    tog.checked = !enable;
  } finally {
    tog.disabled = false;
  }
}

async function refreshRtpStats() {
  // Only refresh while the dashboard is visible and protection is on.
  if ($(".nav-item.active").dataset.view !== "dashboard") return;
  try {
    const rt = await api("/api/realtime");
    if (!rt.running) { clearInterval(rtpPoll); }
    renderRtp(rt);
  } catch (_) {}
}

function animateNum(el, target) {
  target = Number(target) || 0;
  const start = Number(el.dataset.v || 0);
  const t0 = performance.now();
  const dur = 480;
  function step(t) {
    const p = Math.min(1, (t - t0) / dur);
    const eased = 1 - Math.pow(1 - p, 3);
    el.textContent = Math.round(start + (target - start) * eased);
    if (p < 1) requestAnimationFrame(step);
    else el.dataset.v = target;
  }
  requestAnimationFrame(step);
}

/* ---------------- scan ---------------- */
let scanMode = "quick";
let pollTimer = null;

$$(".mode").forEach((m) =>
  m.addEventListener("click", () => {
    $$(".mode").forEach((x) => x.classList.remove("sel"));
    m.classList.add("sel");
    scanMode = m.dataset.mode;
    $("#custom-field").hidden = scanMode !== "custom";
  })
);

$("#btn-scan").addEventListener("click", async () => {
  const body = { type: scanMode, quarantine: $("#scan-autoq").checked };
  if (scanMode === "custom") {
    const paths = $("#custom-paths").value.split("\n").map((s) => s.trim()).filter(Boolean);
    if (!paths.length) return toast("Enter at least one path", "err");
    body.paths = paths;
  }
  try {
    await api("/api/scan/start", { method: "POST", body: JSON.stringify(body) });
  } catch (e) { return toast("Could not start: " + e.message, "err"); }
  $("#btn-scan").disabled = true;
  $("#btn-cancel").disabled = false;
  $("#progress").hidden = false;
  $("#scan-result").hidden = true;
  pollScan();
});

$("#btn-cancel").addEventListener("click", async () => {
  try { await api("/api/scan/cancel", { method: "POST" }); toast("Cancelling…"); } catch (_) {}
});

function pollScan() {
  clearTimeout(pollTimer);
  api("/api/scan/progress")
    .then((p) => {
      if (!p.active && !p.done) { resetScanBtns(); return; }
      $("#scan-count").textContent = (p.files || 0) + " files";
      $("#scan-cur").textContent = p.current || "—";
      $("#scan-elapsed").textContent = (p.elapsed || 0) + "s";
      if (p.done && p.summary) { renderScanResult(p.summary); resetScanBtns(); return; }
      pollTimer = setTimeout(pollScan, 500);
    })
    .catch(() => { resetScanBtns(); });
}

function resetScanBtns() {
  $("#btn-scan").disabled = false;
  $("#btn-cancel").disabled = true;
  $("#progress").hidden = true;
}

const confBadge = (c) => {
  const map = { confirmed: "Confirmed", likely: "Likely", review: "Review" };
  return `<span class="conf ${esc(c || "review")}">${esc(map[c] || "Review")}</span>`;
};
const CONF_RANK = { confirmed: 0, likely: 1, review: 2 };

function renderScanResult(s) {
  $("#scan-result").hidden = false;
  $("#r-files").textContent = s.files_scanned || 0;
  $("#r-confirmed").textContent = s.confirmed || 0;
  $("#r-likely").textContent = s.likely || 0;
  $("#r-review").textContent = s.review || 0;
  lastDetections = (s.detections || []).slice();
  if (window._strict) lastDetections = lastDetections.filter((d) => d.confidence !== "review");
  lastDetections.sort((a, b) =>
    (CONF_RANK[a.confidence] ?? 2) - (CONF_RANK[b.confidence] ?? 2)
  );

  const rows = lastDetections.map((d, i) => {
    const conf = d.confidence || "review";
    // Confirmed/likely get a Quarantine action; everything actionable gets Trust.
    const quar = (conf === "confirmed" || conf === "likely")
      ? `<button class="btn sm danger" data-quar="${i}">Quarantine</button>` : "";
    const action = `<div class="cell-actions">
        <button class="btn sm" data-trust="${i}" title="Allowlist this path">Trust</button>
        ${quar}
      </div>`;
    return `<tr data-row="${i}">
      <td class="path" title="${esc(d.path)}">${esc(d.path)}</td>
      <td>${confBadge(conf)}</td>
      <td class="mono">${esc(d.signature)}</td>
      <td class="mono">${esc(d.method)}</td>
      <td>${sevBadge(d.severity)}</td>
      <td data-action>${action}</td></tr>`;
  }).join("");

  $("#r-rows").innerHTML = rows ||
    `<tr><td colspan="6" class="empty" style="padding:24px">No threats found — clean.</td></tr>`;
  $("#r-review-note").hidden = (s.review || 0) === 0;

  const actionable = lastDetections.filter(
    (d) => d.confidence === "confirmed" || d.confidence === "likely"
  ).length;
  $("#btn-quar-all").hidden = actionable === 0;

  $$("#r-rows [data-quar]").forEach((b) =>
    b.addEventListener("click", () => quarantineRow(parseInt(b.dataset.quar, 10), b))
  );
  $$("#r-rows [data-trust]").forEach((b) =>
    b.addEventListener("click", () => trustRow(parseInt(b.dataset.trust, 10), b))
  );

  if ((s.confirmed || 0) > 0) toast(`${s.confirmed} confirmed threat(s)`, "err");
  else if ((s.likely || 0) > 0) toast(`${s.likely} likely threat(s) — review`, "");
  else if ((s.review || 0) > 0) toast(`${s.review} low-confidence item(s) to review`, "");
  else toast("Scan complete — clean", "ok");
}

async function quarantineDetection(d) {
  return api("/api/quarantine/file", {
    method: "POST",
    body: JSON.stringify({
      path: d.path, verdict: d.verdict, method: d.method,
      signature: d.signature, severity: d.severity, sha256: d.sha256 || "",
    }),
  });
}

async function quarantineRow(i, btn) {
  const d = lastDetections[i];
  if (!d) return;
  btn.disabled = true;
  try {
    await quarantineDetection(d);
    const cell = btn.closest("td");
    cell.innerHTML = `<span class="quar-done">✓ Quarantined</span>`;
    toast("File quarantined", "ok");
  } catch (e) {
    btn.disabled = false;
    toast("Quarantine failed: " + e.message, "err");
  }
}

async function trustRow(i, btn) {
  const d = lastDetections[i];
  if (!d) return;
  const path = d.path.split("!")[0]; // archive members → trust the container
  if (!confirm(`Trust "${path}"?\nLinShield will no longer scan or flag it.`)) return;
  btn.disabled = true;
  try {
    await api("/api/trust", { method: "POST", body: JSON.stringify({ path }) });
    const cell = btn.closest("td");
    cell.innerHTML = `<span class="quar-done" style="color:var(--cyan)">✓ Trusted</span>`;
    toast("Path added to trust allowlist", "ok");
  } catch (e) {
    btn.disabled = false;
    toast("Trust failed: " + e.message, "err");
  }
}

$("#btn-quar-all").addEventListener("click", async () => {
  const btn = $("#btn-quar-all");
  btn.disabled = true;
  const targets = lastDetections
    .map((d, i) => ({ d, i }))
    .filter(({ d }) => d.confidence === "confirmed" || d.confidence === "likely");
  let ok = 0, fail = 0;
  const seen = new Set();
  for (const { d, i } of targets) {
    if (seen.has(d.path)) continue; // a file can have multiple detections
    seen.add(d.path);
    try {
      await quarantineDetection(d);
      ok++;
      const cell = document.querySelector(`#r-rows tr[data-row="${i}"] [data-action]`);
      if (cell) cell.innerHTML = `<span class="quar-done">✓ Quarantined</span>`;
    } catch (_) { fail++; }
  }
  btn.hidden = true;
  toast(`Quarantined ${ok} item(s)` + (fail ? `, ${fail} failed` : ""), fail ? "err" : "ok");
});

/* ---------------- quarantine ---------------- */
async function loadQuarantine() {
  let items;
  try { items = await api("/api/quarantine"); } catch (e) { return toast(e.message, "err"); }
  $("#q-empty").hidden = items.length > 0;
  $("#q-rows").innerHTML = items.map((q) =>
    `<tr>
      <td class="mono">#${q.qid}</td>
      <td class="path" title="${esc(q.original_path)}">${esc(q.original_path)}</td>
      <td class="mono">${esc(q.signature || "—")}</td>
      <td>${sevBadge(q.severity || "low")}</td>
      <td class="mono-txt">${fmtAgo(q.quarantined_at)}</td>
      <td><div class="cell-actions">
        <button class="btn sm" data-q="${q.qid}" data-act="restore">Restore</button>
        <button class="btn sm danger" data-q="${q.qid}" data-act="delete">Delete</button>
      </div></td>
    </tr>`).join("");
  $$("#q-rows [data-q]").forEach((b) =>
    b.addEventListener("click", () => qAction(b.dataset.q, b.dataset.act))
  );
}
async function qAction(qid, act) {
  if (act === "delete" && !confirm("Permanently delete this quarantined file?")) return;
  try {
    await api(`/api/quarantine/${qid}/${act}`, { method: "POST" });
    toast(act === "restore" ? "File restored" : "File deleted", "ok");
    loadQuarantine();
  } catch (e) { toast(e.message, "err"); }
}

/* ---------------- history ---------------- */
async function loadHistory() {
  let h;
  try { h = await api("/api/history"); } catch (e) { return toast(e.message, "err"); }
  const scans = h.scans || [], det = h.detections || [], evt = h.events || [];
  $("#h-scans-empty").hidden = scans.length > 0;
  $("#h-scans").innerHTML = scans.map((s) =>
    `<tr><td class="mono">#${s.id}</td><td class="mono">${esc(s.scan_type)}</td>
     <td>${s.files}</td><td class="verdict ${s.infected ? "infected" : ""}">${s.infected}</td>
     <td class="verdict ${s.suspicious ? "suspicious" : ""}">${s.suspicious}</td>
     <td class="mono-txt">${fmtTime(s.started)}</td></tr>`).join("");
  $("#h-det-empty").hidden = det.length > 0;
  $("#h-det").innerHTML = det.map((d) =>
    `<tr><td class="path" title="${esc(d.path)}">${esc(d.path)}</td>
     <td class="verdict ${esc(d.verdict)}">${esc(d.verdict)}</td>
     <td class="mono">${esc(d.signature)}</td><td>${sevBadge(d.severity)}</td>
     <td class="mono-txt">${fmtTime(d.ts)}</td></tr>`).join("");
  $("#h-evt-empty").hidden = evt.length > 0;
  $("#h-evt").innerHTML = evt.map((e) =>
    `<tr><td class="mono">${esc(e.category)}</td><td>${esc(e.title)}</td>
     <td>${sevBadge(e.severity)}</td><td class="path">${esc(e.detail || "")}</td>
     <td class="mono-txt">${fmtTime(e.ts)}</td></tr>`).join("");
}

/* ---------------- tools ---------------- */
function findingsCard(title, findings) {
  const rows = findings.map((f) =>
    `<tr><td class="mono">${esc(f.category)}</td><td>${esc(f.title)}</td>
     <td>${sevBadge(f.severity)}</td><td class="path">${esc(f.detail || "")}</td></tr>`).join("");
  return `<div class="section-title">${esc(title)}</div><div class="card">
    <table><thead><tr><th>Category</th><th>Finding</th><th>Severity</th><th>Detail</th></tr></thead>
    <tbody>${rows}</tbody></table></div>`;
}

$("#btn-rootkit").addEventListener("click", async () => {
  toast("Running rootkit sweep…");
  try {
    const f = await api("/api/rootkit", { method: "POST" });
    $("#tool-out").innerHTML = findingsCard("Rootkit Sweep Results", f);
  } catch (e) { toast(e.message, "err"); }
});
$("#btn-fim-init").addEventListener("click", async () => {
  try {
    const r = await api("/api/fim/init", { method: "POST" });
    toast(`Baseline built — ${r.count} files tracked`, "ok");
  } catch (e) { toast(e.message, "err"); }
});
$("#btn-fim-check").addEventListener("click", async () => {
  try {
    const f = await api("/api/fim/check", { method: "POST" });
    $("#tool-out").innerHTML = findingsCard("File Integrity Check", f);
  } catch (e) { toast(e.message, "err"); }
});
$("#btn-fw").addEventListener("click", async () => {
  try {
    const fw = await api("/api/firewall");
    $("#tool-out").innerHTML = `<div class="section-title">Firewall Status</div>
      <div class="card"><div class="chip-row">
        <span class="chip ${fw.active ? "on" : "warn"}"><span class="led"></span>${esc(fw.backend || "none")}</span>
        <span class="chip ${fw.active ? "on" : "off"}"><span class="led"></span>${fw.active ? "ACTIVE" : "INACTIVE"}</span>
      </div><p style="color:var(--text-dim);margin-top:12px;font-size:12.5px">${esc(fw.detail || "")}</p></div>`;
  } catch (e) { toast(e.message, "err"); }
});

/* ---------------- settings ---------------- */
const lines = (s) => s.split("\n").map((x) => x.trim()).filter(Boolean);

async function loadSettings() {
  let cfg;
  try { cfg = await api("/api/settings"); } catch (e) { return toast(e.message, "err"); }
  $$("[data-cfg]").forEach((el) => { el.checked = !!cfg[el.dataset.cfg]; });
  $("#cfg-maxsize").value = cfg.max_file_size_mb || 256;
  $("#cfg-quick").value = (cfg.quick_scan_paths || []).join("\n");
  $("#cfg-full").value = (cfg.full_scan_roots || []).join("\n");
  $("#cfg-realtime").value = (cfg.realtime_paths || []).join("\n");
  $("#cfg-fim").value = (cfg.fim_paths || []).join("\n");
  $("#cfg-exclude").value = (cfg.exclude || []).join("\n");
  $("#cfg-trusted").value = (cfg.trusted_paths || []).join("\n");
  if ($("#cfg-webhook")) $("#cfg-webhook").value = cfg.alert_webhook || "";
  $("#cfg-host").value = cfg.gui_host || "127.0.0.1";
  $("#cfg-port").value = cfg.gui_port || 8920;
}

$("#btn-save-cfg").addEventListener("click", async () => {
  const body = {};
  $$("[data-cfg]").forEach((el) => { body[el.dataset.cfg] = el.checked; });
  body.max_file_size_mb = parseInt($("#cfg-maxsize").value, 10) || 256;
  body.quick_scan_paths = lines($("#cfg-quick").value);
  body.full_scan_roots = lines($("#cfg-full").value);
  body.realtime_paths = lines($("#cfg-realtime").value);
  body.fim_paths = lines($("#cfg-fim").value);
  body.exclude = lines($("#cfg-exclude").value);
  body.trusted_paths = lines($("#cfg-trusted").value);
  if ($("#cfg-webhook")) body.alert_webhook = $("#cfg-webhook").value.trim();
  body.gui_host = $("#cfg-host").value.trim() || "127.0.0.1";
  body.gui_port = parseInt($("#cfg-port").value, 10) || 8920;
  try {
    await api("/api/settings", { method: "POST", body: JSON.stringify(body) });
    toast("Settings saved", "ok");
  } catch (e) { toast(e.message, "err"); }
});
$("#btn-reset-cfg").addEventListener("click", () => { loadSettings(); toast("Reloaded"); });

/* ---------------- real-time protection toggle ---------------- */
$("#rtp-toggle").addEventListener("change", (e) => setRtp(e.target.checked));

/* ---------------- signature management (tools) ---------------- */
async function loadSignatures() {
  let info;
  try { info = await api("/api/signatures"); } catch (e) { return toast(e.message, "err"); }
  const e = info.engines || {};
  const hashN = (e.hashes && e.hashes.count) || 0;
  const yaraN = (e.yara && e.yara.rules) || 0;
  const yAvail = e.yara && e.yara.available;
  $("#yara-count").className = "chip " + (yAvail ? "on" : "warn");
  $("#yara-count").innerHTML = `<span class="led"></span>${yAvail ? yaraN + " rules loaded" : "YARA engine unavailable"}`;
  $("#hash-count-line").textContent = `${hashN} hash signature(s) loaded · rules dir: ${info.yara_dir}`;
  $("#upd-total").className = "chip " + (yAvail ? "on" : "warn");
  $("#upd-total").innerHTML = `<span class="led"></span>${yaraN} YARA rules active`;

  // populate the community-source dropdown once
  const sel = $("#upd-source");
  if (sel && !sel.dataset.loaded) {
    try {
      const { sources } = await api("/api/yara/sources");
      sel.innerHTML = sources.map((s) => `<option value="${esc(s.name)}">${esc(s.name)}</option>`).join("");
      sel.dataset.loaded = "1";
      window._updSources = sources;
      updDesc();
      sel.addEventListener("change", updDesc);
    } catch (_) {}
  }

  const files = info.user_rules || [];
  if (!files.length) {
    $("#yara-list").innerHTML = `<div class="empty" style="padding:14px">No imported rule files yet.</div>`;
  } else {
    $("#yara-list").innerHTML =
      `<div class="section-title" style="margin:0 0 8px">Imported rule files</div>` +
      files.map((f) =>
        `<div class="toggle-row"><div class="tl mono-txt">${esc(f.name)}<small>${f.rules} rule(s) · ${f.size} B</small></div>
         <button class="btn sm danger" data-del="${esc(f.name)}">Remove</button></div>`).join("");
    $$("#yara-list [data-del]").forEach((b) =>
      b.addEventListener("click", () => deleteYara(b.dataset.del))
    );
  }
}

function updDesc() {
  const sel = $("#upd-source");
  const s = (window._updSources || []).find((x) => x.name === sel.value);
  $("#upd-desc").textContent = s ? `${s.description}  ·  license: ${s.license}` : "";
}

$("#btn-update").addEventListener("click", async () => {
  const source = $("#upd-source").value;
  if (!source) return;
  const btn = $("#btn-update");
  btn.disabled = true;
  const orig = btn.textContent;
  btn.textContent = "Updating…";
  $("#upd-out").innerHTML = `<div class="empty" style="padding:12px">Downloading and validating ${esc(source)} — this can take up to a minute…</div>`;
  try {
    const r = await api("/api/yara/update", { method: "POST", body: JSON.stringify({ source }) });
    $("#upd-out").innerHTML =
      `<div class="card" style="background:var(--ink-850);padding:14px;margin-top:8px">
        <div class="mono-txt" style="color:var(--lime)">✓ ${esc(source)} installed</div>
        <div class="mono-txt" style="color:var(--text-dim);margin-top:6px;font-size:12px">
          ${r.files} file(s) · ${r.rules} rules · ${r.skipped} skipped · ${r.yara_rules_total} total active
        </div>
        ${(r.errors && r.errors.length) ? `<div class="mono-txt" style="color:var(--amber);margin-top:6px;font-size:11.5px">${r.errors.map(esc).join("<br>")}</div>` : ""}
      </div>`;
    toast(`Installed ${r.rules} rules from ${source}`, "ok");
    loadSignatures();
  } catch (e) {
    $("#upd-out").innerHTML = `<div class="card" style="background:var(--ink-850);padding:14px;margin-top:8px"><span style="color:var(--coral)">Update failed: ${esc(e.message)}</span></div>`;
    toast("Update failed: " + e.message, "err");
  } finally {
    btn.disabled = false;
    btn.textContent = orig;
  }
});

$("#yara-file").addEventListener("change", (ev) => {
  const file = ev.target.files && ev.target.files[0];
  if (!file) return;
  if (!$("#yara-name").value.trim()) $("#yara-name").value = file.name;
  const reader = new FileReader();
  reader.onload = () => { $("#yara-text").value = String(reader.result || ""); toast("File loaded — review, then Import"); };
  reader.readAsText(file);
});

$("#btn-yara-import").addEventListener("click", async () => {
  const rules = $("#yara-text").value;
  if (!rules.trim()) return toast("Paste or load a ruleset first", "err");
  const btn = $("#btn-yara-import"); btn.disabled = true;
  try {
    const r = await api("/api/yara/import", {
      method: "POST",
      body: JSON.stringify({ rules, name: $("#yara-name").value.trim() }),
    });
    toast(`Imported · ${r.yara_rules_total} YARA rules active`, "ok");
    $("#yara-text").value = ""; $("#yara-name").value = "";
    loadSignatures();
  } catch (e) {
    toast("Import failed: " + e.message, "err");
  } finally { btn.disabled = false; }
});

async function deleteYara(name) {
  if (!confirm(`Remove rule file "${name}"?`)) return;
  try {
    await api("/api/yara/delete", { method: "POST", body: JSON.stringify({ name }) });
    toast("Removed", "ok");
    loadSignatures();
  } catch (e) { toast(e.message, "err"); }
}

$("#btn-add-hash").addEventListener("click", async () => {
  const sha256 = $("#hash-digest").value.trim().toLowerCase();
  const name = $("#hash-name").value.trim();
  const severity = $("#hash-sev").value;
  if (!/^[0-9a-f]{64}$/.test(sha256)) return toast("Enter a valid 64-char SHA-256", "err");
  try {
    const r = await api("/api/signatures/add-hash", {
      method: "POST", body: JSON.stringify({ sha256, name, severity }),
    });
    toast(`Signature added · ${r.hash_count} total`, "ok");
    $("#hash-digest").value = ""; $("#hash-name").value = "";
    loadSignatures();
  } catch (e) { toast("Failed: " + e.message, "err"); }
});

$("#btn-sig-reload").addEventListener("click", async () => {
  try { await api("/api/signatures/reload", { method: "POST" }); toast("Signatures reloaded", "ok"); loadSignatures(); }
  catch (e) { toast(e.message, "err"); }
});

/* ---------------- top bar ---------------- */
$("#btn-refresh").addEventListener("click", () => {
  const active = $(".nav-item.active").dataset.view;
  go(active);
  toast("Refreshed");
});
$("#btn-report").addEventListener("click", () => {
  window.open("/api/report?format=html", "_blank");
});

/* ---------------- boot ---------------- */
loadDashboard();
