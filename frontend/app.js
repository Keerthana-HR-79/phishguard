// PhishGuard AI — website logic for both pages (URL checker + dashboard).

const API_BASE = location.hostname === "localhost" || location.hostname === "127.0.0.1"
  ? "http://127.0.0.1:8000"
  : "https://phishguard-ai-simple-api.onrender.com";   // Render service "phishguard-ai-simple-api"; update after deploy

const COLORS = { PHISHING: "#ef4444", SUSPICIOUS: "#f59e0b", SAFE: "#22c55e" };
const ICONS  = { PHISHING: "🚨", SUSPICIOUS: "⚠️", SAFE: "✅" };
const $ = (id) => document.getElementById(id);

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

async function api(path, options = {}) {
  const res = await fetch(API_BASE + path, { ...options, signal: AbortSignal.timeout(15000) });
  if (res.status === 429) throw new Error("too many checks, try again in a minute");
  if (!res.ok) throw new Error(`API returned ${res.status}`);
  return res.json();
}

// ── URL checker ──────────────────────────────────────────────────────────────
async function check() {
  const url = $("urlInput").value.trim();
  $("error").hidden = true;
  $("result").innerHTML = "";
  if (!url) return;

  $("checkBtn").disabled = true;
  $("checkBtn").textContent = "Checking…";
  try {
    const d = await api("/predict_url", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    const color = COLORS[d.result];
    $("result").innerHTML = `
      <div class="rc-card" style="border-color:${color}55">
        <div class="rc-header">
          <div class="rc-icon">${ICONS[d.result]}</div>
          <div>
            <div class="rc-verdict" style="color:${color}">${esc(d.result)}</div>
            <div class="rc-sub">Risk score: ${d.risk_score.toFixed(1)} / 10</div>
          </div>
        </div>
        <div class="rc-bar-track"><div class="rc-bar-fill" style="width:${d.risk_score * 10}%;background:${color}"></div></div>
        <div class="rc-reasons"><div class="rc-reasons-title">Why</div>
          <ul>${d.reasons.map((r) => `<li>${esc(r)}</li>`).join("")}</ul></div>
        <div class="rc-meta">
          <div class="rc-meta-row"><span class="rc-meta-key">Domain</span><span class="rc-meta-val">${esc(d.domain)}</span></div>
          <div class="rc-meta-row"><span class="rc-meta-key">ML probability</span><span class="rc-meta-val">${(d.ml_probability * 100).toFixed(1)}%</span></div>
          <div class="rc-meta-row"><span class="rc-meta-key">Domain age</span><span class="rc-meta-val">${d.domain_age_days == null ? "Not checked / unknown" : `${d.domain_age_days} days`}</span></div>
        </div>
      </div>`;
  } catch (e) {
    $("error").textContent = `Could not reach the API at ${API_BASE} (${e.message}).`;
    $("error").hidden = false;
  } finally {
    $("checkBtn").disabled = false;
    $("checkBtn").textContent = "Check";
  }
}

function initChecker() {
  $("checkBtn").addEventListener("click", check);
  $("urlInput").addEventListener("keydown", (e) => { if (e.key === "Enter") check(); });
  for (const ex of ["https://secure-login-update-account.com", "http://45.12.67.89/login",
                    "https://paypa1.com@secure-update.xyz", "https://google.com"]) {
    const b = document.createElement("button");
    b.className = "exBtn";
    b.textContent = ex;
    b.onclick = () => { $("urlInput").value = ex; check(); };
    $("examples").appendChild(b);
  }
}

// ── Dashboard ────────────────────────────────────────────────────────────────
async function loadDashboard() {
  const root = $("dashboardRoot");
  try {
    const [s, recent] = await Promise.all([api("/stats"), api("/recent?limit=15")]);

    const kpis = [
      [s.total_scans, "Total Scans", ""], [s.phishing_count, "Phishing", COLORS.PHISHING],
      [s.suspicious_count, "Suspicious", COLORS.SUSPICIOUS], [s.safe_count, "Safe", COLORS.SAFE],
      [`${s.detection_rate}%`, "Detection Rate", ""], [`${s.avg_response_time_ms} ms`, "Avg Response", ""],
    ].map(([v, label, c]) => `<div class="statCard"><div class="statVal" style="color:${c}">${esc(v)}</div>
      <div class="statLabel">${label}</div></div>`).join("");

    const max = Math.max(1, ...s.daily_breakdown.map((d) => d.total));
    const bars = s.daily_breakdown.map((d) => `<div class="bar"><div class="barWrap">
      <div class="barTotal" style="height:${d.total / max * 100}%"></div>
      <div class="barPhishing" style="height:${d.phishing / max * 100}%"></div></div>
      <div class="barLabel">${esc(d.day.slice(5))}</div></div>`).join("");

    const rows = recent.map((e) => `<tr><td class="tdMuted">${esc(e.timestamp.slice(11, 19))}</td>
      <td class="tdContent">${esc(e.domain)}</td>
      <td><span class="badge badge-${e.result.toLowerCase()}">${esc(e.result)}</span></td>
      <td class="tdScore">${e.risk_score.toFixed(1)}</td></tr>`).join("");

    const threats = s.top_threats.map((t) => `<tr><td class="tdContent">${esc(t.domain)}</td>
      <td class="tdScore">${t.count}</td></tr>`).join("");

    root.innerHTML = `
      <div class="kpiGrid">${kpis}</div>
      <div class="chartCard"><div class="chartTitle">Last 7 days</div>
        ${bars ? `<div class="chart">${bars}</div>
        <div class="chartLegend"><span>■ Total</span><span style="color:${COLORS.PHISHING}">■ Phishing</span></div>`
               : `<div class="noData">No scans yet.</div>`}</div>
      <div class="tableCard"><div class="tableTitle">Recent scans</div><div class="tableWrap">
        <table class="table"><thead><tr><th>Time</th><th>Domain</th><th>Result</th><th>Score</th></tr></thead>
        <tbody>${rows}</tbody></table></div></div>
      ${threats ? `<div class="tableCard"><div class="tableTitle">Most-flagged domains</div><div class="tableWrap">
        <table class="table"><thead><tr><th>Domain</th><th>Times flagged</th></tr></thead>
        <tbody>${threats}</tbody></table></div></div>` : ""}`;
  } catch (e) {
    root.innerHTML = `<div class="error">Could not load the dashboard from ${esc(API_BASE)} (${esc(e.message)}).</div>`;
  }
}

if ($("checkBtn")) initChecker();
if ($("dashboardRoot")) {
  $("refreshBtn").addEventListener("click", loadDashboard);
  loadDashboard();
}
