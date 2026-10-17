// PhishGuard AI — background worker.
// Checks every page you open, sets the icon badge, and shows a warning banner
// on phishing pages. The popup asks this worker for results too, so the API
// address and the cache live in one place.

const API_BASE = "https://phishguard-backend-v2-qxrz.onrender.com";  // or http://localhost:8000
const CACHE_MS = 60 * 1000;
const cache = new Map();   // url -> { data, time }

async function checkUrl(url) {
  const hit = cache.get(url);
  if (hit && Date.now() - hit.time < CACHE_MS) return hit.data;

  const res = await fetch(`${API_BASE}/predict_url`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
    signal: AbortSignal.timeout(10000),
  });
  if (!res.ok) throw new Error(`API error ${res.status}`);
  const data = await res.json();
  cache.set(url, { data, time: Date.now() });
  if (cache.size > 200) cache.delete(cache.keys().next().value);
  return data;
}

function isCheckable(url) {
  return /^https?:\/\//.test(url || "");
}

function setBadge(tabId, result) {
  const badge = {
    PHISHING:   ["⛔", "#ef4444"],
    SUSPICIOUS: ["⚠", "#f59e0b"],
    SAFE:       ["✓", "#22c55e"],
  }[result];
  if (!badge) return;
  chrome.action.setBadgeText({ tabId, text: badge[0] });
  chrome.action.setBadgeBackgroundColor({ tabId, color: badge[1] });
}

// Runs inside the page. Uses textContent only, so reason text can never inject HTML.
function showBanner(score, reasons) {
  if (document.getElementById("phishguard-banner")) return;
  const bar = document.createElement("div");
  bar.id = "phishguard-banner";
  bar.setAttribute("role", "alert");
  bar.style.cssText =
    "position:fixed;top:0;left:0;right:0;z-index:2147483647;padding:12px 20px;" +
    "background:#1a0a0a;border-bottom:3px solid #ef4444;color:#fca5a5;" +
    "font:14px -apple-system,sans-serif;display:flex;gap:14px;align-items:flex-start";

  const text = document.createElement("div");
  text.style.flex = "1";
  text.textContent = `🚨 PhishGuard AI: Phishing detected (risk ${score.toFixed(1)}/10) — ${reasons.join(" · ")}`;

  const close = document.createElement("button");
  close.textContent = "✕";
  close.style.cssText = "background:none;border:none;color:#fca5a5;font-size:18px;cursor:pointer";
  close.onclick = () => bar.remove();

  bar.append(text, close);
  (document.body || document.documentElement).prepend(bar);
}

chrome.tabs.onUpdated.addListener(async (tabId, info, tab) => {
  if (info.status !== "complete" || !isCheckable(tab.url)) return;
  try {
    const data = await checkUrl(tab.url);
    setBadge(tabId, data.result);
    if (data.result === "PHISHING") {
      chrome.scripting.executeScript({
        target: { tabId },
        func: showBanner,
        args: [Number(data.risk_score) || 0, (data.reasons || []).slice(0, 3)],
      }).catch(() => {});   // some pages (e.g. Chrome Web Store) block scripts
    }
  } catch {
    // backend offline — stay quiet
  }
});

// Popup asks: { url } -> { data } or { error }
chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  if (!isCheckable(msg.url)) {
    reply({ error: "This page cannot be checked." });
    return;
  }
  checkUrl(msg.url)
    .then((data) => reply({ data }))
    .catch((e) => reply({
      error: e.name === "TimeoutError" ? "Request timed out." : "Could not reach the PhishGuard API.",
    }));
  return true;   // keep the channel open for the async reply
});
