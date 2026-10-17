// PhishGuard AI — popup. Asks the background worker to check the current tab.

const VERDICT = {
  PHISHING:   { icon: "🚨", label: "Phishing Detected", color: "#ef4444" },
  SUSPICIOUS: { icon: "⚠️", label: "Suspicious Page",   color: "#f59e0b" },
  SAFE:       { icon: "✅", label: "Safe",               color: "#22c55e" },
};

const $ = (id) => document.getElementById(id);
let currentUrl = "";

async function check() {
  $("status").textContent = "Checking URL…";
  $("result").hidden = true;
  const { data, error } = await chrome.runtime.sendMessage({ url: currentUrl });
  if (error) {
    $("status").textContent = error;
    return;
  }
  const v = VERDICT[data.result] || VERDICT.SUSPICIOUS;
  $("status").textContent = "";
  $("result").hidden = false;
  $("icon").textContent = v.icon;
  $("verdict").textContent = v.label;
  $("verdict").style.color = v.color;
  $("score").textContent = `Risk score: ${data.risk_score.toFixed(1)} / 10`;
  $("bar").style.width = `${Math.min(data.risk_score * 10, 100)}%`;
  $("bar").style.background = v.color;
  $("reasons").replaceChildren(...data.reasons.map((r) => {
    const li = document.createElement("li");
    li.textContent = r;
    return li;
  }));
}

chrome.tabs.query({ active: true, currentWindow: true }).then(([tab]) => {
  currentUrl = tab?.url || "";
  $("url").textContent = currentUrl.length > 60 ? currentUrl.slice(0, 60) + "…" : currentUrl;
  check();
});
$("recheck").addEventListener("click", check);
