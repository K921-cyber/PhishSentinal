/**
 * PhishSentinel — popup.js v2.1
 *
 * Architecture: popup.js owns the fetch() call to the backend.
 * content.js only extracts email data and returns it synchronously.
 *
 * Flow:
 *   1. popup.js → sendMessage({action:"extract"}) → content.js
 *   2. content.js → returns {text, links, raw_headers} instantly
 *   3. popup.js → fetch POST to backend (2-3s, popup stays open)
 *   4. popup.js → renders verdict
 */

const BACKEND_URL = "http://127.0.0.1:5000/api/scan";

document.addEventListener("DOMContentLoaded", () => {
  const scanBtn      = document.getElementById("scan-btn");
  const statusEl     = document.getElementById("status");
  const gaugeWrap    = document.getElementById("gauge-wrap");
  const enginesWrap  = document.getElementById("engines-wrap");
  const findingsWrap = document.getElementById("findings-wrap");
  const linksWrap    = document.getElementById("links-wrap");
  const escalBadge   = document.getElementById("escalation-badge");
  const gaugeScore   = document.getElementById("gauge-score");
  const gaugeLabel   = document.getElementById("gauge-label");
  const gaugeFill    = document.getElementById("gauge-fill");
  const scanTime     = document.getElementById("scan-time");

  hideAll();

  scanBtn.addEventListener("click", async () => {
    hideAll();
    setStatus("⟫ Extracting email data…");
    scanBtn.disabled = true;

    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

      if (!tab?.id) { setStatus("❌ No active tab found."); return; }

      // Step 1: inject content script
      try {
        await chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ["content.js"] });
      } catch (_) { /* already injected */ }

      // Step 2: extract email data from DOM (synchronous, instant)
      const extracted = await new Promise((resolve) => {
        chrome.tabs.sendMessage(tab.id, { action: "extract" }, (resp) => {
          if (chrome.runtime.lastError) {
            resolve({ success: false, error: chrome.runtime.lastError.message });
          } else {
            resolve(resp || { success: false, error: "No response from content script." });
          }
        });
      });

      if (!extracted.success) {
        setStatus(`❌ ${extracted.error || "Could not read email. Make sure an email is open."}`);
        return;
      }

      const { text, links, raw_headers } = extracted;
      setStatus(`⟫ Scanning ${links.length} link(s) across 4 engines…`);

      // Step 3: popup does the fetch (stays alive, no channel race)
      let verdict;
      try {
        const resp = await fetch(BACKEND_URL, {
          method : "POST",
          headers: { "Content-Type": "application/json" },
          body   : JSON.stringify({ text, links, raw_headers }),
        });

        if (!resp.ok) {
          const errText = await resp.text().catch(() => resp.statusText);
          setStatus(`❌ Server error ${resp.status}: ${errText}`);
          return;
        }

        verdict = await resp.json();
      } catch (fetchErr) {
        setStatus(`❌ Cannot reach backend. Is "python main.py" running? (${fetchErr.message})`);
        return;
      }

      // Step 4: render
      await renderVerdict(verdict);
      setStatus(`✔ Scan complete · ${verdict.scan_time_ms ?? "—"}ms`);

    } catch (err) {
      setStatus(`❌ ${err.message}`);
    } finally {
      scanBtn.disabled = false;
    }
  });

  // ── Helpers ────────────────────────────────────────────────────────────────
  function hideAll() {
    gaugeWrap.style.display    = "none";
    enginesWrap.style.display  = "none";
    findingsWrap.style.display = "none";
    linksWrap.style.display    = "none";
    escalBadge.style.display   = "none";
    document.body.className    = "";
    document.getElementById("findings-list").innerHTML = "";
    document.getElementById("links-body").innerHTML    = "";
    gaugeFill.style.width  = "0%";
    gaugeScore.textContent = "";
    gaugeLabel.textContent = "";
  }

  function setStatus(msg) { statusEl.textContent = msg; }
  function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

  function scoreColour(s) {
    if (s >= 60) return "var(--glow-r)";
    if (s >= 35) return "var(--glow-y)";
    return "var(--glow-g)";
  }

  function esc(s) {
    return String(s ?? "")
      .replace(/&/g,"&amp;").replace(/</g,"&lt;")
      .replace(/>/g,"&gt;").replace(/"/g,"&quot;");
  }

  function animateCounter(el, from, to, duration) {
    const start = performance.now();
    function step(now) {
      const t    = Math.min((now - start) / duration, 1);
      const ease = t < 0.5 ? 2*t*t : -1+(4-2*t)*t;
      el.textContent = Math.round(from + (to - from) * ease);
      if (t < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }

  // ── Render verdict ─────────────────────────────────────────────────────────
  async function renderVerdict(v) {
    const colourClass = { RED:"theme-red", YELLOW:"theme-yellow", GREEN:"theme-green" }[v.colour] || "theme-yellow";
    document.body.classList.add(colourClass);

    const riskLabels = {
      HIGH  : "⚠  PHISHING DETECTED",
      MEDIUM: "△  SUSPICIOUS — REVIEW",
      LOW   : "✔  APPEARS SAFE",
    };

    gaugeWrap.style.display = "block";
    gaugeLabel.textContent  = riskLabels[v.overall_risk] || v.overall_risk;
    scanTime.textContent    = v.scan_time_ms ? `${v.scan_time_ms}ms` : "";
    animateCounter(gaugeScore, 0, v.overall_score, 900);
    setTimeout(() => { gaugeFill.style.width = v.overall_score + "%"; }, 60);

    if (v.escalated) escalBadge.style.display = "block";

    await sleep(150);
    renderEngineBars(v.engine_scores || {});
    enginesWrap.style.display = "block";

    await sleep(80);
    const findings = v.all_findings || [];
    if (findings.length) { renderFindings(findings); findingsWrap.style.display = "block"; }

    await sleep(80);
    const urlResults = v.detail?.domain?.urls || [];
    if (urlResults.length) { renderLinkTable(urlResults, v.detail?.heuristic); linksWrap.style.display = "block"; }
  }

  function renderEngineBars(scores) {
    [
      { id:"eng-ml",        key:"ml"        },
      { id:"eng-domain",    key:"domain"    },
      { id:"eng-heuristic", key:"heuristic" },
      { id:"eng-header",    key:"header"    },
    ].forEach(({ id, key }) => {
      const row   = document.getElementById(id);
      const bar   = row.querySelector(".engine-bar-fill");
      const val   = row.querySelector(".engine-val");
      const score = scores[key] ?? 0;
      const col   = scoreColour(score);
      val.textContent      = Math.round(score);
      val.style.color      = col;
      bar.style.background = col;
      bar.style.boxShadow  = `0 0 6px ${col}55`;
      setTimeout(() => { bar.style.width = score + "%"; }, 100);
    });
  }

  function pickIcon(text) {
    const t = text.toLowerCase();
    if (t.includes("raw ip"))                    return "⚡";
    if (t.includes("day") && t.includes("old"))  return "📅";
    if (t.includes("ssl") || t.includes("cert")) return "🔒";
    if (t.includes("tld"))                        return "🌐";
    if (t.includes("subdomain"))                  return "🔗";
    if (t.includes("display-name"))               return "🎭";
    if (t.includes("spf"))                        return "📧";
    if (t.includes("dkim"))                       return "🔑";
    if (t.includes("dmarc"))                      return "🛡";
    if (t.includes("typosquat"))                  return "📝";
    if (t.includes("homograph"))                  return "🔄";
    if (t.includes("redirect"))                   return "↪";
    if (t.includes("ml confidence"))              return "🤖";
    return "•";
  }

  function renderFindings(findings) {
    const list   = document.getElementById("findings-list");
    const unique = [...new Set(findings)].slice(0, 20);
    unique.forEach((text, i) => {
      const div = document.createElement("div");
      div.className = "finding";
      div.style.animationDelay = (i * 35) + "ms";
      div.innerHTML = `<span class="finding-icon">${pickIcon(text)}</span><span class="finding-text">${esc(text)}</span>`;
      list.appendChild(div);
    });
  }

  function renderLinkTable(urlResults, heuristic) {
    const body = document.getElementById("links-body");
    (heuristic?.expanded_urls || []);
    urlResults.forEach(r => {
      const row       = document.createElement("div");
      row.className   = "link-row";
      const riskClass = { HIGH:"high", MEDIUM:"medium", LOW:"low" }[r.risk] || "medium";
      const age       = r.domain_age_days != null ? r.domain_age_days + "d" : "—";
      const displayUrl= (r.url||"").length > 38 ? (r.url||"").slice(0,35)+"…" : (r.url||"");
      row.innerHTML   = `
        <span class="link-url" title="${esc(r.url||"")}">${esc(displayUrl)}${r.is_raw_ip?'<span class="badge badge-ip">IP</span>':""}</span>
        <span class="link-age">${age}</span>
        <span class="link-risk"><span class="badge badge-${riskClass}">${r.risk||"?"}</span></span>`;
      body.appendChild(row);
    });
  }
});