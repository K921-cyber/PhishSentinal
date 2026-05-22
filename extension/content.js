
const MAX_LINKS = 30;

const BODY_SELECTORS = [
  ".a3s.aiL",
  ".gs .ii",
  '[aria-label="Message body"]',
  ".ReadMsgBody",
  ".rps_0fa",
  ".msg-body",
  "article[role='main']",
  "main",
];

function findEmailBody() {
  for (const sel of BODY_SELECTORS) {
    const el = document.querySelector(sel);
    if (el && el.innerText.trim().length > 10) return el;
  }
  return document.body;
}

function unwrapUrl(raw) {
  try {
    const url = new URL(raw, window.location.href);
    if (url.hostname.includes("google.com") && url.pathname === "/url") {
      return url.searchParams.get("q") || raw;
    }
    if (url.hostname.includes("safelinks.protection.outlook.com")) {
      return url.searchParams.get("url") || raw;
    }
  } catch (_) {}
  return raw;
}

function extractLinks(container) {
  const anchors = Array.from(container.querySelectorAll("a[href]"));
  const seen = new Set();
  const links = [];
  for (const a of anchors) {
    let raw = (a.getAttribute("href") || "").trim();
    if (!raw || raw.startsWith("mailto:") || raw.startsWith("#") || raw.startsWith("javascript:")) continue;
    const real = unwrapUrl(raw);
    if (!seen.has(real)) {
      seen.add(real);
      links.push(real);
    }
    if (links.length >= MAX_LINKS) break;
  }
  return links;
}

function extractHeaderSignals() {
  const lines = [];
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, null);
  let node;
  while ((node = walker.nextNode())) {
    const t = node.textContent.trim();
    if (t && (t.startsWith("spf=") || t.startsWith("dkim=") || t.startsWith("dmarc=") ||
              t.includes("Authentication-Results") || t.includes("Received-SPF"))) {
      lines.push(t);
    }
  }
  return lines.join("\n");
}

// Listen for "extract" message — return data immediately, no fetch
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg.action === "extract") {
    try {
      const body = findEmailBody();
      sendResponse({
        success    : true,
        text       : body.innerText.trim(),
        links      : extractLinks(body),
        raw_headers: extractHeaderSignals(),
      });
    } catch (err) {
      sendResponse({ success: false, error: err.message });
    }
    return false; // synchronous response — no async needed
  }
});
