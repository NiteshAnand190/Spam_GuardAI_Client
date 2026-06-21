// ========================================================
// PLATFORM DETECTION
// ========================================================
const host = window.location.hostname;
const IS_GMAIL   = host === "mail.google.com";
const IS_OUTLOOK = /outlook\.(live|office|office365)\.com/.test(host);

// ========================================================
// CONFIGURATION
// BACKEND_URL is public. The X-SpamGuard-Key sent below is an anti-abuse
// throttling token, NOT a real secret — anything shipped inside a content
// script is readable by any user. The backend's actual protection is its
// per-IP rate limit; the key only deters casual scripted abuse.
// ========================================================
const BACKEND_URL = "https://niteshanand-spamguard-api.hf.space";

// Cache: emailKey -> result object
const scanCache = new Map();

// ========================================================
// DOM SELECTORS PER PLATFORM
// ========================================================
function getEmailData() {
  if (IS_GMAIL)   return getGmailData();
  if (IS_OUTLOOK) return getOutlookData();
  return null;
}

function getGmailData() {
  // In a thread there are many .a3s message bodies. Old ones are collapsed
  // (hidden), the newest reply is expanded. Pick the LAST visible message —
  // that's the one the user is actually reading.
  const visibleBodies = Array.from(document.querySelectorAll('.a3s'))
    .filter(el => el.offsetParent !== null && el.innerText.trim().length > 0);
  const bodyEl = visibleBodies[visibleBodies.length - 1];
  if (!bodyEl) return null;

  const subjectEl = document.querySelector('h2[data-thread-perm-id]');

  // Sender = the sender of THAT latest message, not the thread's first sender.
  let sender = "Unknown";
  const msgContainer = bodyEl.closest('.gs') || bodyEl.closest('[data-message-id]');
  const senderEl = (msgContainer && msgContainer.querySelector('span.gD'));
  if (senderEl) {
    sender = senderEl.getAttribute("email") || senderEl.innerText;
  } else {
    const allSenders = document.querySelectorAll('span.gD');
    if (allSenders.length) {
      const last = allSenders[allSenders.length - 1];
      sender = last.getAttribute("email") || last.innerText;
    }
  }

  return {
    body:    bodyEl.innerText.trim(),
    subject: subjectEl ? subjectEl.innerText.trim() : "No Subject",
    sender
  };
}

function getOutlookData() {
  // Outlook threads also stack multiple message bodies. Prefer the LAST visible
  // [role="document"] (the most recent expanded message), with fallbacks.
  const docs = Array.from(document.querySelectorAll('[role="document"]'))
    .filter(el => el.offsetParent !== null && el.innerText.trim().length > 0);
  const bodyEl = (
    docs[docs.length - 1] ||
    document.querySelector('[data-scope="message-view"]') ||
    document.querySelector('.ReadingPane .allowTextSelection')
  );
  if (!bodyEl) return null;

  const subjectEl = (
    document.querySelector('[data-scope="message-view"] [role="heading"]') ||
    document.querySelector('.ReadingPane h1') ||
    document.querySelector('[aria-label*="ubject"]')
  );

  let sender = "Unknown";
  const allTitled = document.querySelectorAll('[title*="@"]');
  if (allTitled.length > 0) sender = allTitled[0].getAttribute("title");

  return {
    body:    bodyEl.innerText.trim(),
    subject: subjectEl ? subjectEl.innerText.trim() : "No Subject",
    sender
  };
}

// ========================================================
// EMAIL KEY (for caching — stable message ID only, not full URL)
// Opening/closing attachments can change the URL slightly; extracting
// only the message ID ensures the same email always hits the cache.
// ========================================================
function getEmailKey() {
  if (IS_GMAIL) {
    const match = location.hash.match(/[a-zA-Z0-9]{16,}/);
    return match ? `gmail:${match[0]}` : location.href;
  }
  if (IS_OUTLOOK) {
    const match = location.href.match(/\/id\/([^/?#]+)/);
    return match ? `outlook:${match[1]}` : location.href;
  }
  return location.href;
}

// ========================================================
// UI CREATION
// ========================================================
const logoUrl = chrome.runtime.getURL("logo.png");

const overlay = document.createElement("div");
overlay.id = "spam-guard-overlay";
overlay.className = "minimized";
overlay.style.bottom = "30px";
overlay.style.right  = "30px";

overlay.innerHTML = `
  <div id="sg-minimized-icon">
    <img src="${logoUrl}" style="width:100%;height:100%;object-fit:cover;pointer-events:none;border-radius:50%;">
  </div>

  <div id="sg-expanded-view">
    <div class="sg-header" id="sg-drag-header">
      <div style="display:flex;align-items:center;pointer-events:none;">
        <span>🛡️ Spam Guard</span>
      </div>
      <div>
        <span id="sg-power" class="sg-power-btn" title="Turn Off Extension">OFF</span>
        <span id="sg-minimize" style="font-size:18px;cursor:pointer;">−</span>
      </div>
    </div>
    <div class="sg-content">
      <div class="sg-verdict" id="sg-verdict">Waiting...</div>
      <div class="sg-score" id="sg-score"></div>
      <div class="sg-explanation" id="sg-explanation">Open an email to scan.</div>
    </div>
  </div>
`;
document.body.appendChild(overlay);

// ========================================================
// DRAG & DROP
// ========================================================
let isDragging = false;
let hasMoved   = false;
let dragOffset = { x: 0, y: 0 };

const header  = document.getElementById("sg-drag-header");
const minIcon = document.getElementById("sg-minimized-icon");

function startDrag(e) {
  if (e.button !== 0) return;
  if (e.target.id === "sg-power" || e.target.id === "sg-minimize") return;
  isDragging = true;
  hasMoved   = false;
  const rect = overlay.getBoundingClientRect();
  dragOffset.x = e.clientX - rect.left;
  dragOffset.y = e.clientY - rect.top;
  overlay.style.bottom = "auto";
  overlay.style.right  = "auto";
  overlay.style.left   = rect.left + "px";
  overlay.style.top    = rect.top  + "px";
  document.addEventListener("mousemove", doDrag);
  document.addEventListener("mouseup", stopDrag);
  e.preventDefault();
}

function doDrag(e) {
  if (!isDragging) return;
  hasMoved = true;
  let newX = e.clientX - dragOffset.x;
  let newY = e.clientY - dragOffset.y;
  const wW = window.innerWidth, wH = window.innerHeight;
  const oW = overlay.offsetWidth, oH = overlay.offsetHeight;
  newX = Math.max(0, Math.min(newX, wW - oW));
  newY = Math.max(0, Math.min(newY, wH - oH));
  overlay.style.left = newX + "px";
  overlay.style.top  = newY + "px";
}

function stopDrag() {
  isDragging = false;
  document.removeEventListener("mousemove", doDrag);
  document.removeEventListener("mouseup", stopDrag);
}

header.addEventListener("mousedown", startDrag);
minIcon.addEventListener("mousedown", startDrag);

// ========================================================
// BOUNDARY CHECK (prevent overflow when expanding)
// ========================================================
function adjustPosition() {
  if (overlay.style.left && overlay.style.left !== "auto") {
    const winW = window.innerWidth;
    const winH = window.innerHeight;
    let left = parseFloat(overlay.style.left);
    let top  = parseFloat(overlay.style.top);
    if (left + 320 > winW) overlay.style.left = Math.max(0, winW - 340) + "px";
    if (top  > winH - 200) overlay.style.top  = Math.max(0, winH - 300) + "px";
  }
}

// ========================================================
// UI STATE
// ========================================================
minIcon.addEventListener("click", () => {
  if (!hasMoved) {
    overlay.classList.remove("minimized");
    adjustPosition();
  }
});

document.getElementById("sg-minimize").addEventListener("click", (e) => {
  e.stopPropagation();
  overlay.classList.add("minimized");
});

document.getElementById("sg-power").addEventListener("click", (e) => {
  e.stopPropagation();
  chrome.storage.local.get("isActive", (data) => {
    const currentlyActive = data.isActive !== false;
    const newState = !currentlyActive;
    chrome.storage.local.set({ isActive: newState });
    const btn = document.getElementById("sg-power");
    if (newState) {
      btn.innerText = "OFF";
      btn.style.color = "";
      updateUI("Scanning...", "gray", 0, "Running ML model + AI analysis...");
      setTimeout(scanEmail, 500);
    } else {
      btn.innerText = "ON";
      btn.style.color = "#28a745";
      updateUI("Shield Paused", "gray", 0, "SpamGuard is paused. Click ON to resume.");
    }
  });
});

chrome.storage.local.get("isActive", (data) => {
  if (data.isActive === false) overlay.style.display = "none";
});

chrome.runtime.onMessage.addListener((request) => {
  if (request.action === "TOGGLE_WIDGET") {
    overlay.style.display = request.state ? "block" : "none";
  }
});

// ========================================================
// EMAIL DETECTION (URL CHANGE WATCHER)
// ========================================================
function isEmailOpen() {
  const url = location.href;
  if (IS_GMAIL) {
    // Gmail email URLs always end with a long alphanumeric hash (16+ chars)
    // regardless of which view opened them: inbox, spam, search, all, sent,
    // starred, label, category, etc.
    return /#.+\/[a-zA-Z0-9]{16,}/.test(url);
  }
  if (IS_OUTLOOK) return /\/mail\/.+\/id\//.test(url) || /\/(inbox|junkemail|sentitems)\//i.test(url);
  return false;
}

let lastUrl = location.href;

new MutationObserver(() => {
  if (location.href !== lastUrl) {
    lastUrl = location.href;
    chrome.storage.local.get("isActive", (data) => {
      if (isEmailOpen() && data.isActive !== false) {
        overlay.classList.remove("minimized");
        adjustPosition();
        const cached = scanCache.get(getEmailKey());
        if (cached) {
          renderResult(cached);
        } else {
          updateUI("Scanning...", "gray", 0, "Analyzing content and sender...");
          setTimeout(scanEmail, 1200);
        }
      }
    });
  }
}).observe(document, { subtree: true, childList: true });

// ========================================================
// VERIFIED SENDER BADGE DETECTION — Gmail & Outlook
// Both platforms show a ✓ badge for cryptographically verified senders.
// If the email client itself verified the sender, SpamGuard trusts it too.
// ========================================================
function isVerifiedSender() {
  if (IS_GMAIL) {
    // Gmail BIMI verified badge — blue checkmark near sender name
    return !!(
      document.querySelector('[data-tooltip*="Sender is verified"]') ||
      document.querySelector('[data-tooltip*="sender is verified"]') ||
      document.querySelector('[aria-label*="Verified sender"]') ||
      document.querySelector('[aria-label*="verified sender"]') ||
      document.querySelector('img[alt*="verified"]') ||
      document.querySelector('.aZo') ||
      document.querySelector('[data-hovercard-id] ~ span[title*="verified"]')
    );
  }
  if (IS_OUTLOOK) {
    // Outlook verified sender / Microsoft-verified badge
    return !!(
      document.querySelector('[aria-label*="Verified sender"]') ||
      document.querySelector('[aria-label*="verified sender"]') ||
      document.querySelector('[title*="Verified"]') ||
      document.querySelector('[data-automationid*="verified"]') ||
      document.querySelector('[data-testid*="verified"]') ||
      // Outlook uses data-icon-name for badge icons
      document.querySelector('[data-icon-name="CheckmarkCircle"]') ||
      document.querySelector('[data-icon-name="Verified"]')
    );
  }
  return false;
}

// ========================================================
// CORE SCAN LOGIC
// ========================================================
async function scanEmail() {
  const cached = scanCache.get(getEmailKey());
  if (cached) { renderResult(cached); return; }

  const emailData = getEmailData();
  if (!emailData || !emailData.body) {
    updateUI("⚠️ Can't Read Email", "orange", 0, "SpamGuard couldn't access the email content.");
    return;
  }

  // Wait for trust engine to load sender history from storage
  await trustEngine.ready();

  // ── 0. Platform verified sender badge — trust anything the email client verified ──
  if (isVerifiedSender()) {
    trustEngine.recordSender(emailData.sender);
    const platform = IS_GMAIL ? "Gmail" : "Outlook";
    updateUI("✅ Verified Sender", "green", 98, `${platform} has verified this sender's identity.`);
    return;
  }

  // ── 1. Instant domain risk check (no network required) ──────────────────────
  const domainAnalysis = trustEngine.analyzeDomain(emailData.sender);

  // ── 1b. Personal / free-email domain claiming corporate identity ─────────
  // Detects social engineering: free/ISP email + company-claiming subject.
  // Runs before the SAFE branch so even well-known-provider senders get caught.
  const personalClaim = trustEngine.analyzePersonalDomainClaim(emailData.sender, emailData.subject);
  if (personalClaim) {
    updateUI("⚠️ Suspicious Identity", "red", 85,
      personalClaim + " Do not click links or share any information.");
    return;
  }

  // ── 1c. Display name brand impersonation ──────────────────────────────────
  // Catches "State-Farm-Rewards-Team <return@e194gu9q.cabdey.co.nl>" style
  // phishing where a trusted brand appears in the display name but the actual
  // sending domain is completely unrelated.
  const displaySpoof = trustEngine.analyzeDisplayNameSpoofing(emailData.sender);
  if (displaySpoof) {
    updateUI("🚨 BRAND IMPERSONATION", "red", 93,
      displaySpoof + " Do not click any links or provide any information.");
    return;
  }

  if (domainAnalysis.risk === "PHISHING") {
    updateUI(
      "🚨 PHISHING DOMAIN",
      "red", 99,
      `${domainAnalysis.reason}. Do NOT click any links or provide any information.`
    );
    return;
  }

  chrome.storage.local.get("isActive", async () => {
    // Check URL for direct spam/junk folder navigation, and also check the
    // Gmail folder label rendered in the DOM (catches emails opened via search).
    const isSpamFolder = location.href.includes("#spam") ||
      /junkemail/i.test(location.href) ||
      !!(IS_GMAIL && document.querySelector('.aKh [title="Spam"], .nH [title="Spam"]')) ||
      !!(IS_OUTLOOK && document.querySelector('[aria-label*="Junk Email"]'));

    // ── 2. Verified brand domain → skip scan entirely ────────────────────────
    // Verified brand domains (Google, Microsoft, Indeed, LinkedIn, etc.) should
    // never be flagged as spam regardless of email content.
    const learned = trustEngine.getLearnedTrust(emailData.sender);
    if (domainAnalysis.risk === "SAFE" && !isSpamFolder) {
      const note = learned ? ` ${learned.reason}.` : "";
      updateUI("✅ Verified Sender", "green", 95, `Domain verified as trusted.${note}`);
      trustEngine.recordSender(emailData.sender);
      return;
    }

    // Learned trust for non-brand domains (e.g. personal/work addresses used frequently)
    if (learned && learned.level === "HIGH" && !isSpamFolder) {
      updateUI("✅ Trusted Sender", "green", 90, `${learned.reason}.`);
      return;
    }

    // ── 3. Run ML + AI backend analysis ──────────────────────────────────────
    updateUI("Scanning...", "gray", 0, "Running ML model + AI analysis...");

    let result = null;

    try {
      const res = await fetch(`${BACKEND_URL}/analyze`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-SpamGuard-Key": "sg_nitesh_2024_xK9mP_19_injnfjn_2001"
        },
        body: JSON.stringify({
          subject: emailData.subject,
          body:    emailData.body.substring(0, 2500),
          sender:  emailData.sender
        }),
        signal: AbortSignal.timeout(20000)
      });

      if (res.status === 429) {
        updateUI("⚠️ Rate Limited", "orange", 0, "Too many requests. Please wait a moment and try again.");
        return;
      }

      if (!res.ok) {
        updateUI("⚠️ Service Error", "orange", 0, `Backend returned ${res.status}. Try again shortly.`);
        return;
      }

      result = await res.json();
    } catch (error) {
      if (error.name === "TimeoutError") {
        updateUI("⏳ Waking Up...", "gray", 0, "Backend is starting (free tier). Retrying in 10 seconds...");
        setTimeout(scanEmail, 10000);
      } else {
        updateUI("Connection Error", "orange", 0, "Check your internet connection.");
      }
      return;
    }

    // ── 4. Suspicious domain overrides ML result ──────────────────────────────
    // A lookalike / impersonation domain is a fraud signal, not mere junk —
    // even if the email body reads clean, treat it as phishing.
    if (domainAnalysis.risk === "SUSPICIOUS") {
      result.verdict          = "PHISHING";
      result.confidence_score = Math.max(result.confidence_score, 80);
      result.explanation      = `⚠️ Domain Risk: ${domainAnalysis.reason}. Treat any links or requests with caution.`;
    }

    // ── 5. Inbox override — trust the email platform's own spam filter ────────
    // Gmail and Outlook run billion-email trained spam filters. If they put
    // this email in INBOX (not spam/junk), they already cleared it. We defer to
    // their verdict for any non-suspicious domain where our ML isn't highly
    // confident — covering every legitimate sender without needing a domain list.
    // We present a HIGH safety score here (a SAFE verdict must never show a low
    // number), and flag the downgrade so rule 7 won't "learn" a borderline sender.
    let downgradedFromSpam = false;
    if (!isSpamFolder &&
        domainAnalysis.risk === "UNKNOWN" &&
        result.verdict === "SPAM" &&
        result.confidence_score < 92) {
      result.verdict = "SAFE";
      result.explanation = `${IS_GMAIL ? "Gmail" : "Outlook"} placed this in your inbox — their spam filter already cleared it.`;
      result.confidence_score = 85;
      downgradedFromSpam = true;
    }

    // ── 6. Spam-folder emails → always a neutral CAUTION, never green ─────────
    // The provider's own filter already moved this to Spam. We must not show a
    // green "looks safe" badge here, so we surface a CAUTION verdict (no numeric
    // score) and let the user decide. PHISHING (rule 1/4) is never softened.
    if (isSpamFolder && domainAnalysis.risk !== "SUSPICIOUS" && result.verdict !== "PHISHING") {
      result.verdict = "CAUTION";
      result.confidence_score = 0;
      result.explanation = `${IS_GMAIL ? "Google" : "Microsoft"} placed this in your Spam folder. Our scan didn't find a clear threat, but review it carefully before trusting it.`;
    }

    // ── 7. Learn this sender — only record GENUINELY safe senders ─────────────
    // Excludes senders downgraded from SPAM (rule 5) and spam-foldered CAUTION
    // emails (rule 6), so a borderline-spam sender can't be promoted to "Trusted".
    if (result.verdict === "SAFE" && domainAnalysis.risk !== "SUSPICIOUS" && !downgradedFromSpam) {
      trustEngine.recordSender(emailData.sender);
    }

    scanCache.set(getEmailKey(), result);
    renderResult(result);
  });
}

function renderResult(result) {
  if (result.verdict === "PHISHING") {
    updateUI("🚨 PHISHING / FRAUD", "red",    result.confidence_score, result.explanation);
  } else if (result.verdict === "SPAM") {
    updateUI("⚠️ SPAM / JUNK",      "orange", result.confidence_score, result.explanation);
  } else if (result.verdict === "CAUTION") {
    updateUI("⚠️ REVIEW CAREFULLY", "orange", result.confidence_score, result.explanation);
  } else {
    updateUI("✅ LOOKS SAFE",        "green",  result.confidence_score, result.explanation);
  }
}

function updateUI(text, colorClass, confidence, explanation) {
  const verdictEl = document.getElementById("sg-verdict");
  const scoreEl   = document.getElementById("sg-score");
  const expEl     = document.getElementById("sg-explanation");

  verdictEl.className = "sg-verdict";
  verdictEl.innerText = text;
  verdictEl.classList.add(`text-${colorClass}`);

  // Score badge — labelled per verdict colour. Hidden for neutral states.
  scoreEl.className = "sg-score";
  const scoreLabels = { green: "Safety Score", orange: "Spam Score", red: "Threat Score" };
  if (confidence > 0 && scoreLabels[colorClass]) {
    scoreEl.innerHTML = `${scoreLabels[colorClass]} <span class="sg-score-num">${confidence}/100</span>`;
    scoreEl.classList.add(`text-${colorClass}`);
  } else {
    scoreEl.innerText = "";
  }

  expEl.innerText = explanation;
}
