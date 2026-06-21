/**
 * SpamGuard AI — Dynamic Trust Engine
 *
 * Two independent trust signals:
 *   1. Learned trust  — senders you receive from frequently (frequency-based)
 *   2. Domain risk    — detects lookalike/impersonation domains in real-time
 *
 * Domain attacks detected:
 *   - Brand-as-subdomain:  paypal.com.evil.ru
 *   - Homoglyphs:          paypa1.com, g00gle.com, rnicro soft.com
 *   - Levenshtein close:   paytm-support.com, gooogle.com
 *   - Brand-infix hyphens: google-security-alert.com, paypal-support.com
 */

const BRAND_DOMAINS = [
  // Google
  "google.com", "gmail.com", "youtube.com", "accounts.google.com",
  // Microsoft
  "microsoft.com", "outlook.com", "live.com", "hotmail.com", "office.com", "office365.com",
  // Apple
  "apple.com", "icloud.com",
  // Amazon
  "amazon.com", "amazon.in", "aws.amazon.com", "amazonaws.com",
  // PayPal
  "paypal.com",
  // Adobe
  "adobe.com", "adobecc.com",
  // Social / professional
  "facebook.com", "instagram.com", "meta.com", "linkedin.com", "twitter.com", "x.com",
  "pinterest.com", "reddit.com", "discord.com", "telegram.org", "whatsapp.com",
  // Dev platforms
  "github.com", "gitlab.com", "bitbucket.org", "stackoverflow.com",
  // Streaming / entertainment
  "netflix.com", "spotify.com", "primevideo.com", "hotstar.com", "jiocinema.com",
  "twitch.tv", "disneyplus.com",
  // Indian fintech / banks / e-commerce
  "paytm.com", "phonepe.com", "razorpay.com", "gpay.app",
  "hdfcbank.com", "sbi.co.in", "icicibank.com", "axisbank.com", "kotak.com",
  "flipkart.com", "myntra.com", "zomato.com", "swiggy.com", "meesho.com",
  "airtel.in", "jio.com",
  // (bsnl.in intentionally excluded here — it is an ISP mailbox domain, listed
  //  under PERSONAL_ISP_DOMAINS below, not a brand that sends official mail.)
  // Productivity / collaboration / events / design
  "dropbox.com", "zoom.us", "slack.com", "notion.so", "meetup.com",
  "canva.com", "figma.com", "trello.com", "asana.com", "monday.com",
  "atlassian.com", "jira.com", "confluence.com",
  // Cloud / infra / dev tools
  "cloudflare.com", "digitalocean.com", "heroku.com", "vercel.com", "netlify.com",
  "render.com", "railway.app", "supabase.io", "firebase.google.com",
  // E-commerce / payments
  "shopify.com", "stripe.com", "squarespace.com", "wix.com", "wordpress.com",
  "ebay.com", "etsy.com",
  // Job platforms
  "indeed.com", "jobalert.indeed.com",
  "glassdoor.com", "naukri.com", "monster.com",
  "internshala.com", "unstop.com", "hackerearth.com", "hackerrank.com",
  "wellfound.com", "angel.co",
  // Dev / learning
  "leetcode.com", "codechef.com", "codeforces.com", "geeksforgeeks.org",
  "coursera.org", "udemy.com", "edx.org", "khanacademy.org", "pluralsight.com",
  "skillshare.com",
  // Email / marketing infrastructure (these send on behalf of brands)
  "medium.com", "substack.com",
  "mailchimp.com", "sendgrid.net", "amazonses.com", "mailgun.org",
  "constantcontact.com", "klaviyo.com", "brevo.com",
  // Travel / booking
  "booking.com", "airbnb.com", "makemytrip.com", "goibibo.com", "ixigo.com",
  "irctc.co.in",
  // Other major SaaS
  "salesforce.com", "hubspot.com", "zendesk.com", "intercom.io",
  "twilio.com", "sendbird.com",
  // Finance / Insurance (frequently spoofed for reward & refund scams)
  "statefarm.com", "geico.com", "progressive.com", "allstate.com",
  "chase.com", "bankofamerica.com", "wellsfargo.com", "citi.com", "citibank.com",
  "usbank.com", "capitalone.com", "americanexpress.com", "discover.com",
  "federalbank.co.in", "pnbindia.in", "unionbankofindia.co.in", "canarabank.com"
];

const BRAND_SET = new Set(BRAND_DOMAINS);

// Free webmail providers — no legitimate company sends official business email
// from these addresses. A corporate identity claim from any of these is a
// strong social-engineering signal.
const FREE_EMAIL_DOMAINS = new Set([
  'gmail.com', 'yahoo.com', 'yahoo.in', 'yahoo.co.in', 'yahoo.co.uk',
  'hotmail.com', 'hotmail.in', 'outlook.com', 'live.com',
  'protonmail.com', 'proton.me', 'icloud.com', 'me.com', 'mac.com',
  'aol.com', 'zoho.com', 'yandex.com', 'yandex.ru', 'mail.com',
  'gmx.com', 'gmx.net', 'tutanota.com', 'fastmail.com'
]);

// ISP / cable / regional personal email domains.
// No legitimate business ever sends official email from these —
// so a corporate-sounding subject from these is always suspicious.
const PERSONAL_ISP_DOMAINS = new Set([
  // US cable / ISP
  'optimum.net', 'comcast.net', 'verizon.net', 'att.net', 'cox.net',
  'charter.net', 'spectrum.net', 'sbcglobal.net', 'bellsouth.net',
  'earthlink.net', 'roadrunner.com', 'twc.com', 'optonline.net',
  // Indian ISP
  'bsnl.in', 'mtnl.net.in', 'airtelmail.in',
  // Other personal/regional
  'rediffmail.com', 'sify.com', 'in.com'
]);

// Matches corporate identity claims in a subject line.
// e.g. "CreditNirvana - A Perfios Company", "XYZ Pvt Ltd", "ABC Private Limited"
const CORPORATE_CLAIM_RE = /\ba\s+\w[\w\s]{0,25}company\b|\bpvt\.?\s*ltd\.?\b|\bprivate\s+limited\b|\b(inc|corp|llc|llp)\.?(\s|$)|holdings?\b|enterprises?\b/i;

// ── Singleton Trust Engine ────────────────────────────────────────────────────

class TrustEngine {
  constructor() {
    this.history = {};  // { "email@domain.com": { count, firstSeen, lastSeen } }
    this._ready = new Promise(resolve => {
      chrome.storage.local.get("sg_senderHistory", data => {
        this.history = data.sg_senderHistory || {};
        resolve();
      });
    });
  }

  ready() { return this._ready; }

  // ── Record a sender we received a SAFE email from ──────────────────────────
  async recordSender(rawSender) {
    await this._ready;
    const key = _extractEmail(rawSender);
    if (!key) return;

    const now = Date.now();
    if (!this.history[key]) {
      this.history[key] = { count: 0, firstSeen: now, lastSeen: now };
    }
    this.history[key].count++;
    this.history[key].lastSeen = now;

    // Cap at 500 entries — prune oldest on overflow
    const entries = Object.entries(this.history);
    if (entries.length > 500) {
      entries.sort((a, b) => a[1].lastSeen - b[1].lastSeen);
      this.history = Object.fromEntries(entries.slice(-400));
    }

    chrome.storage.local.set({ sg_senderHistory: this.history });
  }

  // ── Frequency-based learned trust ─────────────────────────────────────────
  // Returns: { level: "HIGH"|"MEDIUM", reason: string } | null
  getLearnedTrust(rawSender) {
    const key = _extractEmail(rawSender);
    if (!key) return null;
    const rec = this.history[key];
    if (!rec) return null;
    if (rec.count >= 10) return { level: "HIGH",   reason: `Frequent contact — ${rec.count} emails received` };
    if (rec.count >= 3)  return { level: "MEDIUM", reason: `Known sender — ${rec.count} emails received` };
    return null;
  }

  // ── Personal / free-email domain + corporate identity claim ──────────────
  // Legitimate companies always send from their own domain — never from Gmail,
  // Yahoo, Hotmail, or ISP addresses. A corporate identity claim from any of
  // these is a strong social-engineering / impersonation signal.
  // Returns: reason string | null
  analyzePersonalDomainClaim(rawSender, subject) {
    const domain = _extractDomain(rawSender);
    if (!domain) return null;

    const isFree = FREE_EMAIL_DOMAINS.has(domain);
    const isISP  = PERSONAL_ISP_DOMAINS.has(domain);
    if (!isFree && !isISP) return null;

    const domainLabel = isFree ? `free email address (${domain})` : `personal ISP address (${domain})`;

    if (CORPORATE_CLAIM_RE.test(subject)) {
      return `Sent from a ${domainLabel} but subject claims to be a company — legitimate businesses always use their own domain.`;
    }
    // Also check display name (the "Name" part before <email>)
    const displayName = rawSender.replace(/<[^>]+>/, '').trim();
    if (CORPORATE_CLAIM_RE.test(displayName)) {
      return `Sender display name claims to be a company but email is from a ${domainLabel}.`;
    }
    return null;
  }

  // ── Display name brand impersonation ─────────────────────────────────────
  // Phishing emails often put a trusted brand in the display name
  // ("State-Farm-Rewards-Team <return@e194gu9q.cabdey.co.nl>") while sending
  // from a completely unrelated domain. We tokenise the display name and check
  // for exact-word or two-word-concatenation matches against BRAND_DOMAINS.
  // Returns: reason string | null
  analyzeDisplayNameSpoofing(rawSender) {
    const domain = _extractDomain(rawSender);
    if (!domain) return null;

    // Already a verified brand domain — skip
    if (BRAND_SET.has(domain)) return null;
    if (BRAND_DOMAINS.some(bd => domain.endsWith("." + bd))) return null;

    // Extract display name (everything before the <email> part)
    const angleIdx = rawSender.indexOf("<");
    if (angleIdx <= 0) return null;
    const displayRaw = rawSender.substring(0, angleIdx).trim();
    if (!displayRaw) return null;

    // Split into lowercase alpha-numeric tokens
    const tokens = displayRaw.toLowerCase().split(/[^a-z0-9]+/).filter(t => t.length > 0);

    for (const bd of BRAND_DOMAINS) {
      const bdBase = bd.split(".")[0].toLowerCase();
      if (bdBase.length < 5) continue;

      // Exact single-token match: "PayPal Security Team" → token "paypal"
      if (tokens.includes(bdBase)) {
        return `Display name claims to be "${bd.split(".")[0]}" but email came from "${domain}" — not the real ${bd} address.`;
      }

      // Two consecutive tokens joined: "State Farm Team" → "state"+"farm" = "statefarm"
      for (let i = 0; i < tokens.length - 1; i++) {
        if (tokens[i] + tokens[i + 1] === bdBase) {
          return `Display name claims to be "${bd.split(".")[0]}" but email came from "${domain}" — not the real ${bd} address.`;
        }
      }
    }
    return null;
  }

  // ── Domain risk analysis ───────────────────────────────────────────────────
  // Returns: { risk: "SAFE"|"SUSPICIOUS"|"PHISHING"|"UNKNOWN", reason: string }
  analyzeDomain(rawSender) {
    const domain = _extractDomain(rawSender);
    if (!domain) return { risk: "UNKNOWN", reason: "" };

    // 1. Exact brand match
    if (BRAND_SET.has(domain)) {
      return { risk: "SAFE", reason: "Verified brand domain" };
    }

    // 2. Trusted subdomain — noreply.github.com, accounts.google.com
    const trustedSub = BRAND_DOMAINS.find(bd => domain.endsWith("." + bd));
    if (trustedSub) {
      return { risk: "SAFE", reason: `Trusted subdomain of ${trustedSub}` };
    }

    // 3. Brand-as-subdomain attack: paypal.com.phishing.ru
    //    Attacker puts the legit domain as a prefix before their own TLD
    const brandEmbedded = BRAND_DOMAINS.find(bd => domain.includes(bd + "."));
    if (brandEmbedded) {
      return {
        risk: "PHISHING",
        reason: `Impersonates "${brandEmbedded}" — uses it as a fake subdomain prefix`
      };
    }

    // 4. Homoglyph substitution: paypa1.com, g00gle.com, rnicr0soft.com
    const domainNorm  = _normalizeHomoglyphs(domain);
    const domainBase  = domainNorm.split(".")[0];
    for (const bd of BRAND_DOMAINS) {
      const bdBase = bd.split(".")[0];
      if (domainBase === bdBase && domain.split(".")[0] !== bdBase) {
        return {
          risk: "PHISHING",
          reason: `Uses look-alike characters to impersonate "${bd}" (e.g. 0→o, 1→l, rn→m)`
        };
      }
    }

    // 5. Levenshtein lookalike — DELIBERATELY CONSERVATIVE.
    //    Edit-distance matching is prone to false positives ("noodle"→"google",
    //    "tender"→"render", "canvas"→"canva", "credit"→"reddit"), and a SUSPICIOUS
    //    result is later escalated to a full PHISHING warning — so flagging an
    //    ordinary domain is costly. We therefore only compare against LONGER brand
    //    names (≥7 chars, where coincidental near-collisions with real words are
    //    rare), require an exact 1-character edit for 7–8 char brands, and allow a
    //    2-character edit only for very long brands (≥9 chars, e.g. "microsoft").
    //    Short brands (google, paypal, apple, zoom, slack, canva…) are covered by
    //    the exact-match, subdomain, brand-as-prefix and homoglyph rules above.
    const domainParts = domain.split(".");
    const regLabel    = domainParts.length >= 2
      ? domainParts[domainParts.length - 2]
      : domainParts[0];
    const cleanRegLabel = regLabel.replace(/-/g, "");
    for (const bd of BRAND_DOMAINS) {
      const bdBase = bd.split(".")[0];
      if (bdBase.length < 7) continue;
      const maxDist = bdBase.length >= 9 ? 2 : 1;
      const dist = _levenshtein(cleanRegLabel, bdBase);
      if (dist > 0 && dist <= maxDist) {
        return {
          risk: "SUSPICIOUS",
          reason: `"${domain}" closely resembles "${bd}" (${dist} character difference)`
        };
      }
    }

    // 6. Brand-infix with hyphens — catches the brand name glued to extra words:
    //    brand-first  → google-security-alert.com, paypal-support.com
    //    brand-last   → secure-paypal.com, account-google.com, login-microsoft.com
    //    brand-middle → mail-paypal-login.com
    //    Uses the registrable label, so "email.meetup.com" → "meetup" is unaffected.
    //    Excludes the case where the label IS exactly the brand (handled above).
    const brandInfix = BRAND_DOMAINS.find(bd => {
      const b = bd.split(".")[0];
      if (b.length < 4) return false;
      if (regLabel === b) return false;          // the label IS the brand → not an infix
      return (
        regLabel.startsWith(b + "-") ||          // brand-...
        regLabel.endsWith("-" + b)   ||          // ...-brand
        regLabel.includes("-" + b + "-")         // ...-brand-...
      );
    });
    if (brandInfix) {
      return {
        risk: "SUSPICIOUS",
        reason: `Contains brand name "${brandInfix.split(".")[0]}" combined with extra words — likely impersonation`
      };
    }

    return { risk: "UNKNOWN", reason: "" };
  }
}

// ── Pure utility functions ────────────────────────────────────────────────────

function _extractEmail(rawSender) {
  if (!rawSender) return null;
  const m = rawSender.match(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/);
  return m ? m[0].toLowerCase() : null;
}

function _extractDomain(rawSender) {
  const email = _extractEmail(rawSender);
  return email ? email.split("@")[1] : null;
}

function _normalizeHomoglyphs(str) {
  return str.toLowerCase()
    .replace(/rn/g, "m").replace(/vv/g, "w").replace(/cl/g, "d")  // multi-char first
    .replace(/0/g,  "o").replace(/1/g,  "l").replace(/3/g,  "e")
    .replace(/4/g,  "a").replace(/5/g,  "s").replace(/6/g,  "b")
    .replace(/7/g,  "t").replace(/8/g,  "b");
}

function _levenshtein(a, b) {
  const m = a.length, n = b.length;
  // Build dp table row by row
  let prev = Array.from({ length: n + 1 }, (_, j) => j);
  for (let i = 1; i <= m; i++) {
    const curr = [i];
    for (let j = 1; j <= n; j++) {
      curr[j] = a[i - 1] === b[j - 1]
        ? prev[j - 1]
        : 1 + Math.min(prev[j], curr[j - 1], prev[j - 1]);
    }
    prev = curr;
  }
  return prev[n];
}

// Export singleton — content.js references this global
const trustEngine = new TrustEngine();
