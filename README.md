# SpamGuard AI — Chrome Extension

> Real-time phishing and spam detection for **Gmail** and **Outlook**, powered by a hybrid ML + LLM pipeline.

SpamGuard AI is a Chrome extension that automatically analyzes every email you open and flags it as **SAFE**, **SPAM**, or **PHISHING** — right inside your inbox. No copy-pasting, no switching tabs.

---

## What it detects

| Verdict | Meaning | What to do |
|---|---|---|
| ✅ **SAFE** | Legitimate mail | Read normally |
| ⚠️ **SPAM** | Unwanted junk / marketing | Ignore or unsubscribe |
| 🚨 **PHISHING** | Active attempt to steal money or info | **Do not click. Do not reply.** |
| 🚨 **BRAND IMPERSONATION** | Display name fakes a trusted brand | **Do not click.** |

Specifically catches:
- Emails from **free/personal addresses** (Gmail, Yahoo, Hotmail) that claim to be a company
- **Display-name spoofing** — e.g. "State-Farm-Rewards-Team" sent from a random domain
- **Homoglyph attacks** — look-alike domains (paypa1.com, arnazon.com)
- **Levenshtein lookalikes** — domains 1-2 characters off from real brands
- **Subdomain abuse** — paypal.com.evil.ru
- A full ML + LLM scan for anything not caught locally

---

## Installation (takes ~30 seconds)

**Chrome does not allow extensions from outside the Web Store to install with one click.**  
You need to load it as an "unpacked extension" — this is safe and standard for developer/preview extensions.

### Step 1 — Download

Click **Code → Download ZIP** on this page, then unzip it anywhere (e.g. your Desktop).

### Step 2 — Load in Chrome

1. Open a new tab and go to: `chrome://extensions`
2. Toggle **Developer mode** ON (top-right corner)
3. Click **Load unpacked**
4. Select the unzipped folder (the one containing `manifest.json`)
5. The SpamGuard shield icon appears in your toolbar — done!

> **Brave, Edge, Arc** — same steps, same `chrome://extensions` page.

---

## How to use

1. Open **Gmail** (`mail.google.com`) or **Outlook** (`outlook.live.com` / `outlook.office.com`)
2. Click any email to open it
3. A verdict widget appears in the **bottom-right corner** of the page within 1–3 seconds

The widget shows the verdict, a confidence score (0–100), and an explanation of why the email was flagged.

---

## How it works

```
Your email tab
┌──────────────────────────────┐
│  Chrome Extension (MV3)       │
│  • Reads sender + subject     │         HTTPS /analyze
│  • Local heuristics first     │ ──────────────────────►  FastAPI backend
│  • Falls back to backend      │                          (Hugging Face Spaces)
│  • Shows verdict overlay      │ ◄──────────────────────  TF-IDF+SVM  +  Groq LLaMA 3.1
└──────────────────────────────┘     { verdict, score, reason }
```

Most legitimate email (verified brands, frequent contacts) is decided **on-device in milliseconds** — no data leaves your browser. Only ambiguous emails are sent to the backend.

---

## Privacy

- Email content is sent to the backend **only when necessary** (ambiguous emails)
- Verified brands and trusted senders are decided entirely on-device
- Learned sender history is stored in `chrome.storage.local` on your machine only — never uploaded

---


## Troubleshooting

| Problem | Fix |
|---|---|
| Widget doesn't appear | Make sure the extension is enabled at `chrome://extensions` |
| Widget appears but shows an error | The backend may be waking up (free tier sleeps after inactivity) — wait 10 seconds and click the email again |
| Analysis seems wrong | Click the email again to re-scan; if consistently wrong, the email may have unusual encoding |
| After updating extension files | Go to `chrome://extensions` → Reload the extension, then **refresh** your Gmail/Outlook tab (F5) |
