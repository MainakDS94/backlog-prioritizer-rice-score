# Backlog Prioritizer (RICE)

A lightweight, **local-only** web tool to prioritize GitLab issues and work items using the **RICE framework**.

Designed for Product Owners who want a **fast, private, zero-backend** way to rank backlog items without exporting data or relying on third-party tools.

---

## ✨ Features

- Add **GitLab Issue** or **Work Item** URLs
- Automatic title fetching via GitLab API
- Supports both:
  - `/issues/:id`
  - `/work_items/:id`
- RICE scoring (Reach, Impact, Confidence, Effort — scale 1–3)
- Auto-sort by RICE or manual ordering
- Remove individual items (trash icon)
- Clean, distraction-free UI
- Works fully on **GitHub Pages / static hosting**

---

## 🔐 Security & Privacy Model

This app is **100% client-side**.

- Your GitLab Personal Access Token (PAT) is:
  - Encrypted locally using **AES-256-GCM**
  - Derived from a **passphrase you choose**
  - Stored only in `localStorage`
- The token is **never sent anywhere except GitLab**
- No backend, no analytics, no tracking
- Unlocking keeps the token **only in memory for the current tab**

If you clear browser storage or reset pairing, the token is gone.

---

## 🔗 Supported GitLab URLs

Examples:

https://issues.example.com/group/project/-/issues/1579
https://issues.example.com/group/project/-/work_items/1566

Both formats are accepted automatically.

## 📊 RICE Scoring

RICE is calculated as:

(Reach × Impact × Confidence) ÷ Effort

- Each value ranges from 1 to 3
- Final score is recalculated instantly
- Auto-sort ranks highest RICE first

## 🧠 Intended Use

- Personal backlog grooming

- Sprint planning preparation

- Feature prioritization discussions

- Product discovery ranking

- PO / PM private decision support

This tool is intentionally **single-user and local**.

## 🚀 How to Use

1. Open the app (locally or via GitHub Pages)
2. Pair your browser with a GitLab Personal Access Token (one-time)
3. Unlock with your passphrase
4. Paste GitLab issue or work item URLs
5. Score items using the RICE framework
6. Sort automatically by RICE or reorder manually
7. Remove items when done

## 🛠 Tech Stack

- Vanilla HTML / CSS / JavaScript
- Web Crypto API (PBKDF2 + AES-GCM)
- GitLab REST API v4
- No frameworks
- No dependencies

## ⚠️ Notes & Limitations

- CORS rules depend on your GitLab instance  
  (most self-hosted instances work fine)
- The GitLab token must have permission to read the project
- Data is browser-profile specific

## 🧩 Why This Exists

Most backlog tools are:

- Overkill
- Slow
- Cloud-locked
- Hard to customize

This tool is:

- Fast
- Local
- Secure
- Built for real Product Owner workflows

## 📄 License

MIT — use, modify, fork freely.
