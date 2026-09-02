# DeltaCare — AI Setup Prompt & Handoff Guide

Paste the section below into the next AI (on your 2nd PC) along with this project folder.
It explains what the project is, how to run it, where the secrets live, and what remains.

---

## PASTE THIS PROMPT INTO THE NEXT AI

You are helping me set up "DeltaCare", a campus issue-reporting and lost-and-found web app
(desktop + installable mobile PWA), all served locally on my own PC over Wi-Fi.

CONTEXT:
- Node.js project (Express backend + React/Vite frontend). Uses a local JSON database
  (`data/db.json`) with serialized atomic writes. Do NOT replace it with a real DB.
- Backend: `server/index.js` (port 3001). Desktop frontend: `src/main.jsx` (Vite, port 5173).
- Mobile PWA: `mobile/` served by `vite.mobile.config.js` (port 8080, proxies /api -> :3001).
- Real Twilio SMS/WhatsApp + SMTP email delivery is wired in but currently NOT fully active.

SECRETS: A `.env` file already exists in the project root and is git-ignored. It contains real
Twilio credentials that MUST be preserved and never committed/logged:
  TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_API_KEY_SID.
Do not regenerate or overwrite `.env` unless asked.

HOW TO RUN (from the project root):
  npm install
  npm run dev        # starts backend (3001) + desktop (5173); prints all IPs/ports banner
  npm run mobile     # in a second terminal; starts mobile PWA on port 8080
Open desktop at http://localhost:5173 and mobile at http://<LAN-IP>:8080.
Default admin login: admin@deltacare.local / DeltaCare@00000  (override via ADMIN_EMAIL/ADMIN_PASSWORD).

WHAT REMAINS TO COMPLETE TWILIO (requires the human's Twilio console + their phone — you cannot do these):
  1. Set TWILIO_SMS_FROM in .env to a purchased, SMS-capable Twilio number.
  2. Set TWILIO_WHATSAPP_FROM in .env to the WhatsApp sandbox number, and have the human send the
     join code from their WhatsApp to activate it.
  3. Verify the recipient phone number in Twilio (trial sends only to verified numbers).
Once set, restart the server. The admin "Templates / Communications" panel has a "Test a delivery
channel" control (Test SMS / WhatsApp / Email) to verify end-to-end.

USEFUL COMMANDS:  npm run mobile:build  |  npm run build  |  npm run icons  |  node --check server/index.js

TASKS I EXPECT FROM YOU:
- Run `npm install`, start the servers, confirm the startup banner lists all IPs/ports.
- Confirm all three services respond (API 3001, desktop 5173, mobile 8080).
- Keep the existing architecture, theme (forest green #173f35 + coral #ed7f67), and feature set intact.
- Do not change or expose .env credentials.

---

## Project overview
DeltaCare is "CampusCare AI"-style software: student/staff self-service reporting plus an admin
operations workspace. Key features: issue reporting with AI category/priority + impact×urgency
priority matrix + business-hours SLA + auto-escalation; Lost & Found with explainable matching,
claims, custody, storage bins, disposal; RBAC roles/permissions; anonymous reporting; moderation;
analytics; audit log; import/export/backups/restore; WhatsApp/Email/SMS delivery; and a mobile PWA.

## Architecture
- Express 5 backend with cookie sessions (JWT), Argon2-style bcrypt password hashing, rate limiting,
  serialized JSON writes, audit log.
- React 19 + Vite desktop app; mobile-first React PWA under `mobile/`.
- Data model: single JSON per collection in `data/db.json` (see server `ensureCollections`).

## Key files
- `server/index.js`      — all API routes, auth, AI, matching, escalation, communications, demo data
- `src/main.jsx`         — desktop UI
- `src/styles.css`       — desktop theme
- `mobile/src/main.jsx`  — mobile UI (bottom nav)
- `mobile/src/styles.css`— mobile theme
- `vite.mobile.config.js`— mobile dev server (port 8080, /api proxy)
- `.env`                 — real Twilio credentials (SECRET — never commit)
- `.env.example`         — blank credential template
- `scripts/gen-icons.js` — regenerate PWA icons
- `data/db.json`         — local JSON database

## Status of integrations
- In-app notifications: ACTIVE
- Twilio SMS + WhatsApp: code complete + credentials valid; needs From numbers + verified recipient
- SMTP email: wired; needs SMTP host/credentials in .env to activate
- WhatsApp webhook ingestion, OCR/image jobs: represented by queued job records
