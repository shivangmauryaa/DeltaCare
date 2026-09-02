# DeltaCare

A responsive campus issue and lost-and-found portal with local JSON storage.

## Run locally

```powershell
npm.cmd install
npm.cmd run dev
```

Open `http://localhost:5173`.

For a production-style run:

```powershell
npm.cmd run build
$env:NODE_ENV='production'
$env:JWT_SECRET='replace-with-a-long-random-secret'
npm.cmd start
```

Open `http://localhost:3001`.

## Current flows

- Public DeltaCare landing page
- Student/faculty registration and login
- Cookie-based authenticated sessions
- Forgot-password verification and password reset
- Campus issue reporting with tracking IDs
- Lost and found reporting with tracking IDs
- Personal activity overview and status counts
- Local JSON persistence with serialized, atomic writes
- Basic audit events for key actions
- Administrator operations workspace at `/admin`
- Admin issue queues, lost-and-found registry, user list, and status controls
- AI-assisted category/priority suggestions, safety rules, duplicate candidates, routing, and SLA deadlines
- Issue search/filtering, detail timelines, public comments, reopen/confirmation, and satisfaction feedback
- Photo/camera evidence with validation, hashing, and OCR/image-processing job records
- Lost/found attribute, image, location and time scoring with explainable match components
- Found-item inventory tags, custody events, private claim evidence, and approval/rejection workflows
- In-app notifications, global search, voluntary geolocation, QR/tag resolution, and an offline draft/outbox
- Profile, language, channel preferences, privacy consent, and personal data export
- Admin analytics, SLA/return KPIs, department/routing configuration, access suspension, and roles
- Audit viewer, bulk issue operations, versioned API aliases, signed webhook intake, system health, and job retry
- Validated import/export, timestamped backups, and guarded restore endpoints
- Installable production PWA shell with offline caching
- Role-based access control (RBAC) with an editable roles/permissions matrix and per-user role assignment
- Impact × urgency priority matrix with a business-hours SLA calendar (working hours/days)
- Auto-escalation rules that surface at-risk issues before SLA breach, with active-escalation queue
- Workload-aware AI assignee recommendation and a dedicated assignment workspace
- Anonymous reporting for sensitive complaints plus report moderation/flagging controls
- Lost & found match review (accept/reject), storage-bin inventory management, sensitive-item handling, and disposal workflow
- Configurable notification templates, data-retention preview/purge, and AI feedback capture

## Prototype administrator

- Email: `admin@deltacare.local`
- Password: `DeltaCare@00000`

Signing in with this account automatically opens `/admin`. Set `ADMIN_EMAIL` and `ADMIN_PASSWORD` before the first server start to replace these defaults.

## Prototype note

The testing OTP is intentionally fixed to `00000`. Replace this with expiring, randomly generated codes and a real delivery provider before any public deployment.

Local data is stored in `data/db.json`. The JSON repository is intended for a single Node process and prototype use only.

## Mobile PWA (Android / iOS)

A mobile-first installable PWA (`mobile/`) uses the same DeltaCare theme and connects live to the same backend/DB. It is served on port **8080** (port 6000 is blocked by browsers as an "unsafe port") so a phone on the same Wi-Fi can open it in a browser and add it to the home screen like a native app.

```powershell
# backend API (3001) must be running first
npm.cmd run dev

# then, in a second terminal
npm.cmd run mobile
```

Open on the phone: `http://192.168.1.105:8080` (use the PC's current Wi-Fi LAN address; see below). Vite proxies `/api` to the backend on `:3001`, so sessions and data stay in sync with the desktop app.

- **Add to home screen:** Android — browser menu → "Add to Home screen"; iOS — Share → "Add to Home Screen".
- Install icons and PWA manifest are generated under `mobile/public` (run `npm run icons` to regenerate).
- Production bundle: `npm run mobile:build` (outputs to `dist-mobile/`).

## Access from another device

The development server listens on all network interfaces. Devices on the same Wi-Fi can open the PC's current LAN address, for example `http://192.168.1.105:5173` (desktop) or `http://192.168.1.105:8080` (mobile). The address may change after reconnecting to Wi-Fi, and Windows Firewall must allow Node.js on the active network.

## Integration note

Email, WhatsApp and SMS webhook ingestion is implemented behind `WEBHOOK_SECRET`, while actual outbound delivery still requires provider credentials. OCR and image-feature work is represented by retryable jobs; connecting production ML/provider workers is the remaining deployment-specific step.
