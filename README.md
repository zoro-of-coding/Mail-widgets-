# Mail Widgets (Windows Gmail Desktop Widget via Electron)

Lightweight Windows desktop Gmail widget built with Electron + vanilla HTML/CSS/JS.

## Implemented behavior

- Desktop-widget style window (Windows-focused)
- Hidden from taskbar and Alt+Tab by using tool-window style
- Attempts to persist on desktop layer and behind normal app windows
- Re-applies desktop-layer styling periodically (helps after shell state changes such as **Win + D**)
- Gmail OAuth (`gmail.readonly`) with token storage via Windows Credential Manager when `keytar` is available
- Encrypted local token storage fallback when credential-manager integration is unavailable
- Fetch filter: `is:unread newer_than:1d`
- Auto-refresh every 5 minutes
- Minimal transparent UI listing sender, subject, and time

> Caveat: Desktop-layer behavior depends on Windows shell internals. This implementation uses Win32 interop through PowerShell and is intentionally Windows-first.

## 1) Google Cloud OAuth setup

1. Open Google Cloud Console: https://console.cloud.google.com/
2. Create/select a project.
3. Enable **Gmail API**.
4. Configure OAuth consent screen.
5. Create OAuth Client ID:
   - App type: **Desktop app**
6. Add this redirect URI:
   - `http://127.0.0.1:42813/oauth2/callback`

## 2) Place OAuth config

Create `config/google_oauth.json` (copy from `config/google_oauth.example.json`):

```json
{
  "client_id": "YOUR_GOOGLE_OAUTH_CLIENT_ID.apps.googleusercontent.com",
  "client_secret": "YOUR_GOOGLE_OAUTH_CLIENT_SECRET"
}
```

Alternative: set env var `MAIL_WIDGETS_OAUTH_CONFIG` to an absolute path of that JSON file.

## 3) Run on Windows

Prerequisites:

- Node.js + npm

Commands:

```bash
npm install
npm run dev
```

Build installer/binary:

```bash
npm run build
```

Platform-focused installer commands:

```bash
npm run build:windows   # nsis + msi
npm run build:linux     # appimage + deb
npm run build:macos     # dmg
```

Build output location:

- `release/`

## 4) Security notes

- Uses Google OAuth scope `https://www.googleapis.com/auth/gmail.readonly` (read-only mailbox access).
- Prefers OS credential storage (`keytar`) and falls back to encrypted local storage.
- Do not commit real OAuth credentials to git. Keep `config/google_oauth.json` local/private.
