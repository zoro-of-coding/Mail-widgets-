# Mail Widgets (Windows Gmail Desktop Widget via Tauri)

Lightweight Windows desktop Gmail widget built with Tauri + vanilla HTML/CSS/JS.

## Implemented behavior

- Desktop-widget style window (Windows-focused)
- Stays behind normal app windows
- Hidden from Alt+Tab
- Hidden from taskbar
- Attempts to persist on desktop layer when **Win + D** is used
- Gmail OAuth (`gmail.readonly`) with token storage in Windows credential store via `keyring`
- Fetch filter: `is:unread newer_than:1d`
- Auto-refresh every 5 minutes
- Minimal transparent UI listing sender, subject, and time

> Caveat: Desktop-layer behavior depends on Windows shell internals. This implementation uses Win32 parent/style interop and is intentionally Windows-only for MVP.

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

- Rust toolchain
- Node.js + npm
- Visual Studio C++ Build Tools
- Microsoft Edge WebView2 runtime

Commands:

```bash
npm install
npm run dev
```

Build installer/binary:

```bash
npm run build
```

## 4) Security notes

- Uses Google OAuth scope `https://www.googleapis.com/auth/gmail.readonly` (read-only mailbox access).
- Tokens are persisted via the OS credential store (`keyring`) rather than plain frontend storage.
- Do not commit real OAuth credentials to git. Keep `config/google_oauth.json` local/private.
