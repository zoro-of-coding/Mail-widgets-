import { app, BrowserWindow, ipcMain, shell, safeStorage } from "electron";
import { createHash, randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import http from "node:http";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, "..");

const OAUTH_SCOPE = "https://www.googleapis.com/auth/gmail.readonly";
const AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_URL = "https://oauth2.googleapis.com/token";
const REDIRECT_URI = "http://127.0.0.1:42813/oauth2/callback";
const MESSAGE_QUERY = "is:unread newer_than:1d";
const TOKEN_SERVICE = "mail_widgets_gmail";
const TOKEN_USER = "oauth_tokens";

let mainWindow;
let keytarClient;

const nowSeconds = () => Math.floor(Date.now() / 1000);

const base64Url = (buffer) =>
  buffer
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");

const buildPkce = () => {
  const verifier = base64Url(randomBytes(72));
  const challenge = base64Url(createHash("sha256").update(verifier).digest());
  return { verifier, challenge };
};

const oauthConfigPath = () => {
  if (process.env.MAIL_WIDGETS_OAUTH_CONFIG && fs.existsSync(process.env.MAIL_WIDGETS_OAUTH_CONFIG)) {
    return process.env.MAIL_WIDGETS_OAUTH_CONFIG;
  }

  const local = path.join(rootDir, "config", "google_oauth.json");
  if (fs.existsSync(local)) {
    return local;
  }

  const bundled = path.join(process.resourcesPath, "config", "google_oauth.json");
  if (fs.existsSync(bundled)) {
    return bundled;
  }

  return null;
};

const readOAuthConfig = () => {
  const configPath = oauthConfigPath();
  if (!configPath) {
    throw new Error("Missing OAuth config. Add config/google_oauth.json or set MAIL_WIDGETS_OAUTH_CONFIG");
  }

  const parsed = JSON.parse(fs.readFileSync(configPath, "utf-8"));
  if (!parsed.client_id) {
    throw new Error("OAuth config is missing client_id");
  }

  return parsed;
};

const tokenFilePath = () => path.join(app.getPath("userData"), "oauth_tokens.json");

const loadFileTokens = () => {
  const filePath = tokenFilePath();
  if (!fs.existsSync(filePath)) {
    return null;
  }

  const raw = fs.readFileSync(filePath);
  const decoded = safeStorage.isEncryptionAvailable()
    ? safeStorage.decryptString(raw)
    : raw.toString("utf-8");

  return JSON.parse(decoded);
};

const saveFileTokens = (tokens) => {
  const filePath = tokenFilePath();
  const raw = JSON.stringify(tokens);
  const encoded = safeStorage.isEncryptionAvailable()
    ? safeStorage.encryptString(raw)
    : Buffer.from(raw, "utf-8");

  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, encoded);
};

const getKeytar = async () => {
  if (keytarClient !== undefined) {
    return keytarClient;
  }

  try {
    const module = await import("keytar");
    keytarClient = module.default ?? module;
  } catch {
    keytarClient = null;
  }

  return keytarClient;
};

const loadTokens = async () => {
  const keytar = await getKeytar();
  if (keytar) {
    const raw = await keytar.getPassword(TOKEN_SERVICE, TOKEN_USER);
    return raw ? JSON.parse(raw) : null;
  }

  return loadFileTokens();
};

const saveTokens = async (tokens) => {
  const keytar = await getKeytar();
  if (keytar) {
    await keytar.setPassword(TOKEN_SERVICE, TOKEN_USER, JSON.stringify(tokens));
    return;
  }

  saveFileTokens(tokens);
};

const exchangeCodeForTokens = async (code, verifier, config) => {
  const form = new URLSearchParams({
    client_id: config.client_id,
    code,
    code_verifier: verifier,
    redirect_uri: REDIRECT_URI,
    grant_type: "authorization_code"
  });

  if (config.client_secret) {
    form.set("client_secret", config.client_secret);
  }

  const response = await fetch(TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form
  });

  if (!response.ok) {
    throw new Error(`Token exchange failed: ${response.status}`);
  }

  const token = await response.json();
  return {
    refresh_token: token.refresh_token ?? "",
    access_token: token.access_token,
    expires_at: nowSeconds() + Math.max((token.expires_in ?? 0) - 30, 0)
  };
};

const refreshAccessToken = async (config, tokens) => {
  const form = new URLSearchParams({
    client_id: config.client_id,
    refresh_token: tokens.refresh_token,
    grant_type: "refresh_token"
  });

  if (config.client_secret) {
    form.set("client_secret", config.client_secret);
  }

  const response = await fetch(TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form
  });

  if (!response.ok) {
    throw new Error(`Token refresh failed: ${response.status}`);
  }

  const token = await response.json();
  const updated = {
    ...tokens,
    access_token: token.access_token,
    expires_at: nowSeconds() + Math.max((token.expires_in ?? 0) - 30, 0)
  };

  if (token.refresh_token) {
    updated.refresh_token = token.refresh_token;
  }

  await saveTokens(updated);
  return updated;
};

const getAccessToken = async () => {
  const config = readOAuthConfig();
  let tokens = await loadTokens();

  if (!tokens) {
    throw new Error("No refresh token available. Sign in first.");
  }

  const expired = !tokens.access_token || (tokens.expires_at ?? 0) <= nowSeconds();
  if (expired) {
    if (!tokens.refresh_token) {
      throw new Error("No refresh token available. Sign in first.");
    }

    tokens = await refreshAccessToken(config, tokens);
  }

  if (!tokens.access_token) {
    throw new Error("No access token found.");
  }

  return tokens.access_token;
};

const readOAuthCodeViaLoopback = () =>
  new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      try {
        const callbackUrl = new URL(req.url ?? "/", "http://localhost");

        res.writeHead(200, { "Content-Type": "text/plain; charset=utf-8" });
        res.end("Authentication complete. You can close this tab.");

        const error = callbackUrl.searchParams.get("error");
        if (error) {
          reject(new Error(`OAuth error: ${error}`));
          return;
        }

        const code = callbackUrl.searchParams.get("code");
        if (!code) {
          reject(new Error("OAuth callback missing code"));
          return;
        }

        resolve(code);
      } catch (error) {
        reject(error);
      } finally {
        server.close();
      }
    });

    server.on("error", reject);
    server.listen(42813, "127.0.0.1");
  });

const applyWindowsDesktopWidgetStyle = () => {
  if (process.platform !== "win32" || !mainWindow) {
    return;
  }

  const nativeHandle = mainWindow.getNativeWindowHandle();
  const hwnd = Number(
    nativeHandle.length >= 8
      ? nativeHandle.readBigUInt64LE(0)
      : nativeHandle.readUInt32LE(0)
  );

  const script = `
Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class WinApi {
  [DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);
  [DllImport("user32.dll")] public static extern int GetWindowLong(IntPtr hWnd, int nIndex);
  [DllImport("user32.dll")] public static extern int SetWindowLong(IntPtr hWnd, int nIndex, int dwNewLong);
  [DllImport("user32.dll")] public static extern IntPtr SetParent(IntPtr hWndChild, IntPtr hWndNewParent);
  [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter, int X, int Y, int cx, int cy, uint uFlags);
}
"@
$hwnd = [IntPtr]${hwnd}
$GWL_EXSTYLE = -20
$WS_EX_TOOLWINDOW = 0x00000080
$WS_EX_APPWINDOW = 0x00040000
$HWND_BOTTOM = [IntPtr]1
$SWP_NOMOVE = 0x0002
$SWP_NOSIZE = 0x0001
$SWP_NOACTIVATE = 0x0010
$SWP_SHOWWINDOW = 0x0040
$style = [WinApi]::GetWindowLong($hwnd, $GWL_EXSTYLE)
$updated = ($style -bor $WS_EX_TOOLWINDOW) -band (-bnot $WS_EX_APPWINDOW)
[WinApi]::SetWindowLong($hwnd, $GWL_EXSTYLE, $updated) | Out-Null
$progman = [WinApi]::FindWindow("Progman", $null)
if ($progman -ne [IntPtr]::Zero) { [WinApi]::SetParent($hwnd, $progman) | Out-Null }
[WinApi]::SetWindowPos($hwnd, $HWND_BOTTOM, 0, 0, 0, 0, $SWP_NOMOVE -bor $SWP_NOSIZE -bor $SWP_NOACTIVATE -bor $SWP_SHOWWINDOW) | Out-Null
`;

  const child = spawn("powershell", ["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script], {
    windowsHide: true
  });

  child.on("error", () => {});
};

const createWindow = () => {
  mainWindow = new BrowserWindow({
    title: "Daily Gmail Widget",
    width: 360,
    height: 520,
    resizable: false,
    frame: false,
    transparent: true,
    skipTaskbar: true,
    webPreferences: {
      preload: path.join(__dirname, "preload.mjs"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false
    }
  });

  mainWindow.loadFile(path.join(rootDir, "src", "index.html"));

  if (process.platform === "win32") {
    applyWindowsDesktopWidgetStyle();
    setTimeout(applyWindowsDesktopWidgetStyle, 400);
    setInterval(applyWindowsDesktopWidgetStyle, 5000);
  }
};

ipcMain.handle("start_oauth_flow", async () => {
  const config = readOAuthConfig();
  const { verifier, challenge } = buildPkce();

  const authUrl = new URL(AUTH_URL);
  authUrl.searchParams.set("client_id", config.client_id);
  authUrl.searchParams.set("redirect_uri", REDIRECT_URI);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("scope", OAUTH_SCOPE);
  authUrl.searchParams.set("code_challenge", challenge);
  authUrl.searchParams.set("code_challenge_method", "S256");
  authUrl.searchParams.set("access_type", "offline");
  authUrl.searchParams.set("prompt", "consent");

  const codePromise = readOAuthCodeViaLoopback();
  await shell.openExternal(authUrl.toString());

  const code = await codePromise;
  let tokens = await exchangeCodeForTokens(code, verifier, config);

  if (!tokens.refresh_token) {
    const existing = await loadTokens();
    if (existing?.refresh_token) {
      tokens.refresh_token = existing.refresh_token;
    }
  }

  if (!tokens.refresh_token) {
    throw new Error("Google did not return a refresh token. Revoke app access and sign in again.");
  }

  await saveTokens(tokens);
});

ipcMain.handle("auth_status", async () => {
  const tokens = await loadTokens();
  return { authenticated: Boolean(tokens?.refresh_token) };
});

ipcMain.handle("fetch_daily_unread_messages", async () => {
  const accessToken = await getAccessToken();

  const listUrl = new URL("https://gmail.googleapis.com/gmail/v1/users/me/messages");
  listUrl.searchParams.set("q", MESSAGE_QUERY);
  listUrl.searchParams.set("maxResults", "20");

  const authHeader = ["Bearer", accessToken].join(" ");
  const listResponse = await fetch(listUrl, {
    headers: { Authorization: authHeader }
  });

  if (!listResponse.ok) {
    throw new Error(`Unable to list Gmail messages: ${listResponse.status}`);
  }

  const listData = await listResponse.json();
  const ids = (listData.messages ?? []).map((message) => message.id);

  const summaries = await Promise.all(
    ids.map(async (id) => {
      const detailUrl = new URL(`https://gmail.googleapis.com/gmail/v1/users/me/messages/${id}`);
      detailUrl.searchParams.set("format", "metadata");
      detailUrl.searchParams.append("metadataHeaders", "From");
      detailUrl.searchParams.append("metadataHeaders", "Subject");
      detailUrl.searchParams.append("metadataHeaders", "Date");

      const detailResponse = await fetch(detailUrl, {
        headers: { Authorization: authHeader }
      });

      if (!detailResponse.ok) {
        throw new Error(`Unable to fetch Gmail message ${id}: ${detailResponse.status}`);
      }

      const detail = await detailResponse.json();
      const headers = detail.payload?.headers ?? [];
      const sender = headers.find((header) => header.name?.toLowerCase() === "from")?.value ?? "Unknown sender";
      const subject =
        headers.find((header) => header.name?.toLowerCase() === "subject")?.value ?? "(No subject)";
      const timestampMs = Number(detail.internalDate) || Date.now();

      return {
        id: detail.id,
        threadId: detail.threadId,
        sender,
        subject,
        snippet: detail.snippet,
        timestampMs,
        gmailUrl: `https://mail.google.com/mail/u/0/#inbox/${detail.id}`
      };
    })
  );

  return summaries.sort((a, b) => b.timestampMs - a.timestampMs).slice(0, 10);
});

ipcMain.handle("open_external_url", async (_event, { url }) => {
  await shell.openExternal(url);
});

app.whenReady().then(() => {
  createWindow();

  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    app.quit();
  }
});
