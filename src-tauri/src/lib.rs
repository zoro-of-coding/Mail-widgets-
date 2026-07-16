use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use keyring::Entry;
use rand::{distributions::Alphanumeric, Rng};
use raw_window_handle::{HasWindowHandle, RawWindowHandle};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tauri::{Manager, WebviewWindow};
use url::Url;

const OAUTH_SCOPE: &str = "https://www.googleapis.com/auth/gmail.readonly";
const AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const REDIRECT_URI: &str = "http://127.0.0.1:42813/oauth2/callback";
const TOKEN_SERVICE: &str = "mail_widgets_gmail";
const TOKEN_USER: &str = "oauth_tokens";
const MESSAGE_QUERY: &str = "is:unread newer_than:1d";

#[derive(Debug, Deserialize)]
struct OAuthConfig {
    client_id: String,
    client_secret: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct StoredTokens {
    refresh_token: String,
    access_token: Option<String>,
    expires_at: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
    refresh_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GmailListResponse {
    messages: Option<Vec<GmailMessageId>>,
}

#[derive(Debug, Deserialize)]
struct GmailMessageId {
    id: String,
}

#[derive(Debug, Deserialize)]
struct GmailMessageResponse {
    id: String,
    #[serde(rename = "threadId")]
    thread_id: String,
    snippet: String,
    #[serde(rename = "internalDate")]
    internal_date: String,
    payload: GmailPayload,
}

#[derive(Debug, Deserialize)]
struct GmailPayload {
    headers: Vec<GmailHeader>,
}

#[derive(Debug, Deserialize)]
struct GmailHeader {
    name: String,
    value: String,
}

#[derive(Debug, Serialize)]
struct AuthStatus {
    authenticated: bool,
}

#[derive(Debug, Serialize)]
struct GmailMessageSummary {
    id: String,
    #[serde(rename = "threadId")]
    thread_id: String,
    sender: String,
    subject: String,
    snippet: String,
    #[serde(rename = "timestampMs")]
    timestamp_ms: u64,
    #[serde(rename = "gmailUrl")]
    gmail_url: String,
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn build_pkce() -> (String, String) {
    let verifier: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(96)
        .map(char::from)
        .collect();
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let challenge = URL_SAFE_NO_PAD.encode(hasher.finalize());
    (verifier, challenge)
}

fn oauth_config_path() -> Option<PathBuf> {
    if let Ok(env_path) = std::env::var("MAIL_WIDGETS_OAUTH_CONFIG") {
        let candidate = PathBuf::from(env_path);
        if candidate.exists() {
            return Some(candidate);
        }
    }

    let local = PathBuf::from("config/google_oauth.json");
    if local.exists() {
        return Some(local);
    }

    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let bundled = parent.join("config/google_oauth.json");
            if bundled.exists() {
                return Some(bundled);
            }
        }
    }

    None
}

fn read_oauth_config() -> Result<OAuthConfig, String> {
    let path = oauth_config_path().ok_or_else(|| {
        "Missing OAuth config. Add config/google_oauth.json or set MAIL_WIDGETS_OAUTH_CONFIG"
            .to_string()
    })?;

    let raw = std::fs::read_to_string(path).map_err(|err| err.to_string())?;
    serde_json::from_str::<OAuthConfig>(&raw).map_err(|err| err.to_string())
}

fn token_entry() -> Result<Entry, String> {
    Entry::new(TOKEN_SERVICE, TOKEN_USER).map_err(|err| err.to_string())
}

fn save_tokens(tokens: &StoredTokens) -> Result<(), String> {
    let entry = token_entry()?;
    let encoded = serde_json::to_string(tokens).map_err(|err| err.to_string())?;
    entry.set_password(&encoded).map_err(|err| err.to_string())
}

fn load_tokens() -> Result<StoredTokens, String> {
    let entry = token_entry()?;
    let value = entry.get_password().map_err(|err| err.to_string())?;
    serde_json::from_str(&value).map_err(|err| err.to_string())
}

async fn exchange_code_for_tokens(
    code: &str,
    verifier: &str,
    config: &OAuthConfig,
) -> Result<StoredTokens, String> {
    let mut form: HashMap<&str, String> = HashMap::new();
    form.insert("client_id", config.client_id.clone());
    form.insert("code", code.to_string());
    form.insert("code_verifier", verifier.to_string());
    form.insert("redirect_uri", REDIRECT_URI.to_string());
    form.insert("grant_type", "authorization_code".to_string());
    if let Some(secret) = &config.client_secret {
        form.insert("client_secret", secret.clone());
    }

    let client = Client::new();
    let response = client
        .post(TOKEN_URL)
        .form(&form)
        .send()
        .await
        .map_err(|err| err.to_string())?
        .error_for_status()
        .map_err(|err| err.to_string())?;

    let token = response
        .json::<TokenResponse>()
        .await
        .map_err(|err| err.to_string())?;

    Ok(StoredTokens {
        refresh_token: token.refresh_token.unwrap_or_default(),
        access_token: Some(token.access_token),
        expires_at: Some(now_seconds() + token.expires_in.saturating_sub(30)),
    })
}

async fn refresh_access_token(
    config: &OAuthConfig,
    mut tokens: StoredTokens,
) -> Result<StoredTokens, String> {
    let mut form: HashMap<&str, String> = HashMap::new();
    form.insert("client_id", config.client_id.clone());
    form.insert("refresh_token", tokens.refresh_token.clone());
    form.insert("grant_type", "refresh_token".to_string());
    if let Some(secret) = &config.client_secret {
        form.insert("client_secret", secret.clone());
    }

    let response = Client::new()
        .post(TOKEN_URL)
        .form(&form)
        .send()
        .await
        .map_err(|err| err.to_string())?
        .error_for_status()
        .map_err(|err| err.to_string())?;

    let token = response
        .json::<TokenResponse>()
        .await
        .map_err(|err| err.to_string())?;

    tokens.access_token = Some(token.access_token);
    tokens.expires_at = Some(now_seconds() + token.expires_in.saturating_sub(30));

    if let Some(refresh_token) = token.refresh_token {
        tokens.refresh_token = refresh_token;
    }

    save_tokens(&tokens)?;
    Ok(tokens)
}

async fn get_access_token() -> Result<String, String> {
    let config = read_oauth_config()?;
    let mut tokens = load_tokens()?;

    let expired = tokens.expires_at.unwrap_or_default() <= now_seconds();
    if tokens.access_token.is_none() || expired {
        if tokens.refresh_token.is_empty() {
            return Err("No refresh token available. Sign in first.".to_string());
        }
        tokens = refresh_access_token(&config, tokens).await?;
    }

    tokens
        .access_token
        .clone()
        .ok_or_else(|| "No access token found.".to_string())
}

fn read_oauth_code_via_loopback() -> Result<String, String> {
    let listener = TcpListener::bind("127.0.0.1:42813").map_err(|err| err.to_string())?;
    listener
        .set_nonblocking(false)
        .map_err(|err| err.to_string())?;

    let (mut stream, _) = listener.accept().map_err(|err| err.to_string())?;

    let mut buffer = [0_u8; 4096];
    let read = stream.read(&mut buffer).map_err(|err| err.to_string())?;
    let request = String::from_utf8_lossy(&buffer[..read]);
    let first_line = request.lines().next().unwrap_or_default();

    let path = first_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| "Invalid OAuth callback request".to_string())?;

    let callback_url =
        Url::parse(&format!("http://localhost{path}")).map_err(|err| err.to_string())?;

    let response_body = "Authentication complete. You can close this tab.";
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        response_body.len(),
        response_body
    );
    let _ = stream.write_all(response.as_bytes());

    if let Some(error) = callback_url
        .query_pairs()
        .find(|(key, _)| key == "error")
        .map(|(_, value)| value.to_string())
    {
        return Err(format!("OAuth error: {error}"));
    }

    callback_url
        .query_pairs()
        .find(|(key, _)| key == "code")
        .map(|(_, value)| value.to_string())
        .ok_or_else(|| "OAuth callback missing code".to_string())
}

#[tauri::command]
async fn start_oauth_flow() -> Result<(), String> {
    let config = read_oauth_config()?;
    let (verifier, challenge) = build_pkce();

    let mut auth_url = Url::parse(AUTH_URL).map_err(|err| err.to_string())?;
    auth_url
        .query_pairs_mut()
        .append_pair("client_id", &config.client_id)
        .append_pair("redirect_uri", REDIRECT_URI)
        .append_pair("response_type", "code")
        .append_pair("scope", OAUTH_SCOPE)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("access_type", "offline")
        .append_pair("prompt", "consent");

    webbrowser::open(auth_url.as_str()).map_err(|err| err.to_string())?;

    let code = tauri::async_runtime::spawn_blocking(read_oauth_code_via_loopback)
        .await
        .map_err(|err| err.to_string())??;

    let mut tokens = exchange_code_for_tokens(&code, &verifier, &config).await?;
    if tokens.refresh_token.is_empty() {
        if let Ok(existing) = load_tokens() {
            if !existing.refresh_token.is_empty() {
                tokens.refresh_token = existing.refresh_token;
            }
        }
    }

    if tokens.refresh_token.is_empty() {
        return Err(
            "Google did not return a refresh token. Revoke app access and sign in again."
                .to_string(),
        );
    }

    save_tokens(&tokens)
}

#[tauri::command]
fn auth_status() -> AuthStatus {
    let authenticated = load_tokens()
        .map(|tokens| !tokens.refresh_token.is_empty())
        .unwrap_or(false);

    AuthStatus { authenticated }
}

#[tauri::command]
async fn fetch_daily_unread_messages() -> Result<Vec<GmailMessageSummary>, String> {
    let access_token = get_access_token().await?;
    let client = Client::new();

    let list_response = client
        .get("https://gmail.googleapis.com/gmail/v1/users/me/messages")
        .bearer_auth(&access_token)
        .query(&[("q", MESSAGE_QUERY), ("maxResults", "20")])
        .send()
        .await
        .map_err(|err| err.to_string())?
        .error_for_status()
        .map_err(|err| err.to_string())?
        .json::<GmailListResponse>()
        .await
        .map_err(|err| err.to_string())?;

    let mut summaries = Vec::new();

    for message in list_response.messages.unwrap_or_default() {
        let detail = client
            .get(format!(
                "https://gmail.googleapis.com/gmail/v1/users/me/messages/{}",
                message.id
            ))
            .bearer_auth(&access_token)
            .query(&[
                ("format", "metadata"),
                ("metadataHeaders", "From"),
                ("metadataHeaders", "Subject"),
                ("metadataHeaders", "Date"),
            ])
            .send()
            .await
            .map_err(|err| err.to_string())?
            .error_for_status()
            .map_err(|err| err.to_string())?
            .json::<GmailMessageResponse>()
            .await
            .map_err(|err| err.to_string())?;

        let sender = detail
            .payload
            .headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case("From"))
            .map(|header| header.value.clone())
            .unwrap_or_else(|| "Unknown sender".to_string());

        let subject = detail
            .payload
            .headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case("Subject"))
            .map(|header| header.value.clone())
            .unwrap_or_else(|| "(No subject)".to_string());

        let timestamp_ms = detail
            .internal_date
            .parse::<u64>()
            .unwrap_or_else(|_| now_seconds() * 1000);

        summaries.push(GmailMessageSummary {
            id: detail.id.clone(),
            thread_id: detail.thread_id,
            sender,
            subject,
            snippet: detail.snippet,
            timestamp_ms,
            gmail_url: format!("https://mail.google.com/mail/u/0/#inbox/{}", detail.id),
        });
    }

    summaries.sort_by(|left, right| right.timestamp_ms.cmp(&left.timestamp_ms));
    summaries.truncate(10);
    Ok(summaries)
}

#[tauri::command]
fn open_external_url(url: String) -> Result<(), String> {
    webbrowser::open(&url).map_err(|err| err.to_string())?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn set_desktop_widget_window(window: &WebviewWindow) -> Result<(), String> {
    use windows::core::PCWSTR;
    use windows::w;
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::WindowsAndMessaging::{
        FindWindowW, GetWindowLongW, SetParent, SetWindowLongW, SetWindowPos, GWL_EXSTYLE,
        HWND_BOTTOM, SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOSIZE, SWP_SHOWWINDOW, WS_EX_APPWINDOW,
        WS_EX_TOOLWINDOW,
    };

    let hwnd = match window
        .window_handle()
        .map_err(|err| err.to_string())?
        .as_raw()
    {
        RawWindowHandle::Win32(handle) => HWND(handle.hwnd.get() as isize),
        _ => return Ok(()),
    };

    // Convert the widget into a tool window so it stays out of Alt+Tab and taskbar lists.
    let ex_style = unsafe { GetWindowLongW(hwnd, GWL_EXSTYLE) as u32 };
    let updated_style = (ex_style | WS_EX_TOOLWINDOW.0 as u32) & !(WS_EX_APPWINDOW.0 as u32);
    unsafe {
        SetWindowLongW(hwnd, GWL_EXSTYLE, updated_style as i32);
    }

    // Attach to the desktop host window and push behind regular application windows.
    let progman = unsafe { FindWindowW(w!("Progman"), PCWSTR::null()) };
    if progman.0 != 0 {
        unsafe {
            let _ = SetParent(hwnd, progman);
        }
    }

    unsafe {
        let _ = SetWindowPos(
            hwnd,
            HWND_BOTTOM,
            0,
            0,
            0,
            0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_SHOWWINDOW,
        );
    }

    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            if let Some(window) = app.get_webview_window("main") {
                #[cfg(target_os = "windows")]
                {
                    set_desktop_widget_window(&window)?;
                }

                let window_clone = window.clone();
                tauri::async_runtime::spawn(async move {
                    tauri::async_runtime::sleep(Duration::from_millis(400)).await;
                    #[cfg(target_os = "windows")]
                    let _ = set_desktop_widget_window(&window_clone);
                });
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            start_oauth_flow,
            auth_status,
            fetch_daily_unread_messages,
            open_external_url
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
