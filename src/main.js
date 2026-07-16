const REFRESH_MS = 5 * 60 * 1000;

let statusEl;
let listEl;
let signInBtn;

const api = window.mailWidgets;

const formatErrorMessage = (error) => {
  const raw = error instanceof Error ? error.message : String(error ?? "Unknown error");
  const cleaned = raw
    .replace(/^Error invoking remote method '[^']+':\s*/i, "")
    .replace(/^Error:\s*/i, "")
    .trim();

  if (/Missing OAuth config/i.test(cleaned)) {
    return "Missing OAuth config. Add config/google_oauth.json with your Google client_id, then restart.";
  }

  return cleaned || "Unknown error";
};

const fmtTime = (timestampMs) => {
  if (!timestampMs) return "";
  const date = new Date(Number(timestampMs));
  if (Number.isNaN(date.getTime())) return "";
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
};

const setStatus = (text) => {
  statusEl.textContent = text;
};

const renderMessages = (messages) => {
  listEl.innerHTML = "";

  if (!messages.length) {
    const emptyEl = document.createElement("li");
    emptyEl.className = "empty";
    emptyEl.textContent = "No unread mail in the last day.";
    listEl.appendChild(emptyEl);
    return;
  }

  messages.forEach((message) => {
    const li = document.createElement("li");
    li.className = "message";

    const link = document.createElement("a");
    link.href = "#";
    link.className = "message-link";
    link.addEventListener("click", async (event) => {
      event.preventDefault();
      await api.openExternalUrl(message.gmailUrl);
    });

    const sender = document.createElement("div");
    sender.className = "sender";
    sender.textContent = message.sender;

    const subject = document.createElement("div");
    subject.className = "subject";
    subject.textContent = message.subject;

    const time = document.createElement("div");
    time.className = "time";
    time.textContent = fmtTime(message.timestampMs);

    link.append(sender, subject, time);
    li.appendChild(link);
    listEl.appendChild(li);
  });
};

const loadMessages = async () => {
  try {
    setStatus("Refreshing unread daily messages...");
    const messages = await api.fetchDailyUnreadMessages();
    renderMessages(messages);
    setStatus(`Updated ${new Date().toLocaleTimeString()}`);
  } catch (error) {
    setStatus(`Unable to refresh: ${formatErrorMessage(error)}`);
  }
};

const signIn = async () => {
  try {
    setStatus("Opening Google sign-in in your browser...");
    await api.startOAuthFlow();
    signInBtn.style.display = "none";
    await loadMessages();
  } catch (error) {
    setStatus(`Sign-in failed: ${formatErrorMessage(error)}`);
  }
};

window.addEventListener("DOMContentLoaded", async () => {
  statusEl = document.querySelector("#status-text");
  listEl = document.querySelector("#messages");
  signInBtn = document.querySelector("#signin-btn");

  signInBtn.addEventListener("click", signIn);
  document.querySelector("#refresh-btn").addEventListener("click", loadMessages);

  try {
    const { authenticated } = await api.authStatus();
    signInBtn.style.display = authenticated ? "none" : "inline-flex";

    if (authenticated) {
      await loadMessages();
    } else {
      setStatus("Sign in to load unread Gmail from the last day.");
    }
  } catch (error) {
    setStatus(`Startup failed: ${formatErrorMessage(error)}`);
  }

  setInterval(loadMessages, REFRESH_MS);
});
