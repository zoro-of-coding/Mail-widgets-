import { contextBridge, ipcRenderer } from "electron";

contextBridge.exposeInMainWorld("mailWidgets", {
  startOAuthFlow: () => ipcRenderer.invoke("start_oauth_flow"),
  authStatus: () => ipcRenderer.invoke("auth_status"),
  fetchDailyUnreadMessages: () => ipcRenderer.invoke("fetch_daily_unread_messages"),
  openExternalUrl: (url) => ipcRenderer.invoke("open_external_url", { url })
});
