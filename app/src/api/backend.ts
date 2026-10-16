// Thin typed wrapper around Tauri commands and events.
// In a plain browser (design preview) calls are served by the mock backend.

import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { mock } from "./mock";
import type * as T from "./types";

export const isTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

export async function call<R>(cmd: string, args?: Record<string, unknown>): Promise<R> {
  if (isTauri) return invoke<R>(cmd, args);
  return mock.invoke<R>(cmd, args);
}

/** Subscribes to a backend event; returns an unsubscribe function. */
export function on<P>(event: string, handler: (payload: P) => void): () => void {
  if (!isTauri) return mock.on(event, handler as (p: unknown) => void);
  let unlisten: (() => void) | null = null;
  let cancelled = false;
  listen<P>(event, (e) => handler(e.payload)).then((u) => {
    if (cancelled) u();
    else unlisten = u;
  });
  return () => {
    cancelled = true;
    unlisten?.();
  };
}

export function errorText(e: unknown): string {
  if (typeof e === "string") return e;
  if (e instanceof Error) return e.message;
  return JSON.stringify(e);
}

export const api = {
  appInfo: () => call<T.AppInfo>("app_info"),
  dashboard: () => call<T.Dashboard>("get_dashboard"),
  settings: () => call<T.Settings>("get_settings"),
  saveSettings: (settings: T.Settings) => call<T.Settings>("save_settings", { settings }),
  nextScheduledScan: () => call<number | null>("next_scheduled_scan"),

  startScan: (kind: T.ScanKind, paths: string[] = [], limited = false) => call<string>("start_scan", { kind, paths, limited }),
  pauseScan: () => call<void>("pause_scan"),
  resumeScan: () => call<void>("resume_scan"),
  cancelScan: () => call<void>("cancel_scan"),
  scanState: () => call<T.ScanState>("get_scan_state"),
  scanFileNow: (path: string) => call<T.FileVerdict>("scan_file_now", { path }),

  threats: () => call<T.ThreatEntry[]>("list_threats"),
  resolveThreats: (ids: string[], action: "quarantine" | "delete" | "ignore" | "allow" | "uninstall") =>
    call<T.ActionResult[]>("resolve_threats", { ids, action }),

  quarantine: () => call<T.QuarantineItem[]>("list_quarantine"),
  restoreQuarantine: (ids: string[], allow: boolean) => call<T.ActionResult[]>("restore_quarantine", { ids, allow }),
  deleteQuarantine: (ids: string[]) => call<T.ActionResult[]>("delete_quarantine", { ids }),

  history: () => call<T.ScanRecord[]>("get_history"),
  clearHistory: () => call<void>("clear_history"),
  exportReport: (id: string, format: "json" | "html", path?: string) =>
    call<string>("export_report", { id, format, path: path ?? null }),

  realtimeStatus: () => call<T.RealtimeStatus>("get_realtime_status"),
  setRealtime: (enabled: boolean) => call<T.RealtimeStatus>("set_realtime", { enabled }),
  realtimeEvents: () => call<T.RealtimeEvent[]>("get_realtime_events"),
  defaultWatchPaths: () => call<string[]>("get_default_watch_paths"),
  networkStatus: () => call<T.NetworkStatus>("get_network_status"),
  scanNetwork: () => call<T.NetworkStatus>("scan_network_now"),
  setNetworkProtection: (enabled: boolean) => call<T.NetworkStatus>("set_network_protection", { enabled }),
  dismissNetworkAlert: (id: string) => call<T.NetworkStatus>("dismiss_network_alert", { id }),

  dbInfo: () => call<T.DbInfo>("get_db_info"),
  checkUpdates: () => call<T.UpdateCheck>("check_updates"),
  applyUpdate: () => call<T.DbInfo>("apply_update"),
  importSignatures: (paths: string[]) => call<T.DbInfo>("import_signatures", { paths }),
  userSignatures: () => call<T.UserSignatureFile[]>("list_user_signatures"),
  removeUserSignature: (name: string) => call<T.DbInfo>("remove_user_signature", { name }),
  reloadSignatures: () => call<T.DbInfo>("reload_signatures"),

  startupItems: () => call<T.StartupItem[]>("list_startup_items"),
  browseRoots: () => call<T.DirEntry[]>("browse_roots"),
  listDir: (path: string) => call<T.DirListing>("list_dir", { path }),
  needsFullDiskAccess: () => call<boolean>("needs_full_disk_access"),
  openPrivacySettings: () => call<void>("open_privacy_settings"),
  restartApp: () => call<void>("restart_app"),
  revealPath: (path: string) => call<void>("reveal_path", { path }),

  deviceSecurity: () => call<T.DeviceSecurity>("get_device_security"),
  storageAccess: () => call<T.StorageAccess>("get_storage_access"),
  requestStorageAccess: () => call<void>("request_storage_access"),
  pickFileNative: () => call<T.PickedFile>("pick_file_native"),
  appReport: () => call<T.AppReport[]>("get_app_report"),
  uninstallApp: (packageName: string) => call<void>("uninstall_app", { packageName }),
  openAppSettings: (packageName: string) => call<void>("open_app_settings", { packageName }),
};
