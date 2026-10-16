// In-memory backend used when the UI runs in a regular browser (design
// preview, UI tests). Select a platform with `?platform=android|ios|macos|windows`.

import type * as T from "./types";

type Handler = (payload: unknown) => void;
const listeners = new Map<string, Set<Handler>>();

function emit(event: string, payload: unknown) {
  listeners.get(event)?.forEach((h) => h(payload));
}

const params = new URLSearchParams(typeof location !== "undefined" ? location.search : "");
const platform = (params.get("platform") as T.Platform) || "windows";
const macStore = platform === "macos" && params.get("store") === "1";
const now = () => Math.floor(Date.now() / 1000);
const uid = () => Math.random().toString(16).slice(2, 14) + Math.random().toString(16).slice(2, 14);

const home =
  platform === "windows"
    ? "C:\\Users\\user"
    : platform === "macos"
      ? "/Users/user"
      : platform === "android"
        ? "/storage/emulated/0"
        : "/var/mobile/Containers/Data/Application/SecCorp";
const sep = platform === "windows" ? "\\" : "/";
const p = (...parts: string[]) => [home, ...parts].join(sep);

const desktop = platform === "windows" || platform === "macos" || platform === "linux";
const features: T.Features = {
  realtime: !macStore,
  processes: desktop && !macStore,
  startupItems: desktop && !macStore,
  installedApps: platform === "android",
  deviceCheck: platform === "android" || platform === "ios",
  tray: desktop && !macStore,
  autostart: desktop && !macStore,
  schedule: desktop && !macStore,
  folderPicker: desktop,
  folderBrowser: platform === "android",
  fullScan: platform !== "ios" && !macStore,
  storagePermission: platform === "android",
  fullDiskAccess: platform === "macos" && !macStore,
  removableMedia: desktop && !macStore,
  networkProtection: desktop && !macStore,
  onDemandOnly: platform === "ios" || macStore,
};

let settings: T.Settings = {
  language: (params.get("lang") as T.Settings["language"]) || "auto",
  theme: (params.get("theme") as T.Settings["theme"]) || "system",
  realtimeEnabled: platform !== "ios" && !macStore,
  networkMonitorEnabled: desktop && !macStore,
  networkThreatIntel: desktop && !macStore,
  networkSpywareHeuristics: desktop && !macStore,
  realtimePaths: [],
  autoQuarantine: true,
  notifications: true,
  heuristics: "normal",
  scanArchives: true,
  maxFileSizeMb: 512,
  exclusions: [],
  useCache: true,
  allowedHashes: [],
  schedule: { enabled: true, kind: "quick", frequency: "weekly", weekday: 2, hour: 12, minute: 0, lastRun: 0 },
  launchAtLogin: true,
  startMinimized: true,
  closeToTray: !macStore,
  updateUrl: "https://updates.example.com/seccom/update.json",
  autoUpdate: true,
  scanInstalledApps: true,
  scanNewApps: true,
  watchDownloads: true,
  onboardingDone: params.get("onboarding") !== "1",
};

const verdict = (path: string, name: string, v: T.Verdict, kind: T.Detection["kind"], desc: string, location?: string): T.FileVerdict => ({
  path,
  size: 68 + Math.floor(Math.random() * 90000),
  sha256: uid() + uid() + uid() + uid().slice(0, 4),
  fileType: "pe",
  verdict: v,
  score: kind === "heuristic" ? 45 : 0,
  detections: [{ name, kind, severity: v === "malicious" ? "high" : "medium", score: kind === "heuristic" ? 45 : 0, description: desc, location }],
  durationMs: 3,
});

let threats: T.ThreatEntry[] = params.get("threats") === "1"
  ? [{ id: uid(), verdict: verdict(p("Downloads", "invoice.pdf.exe"), "Heur.Filename.DoubleExtension", "suspicious", "heuristic", "Program disguised as a .pdf file"), source: "realtime", detectedAt: now() - 600 }]
  : [];

let quarantine: T.QuarantineItem[] = [
  { id: uid(), originalPath: p("Downloads", "setup_crack.exe"), fileName: "setup_crack.exe", threat: "Heur.Exe.PackedCode", size: 2_481_152, sha256: uid() + uid(), quarantinedAt: now() - 86400 * 3 },
  { id: uid(), originalPath: p("Downloads", "eicar.com"), fileName: "eicar.com", threat: "EICAR-Test-File", size: 68, sha256: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", quarantinedAt: now() - 86400 * 9 },
];

let history: T.ScanRecord[] = [
  { id: uid(), kind: "full", startedAt: now() - 86400 * 2 - 3600, finishedAt: now() - 86400 * 2, filesScanned: 284_513, filesCached: 0, filesSkipped: 112, bytesScanned: 186_431_000_000, errors: 37, cancelled: false, threatCount: 1, threats: [verdict(p("Downloads", "setup_crack.exe"), "Heur.Exe.PackedCode", "suspicious", "heuristic", "Code section is compressed or encrypted")], roots: [platform === "windows" ? "C:\\" : "/"], limited: false },
  { id: uid(), kind: "quick", startedAt: now() - 86400 * 9 - 120, finishedAt: now() - 86400 * 9, filesScanned: 12_904, filesCached: 0, filesSkipped: 3, bytesScanned: 9_200_000_000, errors: 0, cancelled: false, threatCount: 1, threats: [verdict(p("Downloads", "eicar.com"), "EICAR-Test-File", "malicious", "hash", "Known malicious file (SHA256 match)")], roots: [p("Downloads")], limited: false },
];

let stats: T.Stats = {
  filesScanned: 1_284_113,
  threatsFound: 3,
  threatsNeutralized: 2,
  scansCompleted: 14,
  realtimeScanned: 5_210,
  lastScanAt: now() - 86400 * 2,
  lastFullScanAt: now() - 86400 * 2,
  installedAt: now() - 86400 * 40,
};

const db: T.DbInfo = {
  version: "2026.10.13.1",
  released: now() - 3600 * 5,
  loadedAt: now(),
  hashSignatures: 3_412_870,
  bodySignatures: 128_446,
  rules: 812,
  skipped: 1_204,
  sources: [
    { name: "SecCorp built-in", kind: "builtin", signatures: 3, skipped: 0 },
    { name: "main.cvd (v62)", kind: "clamav-cvd", signatures: 3_380_000, skipped: 900 },
    { name: "malwarebazaar.csv", kind: "hash-list", signatures: 32_870, skipped: 0 },
    { name: "rules.yar", kind: "yara", signatures: 812, skipped: 0 },
  ],
  warnings: [],
};

let realtimeEvents: T.RealtimeEvent[] = [
  { time: now() - 40, path: p("Downloads", "report-q3.xlsx"), verdict: "clean", threatName: null, action: "none" },
  { time: now() - 400, path: p("Downloads", "eicar_test.zip"), verdict: "malicious", threatName: "EICAR-Test-File", action: "quarantined" },
  { time: now() - 1900, path: p("Desktop", "notes.txt"), verdict: "clean", threatName: null, action: "none" },
];

let networkAlerts: T.NetworkAlert[] = params.get("networkThreat") === "1"
  ? [{
      id: "network-demo-alert",
      detectedAt: now() - 75,
      severity: "malicious",
      kind: "known_c2",
      process: platform === "windows" ? "update.exe" : "update-agent",
      executable: platform === "windows" ? p("Downloads", "update.exe") : "/private/tmp/.update/update-agent",
      remoteAddress: "162.243.103.246",
      remotePort: 4444,
      reasons: ["known_c2", "suspicious_location", "risky_port"],
    }]
  : [];

const networkConnections: T.NetworkConnection[] = [
  {
    protocol: "TCP",
    localAddress: "192.168.1.40",
    localPort: 52144,
    remoteAddress: "142.250.74.110",
    remotePort: 443,
    state: "ESTABLISHED",
    pid: 902,
    process: "browser",
    executable: platform === "windows" ? "C:\\Program Files\\Browser\\browser.exe" : "/Applications/Browser.app/Contents/MacOS/Browser",
    verdict: "clean",
    reasons: [],
  },
  {
    protocol: "TCP",
    localAddress: "127.0.0.1",
    localPort: 3000,
    remoteAddress: null,
    remotePort: null,
    state: "LISTEN",
    pid: 1102,
    process: "node",
    executable: "/usr/local/bin/node",
    verdict: "clean",
    reasons: [],
  },
];

function networkStatus(): T.NetworkStatus {
  const flagged = networkAlerts.length
    ? [{ ...networkConnections[0], process: networkAlerts[0].process, executable: networkAlerts[0].executable, remoteAddress: networkAlerts[0].remoteAddress, remotePort: networkAlerts[0].remotePort, verdict: networkAlerts[0].severity, reasons: networkAlerts[0].reasons }]
    : [];
  return {
    supported: desktop,
    enabled: settings.networkMonitorEnabled,
    running: settings.networkMonitorEnabled,
    scanning: false,
    lastScanAt: now() - 20,
    activeConnections: 1 + flagged.length,
    listeningPorts: 1,
    indicatorCount: 5,
    intelligenceUpdatedAt: now() - 600,
    connections: [...flagged, ...networkConnections],
    alerts: networkAlerts,
    error: null,
  };
}

let scanTimer: ReturnType<typeof setInterval> | null = null;
let scan: { id: string; kind: T.ScanKind; progress: T.ScanProgress; threats: T.ThreatEntry[]; tick: number } | null = null;

function dashboard(): T.Dashboard {
  const issues: T.IssueCode[] = [];
  if (threats.length) issues.push("threats");
  if (!settings.realtimeEnabled) issues.push("realtime_off");
  if (desktop && !settings.networkMonitorEnabled) issues.push("network_off");
  else if (networkAlerts.length) issues.push("network_alert");
  if (platform === "macos" && params.get("fda") === "1") issues.push("full_disk_access");
  if (platform === "android" && params.get("storage") === "0") issues.push("storage_access");
  return {
    status: threats.length ? "danger" : issues.filter((i) => i !== "full_disk_access").length ? "attention" : "protected",
    issues,
    realtime: realtimeStatus(),
    network: networkStatus(),
    db,
    dbReady: true,
    stats,
    activeThreats: threats.length,
    quarantineCount: quarantine.length,
    quarantineBytes: quarantine.reduce((a, q) => a + q.size, 0),
    lastScan: history[0] ?? null,
    scanRunning: !!scan,
  };
}

const noDiskAccess = platform === "macos" && params.get("fda") === "1";

function realtimeStatus(): T.RealtimeStatus {
  const watched =
    platform === "android"
      ? [p("Download")]
      : platform === "ios"
        ? [p("Documents")]
        : noDiskAccess
          ? [p("Library", "LaunchAgents"), "/Library/LaunchAgents", "/Library/LaunchDaemons"]
          : [p("Downloads"), p("Desktop"), p("Documents")];
  return {
    supported: true,
    enabled: settings.realtimeEnabled,
    running: settings.realtimeEnabled,
    watched: settings.realtimeEnabled ? watched : [],
    scanned: stats.realtimeScanned,
    error: null,
    limited: noDiskAccess,
  };
}

let scanLimited = false;

function startScan(kind: T.ScanKind, limited = false) {
  if (scan) throw "busy";
  if (noDiskAccess && kind !== "custom" && !limited) throw "fda_required";
  scanLimited = noDiskAccess;
  const total = kind === "full" ? 48_000 : kind === "apps" ? 86 : 6_400;
  scan = {
    id: uid(),
    kind,
    tick: 0,
    threats: [],
    progress: { filesScanned: 0, filesDiscovered: 0, filesCached: 0, filesSkipped: 0, bytesScanned: 0, threats: 0, errors: 0, walkDone: false, paused: false, cancelled: false, currentPath: "", elapsedMs: 0 },
  };
  const files = ["Downloads", "Desktop", "Documents", "AppData", "Projects"];
  scanTimer = setInterval(() => {
    if (!scan) return;
    const pr = scan.progress;
    if (!pr.paused) {
      scan.tick++;
      pr.elapsedMs += 200;
      pr.filesDiscovered = Math.min(total, pr.filesDiscovered + Math.ceil(total / 12));
      pr.walkDone = pr.filesDiscovered >= total;
      pr.filesScanned = Math.min(pr.filesDiscovered, pr.filesScanned + Math.ceil(total / 30));
      pr.bytesScanned += 38_000_000;
      pr.currentPath = p(files[scan.tick % files.length], `folder-${scan.tick}`, `document-${scan.tick * 7}.pdf`);
      if (scan.tick === 9 || (scan.tick === 17 && kind !== "apps")) {
        const v =
          scan.tick === 9
            ? verdict(p("Downloads", "eicar.com"), "EICAR-Test-File", "malicious", "hash", "Known malicious file (SHA256 match)")
            : verdict(p("Downloads", "photos", "holiday.jpg.scr"), "Heur.Filename.DoubleExtension", "suspicious", "heuristic", "Program disguised as a .jpg file");
        const entry: T.ThreatEntry = { id: uid(), verdict: v, source: "scan", detectedAt: now() };
        scan.threats.push(entry);
        threats = [entry, ...threats];
        pr.threats++;
        emit("scan://threat", entry);
      }
    }
    emit("scan://progress", { scanId: scan.id, kind: scan.kind, ...pr });
    if (pr.walkDone && pr.filesScanned >= total) finishScan(false);
  }, 200);
  return scan.id;
}

function finishScan(cancelled: boolean) {
  if (!scan) return;
  if (scanTimer) clearInterval(scanTimer);
  const s = scan;
  scan = null;
  const record: T.ScanRecord = {
    id: s.id,
    kind: s.kind,
    startedAt: now() - Math.round(s.progress.elapsedMs / 1000),
    finishedAt: now(),
    filesScanned: s.progress.filesScanned,
    filesCached: 0,
    filesSkipped: 2,
    bytesScanned: s.progress.bytesScanned,
    errors: 0,
    cancelled,
    threatCount: s.threats.length,
    threats: s.threats.map((t) => t.verdict),
    roots: scanLimited ? [p("Library", "LaunchAgents"), "/Users/Shared", "/private/tmp"] : [p("Downloads")],
    limited: scanLimited,
  };
  history = [record, ...history];
  stats = { ...stats, filesScanned: stats.filesScanned + record.filesScanned, threatsFound: stats.threatsFound + record.threatCount, scansCompleted: stats.scansCompleted + 1, lastScanAt: now() };
  emit("scan://finished", record);
  emit("status://changed", null);
}

const apps: T.AppReport[] = [
  { packageName: "com.flashlight.superbright", label: "Super Flashlight", versionName: "3.2.1", installer: "", trustedSource: false, isSystem: false, icon: null, verdict: "suspicious", threatName: "Heur.Android.RiskyPermissions", riskScore: 50, riskReasons: ["sms", "accessibility", "overlay", "unknown_source"], permissionsCount: 31, lastUpdateTime: Date.now() - 86400000 * 3 },
  { packageName: "com.example.bank", label: "Мой Банк", versionName: "12.4.0", installer: "com.android.vending", trustedSource: true, isSystem: false, icon: null, verdict: "clean", threatName: null, riskScore: 15, riskReasons: ["sms", "contacts"], permissionsCount: 22, lastUpdateTime: Date.now() - 86400000 * 10 },
  { packageName: "org.telegram.messenger", label: "Telegram", versionName: "11.2.3", installer: "com.android.vending", trustedSource: true, isSystem: false, icon: null, verdict: "clean", threatName: null, riskScore: 10, riskReasons: ["microphone", "contacts"], permissionsCount: 54, lastUpdateTime: Date.now() - 86400000 * 1 },
  { packageName: "com.example.notes", label: "Notes", versionName: "2.0", installer: "com.android.vending", trustedSource: true, isSystem: false, icon: null, verdict: "clean", threatName: null, riskScore: 0, riskReasons: [], permissionsCount: 4, lastUpdateTime: Date.now() - 86400000 * 30 },
];

const handlers: Record<string, (a: Record<string, unknown>) => unknown> = {
  app_info: () => ({ version: "1.0.0", engineVersion: "1.0.0", platform, arch: "aarch64", features, updateConfigured: true, updateMode: "signed", dataDir: p(".seccom") }),
  get_dashboard: () => dashboard(),
  get_settings: () => settings,
  save_settings: (a) => {
    settings = a.settings as T.Settings;
    emit("status://changed", null);
    return settings;
  },
  next_scheduled_scan: () => (settings.schedule.enabled ? now() + 86400 * 2 : null),
  start_scan: (a) => startScan(a.kind as T.ScanKind, Boolean(a.limited)),
  pause_scan: () => scan && (scan.progress.paused = true),
  resume_scan: () => scan && (scan.progress.paused = false),
  cancel_scan: () => {
    if (scan) scan.progress.cancelled = true;
    finishScan(true);
  },
  get_scan_state: () =>
    scan
      ? { running: true, scanId: scan.id, kind: scan.kind, progress: scan.progress, threats: scan.threats }
      : { running: false, scanId: null, kind: null, progress: null, threats: [] },
  scan_file_now: (a) => {
    const path = String(a.path);
    const bad = /eicar|\.(scr|exe)$/i.test(path);
    return bad ? verdict(path, "EICAR-Test-File", "malicious", "hash", "Known malicious file (SHA256 match)") : { path, size: 1024, fileType: "text", verdict: "clean", score: 0, detections: [], durationMs: 2 };
  },
  list_threats: () => {
    const rank = { malicious: 2, suspicious: 1, clean: 0 } as const;
    return [...threats].sort(
      (a, b) => rank[b.verdict.verdict] - rank[a.verdict.verdict] || b.verdict.score - a.verdict.score || b.detectedAt - a.detectedAt,
    );
  },
  resolve_threats: (a) => {
    const ids = a.ids as string[];
    const action = a.action as string;
    const results = ids.map((id) => ({ id, ok: true, error: null, path: null }));
    for (const id of ids) {
      const t = threats.find((x) => x.id === id);
      if (t && action === "quarantine")
        quarantine = [{ id: uid(), originalPath: t.verdict.path, fileName: t.verdict.path.split(/[\\/]/).pop() ?? "", threat: t.verdict.detections[0]?.name ?? "", size: t.verdict.size, sha256: t.verdict.sha256 ?? "", quarantinedAt: now() }, ...quarantine];
    }
    threats = threats.filter((t) => !ids.includes(t.id));
    if (action === "quarantine" || action === "delete") stats = { ...stats, threatsNeutralized: stats.threatsNeutralized + ids.length };
    emit("status://changed", null);
    return results;
  },
  list_quarantine: () => quarantine,
  restore_quarantine: (a) => {
    const ids = a.ids as string[];
    const restored = quarantine.filter((q) => ids.includes(q.id));
    quarantine = quarantine.filter((q) => !ids.includes(q.id));
    return restored.map((q) => ({ id: q.id, ok: true, error: null, path: q.originalPath }));
  },
  delete_quarantine: (a) => {
    const ids = a.ids as string[];
    quarantine = quarantine.filter((q) => !ids.includes(q.id));
    return ids.map((id) => ({ id, ok: true, error: null, path: null }));
  },
  get_history: () => history,
  clear_history: () => {
    history = [];
  },
  export_report: (a) => p("Downloads", `seccorp-report.${a.format}`),
  get_realtime_status: () => realtimeStatus(),
  set_realtime: (a) => {
    settings = { ...settings, realtimeEnabled: Boolean(a.enabled) };
    emit("status://changed", null);
    return realtimeStatus();
  },
  get_realtime_events: () => realtimeEvents,
  get_default_watch_paths: () => realtimeStatus().watched.length ? realtimeStatus().watched : [p("Downloads"), p("Desktop")],
  get_network_status: () => networkStatus(),
  scan_network_now: () => networkStatus(),
  set_network_protection: (a) => {
    settings = { ...settings, networkMonitorEnabled: Boolean(a.enabled) };
    emit("status://changed", null);
    return networkStatus();
  },
  dismiss_network_alert: (a) => {
    networkAlerts = networkAlerts.filter((alert) => alert.id !== String(a.id));
    emit("status://changed", null);
    return networkStatus();
  },
  get_db_info: () => db,
  check_updates: () => ({ configured: true, available: false, current: db.version, latest: db.version, released: db.released, size: 48_000_000, notes: null, checkedAt: now() }),
  apply_update: () => db,
  import_signatures: () => db,
  list_user_signatures: () => [
    { name: "company-rules.yar", size: 18_204, modified: now() - 86400 * 4 },
    { name: "malwarebazaar.csv", size: 4_200_311, modified: now() - 86400 },
  ],
  remove_user_signature: () => db,
  reload_signatures: () => db,
  list_startup_items: () =>
    platform === "macos"
      ? [
          { name: "com.example.updater", command: "/Library/Application Support/Example/updater --daemon", path: "/Library/Application Support/Example/updater", location: "/Library/LaunchDaemons" },
          { name: "com.dropbox.dropboxmacupdate.agent", command: "/Applications/Dropbox.app/Contents/MacOS/DropboxMacUpdate", path: "/Applications/Dropbox.app/Contents/MacOS/DropboxMacUpdate", location: p("Library", "LaunchAgents") },
        ]
      : [
          { name: "OneDrive", command: '"C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe" /background', path: "C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe", location: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" },
          { name: "SecurityHealth", command: "%windir%\\system32\\SecurityHealthSystray.exe", path: "C:\\Windows\\system32\\SecurityHealthSystray.exe", location: "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" },
          { name: "Telegram Desktop", command: '"C:\\Users\\user\\AppData\\Roaming\\Telegram Desktop\\Telegram.exe" -autostart', path: "C:\\Users\\user\\AppData\\Roaming\\Telegram Desktop\\Telegram.exe", location: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" },
        ],
  browse_roots: () => [{ name: "Внутренняя память", path: home, isDir: true, size: 0 }],
  list_dir: (a) => {
    const path = String(a.path);
    const names = ["Download", "Documents", "DCIM", "Pictures", "Music", "Telegram", "Bluetooth"];
    return { path, parent: path === home ? null : path.split("/").slice(0, -1).join("/"), entries: names.map((n) => ({ name: n, path: `${path}/${n}`, isDir: true, size: 0 })).concat([{ name: "readme.txt", path: `${path}/readme.txt`, isDir: false, size: 1200 }]) };
  },
  needs_full_disk_access: () => noDiskAccess,
  open_privacy_settings: () => undefined,
  restart_app: () => {
    window.location.reload();
  },
  reveal_path: () => undefined,
  get_device_security: () =>
    platform === "ios"
      ? { platform: "ios", osVersion: "18.6", model: "iPhone", manufacturer: "Apple", sdkInt: null, securityPatch: null, screenLock: true, biometrics: true, biometryType: "faceId", developerOptions: null, usbDebugging: null, storageEncrypted: null, notificationsAllowed: null }
      : { platform: "android", osVersion: "15", model: "Pixel 8", manufacturer: "Google", sdkInt: 35, securityPatch: "2026-08-05", screenLock: true, biometrics: null, biometryType: null, developerOptions: true, usbDebugging: false, storageEncrypted: true, notificationsAllowed: true },
  get_storage_access: () => ({ granted: params.get("storage") !== "0", allFilesAccess: true }),
  request_storage_access: () => undefined,
  pick_file_native: () => ({ cancelled: false, path: p("Download", "document.pdf"), name: "document.pdf" }),
  get_app_report: () => apps,
  uninstall_app: () => undefined,
  open_app_settings: () => undefined,
};

export const mock = {
  async invoke<R>(cmd: string, args: Record<string, unknown> = {}): Promise<R> {
    await new Promise((r) => setTimeout(r, 60));
    const h = handlers[cmd];
    if (!h) throw `mock: unknown command ${cmd}`;
    return h(args) as R;
  },
  on(event: string, handler: Handler): () => void {
    if (!listeners.has(event)) listeners.set(event, new Set());
    listeners.get(event)!.add(handler);
    return () => listeners.get(event)?.delete(handler);
  },
};

// Simulate real-time activity in the preview.
if (typeof window !== "undefined" && !("__TAURI_INTERNALS__" in window)) {
  setInterval(() => {
    if (!settings.realtimeEnabled) return;
    const ev: T.RealtimeEvent = { time: now(), path: p("Downloads", `file-${Math.floor(Math.random() * 999)}.pdf`), verdict: "clean", threatName: null, action: "none" };
    realtimeEvents = [ev, ...realtimeEvents].slice(0, 50);
    stats = { ...stats, realtimeScanned: stats.realtimeScanned + 1 };
    emit("realtime://event", ev);
  }, 7000);
}
