// Types mirroring the Rust DTOs (see app/src-tauri/src/model.rs and the engine).

export type Platform = "windows" | "macos" | "android" | "ios" | "linux";
export type Verdict = "clean" | "suspicious" | "malicious";
export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type HeuristicLevel = "off" | "low" | "normal" | "high";
export type ScanKind = "quick" | "full" | "custom" | "apps";

export interface Features {
  realtime: boolean;
  processes: boolean;
  startupItems: boolean;
  installedApps: boolean;
  deviceCheck: boolean;
  tray: boolean;
  autostart: boolean;
  schedule: boolean;
  folderPicker: boolean;
  folderBrowser: boolean;
  fullScan: boolean;
  storagePermission: boolean;
  fullDiskAccess: boolean;
  removableMedia: boolean;
}

export interface AppInfo {
  version: string;
  engineVersion: string;
  platform: Platform;
  arch: string;
  features: Features;
  updateConfigured: boolean;
  updateMode: "signed" | "freshclam" | "none";
  dataDir: string;
}

export interface Detection {
  name: string;
  kind: "hash" | "pattern" | "rule" | "heuristic";
  severity: Severity;
  score: number;
  description: string;
  location?: string;
}

export interface FileVerdict {
  path: string;
  size: number;
  sha256?: string;
  fileType: string;
  verdict: Verdict;
  score: number;
  detections: Detection[];
  skipped?: string;
  durationMs: number;
}

export interface ThreatEntry {
  id: string;
  verdict: FileVerdict;
  source: "scan" | "realtime" | "service" | "apps";
  detectedAt: number;
  packageName?: string;
  appLabel?: string;
}

export interface ScanProgress {
  filesScanned: number;
  filesDiscovered: number;
  filesCached: number;
  filesSkipped: number;
  bytesScanned: number;
  threats: number;
  errors: number;
  walkDone: boolean;
  paused: boolean;
  cancelled: boolean;
  currentPath: string;
  elapsedMs: number;
}

export interface ScanProgressEvent extends ScanProgress {
  scanId: string;
  kind: ScanKind;
}

export interface ScanState {
  running: boolean;
  scanId: string | null;
  kind: ScanKind | null;
  progress: ScanProgress | null;
  threats: ThreatEntry[];
}

export interface ScanRecord {
  id: string;
  kind: ScanKind;
  startedAt: number;
  finishedAt: number;
  filesScanned: number;
  filesCached: number;
  filesSkipped: number;
  bytesScanned: number;
  errors: number;
  cancelled: boolean;
  threatCount: number;
  threats: FileVerdict[];
  roots: string[];
  /** macOS without Full Disk Access: privacy-protected folders were skipped. */
  limited: boolean;
}

export interface Stats {
  filesScanned: number;
  threatsFound: number;
  threatsNeutralized: number;
  scansCompleted: number;
  realtimeScanned: number;
  lastScanAt: number | null;
  lastFullScanAt: number | null;
  installedAt: number;
}

export interface SourceInfo {
  name: string;
  kind: string;
  signatures: number;
  skipped: number;
}

export interface DbInfo {
  version: string;
  released: number;
  loadedAt: number;
  hashSignatures: number;
  bodySignatures: number;
  rules: number;
  skipped: number;
  sources: SourceInfo[];
  warnings: string[];
}

export interface RealtimeStatus {
  supported: boolean;
  enabled: boolean;
  running: boolean;
  watched: string[];
  scanned: number;
  error: string | null;
  /** macOS without Full Disk Access: privacy-protected folders are not monitored. */
  limited: boolean;
}

export interface RealtimeEvent {
  time: number;
  path: string;
  verdict: Verdict;
  threatName: string | null;
  action: "none" | "quarantined" | "failed";
}

export type IssueCode =
  | "threats"
  | "realtime_off"
  | "realtime_error"
  | "never_scanned"
  | "no_recent_scan"
  | "db_outdated"
  | "storage_access"
  | "full_disk_access";

export interface Dashboard {
  status: "protected" | "attention" | "danger";
  issues: IssueCode[];
  realtime: RealtimeStatus;
  db: DbInfo;
  dbReady: boolean;
  stats: Stats;
  activeThreats: number;
  quarantineCount: number;
  quarantineBytes: number;
  lastScan: ScanRecord | null;
  scanRunning: boolean;
}

export interface Schedule {
  enabled: boolean;
  kind: "quick" | "full";
  frequency: "daily" | "weekly";
  weekday: number;
  hour: number;
  minute: number;
  lastRun: number;
}

export interface Settings {
  language: "auto" | "ru" | "en";
  theme: "system" | "dark" | "light";
  realtimeEnabled: boolean;
  realtimePaths: string[];
  autoQuarantine: boolean;
  notifications: boolean;
  heuristics: HeuristicLevel;
  scanArchives: boolean;
  maxFileSizeMb: number;
  exclusions: string[];
  useCache: boolean;
  allowedHashes: string[];
  schedule: Schedule;
  launchAtLogin: boolean;
  startMinimized: boolean;
  closeToTray: boolean;
  updateUrl: string;
  autoUpdate: boolean;
  scanInstalledApps: boolean;
  scanNewApps: boolean;
  watchDownloads: boolean;
  onboardingDone: boolean;
}

export interface QuarantineItem {
  id: string;
  originalPath: string;
  fileName: string;
  threat: string;
  size: number;
  sha256: string;
  quarantinedAt: number;
}

export interface ActionResult {
  id: string;
  ok: boolean;
  error: string | null;
  path: string | null;
}

export interface UpdateCheck {
  configured: boolean;
  available: boolean;
  current: string;
  latest: string | null;
  released: number | null;
  size: number | null;
  notes: string | null;
  checkedAt: number;
}

export interface UpdateProgress {
  stage: "checking" | "downloading" | "verifying" | "installing" | "done" | "error";
  downloaded: number;
  total: number;
  message: string | null;
}

export interface StartupItem {
  name: string;
  command: string;
  path: string | null;
  location: string;
}

export interface DirEntry {
  name: string;
  path: string;
  isDir: boolean;
  size: number;
}

export interface DirListing {
  path: string;
  parent: string | null;
  entries: DirEntry[];
}

export interface RemovableMedia {
  name: string;
  path: string;
}

export interface UserSignatureFile {
  name: string;
  size: number;
  modified: number;
}

export interface AppReport {
  packageName: string;
  label: string;
  versionName: string;
  installer: string;
  trustedSource: boolean;
  isSystem: boolean;
  icon: string | null;
  verdict: Verdict;
  threatName: string | null;
  riskScore: number;
  riskReasons: string[];
  permissionsCount: number;
  lastUpdateTime: number;
}

export interface DeviceSecurity {
  platform: string;
  osVersion: string;
  model: string;
  manufacturer: string;
  sdkInt: number | null;
  securityPatch: string | null;
  screenLock: boolean | null;
  biometrics: boolean | null;
  biometryType: string | null;
  developerOptions: boolean | null;
  usbDebugging: boolean | null;
  storageEncrypted: boolean | null;
  notificationsAllowed: boolean | null;
}

export interface StorageAccess {
  granted: boolean;
  allFilesAccess: boolean;
}

export interface PickedFile {
  cancelled: boolean;
  path: string | null;
  name: string | null;
}
