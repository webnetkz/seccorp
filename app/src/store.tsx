import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { api, errorText, on } from "./api/backend";
import type * as T from "./api/types";
import { detectLang, I18nProvider, type Lang } from "./i18n";

export type Route =
  | "dashboard"
  | "scan"
  | "threats"
  | "protection"
  | "network"
  | "quarantine"
  | "history"
  | "signatures"
  | "settings"
  | "apps"
  | "device";

export interface LiveScan {
  running: boolean;
  scanId: string | null;
  kind: T.ScanKind | null;
  progress: T.ScanProgress | null;
  threats: T.ThreatEntry[];
  lastRecord: T.ScanRecord | null;
}

export interface Toast {
  id: number;
  text: string;
  kind: "info" | "success" | "error";
}

/** A pending request for macOS Full Disk Access (optionally the scan that needed it). */
export interface DiskAccessRequest {
  kind?: T.ScanKind;
  paths?: string[];
}

export interface ConfirmOptions {
  title: string;
  text?: string;
  confirm: string;
  danger?: boolean;
}

interface Store {
  info: T.AppInfo | null;
  settings: T.Settings | null;
  dashboard: T.Dashboard | null;
  scan: LiveScan;
  route: Route;
  navigate: (r: Route) => void;
  refresh: () => Promise<void>;
  updateSettings: (patch: Partial<T.Settings>) => Promise<void>;
  reloadSettings: () => Promise<void>;
  startScan: (kind: T.ScanKind, paths?: string[], opts?: { limited?: boolean }) => Promise<void>;
  diskAccess: DiskAccessRequest | null;
  showDiskAccess: (req?: DiskAccessRequest) => void;
  closeDiskAccess: () => void;
  mediaPrompt: T.RemovableMedia | null;
  dismissMedia: () => void;
  scanMedia: () => void;
  toast: (text: string, kind?: Toast["kind"]) => void;
  toasts: Toast[];
  confirm: (o: ConfirmOptions) => Promise<boolean>;
  confirmState: (ConfirmOptions & { resolve: (v: boolean) => void }) | null;
  closeConfirm: (v: boolean) => void;
  dark: boolean;
}

const Ctx = createContext<Store | null>(null);

const emptyScan: LiveScan = { running: false, scanId: null, kind: null, progress: null, threats: [], lastRecord: null };

function useSystemDark(): boolean {
  const q = typeof window !== "undefined" ? window.matchMedia("(prefers-color-scheme: dark)") : null;
  const [dark, setDark] = useState(q ? q.matches : true);
  useEffect(() => {
    if (!q) return;
    const h = (e: MediaQueryListEvent) => setDark(e.matches);
    q.addEventListener("change", h);
    return () => q.removeEventListener("change", h);
  }, [q]);
  return dark;
}

export function AppProvider({ children }: { children: ReactNode }) {
  const [info, setInfo] = useState<T.AppInfo | null>(null);
  const [settings, setSettings] = useState<T.Settings | null>(null);
  const [dashboard, setDashboard] = useState<T.Dashboard | null>(null);
  const [scan, setScan] = useState<LiveScan>(emptyScan);
  const [route, setRoute] = useState<Route>("dashboard");
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [confirmState, setConfirmState] = useState<Store["confirmState"]>(null);
  const [diskAccess, setDiskAccess] = useState<DiskAccessRequest | null>(null);
  const [mediaQueue, setMediaQueue] = useState<T.RemovableMedia[]>([]);
  const toastId = useRef(1);
  const systemDark = useSystemDark();

  const toast = useCallback((text: string, kind: Toast["kind"] = "info") => {
    const id = toastId.current++;
    setToasts((t) => [...t, { id, text, kind }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), kind === "error" ? 6000 : 3500);
  }, []);

  const refresh = useCallback(async () => {
    try {
      setDashboard(await api.dashboard());
    } catch (e) {
      console.error(e);
    }
  }, []);

  useEffect(() => {
    (async () => {
      try {
        const [i, s, st] = await Promise.all([api.appInfo(), api.settings(), api.scanState()]);
        setInfo(i);
        setSettings(s);
        if (st.running) setScan({ ...emptyScan, running: true, scanId: st.scanId, kind: st.kind, progress: st.progress, threats: st.threats });
        document.documentElement.dataset.platform = i.platform;
      } catch (e) {
        console.error(e);
      }
      refresh();
    })();
  }, [refresh]);

  useEffect(() => {
    const offs = [
      on("status://changed", () => refresh()),
      on("db://reloaded", () => refresh()),
      on<T.RemovableMedia>("media://inserted", (media) =>
        setMediaQueue((queue) => (queue.some((item) => item.path === media.path) ? queue : [...queue, media])),
      ),
      on<T.ScanProgressEvent>("scan://progress", (p) =>
        setScan((s) => ({
          ...s,
          running: true,
          scanId: p.scanId,
          kind: p.kind,
          progress: p,
        })),
      ),
      on<T.ThreatEntry>("scan://threat", (t) => setScan((s) => ({ ...s, threats: [...s.threats, t] }))),
      on<T.ScanRecord>("scan://finished", (r) => {
        setScan((s) => ({ ...s, running: false, lastRecord: r }));
        refresh();
      }),
    ];
    return () => offs.forEach((o) => o());
  }, [refresh]);

  // Periodic refresh keeps relative times and background events current.
  useEffect(() => {
    const id = setInterval(refresh, 30_000);
    return () => clearInterval(id);
  }, [refresh]);

  const theme = settings?.theme ?? "system";
  const dark = theme === "dark" || (theme === "system" && systemDark);
  useEffect(() => {
    document.documentElement.dataset.theme = dark ? "dark" : "light";
  }, [dark]);

  const lang: Lang = detectLang(settings?.language ?? "auto");
  useEffect(() => {
    document.documentElement.lang = lang;
  }, [lang]);

  const updateSettings = useCallback(
    async (patch: Partial<T.Settings>) => {
      if (!settings) return;
      const next = { ...settings, ...patch };
      setSettings(next);
      try {
        setSettings(await api.saveSettings(next));
      } catch (e) {
        toast(errorText(e), "error");
        setSettings(settings);
      }
    },
    [settings, toast],
  );

  const reloadSettings = useCallback(async () => {
    try {
      setSettings(await api.settings());
    } catch (e) {
      console.error(e);
    }
  }, []);

  const startScan = useCallback(
    async (kind: T.ScanKind, paths: string[] = [], opts: { limited?: boolean } = {}) => {
      try {
        setScan({ ...emptyScan, running: true, kind });
        setRoute("scan");
        const id = await api.startScan(kind, paths, opts.limited ?? false);
        setScan((s) => ({ ...s, scanId: id }));
      } catch (e) {
        const msg = errorText(e);
        setScan((s) => ({ ...s, running: false }));
        if (msg === "fda_required") {
          // macOS would interrupt the scan with a consent prompt for every protected folder.
          setDiskAccess({ kind, paths });
          return;
        }
        toast(msg === "busy" ? (lang === "ru" ? "Проверка уже идёт" : "A scan is already running") : msg, "error");
      }
    },
    [toast, lang],
  );

  const showDiskAccess = useCallback((req: DiskAccessRequest = {}) => setDiskAccess(req), []);
  const closeDiskAccess = useCallback(() => setDiskAccess(null), []);

  const dismissMedia = useCallback(() => setMediaQueue((queue) => queue.slice(1)), []);
  const scanMedia = useCallback(() => {
    const media = mediaQueue[0];
    if (!media) return;
    if (scan.running) {
      toast(lang === "ru" ? "Дождитесь завершения текущей проверки" : "Wait for the current scan to finish", "info");
      return;
    }
    setMediaQueue((queue) => queue.slice(1));
    void startScan("custom", [media.path]);
  }, [lang, mediaQueue, scan.running, startScan, toast]);

  const confirm = useCallback((o: ConfirmOptions) => new Promise<boolean>((resolve) => setConfirmState({ ...o, resolve })), []);
  const closeConfirm = useCallback(
    (v: boolean) => {
      confirmState?.resolve(v);
      setConfirmState(null);
    },
    [confirmState],
  );

  const navigate = useCallback((r: Route) => {
    setRoute(r);
    document.querySelector(".content")?.scrollTo({ top: 0 });
  }, []);

  const value = useMemo<Store>(
    () => ({
      info,
      settings,
      dashboard,
      scan,
      route,
      navigate,
      refresh,
      updateSettings,
      reloadSettings,
      startScan,
      diskAccess,
      showDiskAccess,
      closeDiskAccess,
      mediaPrompt: mediaQueue[0] ?? null,
      dismissMedia,
      scanMedia,
      toast,
      toasts,
      confirm,
      confirmState,
      closeConfirm,
      dark,
    }),
    [
      info,
      settings,
      dashboard,
      scan,
      route,
      navigate,
      refresh,
      updateSettings,
      reloadSettings,
      startScan,
      diskAccess,
      showDiskAccess,
      closeDiskAccess,
      mediaQueue,
      dismissMedia,
      scanMedia,
      toast,
      toasts,
      confirm,
      confirmState,
      closeConfirm,
      dark,
    ],
  );

  return (
    <Ctx.Provider value={value}>
      <I18nProvider lang={lang}>{children}</I18nProvider>
    </Ctx.Provider>
  );
}

export function useStore(): Store {
  const v = useContext(Ctx);
  if (!v) throw new Error("AppProvider missing");
  return v;
}
