import { CalendarClock, Folder, FolderPlus, ListChecks, Radar, RotateCcw, Rocket, Trash2, TriangleAlert } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { api, errorText, on } from "../api/backend";
import type { RealtimeEvent, StartupItem } from "../api/types";
import { Badge, Button, Card, CardHeader, Empty, PageHeader, Segmented, Setting, Toggle } from "../components/ui";
import { useI18n } from "../i18n";
import { useStore } from "../store";
import { dateTime, fileName, middle, time } from "../utils/format";
import { pickFolders } from "../utils/pick";

export function ProtectionPage() {
  const i18n = useI18n();
  const { t } = i18n;
  const { info, settings, dashboard, updateSettings, reloadSettings, refresh, toast, showDiskAccess } = useStore();
  const [events, setEvents] = useState<RealtimeEvent[]>([]);
  const [defaults, setDefaults] = useState<string[]>([]);
  const [startup, setStartup] = useState<StartupItem[] | null>(null);
  const [nextRun, setNextRun] = useState<number | null>(null);
  const f = info?.features;
  const platform = info?.platform;

  const loadEvents = useCallback(() => api.realtimeEvents().then(setEvents).catch(() => {}), []);
  useEffect(() => {
    loadEvents();
    api.defaultWatchPaths().then(setDefaults).catch(() => {});
    if (f?.startupItems) api.startupItems().then(setStartup).catch(() => setStartup([]));
    const off = on<RealtimeEvent>("realtime://event", (e) => setEvents((x) => [e, ...x].slice(0, 200)));
    return off;
  }, [loadEvents, f?.startupItems]);

  useEffect(() => {
    if (f?.schedule) api.nextScheduledScan().then(setNextRun).catch(() => {});
  }, [f?.schedule, settings?.schedule]);

  if (!settings || !info) return null;
  const rt = dashboard?.realtime;
  const custom = settings.realtimePaths.length > 0;
  const folders = custom ? settings.realtimePaths : defaults;

  const setRealtime = async (v: boolean) => {
    try {
      await api.setRealtime(v);
      await Promise.all([refresh(), reloadSettings()]);
    } catch (e) {
      toast(errorText(e), "error");
    }
  };

  const addFolder = async () => {
    const picked = await pickFolders();
    if (picked.length) updateSettings({ realtimePaths: Array.from(new Set([...(custom ? settings.realtimePaths : defaults), ...picked])) });
  };

  const desc =
    platform === "android" ? t("protection.realtimeDescAndroid") : platform === "ios" ? t("protection.realtimeDescIos") : t("protection.realtimeDesc");
  const statusTone = rt?.running ? "ok" : rt?.enabled ? "danger" : "warn";
  const statusText = rt?.running ? t("protection.statusOn") : rt?.enabled ? t("protection.statusError") : t("protection.statusOff");
  const sched = settings.schedule;
  const weekdays = i18n.raw<string[]>("protection.weekdays");

  return (
    <div className="page">
      <PageHeader title={t("protection.title")} subtitle={t("protection.subtitle")} />

      <Card>
        <CardHeader
          icon={<Radar size={22} />}
          tone={statusTone === "ok" ? "ok" : statusTone === "danger" ? "danger" : "warn"}
          title={t("protection.realtimeTitle")}
          sub={desc}
          right={<Toggle on={settings.realtimeEnabled} onChange={setRealtime} label={t("protection.realtimeTitle")} />}
        />
        <div className="row wrap" style={{ gap: 8 }}>
          <Badge tone={statusTone} dot>
            {statusText}
          </Badge>
          {rt?.error && <span className="faint" style={{ fontSize: 13 }}>{rt.error}</span>}
        </div>
        {rt?.running && rt.limited && (
          <div className="callout warn" style={{ marginTop: 12, alignItems: "center" }}>
            <TriangleAlert size={16} />
            <div className="grow">{t("protection.limited")}</div>
            <Button size="sm" onClick={() => showDiskAccess()}>
              {t("scan.grantAccess")}
            </Button>
          </div>
        )}
        <div className="divider" />
        {platform === "android" ? (
          <>
            <Setting title={t("protection.scanNewApps")} desc={t("protection.scanNewAppsDesc")}>
              <Toggle on={settings.scanNewApps} onChange={(v) => updateSettings({ scanNewApps: v })} />
            </Setting>
            <Setting title={t("protection.watchDownloads")} desc={t("protection.watchDownloadsDesc")}>
              <Toggle on={settings.watchDownloads} onChange={(v) => updateSettings({ watchDownloads: v })} />
            </Setting>
          </>
        ) : (
          <Setting title={t("protection.autoQuarantine")} desc={t("protection.autoQuarantineDesc")}>
            <Toggle on={settings.autoQuarantine} onChange={(v) => updateSettings({ autoQuarantine: v })} />
          </Setting>
        )}
      </Card>

      <div className="grid-2" style={{ marginTop: 16 }}>
        <Card>
          <CardHeader
            icon={<Folder size={20} />}
            title={t("protection.folders")}
            sub={custom ? undefined : t("protection.foldersDefault")}
            right={
              f?.folderPicker ? (
                <div className="row">
                  {custom && (
                    <Button size="sm" variant="ghost" icon={<RotateCcw size={14} />} onClick={() => updateSettings({ realtimePaths: [] })}>
                      {t("protection.resetFolders")}
                    </Button>
                  )}
                  <Button size="sm" icon={<FolderPlus size={15} />} onClick={addFolder}>
                    {t("protection.addFolder")}
                  </Button>
                </div>
              ) : undefined
            }
          />
          {folders.map((p) => (
            <div className="path-chip" key={p}>
              <Folder size={16} color="var(--accent)" />
              <div className="grow" style={{ minWidth: 0 }}>
                <div style={{ fontWeight: 600 }}>{fileName(p)}</div>
                <div className="mono faint ellipsis" title={p}>
                  {middle(p, 64)}
                </div>
              </div>
              {custom && f?.folderPicker && (
                <button
                  className="btn btn-ghost btn-icon"
                  aria-label={t("common.remove")}
                  onClick={() => updateSettings({ realtimePaths: settings.realtimePaths.filter((x) => x !== p) })}
                >
                  <Trash2 size={15} />
                </button>
              )}
            </div>
          ))}
        </Card>

        <Card>
          <CardHeader icon={<ListChecks size={20} />} title={t("protection.events")} />
          {events.length === 0 ? (
            <div className="muted" style={{ fontSize: 13 }}>
              {t("protection.noEvents")}
            </div>
          ) : (
            <div style={{ maxHeight: 320, overflowY: "auto" }}>
              {events.slice(0, 60).map((e, i) => (
                <div className="feed-item" key={`${e.time}-${i}`}>
                  <span className="feed-time">{time(e.time, i18n)}</span>
                  <span className={`dot ${e.verdict}`} />
                  <div className="grow" style={{ minWidth: 0 }}>
                    <div className="ellipsis" title={e.path}>
                      {fileName(e.path)}
                    </div>
                    {e.threatName && (
                      <div style={{ fontSize: 12, color: e.verdict === "malicious" ? "var(--danger)" : "var(--warn)" }}>
                        {e.threatName}
                        {e.action === "quarantined" ? ` · ${t("protection.actionQuarantined")}` : e.action === "failed" ? ` · ${t("protection.actionFailed")}` : ""}
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>

      {f?.schedule && (
        <Card style={{ marginTop: 16 }}>
          <CardHeader
            icon={<CalendarClock size={20} />}
            title={t("protection.schedule")}
            sub={sched.enabled && nextRun ? t("protection.nextRun", { date: dateTime(nextRun, i18n) }) : t("protection.scheduleDesc")}
            right={<Toggle on={sched.enabled} onChange={(v) => updateSettings({ schedule: { ...sched, enabled: v } })} label={t("protection.schedule")} />}
          />
          {sched.enabled && (
            <div className="grid-3">
              <div>
                <div className="metric-label">{t("protection.frequency")}</div>
                <Segmented
                  value={sched.frequency}
                  options={[
                    { value: "daily", label: t("protection.daily") },
                    { value: "weekly", label: t("protection.weekly") },
                  ]}
                  onChange={(v) => updateSettings({ schedule: { ...sched, frequency: v } })}
                />
              </div>
              {sched.frequency === "weekly" && (
                <div>
                  <div className="metric-label">{t("protection.weekday")}</div>
                  <select className="select" value={sched.weekday} onChange={(e) => updateSettings({ schedule: { ...sched, weekday: Number(e.target.value) } })}>
                    {weekdays.map((d, i) => (
                      <option key={d} value={i}>
                        {d}
                      </option>
                    ))}
                  </select>
                </div>
              )}
              <div>
                <div className="metric-label">{t("protection.time")}</div>
                <input
                  className="input"
                  type="time"
                  value={`${String(sched.hour).padStart(2, "0")}:${String(sched.minute).padStart(2, "0")}`}
                  onChange={(e) => {
                    const [h, m] = e.target.value.split(":").map(Number);
                    if (!Number.isNaN(h) && !Number.isNaN(m)) updateSettings({ schedule: { ...sched, hour: h, minute: m } });
                  }}
                />
              </div>
              <div>
                <div className="metric-label">{t("protection.kind")}</div>
                <Segmented
                  value={sched.kind}
                  options={[
                    { value: "quick", label: t("scan.types.quick.title") },
                    { value: "full", label: t("scan.types.full.title") },
                  ]}
                  onChange={(v) => updateSettings({ schedule: { ...sched, kind: v } })}
                />
              </div>
            </div>
          )}
        </Card>
      )}

      {f?.startupItems && (
        <Card style={{ marginTop: 16 }}>
          <CardHeader icon={<Rocket size={20} />} title={t("protection.startup")} sub={t("protection.startupDesc")} />
          {startup && startup.length === 0 && <Empty icon={<Rocket size={26} />} tone="muted" title={t("protection.startupEmpty")} />}
          <div className="list">
            {(startup ?? []).map((s, i) => (
              <div className="list-item" key={`${s.location}-${s.name}-${i}`}>
                <span className="icon-tile sm muted">
                  <Rocket size={15} />
                </span>
                <div className="grow" style={{ minWidth: 0 }}>
                  <div className="list-title ellipsis">{s.name}</div>
                  <div className="list-sub mono ellipsis" title={s.command}>
                    {middle(s.command, 110)}
                  </div>
                </div>
                <span className="chip ellipsis" style={{ maxWidth: 220 }} title={s.location}>
                  {middle(s.location, 34)}
                </span>
              </div>
            ))}
          </div>
        </Card>
      )}
    </div>
  );
}
