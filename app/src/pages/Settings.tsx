import { Bell, Cpu, FolderLock, Globe, HardDrive, Info, KeyRound, Lock, Plus, Power, ScanSearch, Trash2 } from "lucide-react";
import { useEffect, useState } from "react";
import { isPermissionGranted, requestPermission } from "@tauri-apps/plugin-notification";
import { api, errorText, isTauri } from "../api/backend";
import type { StorageAccess } from "../api/types";
import { Badge, Button, Card, CardHeader, PageHeader, Segmented, Setting, Toggle } from "../components/ui";
import { useI18n } from "../i18n";
import { useStore } from "../store";
import { pickFolders } from "../utils/pick";

export function SettingsPage() {
  const { t } = useI18n();
  const { settings, info, updateSettings, toast, confirm } = useStore();
  const [exclusion, setExclusion] = useState("");
  const [storage, setStorage] = useState<StorageAccess | null>(null);
  const [fda, setFda] = useState(false);
  const [notifGranted, setNotifGranted] = useState<boolean | null>(null);

  useEffect(() => {
    if (info?.features.storagePermission) api.storageAccess().then(setStorage).catch(() => {});
    if (info?.features.fullDiskAccess) api.needsFullDiskAccess().then(setFda).catch(() => {});
    if (isTauri) isPermissionGranted().then(setNotifGranted).catch(() => {});
  }, [info]);

  if (!settings || !info) return null;
  const f = info.features;

  const addExclusion = (value: string) => {
    const v = value.trim();
    if (!v || settings.exclusions.includes(v)) return;
    updateSettings({ exclusions: [...settings.exclusions, v] });
    setExclusion("");
  };

  const sizes = [64, 128, 256, 512, 1024, 2048];

  return (
    <div className="page">
      <PageHeader title={t("settings.title")} />

      <div className="grid-fluid">
        <div className="stack">
          <Card>
            <CardHeader icon={<Globe size={20} />} title={t("settings.general")} />
            <Setting title={t("settings.language")} stackMobile>
              <Segmented
                value={settings.language}
                options={(["auto", "ru", "en"] as const).map((v) => ({ value: v, label: t(`settings.languages.${v}`) }))}
                onChange={(v) => updateSettings({ language: v })}
              />
            </Setting>
            <Setting title={t("settings.theme")} stackMobile>
              <Segmented
                value={settings.theme}
                options={(["system", "dark", "light"] as const).map((v) => ({ value: v, label: t(`settings.themes.${v}`) }))}
                onChange={(v) => updateSettings({ theme: v })}
              />
            </Setting>
            <Setting title={t("settings.notifications")} desc={t("settings.notificationsDesc")}>
              <Toggle
                on={settings.notifications}
                onChange={async (v) => {
                  if (v && isTauri && notifGranted === false) {
                    const p = await requestPermission();
                    setNotifGranted(p === "granted");
                  }
                  updateSettings({ notifications: v });
                }}
              />
            </Setting>
          </Card>

          <Card>
            <CardHeader icon={<ScanSearch size={20} />} title={t("settings.scanning")} />
            <Setting title={t("settings.heuristics")} desc={t("settings.heuristicsDesc")} stack>
              <Segmented
                value={settings.heuristics}
                options={(["off", "low", "normal", "high"] as const).map((v) => ({ value: v, label: t(`settings.levels.${v}`) }))}
                onChange={(v) => updateSettings({ heuristics: v })}
              />
            </Setting>
            <Setting title={t("settings.archives")} desc={t("settings.archivesDesc")}>
              <Toggle on={settings.scanArchives} onChange={(v) => updateSettings({ scanArchives: v })} />
            </Setting>
            <Setting title={t("settings.maxSize")} desc={t("settings.maxSizeDesc")}>
              <select className="select select-sm" value={settings.maxFileSizeMb} onChange={(e) => updateSettings({ maxFileSizeMb: Number(e.target.value) })}>
                {Array.from(new Set([...sizes, settings.maxFileSizeMb]))
                  .sort((a, b) => a - b)
                  .map((s) => (
                    <option key={s} value={s}>
                      {s >= 1024 ? `${s / 1024} GB` : `${s} MB`}
                    </option>
                  ))}
              </select>
            </Setting>
            <Setting title={t("settings.cache")} desc={t("settings.cacheDesc")}>
              <Toggle on={settings.useCache} onChange={(v) => updateSettings({ useCache: v })} />
            </Setting>
            {f.installedApps && (
              <Setting title={t("settings.installedApps")} desc={t("settings.installedAppsDesc")}>
                <Toggle on={settings.scanInstalledApps} onChange={(v) => updateSettings({ scanInstalledApps: v })} />
              </Setting>
            )}
          </Card>

          {f.tray && (
            <Card>
              <CardHeader icon={<Power size={20} />} title={t("settings.startup")} />
              <Setting title={t("settings.launchAtLogin")}>
                <Toggle on={settings.launchAtLogin} onChange={(v) => updateSettings({ launchAtLogin: v })} />
              </Setting>
              <Setting title={t("settings.startMinimized")}>
                <Toggle on={settings.startMinimized} onChange={(v) => updateSettings({ startMinimized: v })} />
              </Setting>
              <Setting title={t("settings.closeToTray")} desc={t("settings.closeToTrayDesc")}>
                <Toggle on={settings.closeToTray} onChange={(v) => updateSettings({ closeToTray: v })} />
              </Setting>
            </Card>
          )}
        </div>

        <div className="stack">
          <Card>
            <CardHeader icon={<FolderLock size={20} />} title={t("settings.exclusions")} sub={t("settings.exclusionsDesc")} />
            <div className="input-row" style={{ marginBottom: 12 }}>
              <input
                className="input selectable"
                value={exclusion}
                placeholder={t("settings.exclusionPlaceholder")}
                onChange={(e) => setExclusion(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && addExclusion(exclusion)}
              />
              <Button icon={<Plus size={16} />} onClick={() => addExclusion(exclusion)}>
                {t("settings.addExclusion")}
              </Button>
              {f.folderPicker && (
                <Button
                  variant="ghost"
                  onClick={async () => {
                    const p = await pickFolders();
                    if (p.length) updateSettings({ exclusions: Array.from(new Set([...settings.exclusions, ...p])) });
                  }}
                >
                  {t("common.browse")}
                </Button>
              )}
            </div>
            {settings.exclusions.length === 0 ? (
              <div className="faint" style={{ fontSize: 13 }}>
                {t("settings.noExclusions")}
              </div>
            ) : (
              settings.exclusions.map((x) => (
                <div className="path-chip" key={x}>
                  <span className="grow mono ellipsis" title={x}>
                    {x}
                  </span>
                  <button className="btn btn-ghost btn-icon" aria-label={t("common.remove")} onClick={() => updateSettings({ exclusions: settings.exclusions.filter((e) => e !== x) })}>
                    <Trash2 size={15} />
                  </button>
                </div>
              ))
            )}
            <div className="divider" />
            <Setting title={t("settings.allowed")} desc={t("settings.allowedDesc", { n: settings.allowedHashes.length })}>
              <Button
                size="sm"
                variant="ghost"
                disabled={settings.allowedHashes.length === 0}
                onClick={async () => {
                  if (await confirm({ title: t("settings.allowed"), text: t("settings.allowedDesc", { n: settings.allowedHashes.length }), confirm: t("settings.clearAllowed"), danger: true }))
                    updateSettings({ allowedHashes: [] });
                }}
              >
                {t("settings.clearAllowed")}
              </Button>
            </Setting>
          </Card>

          {!f.onDemandOnly && (
            <Card>
              <CardHeader icon={<KeyRound size={20} />} title={t("settings.updates")} />
              <div className="stack-sm">
                <div className="metric-label">{t("settings.updateUrl")}</div>
                <input
                  className="input selectable mono"
                  defaultValue={settings.updateUrl}
                  placeholder="https://updates.example.com/seccom/update.json"
                  onBlur={(e) => e.target.value !== settings.updateUrl && updateSettings({ updateUrl: e.target.value })}
                />
              </div>
              <Setting title={t("settings.autoUpdate")}>
                <Toggle on={settings.autoUpdate} onChange={(v) => updateSettings({ autoUpdate: v })} />
              </Setting>
            </Card>
          )}

          {(f.storagePermission || f.fullDiskAccess || isTauri) && (
            <Card>
              <CardHeader icon={<Lock size={20} />} title={t("settings.permissions")} />
              {f.storagePermission && (
                <Setting title={t("settings.storageAccess")} desc={t("settings.storageAccessDesc")}>
                  {storage?.granted ? (
                    <Badge tone="ok" dot>
                      {t("settings.granted")}
                    </Badge>
                  ) : (
                    <Button size="sm" variant="primary" onClick={() => api.requestStorageAccess().catch((e) => toast(errorText(e), "error"))}>
                      {t("settings.grant")}
                    </Button>
                  )}
                </Setting>
              )}
              {f.fullDiskAccess && (
                <Setting title={t("settings.fullDiskAccess")} desc={t("settings.fullDiskAccessDesc")} stack={fda}>
                  {fda ? (
                    <div className="row" style={{ gap: 8, flexShrink: 0 }}>
                      <Button size="sm" variant="ghost" onClick={() => api.restartApp().catch((e) => toast(errorText(e), "error"))}>
                        {t("settings.restart")}
                      </Button>
                      <Button size="sm" variant="primary" onClick={() => api.openPrivacySettings().catch((e) => toast(errorText(e), "error"))}>
                        {t("settings.openSettings")}
                      </Button>
                    </div>
                  ) : (
                    <Badge tone="ok" dot>
                      {t("settings.granted")}
                    </Badge>
                  )}
                </Setting>
              )}
              {isTauri && (
                <Setting title={t("settings.notificationPermission")}>
                  {notifGranted ? (
                    <Badge tone="ok" dot>
                      {t("settings.granted")}
                    </Badge>
                  ) : (
                    <Button
                      size="sm"
                      onClick={async () => {
                        const p = await requestPermission();
                        setNotifGranted(p === "granted");
                      }}
                    >
                      <Bell size={14} /> {t("settings.grant")}
                    </Button>
                  )}
                </Setting>
              )}
            </Card>
          )}

          <Card>
            <CardHeader icon={<Info size={20} />} title={t("settings.about")} sub={t("settings.privacy")} />
            <dl className="kv selectable">
              <dt>{t("settings.version")}</dt>
              <dd>SecCorp {info.version}</dd>
              <dt>{t("settings.engine")}</dt>
              <dd className="row" style={{ gap: 6 }}>
                <Cpu size={14} /> seccom-engine {info.engineVersion} (Rust)
              </dd>
              <dt>{t("settings.platform")}</dt>
              <dd>
                {info.platform} · {info.arch}
              </dd>
              <dt>{t("settings.dataDir")}</dt>
              <dd className="mono row" style={{ gap: 6 }}>
                <HardDrive size={14} /> {info.dataDir}
              </dd>
            </dl>
          </Card>
        </div>
      </div>
    </div>
  );
}
