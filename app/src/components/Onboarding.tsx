import { Bell, CheckCircle2, CloudDownload, Database, FolderLock, HardDrive, Radar, ScanSearch } from "lucide-react";
import { useEffect, useState } from "react";
import { isPermissionGranted, requestPermission } from "@tauri-apps/plugin-notification";
import { api, errorText, isTauri, on } from "../api/backend";
import type { DbInfo, UpdateProgress } from "../api/types";
import { useI18n } from "../i18n";
import { useStore } from "../store";
import { Button, Progress, Segmented, Setting, Toggle } from "./ui";

/** First-run walkthrough: language, protection, permissions, first scan. */
export function Onboarding() {
  const { t } = useI18n();
  const { settings, info, updateSettings, startScan, toast } = useStore();
  const [step, setStep] = useState(0);
  const [db, setDb] = useState<DbInfo | null>(null);
  const [dbProgress, setDbProgress] = useState<UpdateProgress | null>(null);
  const [dbBusy, setDbBusy] = useState(false);
  const [dbDownloaded, setDbDownloaded] = useState(false);

  useEffect(() => {
    if (info?.platform !== "android") return;
    api.dbInfo().then(setDb).catch(() => undefined);
    return on<UpdateProgress>("update://progress", setDbProgress);
  }, [info?.platform]);

  if (!settings || !info || settings.onboardingDone) return null;

  const platform = info.platform;
  const needsPermissions = platform === "android" || platform === "ios" || platform === "macos";
  const steps = platform === "android" ? 5 : needsPermissions ? 4 : 3;
  const finish = (scan: boolean) => {
    updateSettings({ onboardingDone: true });
    if (scan) startScan("quick");
  };
  const next = () => setStep((s) => s + 1);

  const askNotifications = async () => {
    try {
      if (isTauri && !(await isPermissionGranted())) await requestPermission();
    } catch (e) {
      toast(errorText(e), "error");
    }
  };

  const downloadDatabase = async () => {
    setDbBusy(true);
    setDbProgress({ stage: "checking", downloaded: 0, total: 0, message: null });
    try {
      const installed = await api.applyUpdate();
      setDb(installed);
      setDbDownloaded(true);
      toast(t("onboarding.databaseUpdated"), "success");
    } catch (e) {
      toast(errorText(e), "error");
    } finally {
      setDbBusy(false);
    }
  };

  const stepKind = (() => {
    if (step === 0) return "welcome";
    if (step === 1) return "protection";
    if (step === 2 && needsPermissions) return "permissions";
    if (step === 3 && platform === "android") return "database";
    return "scan";
  })();

  const dbTotal = db ? db.hashSignatures + db.bodySignatures + db.rules : 0;
  const dbPct = dbProgress?.total ? (dbProgress.downloaded / dbProgress.total) * 100 : 0;

  return (
    <div className="modal-backdrop">
      <div className="modal onboarding">
        <div className="steps">
          {Array.from({ length: steps }).map((_, i) => (
            <span key={i} className={i === step ? "active" : ""} />
          ))}
        </div>

        {stepKind === "welcome" && (
          <>
            <img src="/icon.svg" alt="" style={{ width: 84, height: 84, borderRadius: 22, margin: "0 auto 18px", display: "block", boxShadow: "0 12px 30px rgba(34,184,240,.3)" }} />
            <div className="modal-title" style={{ fontSize: 24 }}>
              {t("onboarding.welcome")}
            </div>
            <p className="modal-text">{t("onboarding.welcomeDesc")}</p>
            <div style={{ margin: "22px 0 4px" }}>
              <div className="metric-label">{t("onboarding.language")}</div>
              <Segmented
                value={settings.language}
                options={(["auto", "ru", "en"] as const).map((v) => ({ value: v, label: t(`settings.languages.${v}`) }))}
                onChange={(v) => updateSettings({ language: v })}
              />
            </div>
            <div className="modal-actions" style={{ justifyContent: "center" }}>
              <Button variant="primary" size="lg" onClick={next}>
                {t("onboarding.start")}
              </Button>
            </div>
          </>
        )}

        {stepKind === "protection" && (
          <>
            <span className="icon-tile lg ok">
              <Radar size={26} />
            </span>
            <div className="modal-title">{t("onboarding.protectionTitle")}</div>
            <p className="modal-text">{t("onboarding.protectionDesc")}</p>
            <div style={{ textAlign: "left", marginTop: 18 }}>
              <Setting title={t("protection.realtimeTitle")}>
                <Toggle on={settings.realtimeEnabled} onChange={(v) => api.setRealtime(v).then(() => updateSettings({ realtimeEnabled: v }))} />
              </Setting>
              {platform !== "android" && (
                <Setting title={t("protection.autoQuarantine")} desc={t("protection.autoQuarantineDesc")}>
                  <Toggle on={settings.autoQuarantine} onChange={(v) => updateSettings({ autoQuarantine: v })} />
                </Setting>
              )}
            </div>
            <div className="modal-actions">
              <Button variant="primary" onClick={next}>
                {t("onboarding.next")}
              </Button>
            </div>
          </>
        )}

        {stepKind === "permissions" && (
          <>
            <span className="icon-tile lg">
              <FolderLock size={26} />
            </span>
            <div className="modal-title">{t("onboarding.permissionsTitle")}</div>
            <p className="modal-text">{platform === "macos" ? t("onboarding.permissionsDescMac") : t("onboarding.permissionsDesc")}</p>
            <div className="stack-sm" style={{ marginTop: 18 }}>
              {platform === "android" && (
                <Button block icon={<FolderLock size={16} />} onClick={() => api.requestStorageAccess().catch((e) => toast(errorText(e), "error"))}>
                  {t("onboarding.storage")}
                </Button>
              )}
              {platform === "macos" && (
                <Button block icon={<HardDrive size={16} />} onClick={() => api.openPrivacySettings().catch((e) => toast(errorText(e), "error"))}>
                  {t("onboarding.fullDisk")}
                </Button>
              )}
              <Button block icon={<Bell size={16} />} onClick={askNotifications}>
                {t("onboarding.notifications")}
              </Button>
            </div>
            <div className="modal-actions">
              <Button variant="ghost" onClick={next}>
                {t("onboarding.skip")}
              </Button>
              <Button variant="primary" onClick={next}>
                {t("onboarding.next")}
              </Button>
            </div>
          </>
        )}

        {stepKind === "database" && (
          <>
            <span className={`icon-tile lg${dbDownloaded ? " ok" : ""}`}>
              {dbDownloaded ? <CheckCircle2 size={26} /> : <Database size={26} />}
            </span>
            <div className="modal-title">{t("onboarding.databaseTitle")}</div>
            <p className="modal-text">
              {dbDownloaded ? t("onboarding.databaseReady", { n: dbTotal.toLocaleString() }) : t("onboarding.databaseDesc")}
            </p>
            {dbBusy && dbProgress && (
              <div style={{ marginTop: 18, textAlign: "left" }}>
                <div className="row-between" style={{ fontSize: 13, marginBottom: 8 }}>
                  <span>{t(`signatures.stages.${dbProgress.stage}`)}</span>
                  {dbProgress.total > 0 && <span className="faint num">{Math.floor(dbPct)}%</span>}
                </div>
                <Progress value={dbPct} indeterminate={dbProgress.stage !== "downloading"} />
              </div>
            )}
            <div className="modal-actions">
              {!dbDownloaded && (
                <Button variant="ghost" disabled={dbBusy} onClick={next}>
                  {t("onboarding.skip")}
                </Button>
              )}
              {dbDownloaded ? (
                <Button variant="primary" onClick={next}>
                  {t("onboarding.next")}
                </Button>
              ) : (
                <Button variant="primary" size="lg" icon={<CloudDownload size={18} />} loading={dbBusy} onClick={downloadDatabase}>
                  {t("onboarding.downloadDatabase")}
                </Button>
              )}
            </div>
          </>
        )}

        {stepKind === "scan" && (
          <>
            <span className="icon-tile lg">
              <ScanSearch size={26} />
            </span>
            <div className="modal-title">{t("onboarding.scanTitle")}</div>
            <p className="modal-text">{t("onboarding.scanDesc")}</p>
            <div className="modal-actions" style={{ justifyContent: "center" }}>
              <Button variant="ghost" onClick={() => finish(false)}>
                {t("onboarding.finish")}
              </Button>
              <Button variant="primary" size="lg" icon={<ScanSearch size={18} />} onClick={() => finish(true)}>
                {t("onboarding.runScan")}
              </Button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
