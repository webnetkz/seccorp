import { Bell, CheckCircle2, Code, Cpu, FolderLock, KeyRound, Lock, LockKeyhole, RefreshCw, ScanFace, ShieldAlert, Usb } from "lucide-react";
import { useCallback, useEffect, useState, type ReactNode } from "react";
import { api, errorText } from "../api/backend";
import type { DeviceSecurity, StorageAccess } from "../api/types";
import { ScoreRing } from "../components/ProgressRing";
import { Badge, Button, Card, PageHeader, Spinner } from "../components/ui";
import { useI18n } from "../i18n";
import { useStore } from "../store";

interface Check {
  key: string;
  icon: ReactNode;
  ok: boolean | null;
  value?: string;
  action?: ReactNode;
}

function patchAgeDays(patch: string | null): number | null {
  if (!patch) return null;
  const d = Date.parse(patch);
  return Number.isNaN(d) ? null : Math.floor((Date.now() - d) / 86_400_000);
}

export function DevicePage() {
  const { t } = useI18n();
  const { info, toast } = useStore();
  const [sec, setSec] = useState<DeviceSecurity | null>(null);
  const [storage, setStorage] = useState<StorageAccess | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setSec(await api.deviceSecurity());
      if (info?.features.storagePermission) setStorage(await api.storageAccess());
    } catch (e) {
      toast(errorText(e), "error");
    } finally {
      setLoading(false);
    }
  }, [info, toast]);

  useEffect(() => {
    load();
    const onFocus = () => load();
    window.addEventListener("focus", onFocus);
    return () => window.removeEventListener("focus", onFocus);
  }, [load]);

  if (!sec) {
    return (
      <div className="page">
        <PageHeader title={t("device.title")} subtitle={t("device.subtitle")} />
        <div className="row" style={{ justifyContent: "center", padding: 40 }}>{loading ? <Spinner size={26} /> : null}</div>
      </div>
    );
  }

  const age = patchAgeDays(sec.securityPatch);
  const checks: Check[] = [
    { key: "screenLock", icon: <Lock size={18} />, ok: sec.screenLock },
    ...(sec.platform === "ios" ? [{ key: "biometrics", icon: <ScanFace size={18} />, ok: sec.biometrics }] : []),
    ...(sec.securityPatch ? [{ key: "securityPatch", icon: <KeyRound size={18} />, ok: age === null ? null : age <= 120, value: sec.securityPatch }] : []),
    ...(sec.developerOptions !== null ? [{ key: "developerOptions", icon: <Code size={18} />, ok: !sec.developerOptions }] : []),
    ...(sec.usbDebugging !== null ? [{ key: "usbDebugging", icon: <Usb size={18} />, ok: !sec.usbDebugging }] : []),
    ...(sec.storageEncrypted !== null ? [{ key: "encryption", icon: <LockKeyhole size={18} />, ok: sec.storageEncrypted }] : []),
    ...(sec.notificationsAllowed !== null ? [{ key: "notifications", icon: <Bell size={18} />, ok: sec.notificationsAllowed }] : []),
    ...(storage
      ? [
          {
            key: "storage",
            icon: <FolderLock size={18} />,
            ok: storage.granted,
            action: !storage.granted ? (
              <Button size="sm" variant="primary" onClick={() => api.requestStorageAccess()}>
                {t("settings.grant")}
              </Button>
            ) : undefined,
          },
        ]
      : []),
  ];
  const known = checks.filter((c) => c.ok !== null);
  const score = known.length ? (known.filter((c) => c.ok).length / known.length) * 100 : 0;
  const color = score >= 85 ? "var(--ok)" : score >= 60 ? "var(--warn)" : "var(--danger)";

  return (
    <div className="page">
      <PageHeader
        title={t("device.title")}
        subtitle={t("device.subtitle")}
        right={
          <Button variant="ghost" icon={<RefreshCw size={15} />} loading={loading} onClick={load}>
            {t("device.refresh")}
          </Button>
        }
      />
      <Card>
        <div className="row" style={{ gap: 20 }}>
          <ScoreRing value={score} color={color} />
          <div className="grow">
            <div className="card-title" style={{ fontSize: 18 }}>
              {t("device.score")}
            </div>
            <div className="muted" style={{ marginTop: 4 }}>
              {sec.manufacturer} {sec.model}
            </div>
            <div className="row" style={{ marginTop: 8, gap: 8 }}>
              <Cpu size={15} className="faint" />
              <span className="faint">
                {sec.platform === "ios" ? "iOS" : "Android"} {sec.osVersion}
                {sec.sdkInt ? ` (API ${sec.sdkInt})` : ""}
              </span>
            </div>
          </div>
        </div>
      </Card>
      <Card style={{ marginTop: 16 }}>
        {checks.map((c) => (
          <div className="check" key={c.key}>
            <span className={`icon-tile sm ${c.ok === null ? "muted" : c.ok ? "ok" : "warn"}`}>{c.icon}</span>
            <div className="grow" style={{ minWidth: 0 }}>
              <div style={{ fontWeight: 600 }}>{t(`device.checks.${c.key}.title`)}</div>
              {c.ok === false && <div className="setting-desc">{t(`device.checks.${c.key}.hint`)}</div>}
              {c.value && <div className="list-sub">{c.value}</div>}
            </div>
            {c.action ??
              (c.ok === null ? (
                <Badge>{t("common.unknown")}</Badge>
              ) : c.ok ? (
                <Badge tone="ok">
                  <CheckCircle2 size={13} /> {t(`device.checks.${c.key}.ok`)}
                </Badge>
              ) : (
                <Badge tone="warn">
                  <ShieldAlert size={13} /> {t(`device.checks.${c.key}.bad`)}
                </Badge>
              ))}
          </div>
        ))}
      </Card>
    </div>
  );
}
