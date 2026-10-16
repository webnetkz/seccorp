import { LayoutGrid, ScanSearch, Settings2, ShieldAlert, Store, Trash2 } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { api, errorText, on } from "../api/backend";
import type { AppReport } from "../api/types";
import { Badge, Button, Card, Empty, PageHeader, Segmented } from "../components/ui";
import { useI18n } from "../i18n";
import { useStore } from "../store";
import { relative } from "../utils/format";

function riskLevel(a: AppReport): "high" | "medium" | "low" | "none" {
  if (a.verdict !== "clean" || a.riskScore >= 40) return "high";
  if (a.riskScore >= 20) return "medium";
  if (a.riskScore > 0) return "low";
  return "none";
}

const riskColor = { high: "var(--danger)", medium: "var(--warn)", low: "var(--accent)", none: "var(--ok)" } as const;
const riskTone = { high: "danger", medium: "warn", low: "accent", none: "ok" } as const;

export function AppsPage() {
  const i18n = useI18n();
  const { t } = i18n;
  const { startScan, scan, toast } = useStore();
  const [apps, setApps] = useState<AppReport[] | null>(null);
  const [filter, setFilter] = useState<"all" | "risky" | "threats">("all");

  useEffect(() => {
    const load = () => api.appReport().then(setApps).catch((e) => toast(errorText(e), "error"));
    load();
    return on("scan://finished", load);
  }, [toast]);

  const shown = useMemo(
    () =>
      (apps ?? []).filter((a) => (filter === "threats" ? a.verdict !== "clean" : filter === "risky" ? riskLevel(a) === "high" || riskLevel(a) === "medium" : true)),
    [apps, filter],
  );
  const reasons = i18n.raw<Record<string, string>>("apps.reasons");

  return (
    <div className="page">
      <PageHeader
        title={t("apps.title")}
        subtitle={t("apps.subtitle")}
        right={
          <Button variant="primary" icon={<ScanSearch size={16} />} disabled={scan.running} onClick={() => startScan("apps")}>
            {t("apps.scanApps")}
          </Button>
        }
      />
      {apps && apps.length === 0 ? (
        <Card>
          <Empty icon={<LayoutGrid size={30} />} title={t("apps.empty")} desc={t("apps.emptyDesc")} />
        </Card>
      ) : (
        <>
          <div className="toolbar">
            <Segmented
              value={filter}
              options={(["all", "risky", "threats"] as const).map((v) => ({ value: v, label: t(`apps.filter.${v}`) }))}
              onChange={setFilter}
            />
          </div>
          <Card>
            <div className="list">
              {shown.map((a) => {
                const level = riskLevel(a);
                return (
                  <div className="list-item" key={a.packageName} style={{ alignItems: "flex-start" }}>
                    <div className="app-icon">{a.icon ? <img src={`data:image/png;base64,${a.icon}`} alt="" /> : a.label.slice(0, 1)}</div>
                    <div className="grow" style={{ minWidth: 0 }}>
                      <div className="row-between" style={{ alignItems: "flex-start", gap: 10 }}>
                        <div style={{ minWidth: 0 }}>
                          <div className="list-title ellipsis">{a.label}</div>
                          <div className="list-sub mono ellipsis">
                            {a.packageName} · {a.versionName}
                          </div>
                        </div>
                        <div className="risk-meter" title={`${a.riskScore}/100`} style={{ flexShrink: 0, marginTop: 7 }}>
                          <span style={{ width: `${Math.max(6, Math.min(100, a.riskScore * 2))}%`, background: riskColor[level] }} />
                        </div>
                      </div>
                      <div className="row wrap" style={{ gap: 8, marginTop: 8 }}>
                        {a.verdict !== "clean" ? (
                          <Badge tone={a.verdict === "malicious" ? "danger" : "warn"} dot>
                            {t(`threats.verdict.${a.verdict}`)}
                          </Badge>
                        ) : (
                          <Badge tone={riskTone[level]} dot>
                            {t(`apps.risk.${level}`)}
                          </Badge>
                        )}
                        <span className="list-sub" style={{ margin: 0 }}>
                          {t("apps.permissions", { n: a.permissionsCount })} · {relative(Math.floor(a.lastUpdateTime / 1000), i18n)}
                        </span>
                      </div>
                      {a.verdict !== "clean" && a.threatName && (
                        <div className="list-sub mono ellipsis" style={{ color: a.verdict === "malicious" ? "var(--danger)" : "var(--warn)", marginTop: 6 }} title={a.threatName}>
                          {a.threatName}
                        </div>
                      )}
                      <div className="row wrap" style={{ gap: 6, marginTop: 8 }}>
                        <span className="chip" title={a.installer}>
                          <Store size={12} style={{ marginRight: 5 }} />
                          {a.trustedSource ? t("apps.store") : t("apps.sideloaded")}
                        </span>
                        {a.riskReasons.map((r) => (
                          <span key={r} className="chip">
                            {reasons[r] ?? r}
                          </span>
                        ))}
                      </div>
                      <div className="row wrap" style={{ gap: 8, marginTop: 10 }}>
                        <Button size="sm" variant={level === "high" ? "danger" : "secondary"} icon={<Trash2 size={14} />} onClick={() => api.uninstallApp(a.packageName).catch((e) => toast(errorText(e), "error"))}>
                          {t("apps.uninstall")}
                        </Button>
                        <Button size="sm" variant="ghost" icon={<Settings2 size={14} />} onClick={() => api.openAppSettings(a.packageName).catch((e) => toast(errorText(e), "error"))}>
                          {t("apps.appSettings")}
                        </Button>
                      </div>
                    </div>
                  </div>
                );
              })}
              {shown.length === 0 && <Empty icon={<ShieldAlert size={26} />} tone="ok" title={t("threats.empty")} />}
            </div>
          </Card>
        </>
      )}
    </div>
  );
}
