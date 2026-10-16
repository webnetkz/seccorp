import {
  Archive,
  ArrowRight,
  Database,
  FileSearch,
  Radar,
  ScanSearch,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  TriangleAlert,
  Zap,
} from "lucide-react";
import { api, errorText } from "../api/backend";
import type { IssueCode } from "../api/types";
import { CheckFileModal, useCheckFile } from "../components/CheckFile";
import { Shield } from "../components/Shield";
import { Badge, Button, Card, CardHeader, Progress, Toggle } from "../components/ui";
import { useI18n } from "../i18n";
import { useStore } from "../store";
import { bytes, compact, date, duration, relative } from "../utils/format";

export function Dashboard() {
  const i18n = useI18n();
  const { t } = i18n;
  const { dashboard: d, info, scan, startScan, navigate, toast, refresh, reloadSettings, showDiskAccess } = useStore();
  const check = useCheckFile();

  if (!d || !info) {
    return (
      <div className="page stack">
        <div className="skeleton" style={{ height: 240 }} />
        <div className="grid-4">
          {[0, 1, 2, 3].map((i) => (
            <div key={i} className="skeleton" style={{ height: 110 }} />
          ))}
        </div>
      </div>
    );
  }

  const onDemandOnly = info.features.onDemandOnly;
  const state = !d.dbReady ? "idle" : d.status;
  const statusKey = !d.dbReady ? "loading" : d.status;
  const issues = d.issues.filter((i) => i !== "threats");

  const fixIssue = async (code: IssueCode) => {
    try {
      switch (code) {
        case "realtime_off":
          await api.setRealtime(true);
          await reloadSettings();
          break;
        case "realtime_error":
          navigate("protection");
          return;
        case "network_off":
          await api.setNetworkProtection(true);
          await reloadSettings();
          break;
        case "network_alert":
        case "network_error":
          navigate("network");
          return;
        case "never_scanned":
        case "no_recent_scan":
          await startScan("quick");
          return;
        case "db_outdated":
          navigate("signatures");
          return;
        case "storage_access":
          await api.requestStorageAccess();
          break;
        case "full_disk_access":
          showDiskAccess();
          return;
        case "threats":
          navigate("threats");
          return;
      }
      refresh();
    } catch (e) {
      toast(errorText(e), "error");
    }
  };

  const progress = scan.progress;
  const pct = progress && progress.walkDone && progress.filesDiscovered ? (progress.filesScanned / progress.filesDiscovered) * 100 : 0;
  const totalSigs = d.db.hashSignatures + d.db.bodySignatures + d.db.rules;

  return (
    <div className="page">
      <Card className={`hero ${state}`}>
        <Shield state={scan.running ? "protected" : state} />
        <div className="hero-body">
          <div className="hero-kicker">
            {scan.running ? (
              <Badge tone="accent" dot>
                {t("dashboard.scanRunning")}
              </Badge>
            ) : onDemandOnly ? (
              <Badge tone="accent" dot>
                {t("dashboard.onDemand")}
              </Badge>
            ) : d.realtime.running ? (
              <Badge tone="ok" dot>
                {t("protection.statusOn")}
              </Badge>
            ) : (
              <Badge tone="warn" dot>
                {t("protection.statusOff")}
              </Badge>
            )}
          </div>
          <h1 className="hero-title">{t(`status.${statusKey}.title`)}</h1>
          <p className="hero-sub">{t(`status.${statusKey}.subtitle`, { n: d.activeThreats })}</p>
          {scan.running && progress ? (
            <div style={{ marginTop: 18, maxWidth: 460 }}>
              <Progress value={pct} indeterminate={!progress.walkDone} />
              <div className="row-between faint" style={{ marginTop: 8, fontSize: 13 }}>
                <span className="num">
                  {i18n.num(progress.filesScanned)} · {duration(progress.elapsedMs, i18n)}
                </span>
                <Button size="sm" variant="ghost" onClick={() => navigate("scan")}>
                  {t("dashboard.goToScan")} <ArrowRight size={14} />
                </Button>
              </div>
            </div>
          ) : (
            <div className="hero-actions">
              {d.status === "danger" ? (
                <Button variant="danger" size="lg" icon={<ShieldAlert size={18} />} onClick={() => navigate("threats")}>
                  {t("dashboard.resolveThreats")}
                </Button>
              ) : onDemandOnly ? (
                <Button variant="primary" size="lg" icon={<FileSearch size={18} />} onClick={check.start}>
                  {t("dashboard.checkFile")}
                </Button>
              ) : (
                <Button variant="primary" size="lg" icon={<Zap size={18} />} onClick={() => startScan("quick")}>
                  {t("dashboard.quickScan")}
                </Button>
              )}
              {onDemandOnly ? (
                <Button size="lg" icon={<ScanSearch size={18} />} onClick={() => navigate("scan")}>
                  {t("dashboard.openScanner")}
                </Button>
              ) : (
                <Button size="lg" icon={<ScanSearch size={18} />} onClick={() => (d.status === "danger" ? startScan("quick") : startScan("full"))}>
                  {d.status === "danger" ? t("dashboard.quickScan") : t("dashboard.fullScan")}
                </Button>
              )}
            </div>
          )}
        </div>
      </Card>

      {issues.length > 0 && (
        <div style={{ marginTop: 16 }}>
          {issues.map((code) => (
            <div className="issue" key={code}>
              <span className={`icon-tile sm ${code === "full_disk_access" || code === "never_scanned" ? "" : "warn"}`}>
                <TriangleAlert size={16} />
              </span>
              <div className="issue-text">{t(`issues.${code}.title`)}</div>
              <Button size="sm" onClick={() => fixIssue(code)}>
                {t(`issues.${code}.action`)}
              </Button>
            </div>
          ))}
        </div>
      )}

      <div className="grid-4" style={{ marginTop: 16 }}>
        <Card className="stat">
          <div className="stat-label">
            <ScanSearch size={16} /> {t("dashboard.filesScanned")}
          </div>
          <div className="stat-value">{compact(d.stats.filesScanned, i18n)}</div>
          <div className="stat-foot">{t("dashboard.checkedRealtime", { n: compact(d.realtime.scanned || d.stats.realtimeScanned, i18n) })}</div>
        </Card>
        <Card className="stat">
          <div className="stat-label">
            <ShieldCheck size={16} /> {t("dashboard.threatsNeutralized")}
          </div>
          <div className="stat-value">{i18n.num(d.stats.threatsNeutralized)}</div>
          <div className="stat-foot">
            {d.activeThreats > 0 ? <span style={{ color: "var(--danger)" }}>{t("dashboard.threatsCount", { n: d.activeThreats })}</span> : t("dashboard.noThreats")}
          </div>
        </Card>
        <Card className="stat" onClick={() => navigate("quarantine")} style={{ cursor: "pointer" }}>
          <div className="stat-label">
            <Archive size={16} /> {t("dashboard.inQuarantine")}
          </div>
          <div className="stat-value">{i18n.num(d.quarantineCount)}</div>
          <div className="stat-foot">{bytes(d.quarantineBytes, i18n)}</div>
        </Card>
        <Card className="stat" onClick={() => navigate("history")} style={{ cursor: "pointer" }}>
          <div className="stat-label">
            <Sparkles size={16} /> {t("dashboard.lastScan")}
          </div>
          <div className="stat-value" style={{ fontSize: 20, paddingTop: 4 }}>
            {relative(d.stats.lastScanAt, i18n)}
          </div>
          <div className="stat-foot">{d.lastScan ? t(`history.kinds.${d.lastScan.kind}`) : "—"}</div>
        </Card>
      </div>

      <div className="grid-2" style={{ marginTop: 16 }}>
        <Card>
          <CardHeader
            icon={<Radar size={20} />}
            tone={d.realtime.running ? "ok" : "warn"}
            title={t("dashboard.realtime")}
            sub={
              d.realtime.running
                ? t("dashboard.watching", { n: d.realtime.watched.length })
                : d.realtime.error ?? t("dashboard.realtimeOff")
            }
            right={
              <Toggle
                on={d.realtime.enabled}
                label={t("dashboard.realtime")}
                onChange={async (v) => {
                  try {
                    await api.setRealtime(v);
                    refresh();
                    reloadSettings();
                  } catch (e) {
                    toast(errorText(e), "error");
                  }
                }}
              />
            }
          />
          <div className="row wrap" style={{ gap: 8 }}>
            {d.realtime.watched.slice(0, 4).map((w) => (
              <span key={w} className="chip mono" title={w}>
                {w.split(/[\\/]/).filter(Boolean).pop()}
              </span>
            ))}
            <Button size="sm" variant="ghost" onClick={() => navigate("protection")}>
              {t("dashboard.configure")} <ArrowRight size={14} />
            </Button>
          </div>
        </Card>

        <Card>
          <CardHeader
            icon={<Database size={20} />}
            title={t("dashboard.database")}
            sub={
              d.db.version.startsWith("builtin")
                ? t("signatures.builtin")
                : `${d.db.version} · ${d.db.released ? t("dashboard.released", { date: date(d.db.released, i18n) }) : ""}`
            }
            right={
              <Button size="sm" onClick={() => navigate("signatures")}>
                {t("dashboard.openSignatures")}
              </Button>
            }
          />
          <div className="row" style={{ gap: 18 }}>
            <div>
              <div className="stat-value" style={{ fontSize: 22 }}>
                {compact(totalSigs, i18n)}
              </div>
              <div className="faint" style={{ fontSize: 12 }}>
                {t("signatures.total")}
              </div>
            </div>
            <div className="grow">
              <div className="row-between faint" style={{ fontSize: 12 }}>
                <span>{t("signatures.hash")}</span>
                <span className="num">{compact(d.db.hashSignatures, i18n)}</span>
              </div>
              <div className="row-between faint" style={{ fontSize: 12, marginTop: 4 }}>
                <span>{t("signatures.body")}</span>
                <span className="num">{compact(d.db.bodySignatures, i18n)}</span>
              </div>
              <div className="row-between faint" style={{ fontSize: 12, marginTop: 4 }}>
                <span>{t("signatures.rules")}</span>
                <span className="num">{compact(d.db.rules, i18n)}</span>
              </div>
            </div>
          </div>
        </Card>
      </div>

      <Card style={{ marginTop: 16 }}>
        <CardHeader
          icon={<Sparkles size={20} />}
          tone={d.lastScan && d.lastScan.threatCount > 0 ? "warn" : "ok"}
          title={t("dashboard.recentActivity")}
          sub={
            d.lastScan
              ? `${t(`history.kinds.${d.lastScan.kind}`)} · ${relative(d.lastScan.finishedAt, i18n)}`
              : undefined
          }
          right={
            d.lastScan && (
              <Button size="sm" variant="ghost" onClick={() => navigate("history")}>
                {t("nav.history")} <ArrowRight size={14} />
              </Button>
            )
          }
        />
        {d.lastScan ? (
          <div className="metrics" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))" }}>
            <div className="metric">
              <div className="metric-label">{t("history.files")}</div>
              <div className="metric-value">{i18n.num(d.lastScan.filesScanned)}</div>
            </div>
            <div className="metric">
              <div className="metric-label">{t("history.size")}</div>
              <div className="metric-value">{bytes(d.lastScan.bytesScanned, i18n)}</div>
            </div>
            <div className="metric">
              <div className="metric-label">{t("history.duration")}</div>
              <div className="metric-value">{duration((d.lastScan.finishedAt - d.lastScan.startedAt) * 1000, i18n)}</div>
            </div>
            <div className={`metric ${d.lastScan.threatCount ? "danger" : ""}`}>
              <div className="metric-label">{t("history.threats")}</div>
              <div className="metric-value">{d.lastScan.threatCount}</div>
            </div>
          </div>
        ) : (
          <div className="muted">{t("dashboard.noScansYet")}</div>
        )}
      </Card>
      <CheckFileModal state={check.state} onClose={check.close} />
    </div>
  );
}
