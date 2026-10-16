import {
  ArrowRight,
  Download,
  FileSearch,
  FolderPlus,
  FilePlus,
  HardDrive,
  LayoutGrid,
  Pause,
  Play,
  ScanSearch,
  ShieldAlert,
  ShieldCheck,
  Square,
  Trash2,
  TriangleAlert,
  X,
  Zap,
} from "lucide-react";
import { useEffect, useMemo, useState, type ReactNode } from "react";
import { api, errorText } from "../api/backend";
import type { ScanKind, ThreatEntry } from "../api/types";
import { CheckFileModal, useCheckFile } from "../components/CheckFile";
import { FolderBrowser } from "../components/FolderBrowser";
import { ProgressRing } from "../components/ProgressRing";
import { ThreatCard } from "../components/ThreatCard";
import { Button, Card, CardHeader, PageHeader } from "../components/ui";
import { useThreatActions } from "../components/useThreatActions";
import { useI18n } from "../i18n";
import { useStore } from "../store";
import { bytes, duration, fileName, middle } from "../utils/format";
import { pickFiles, pickFolders, pickSavePath } from "../utils/pick";

function ScanTypeCard({ icon, title, desc, onClick, recommended, cta }: { icon: ReactNode; title: string; desc: string; onClick: () => void; recommended?: boolean; cta: string }) {
  return (
    <button className={`scan-type ${recommended ? "recommended" : ""}`} onClick={onClick}>
      <span className="icon-tile lg">{icon}</span>
      <div>
        <div className="scan-type-title">{title}</div>
        <div className="scan-type-desc">{desc}</div>
      </div>
      <span className="go" aria-hidden="true">
        <span className="go-label">{cta}</span>
        <ArrowRight size={14} />
      </span>
    </button>
  );
}

function LiveScan() {
  const i18n = useI18n();
  const { t } = i18n;
  const { scan } = useStore();
  const p = scan.progress;
  const pct = p && p.walkDone && p.filesDiscovered ? Math.min(100, (p.filesScanned / p.filesDiscovered) * 100) : 0;
  const speed = p && p.elapsedMs > 500 ? Math.round(p.filesScanned / (p.elapsedMs / 1000)) : 0;
  const kindTitle = scan.kind ? t(`history.kinds.${scan.kind}`) : t("scan.scanning");

  return (
    <Card className="scan-live">
      <ProgressRing value={pct} sweep={!p?.paused}>
        <div className="ring-percent">{p?.walkDone ? `${Math.floor(pct)}%` : "…"}</div>
        <div className="ring-caption">{p?.paused ? t("scan.paused") : p?.walkDone ? t("scan.scanning") : t("scan.preparing")}</div>
      </ProgressRing>
      <div style={{ width: "100%", minWidth: 0 }}>
        <div className="card-title" style={{ fontSize: 20, marginBottom: 14 }}>
          {kindTitle}
        </div>
        <div className="metrics">
          <div className="metric">
            <div className="metric-label">{t("scan.scanned")}</div>
            <div className="metric-value">
              {i18n.num(p?.filesScanned ?? 0)}
              {p?.walkDone ? <span className="faint" style={{ fontSize: 13, fontWeight: 500 }}> / {i18n.num(p.filesDiscovered)}</span> : null}
            </div>
          </div>
          <div className={`metric ${(p?.threats ?? 0) > 0 ? "danger" : ""}`}>
            <div className="metric-label">{t("scan.found")}</div>
            <div className="metric-value">{p?.threats ?? 0}</div>
          </div>
          <div className="metric">
            <div className="metric-label">{t("scan.speed")}</div>
            <div className="metric-value">{t("scan.perSecond", { n: i18n.num(speed) })}</div>
          </div>
          <div className="metric">
            <div className="metric-label">{t("scan.elapsed")}</div>
            <div className="metric-value">{duration(p?.elapsedMs ?? 0, i18n)}</div>
          </div>
        </div>
        <div className="current-file ellipsis" title={p?.currentPath}>
          <div className="faint" style={{ fontFamily: "var(--font)", fontSize: 11, marginBottom: 2 }}>
            {t("scan.current")}
          </div>
          {middle(p?.currentPath ?? "", 96) || "…"}
        </div>
        <div className="row" style={{ marginTop: 16 }}>
          {p?.paused ? (
            <Button variant="primary" icon={<Play size={16} />} onClick={() => api.resumeScan()}>
              {t("scan.resume")}
            </Button>
          ) : (
            <Button icon={<Pause size={16} />} onClick={() => api.pauseScan()}>
              {t("scan.pause")}
            </Button>
          )}
          <Button variant="ghost" icon={<Square size={15} />} onClick={() => api.cancelScan()}>
            {t("scan.stop")}
          </Button>
        </div>
      </div>
    </Card>
  );
}

function ScanResult({ onNew }: { onNew: () => void }) {
  const i18n = useI18n();
  const { t } = i18n;
  const { scan, info, toast, showDiskAccess } = useStore();
  const r = scan.lastRecord!;
  const [active, setActive] = useState<ThreatEntry[]>([]);
  const ids = useMemo(() => new Set(scan.threats.map((x) => x.id)), [scan.threats]);
  const load = () => api.threats().then((all) => setActive(all.filter((x) => ids.has(x.id))));
  const { run, busy } = useThreatActions(load);

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ids]);

  const exportReport = async () => {
    try {
      const path = await pickSavePath(`seccorp-report.html`, "html", info);
      if (path === null) return;
      const saved = await api.exportReport(r.id, "html", path ?? undefined);
      toast(t("history.exported", { path: saved }), "success");
    } catch (e) {
      toast(errorText(e), "error");
    }
  };

  const tone = r.cancelled ? "warn" : r.threatCount ? "danger" : "ok";
  return (
    <div className="stack">
      <Card className="result-banner">
        <span className={`icon-tile ${tone}`}>{r.threatCount ? <ShieldAlert size={30} /> : <ShieldCheck size={30} />}</span>
        <div className="grow">
          <div className="result-title">
            {r.cancelled ? t("scan.resultCancelled") : r.threatCount ? t("scan.resultThreats", { n: r.threatCount }) : t("scan.resultClean")}
          </div>
          <div className="muted" style={{ marginTop: 4 }}>
            {t("scan.resultSummary", {
              files: i18n.num(r.filesScanned),
              size: bytes(r.bytesScanned, i18n),
              time: duration((r.finishedAt - r.startedAt) * 1000, i18n),
            })}
          </div>
          {r.filesSkipped + r.errors > 0 && <div className="faint" style={{ fontSize: 13, marginTop: 2 }}>{t("scan.resultSkipped", { n: i18n.num(r.filesSkipped + r.errors) })}</div>}
        </div>
        <div className="row wrap">
          <Button icon={<Download size={16} />} onClick={exportReport}>
            {t("scan.exportReport")}
          </Button>
          <Button variant="primary" icon={<ScanSearch size={16} />} onClick={onNew}>
            {t("scan.newScan")}
          </Button>
        </div>
      </Card>
      {r.limited && (
        <div className="callout warn" style={{ alignItems: "center" }}>
          <TriangleAlert size={16} />
          <div className="grow">{t("scan.resultLimited")}</div>
          <Button size="sm" onClick={() => showDiskAccess()}>
            {t("scan.grantAccess")}
          </Button>
        </div>
      )}
      {active.length > 0 && (
        <Card>
          <CardHeader
            icon={<ShieldAlert size={20} />}
            tone="danger"
            title={t("scan.threatsFoundTitle")}
            right={
              active.some((a) => !a.packageName) ? (
                <Button variant="primary" size="sm" onClick={() => run(active.filter((a) => !a.packageName), "quarantine")}>
                  {t("threats.quarantineAll")}
                </Button>
              ) : undefined
            }
          />
          {active.map((e) => (
            <ThreatCard key={e.id} entry={e} busy={busy.has(e.id)} onAction={(a) => run([e], a)} canReveal={info?.features.folderPicker} />
          ))}
        </Card>
      )}
    </div>
  );
}

export function ScanPage() {
  const i18n = useI18n();
  const { t } = i18n;
  const { scan, info, dashboard, startScan, navigate, toast } = useStore();
  const [paths, setPaths] = useState<string[]>([]);
  const [customOpen, setCustomOpen] = useState(false);
  const [browser, setBrowser] = useState(false);
  const [showResult, setShowResult] = useState(true);
  const check = useCheckFile();
  const platform = info?.platform;
  const f = info?.features;
  const mobile = platform === "android" || platform === "ios";

  useEffect(() => {
    if (scan.running) setShowResult(true);
  }, [scan.running]);

  if (scan.running) {
    return (
      <div className="page">
        <PageHeader title={t("scan.title")} />
        <LiveScan />
        {scan.threats.length > 0 && (
          <Card style={{ marginTop: 16 }}>
            <CardHeader icon={<ShieldAlert size={20} />} tone="danger" title={t("scan.threatsFoundTitle")} sub={t("scan.resultThreats", { n: scan.threats.length })} />
            {scan.threats.slice(-5).map((e) => (
              <ThreatCard key={e.id} entry={e} />
            ))}
          </Card>
        )}
      </div>
    );
  }

  if (scan.lastRecord && showResult) {
    return (
      <div className="page">
        <PageHeader title={t("scan.title")} />
        <ScanResult onNew={() => setShowResult(false)} />
      </div>
    );
  }

  const addFolders = async () => {
    try {
      if (f?.folderBrowser) return setBrowser(true);
      const picked = await pickFolders();
      setPaths((p) => Array.from(new Set([...p, ...picked])));
    } catch (e) {
      toast(errorText(e), "error");
    }
  };
  const addFiles = async () => {
    try {
      const picked = await pickFiles(info);
      setPaths((p) => Array.from(new Set([...p, ...picked])));
    } catch (e) {
      toast(errorText(e), "error");
    }
  };

  const quick = platform === "android" ? "quickAndroid" : platform === "ios" ? "quickIos" : "quick";
  const full = platform === "android" ? "fullAndroid" : "full";
  // On desktop the single-file check lives in the page header, so the grid keeps three even cards.
  const types: { kind: ScanKind | "file"; key: string; icon: ReactNode; recommended?: boolean }[] = [
    { kind: "quick", key: quick, icon: <Zap size={24} />, recommended: true },
    ...(f?.fullScan ? [{ kind: "full" as const, key: full, icon: <HardDrive size={24} /> }] : []),
    ...(f?.installedApps ? [{ kind: "apps" as const, key: "apps", icon: <LayoutGrid size={24} /> }] : []),
    ...(platform !== "ios" ? [{ kind: "custom" as const, key: "custom", icon: <FolderPlus size={24} /> }] : []),
    ...(mobile ? [{ kind: "file" as const, key: platform === "ios" ? "fileIos" : "file", icon: <FileSearch size={24} /> }] : []),
  ];
  const showCustom = platform !== "ios" && (customOpen || paths.length > 0);

  return (
    <div className="page">
      <PageHeader
        title={t("scan.title")}
        subtitle={t("scan.subtitle")}
        right={
          !mobile ? (
            <Button variant="ghost" icon={<FileSearch size={16} />} onClick={() => check.start()}>
              {t("scan.checkFile")}
            </Button>
          ) : undefined
        }
      />
      {(dashboard?.activeThreats ?? 0) > 0 && (
        <div className="issue" style={{ marginBottom: 16 }}>
          <span className="icon-tile sm danger">
            <ShieldAlert size={16} />
          </span>
          <div className="issue-text">{t("issues.threats.title")}</div>
          <Button size="sm" variant="danger" onClick={() => navigate("threats")}>
            {t("issues.threats.action")}
          </Button>
        </div>
      )}
      <div className="scan-types">
        {types.map((x) => (
          <ScanTypeCard
            key={x.key}
            icon={x.icon}
            recommended={x.recommended}
            title={t(`scan.types.${x.key}.title`)}
            desc={t(`scan.types.${x.key}.desc`)}
            cta={x.kind === "custom" ? t("scan.chooseFolders") : x.kind === "file" ? t("common.choose") : t("scan.start")}
            onClick={() => {
              if (x.kind === "file") return check.start();
              if (x.kind === "custom") {
                setCustomOpen(true);
                return addFolders();
              }
              startScan(x.kind);
            }}
          />
        ))}
      </div>

      {showCustom && (
        <Card style={{ marginTop: 16 }}>
          <CardHeader
            icon={<FolderPlus size={20} />}
            title={t("scan.types.custom.title")}
            sub={paths.length ? t("scan.selection") : t("scan.dropHint")}
            right={
              <div className="row wrap" style={{ justifyContent: "flex-end" }}>
                <Button size="sm" icon={<FolderPlus size={15} />} onClick={addFolders}>
                  {t("scan.chooseFolders")}
                </Button>
                <Button size="sm" icon={<FilePlus size={15} />} onClick={addFiles}>
                  {t("scan.chooseFiles")}
                </Button>
                {paths.length === 0 && (
                  <button className="btn btn-ghost btn-icon" aria-label={t("common.close")} onClick={() => setCustomOpen(false)}>
                    <X size={16} />
                  </button>
                )}
              </div>
            }
          />
          {paths.map((p) => (
            <div className="path-chip" key={p}>
              <span className="mono grow ellipsis" title={p}>
                {middle(p, 90)}
              </span>
              <span className="faint" style={{ fontSize: 12 }}>
                {fileName(p)}
              </span>
              <button className="btn btn-ghost btn-icon" aria-label={t("common.remove")} onClick={() => setPaths(paths.filter((x) => x !== p))}>
                <Trash2 size={15} />
              </button>
            </div>
          ))}
          {paths.length > 0 && (
            <div className="row" style={{ marginTop: 14, justifyContent: "flex-end" }}>
              <Button
                variant="ghost"
                onClick={() => {
                  setPaths([]);
                  setCustomOpen(false);
                }}
              >
                {t("common.clearSelection")}
              </Button>
              <Button variant="primary" icon={<ScanSearch size={16} />} onClick={() => startScan("custom", paths)}>
                {t("scan.start")}
              </Button>
            </div>
          )}
        </Card>
      )}

      <FolderBrowser
        open={browser}
        onClose={() => setBrowser(false)}
        onPick={(p) => {
          setPaths((x) => Array.from(new Set([...x, p])));
          setBrowser(false);
        }}
      />
      <CheckFileModal state={check.state} onClose={check.close} />
    </div>
  );
}
