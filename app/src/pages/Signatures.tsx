import { CloudDownload, Database, FileUp, Fingerprint, Info, Layers, RefreshCw, ShieldCheck, Trash2, TriangleAlert } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { api, errorText, on } from "../api/backend";
import type { DbInfo, UpdateCheck, UpdateProgress, UserSignatureFile } from "../api/types";
import { Badge, Button, Card, CardHeader, PageHeader, Progress, Setting, Toggle } from "../components/ui";
import { useI18n } from "../i18n";
import { useStore } from "../store";
import { bytes, compact, dateTime } from "../utils/format";
import { pickFiles } from "../utils/pick";

export function SignaturesPage() {
  const i18n = useI18n();
  const { t } = i18n;
  const { info, settings, updateSettings, toast, refresh, confirm } = useStore();
  const [db, setDb] = useState<DbInfo | null>(null);
  const [userFiles, setUserFiles] = useState<UserSignatureFile[]>([]);
  const [check, setCheck] = useState<UpdateCheck | null>(null);
  const [progress, setProgress] = useState<UpdateProgress | null>(null);
  const [busy, setBusy] = useState<"check" | "update" | "import" | "reload" | null>(null);
  const [showWarnings, setShowWarnings] = useState(false);

  const load = useCallback(async () => {
    try {
      const [d, u] = await Promise.all([api.dbInfo(), api.userSignatures()]);
      setDb(d);
      setUserFiles(u);
    } catch (e) {
      toast(errorText(e), "error");
    }
  }, [toast]);

  useEffect(() => {
    load();
    const offs = [on<UpdateProgress>("update://progress", setProgress), on<DbInfo>("db://reloaded", (d) => setDb(d))];
    return () => offs.forEach((o) => o());
  }, [load]);

  const doCheck = async () => {
    setBusy("check");
    try {
      setCheck(await api.checkUpdates());
    } catch (e) {
      toast(errorText(e), "error");
    } finally {
      setBusy(null);
    }
  };

  const doUpdate = async () => {
    setBusy("update");
    setProgress({ stage: "checking", downloaded: 0, total: 0, message: null });
    try {
      const d = await api.applyUpdate();
      setDb(d);
      setCheck(await api.checkUpdates());
      toast(t("signatures.stages.done"), "success");
      refresh();
    } catch (e) {
      toast(errorText(e), "error");
    } finally {
      setBusy(null);
    }
  };

  const doImport = async () => {
    try {
      const files = await pickFiles(info);
      if (!files.length) return;
      setBusy("import");
      const d = await api.importSignatures(files);
      setDb(d);
      setUserFiles(await api.userSignatures());
      toast(t("signatures.imported", { n: i18n.num(d.hashSignatures + d.bodySignatures + d.rules) }), "success");
      refresh();
    } catch (e) {
      toast(errorText(e), "error");
    } finally {
      setBusy(null);
    }
  };

  const removeFile = async (name: string) => {
    if (!(await confirm({ title: t("common.remove"), text: name, confirm: t("common.delete"), danger: true }))) return;
    try {
      setDb(await api.removeUserSignature(name));
      setUserFiles(await api.userSignatures());
      refresh();
    } catch (e) {
      toast(errorText(e), "error");
    }
  };

  const reload = async () => {
    setBusy("reload");
    try {
      setDb(await api.reloadSignatures());
    } catch (e) {
      toast(errorText(e), "error");
    } finally {
      setBusy(null);
    }
  };

  if (!db || !info) return null;
  const total = db.hashSignatures + db.bodySignatures + db.rules;
  const builtin = db.version.startsWith("builtin");
  const updating = busy === "update" && progress && progress.stage !== "done" && progress.stage !== "error";
  const pct = progress && progress.total ? (progress.downloaded / progress.total) * 100 : 0;

  return (
    <div className="page">
      <PageHeader
        title={t("signatures.title")}
        subtitle={t("signatures.subtitle")}
        right={
          <Button variant="ghost" icon={<RefreshCw size={15} />} loading={busy === "reload"} onClick={reload}>
            {t("signatures.reload")}
          </Button>
        }
      />

      <Card>
        <CardHeader
          icon={<Database size={22} />}
          title={builtin ? t("signatures.builtin") : db.version}
          sub={
            <>
              {db.released ? `${t("signatures.released")}: ${dateTime(db.released, i18n)} · ` : ""}
              {t("signatures.loaded")}: {dateTime(db.loadedAt, i18n)}
            </>
          }
          right={
            <Badge tone="ok" dot>
              {compact(total, i18n)}
            </Badge>
          }
        />
        <div className="metrics" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))" }}>
          <div className="metric">
            <div className="metric-label row" style={{ gap: 6 }}>
              <Fingerprint size={14} /> {t("signatures.hash")}
            </div>
            <div className="metric-value">{i18n.num(db.hashSignatures)}</div>
          </div>
          <div className="metric">
            <div className="metric-label row" style={{ gap: 6 }}>
              <Layers size={14} /> {t("signatures.body")}
            </div>
            <div className="metric-value">{i18n.num(db.bodySignatures)}</div>
          </div>
          <div className="metric">
            <div className="metric-label row" style={{ gap: 6 }}>
              <ShieldCheck size={14} /> {t("signatures.rules")}
            </div>
            <div className="metric-value">{i18n.num(db.rules)}</div>
          </div>
        </div>
      </Card>

      <div className="grid-2" style={{ marginTop: 16 }}>
        <Card>
          <CardHeader
            icon={<CloudDownload size={20} />}
            title={t("settings.updates")}
            sub={t(info.updateMode === "freshclam" ? "signatures.freshclam" : "signatures.signed")}
          />
          {info.updateMode === "freshclam" && (
            <div className="callout" style={{ marginBottom: 14 }}>
              <Info size={18} />
              <div>{t("signatures.clamavLimits")}</div>
            </div>
          )}
          {!info.updateConfigured ? (
            <div className="callout">
              <Info size={18} />
              <div>{t("signatures.notConfigured")}</div>
            </div>
          ) : (
            <div className="stack-sm">
              {check && !updating && (
                <div className="row" style={{ gap: 8 }}>
                  {check.available ? (
                    <Badge tone="accent" dot>
                      {t("signatures.available", { v: check.latest ?? "" })}
                    </Badge>
                  ) : (
                    <Badge tone="ok" dot>
                      {t("signatures.upToDate")}
                    </Badge>
                  )}
                  {check.size ? <span className="faint num" style={{ fontSize: 12 }}>{bytes(check.size, i18n)}</span> : null}
                </div>
              )}
              {updating && progress && (
                <div>
                  <div className="row-between" style={{ fontSize: 13, marginBottom: 8 }}>
                    <span>{t(`signatures.stages.${progress.stage}`)}</span>
                    {progress.total > 0 && <span className="faint num">{Math.floor(pct)}%</span>}
                  </div>
                  <Progress value={pct} indeterminate={progress.stage !== "downloading"} />
                </div>
              )}
              <div className="row wrap" style={{ marginTop: 6 }}>
                <Button icon={<RefreshCw size={15} />} loading={busy === "check"} disabled={!!busy} onClick={doCheck}>
                  {t("signatures.checkUpdates")}
                </Button>
                <Button variant="primary" icon={<CloudDownload size={16} />} loading={busy === "update"} disabled={!!busy && busy !== "update"} onClick={doUpdate}>
                  {t("signatures.updateNow")}
                </Button>
              </div>
              {check && <div className="faint" style={{ fontSize: 12 }}>{t("signatures.lastChecked", { date: dateTime(check.checkedAt, i18n) })}</div>}
            </div>
          )}
          {settings && (
            <>
              <div className="divider" />
              <Setting title={t("settings.autoUpdate")} desc={t("signatures.autoUpdateDesc")}>
                <Toggle on={settings.autoUpdate} onChange={(v) => updateSettings({ autoUpdate: v })} />
              </Setting>
            </>
          )}
        </Card>

        <Card>
          <CardHeader
            icon={<FileUp size={20} />}
            title={t("signatures.import")}
            sub={t("signatures.importDesc")}
          />
          <Button icon={<FileUp size={16} />} loading={busy === "import"} onClick={doImport}>
            {t("signatures.importButton")}
          </Button>
          <div className="section-title" style={{ marginTop: 18 }}>
            {t("signatures.userFiles")}
          </div>
          {userFiles.length === 0 ? (
            <div className="faint" style={{ fontSize: 13 }}>
              {t("signatures.noUserFiles")}
            </div>
          ) : (
            userFiles.map((f) => (
              <div className="path-chip" key={f.name}>
                <span className="grow ellipsis mono">{f.name}</span>
                <span className="faint num" style={{ fontSize: 12 }}>
                  {bytes(f.size, i18n)}
                </span>
                <button className="btn btn-ghost btn-icon" aria-label={t("common.remove")} onClick={() => removeFile(f.name)}>
                  <Trash2 size={15} />
                </button>
              </div>
            ))
          )}
        </Card>
      </div>

      <Card style={{ marginTop: 16 }}>
        <CardHeader icon={<Layers size={20} />} title={t("signatures.sources")} />
        <div className="list">
          {db.sources.map((s, i) => (
            <div className="list-item" key={`${s.name}-${i}`}>
              <div className="grow" style={{ minWidth: 0 }}>
                <div className="list-title ellipsis">{s.name}</div>
                <div className="list-sub">
                  {s.kind}{s.skipped > 0 ? ` · ${t("signatures.skippedFormats", { n: i18n.num(s.skipped) })}` : ""}
                </div>
              </div>
              <span className="num" style={{ fontWeight: 600 }}>
                {i18n.num(s.signatures)}
              </span>
            </div>
          ))}
        </div>
        {db.warnings.length > 0 && (
          <div style={{ marginTop: 12 }}>
            <Button size="sm" variant="ghost" icon={<TriangleAlert size={14} />} onClick={() => setShowWarnings(!showWarnings)}>
              {t("signatures.warnings", { n: db.warnings.length })}
            </Button>
            {showWarnings && (
              <pre className="current-file selectable" style={{ whiteSpace: "pre-wrap", maxHeight: 240, overflow: "auto" }}>
                {db.warnings.join("\n")}
              </pre>
            )}
          </div>
        )}
      </Card>
    </div>
  );
}
