import { ChevronRight, FileJson, FileText, HardDrive, History, LayoutGrid, ScanSearch, ShieldCheck, Trash2, Zap } from "lucide-react";
import { useEffect, useState } from "react";
import { api, errorText } from "../api/backend";
import type { ScanRecord } from "../api/types";
import { ThreatCard } from "../components/ThreatCard";
import { Badge, Button, Card, Empty, Modal, ModalHeader, PageHeader } from "../components/ui";
import { useI18n } from "../i18n";
import { useStore } from "../store";
import { bytes, dateTime, duration, middle } from "../utils/format";
import { pickSavePath } from "../utils/pick";

const kindIcon = (k: string) =>
  k === "quick" ? <Zap size={17} /> : k === "full" ? <HardDrive size={17} /> : k === "apps" ? <LayoutGrid size={17} /> : <ScanSearch size={17} />;

export function HistoryPage() {
  const i18n = useI18n();
  const { t } = i18n;
  const { confirm, toast, info } = useStore();
  const [items, setItems] = useState<ScanRecord[] | null>(null);
  const [open, setOpen] = useState<ScanRecord | null>(null);

  useEffect(() => {
    api.history().then(setItems).catch((e) => toast(errorText(e), "error"));
  }, [toast]);

  const clear = async () => {
    if (!(await confirm({ title: t("history.clear"), text: t("history.confirmClear"), confirm: t("common.delete"), danger: true }))) return;
    await api.clearHistory();
    setItems([]);
  };

  const exportAs = async (r: ScanRecord, format: "json" | "html") => {
    try {
      const path = await pickSavePath(`seccorp-report-${r.id.slice(0, 8)}.${format}`, format, info);
      if (path === null) return;
      const saved = await api.exportReport(r.id, format, path ?? undefined);
      toast(t("history.exported", { path: saved }), "success");
    } catch (e) {
      toast(errorText(e), "error");
    }
  };

  return (
    <div className="page">
      <PageHeader
        title={t("history.title")}
        subtitle={t("history.subtitle")}
        right={
          items && items.length > 0 ? (
            <Button variant="ghost" icon={<Trash2 size={15} />} onClick={clear}>
              {t("history.clear")}
            </Button>
          ) : undefined
        }
      />
      <Card>
        {items && items.length === 0 ? (
          <Empty icon={<History size={30} />} tone="muted" title={t("history.empty")} desc={t("history.emptyDesc")} />
        ) : (
          <div className="list">
            {(items ?? []).map((r) => (
              <div key={r.id} className="list-item clickable" onClick={() => setOpen(r)}>
                <span className={`icon-tile sm ${r.threatCount ? "danger" : "ok"}`}>{kindIcon(r.kind)}</span>
                <div className="grow" style={{ minWidth: 0 }}>
                  <div className="list-title">
                    {t(`history.kinds.${r.kind}`)}
                    {r.cancelled && <span className="faint" style={{ fontWeight: 500 }}> · {t("history.cancelled")}</span>}
                  </div>
                  <div className="list-sub num">
                    {dateTime(r.startedAt, i18n)} · {duration((r.finishedAt - r.startedAt) * 1000, i18n)} · {i18n.num(r.filesScanned)} · {bytes(r.bytesScanned, i18n)}
                  </div>
                </div>
                {r.threatCount ? (
                  <Badge tone="danger" dot>
                    {t("dashboard.threatsCount", { n: r.threatCount })}
                  </Badge>
                ) : (
                  <Badge tone="ok" dot>
                    {t("dashboard.noThreats")}
                  </Badge>
                )}
                <ChevronRight size={16} className="faint" />
              </div>
            ))}
          </div>
        )}
      </Card>

      <Modal open={!!open} onClose={() => setOpen(null)} wide>
        {open && (
          <>
            <ModalHeader title={t(`history.kinds.${open.kind}`)} onClose={() => setOpen(null)} />
            <div className="row wrap" style={{ gap: 8, marginBottom: 16 }}>
              <span className="faint">{dateTime(open.startedAt, i18n)}</span>
              {open.limited && <Badge tone="warn">{t("history.limited")}</Badge>}
            </div>
            <div className="metrics" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(130px, 1fr))" }}>
              <div className="metric">
                <div className="metric-label">{t("history.files")}</div>
                <div className="metric-value">{i18n.num(open.filesScanned)}</div>
              </div>
              <div className="metric">
                <div className="metric-label">{t("history.size")}</div>
                <div className="metric-value">{bytes(open.bytesScanned, i18n)}</div>
              </div>
              <div className="metric">
                <div className="metric-label">{t("history.duration")}</div>
                <div className="metric-value">{duration((open.finishedAt - open.startedAt) * 1000, i18n)}</div>
              </div>
              <div className="metric">
                <div className="metric-label">{t("history.errors")}</div>
                <div className="metric-value">{i18n.num(open.errors + open.filesSkipped)}</div>
              </div>
            </div>
            {open.roots.length > 0 && (
              <>
                <div className="section-title" style={{ marginTop: 18 }}>
                  {t("history.roots")}
                </div>
                <div className="row wrap" style={{ gap: 6 }}>
                  {open.roots.slice(0, 12).map((r) => (
                    <span key={r} className="chip mono" title={r}>
                      {middle(r, 48)}
                    </span>
                  ))}
                  {open.roots.length > 12 && <span className="chip">+{i18n.num(open.roots.length - 12)}</span>}
                </div>
              </>
            )}
            <div className="section-title" style={{ marginTop: 18 }}>
              {t("history.threats")}
            </div>
            {open.threats.length === 0 ? (
              <div className="row muted">
                <ShieldCheck size={18} color="var(--ok)" /> {t("history.noThreats")}
              </div>
            ) : (
              open.threats.map((v, i) => <ThreatCard key={i} verdict={v} />)
            )}
            <div className="modal-actions">
              <Button icon={<FileJson size={16} />} onClick={() => exportAs(open, "json")}>
                {t("history.exportJson")}
              </Button>
              <Button variant="primary" icon={<FileText size={16} />} onClick={() => exportAs(open, "html")}>
                {t("history.exportHtml")}
              </Button>
            </div>
          </>
        )}
      </Modal>
    </div>
  );
}
