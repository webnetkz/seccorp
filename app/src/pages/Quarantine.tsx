import { Archive, Lock, RotateCcw, Trash2 } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { api, errorText } from "../api/backend";
import type { QuarantineItem } from "../api/types";
import { Button, Card, Empty, PageHeader } from "../components/ui";
import { useI18n } from "../i18n";
import { useStore } from "../store";
import { bytes, dateTime, middle } from "../utils/format";

export function QuarantinePage() {
  const i18n = useI18n();
  const { t } = i18n;
  const { confirm, toast, refresh } = useStore();
  const [items, setItems] = useState<QuarantineItem[] | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => api.quarantine().then(setItems).catch((e) => toast(errorText(e), "error")), [toast]);
  useEffect(() => {
    load();
  }, [load]);

  const total = (items ?? []).reduce((a, q) => a + q.size, 0);
  const ids = [...selected];

  const restore = async (allow: boolean) => {
    const ok = await confirm({ title: allow ? t("quarantine.restoreTrust") : t("quarantine.restore"), text: t("quarantine.confirmRestore"), confirm: t("common.restore") });
    if (!ok) return;
    setBusy(true);
    try {
      const res = await api.restoreQuarantine(ids, allow);
      const done = res.filter((r) => r.ok);
      if (done.length === 1 && done[0].path) toast(t("quarantine.restoredTo", { path: done[0].path }), "success");
      else if (done.length) toast(t("threats.resolved", { n: done.length }), "success");
      const failed = res.find((r) => !r.ok);
      if (failed) toast(t("threats.failed", { msg: failed.error ?? "" }), "error");
    } catch (e) {
      toast(errorText(e), "error");
    } finally {
      setBusy(false);
      setSelected(new Set());
      load();
      refresh();
    }
  };

  const remove = async () => {
    const ok = await confirm({ title: t("quarantine.deleteForever"), text: t("quarantine.confirmDelete"), confirm: t("common.delete"), danger: true });
    if (!ok) return;
    setBusy(true);
    try {
      await api.deleteQuarantine(ids);
    } catch (e) {
      toast(errorText(e), "error");
    } finally {
      setBusy(false);
      setSelected(new Set());
      load();
      refresh();
    }
  };

  const allSelected = items && items.length > 0 && selected.size === items.length;

  return (
    <div className="page">
      <PageHeader
        title={t("quarantine.title")}
        subtitle={t("quarantine.subtitle")}
        right={items && items.length > 0 ? <span className="chip num">{t("quarantine.total", { n: items.length, size: bytes(total, i18n) })}</span> : undefined}
      />
      <Card>
        {items && items.length === 0 ? (
          <Empty icon={<Archive size={30} />} tone="muted" title={t("quarantine.empty")} desc={t("quarantine.emptyDesc")} />
        ) : (
          <>
            <div className="toolbar">
              <label className="row" style={{ cursor: "pointer", gap: 8 }}>
                <input
                  type="checkbox"
                  className="checkbox"
                  checked={!!allSelected}
                  onChange={(e) => setSelected(e.target.checked ? new Set((items ?? []).map((x) => x.id)) : new Set())}
                />
                <span className="muted">{t("common.selectAll")}</span>
              </label>
              <span className="grow" />
              <span className="row faint" style={{ fontSize: 12, gap: 6 }}>
                <Lock size={13} /> ChaCha20-Poly1305
              </span>
            </div>
            <div className="list">
              {(items ?? []).map((q) => (
                <label key={q.id} className={`list-item clickable ${selected.has(q.id) ? "selected" : ""}`}>
                  <input
                    type="checkbox"
                    className="checkbox"
                    checked={selected.has(q.id)}
                    onChange={(e) =>
                      setSelected((s) => {
                        const n = new Set(s);
                        if (e.target.checked) n.add(q.id);
                        else n.delete(q.id);
                        return n;
                      })
                    }
                  />
                  <span className="icon-tile sm danger">
                    <Archive size={15} />
                  </span>
                  <div className="grow" style={{ minWidth: 0 }}>
                    <div className="list-title ellipsis">{q.fileName}</div>
                    <div className="list-sub mono ellipsis" title={q.originalPath}>
                      {middle(q.originalPath, 90)}
                    </div>
                  </div>
                  <div style={{ textAlign: "right", minWidth: 0 }}>
                    <div style={{ fontSize: 13, fontWeight: 600, color: "var(--danger)" }} className="ellipsis">
                      {q.threat}
                    </div>
                    <div className="list-sub num">
                      {dateTime(q.quarantinedAt, i18n)} · {bytes(q.size, i18n)}
                    </div>
                  </div>
                </label>
              ))}
            </div>
          </>
        )}
      </Card>
      {selected.size > 0 && (
        <div className="selection-bar">
          <span className="grow" style={{ fontWeight: 600 }}>
            {t("common.selected", { n: selected.size })}
          </span>
          <Button size="sm" icon={<RotateCcw size={14} />} loading={busy} onClick={() => restore(false)}>
            {t("quarantine.restore")}
          </Button>
          <Button size="sm" variant="ghost" disabled={busy} onClick={() => restore(true)}>
            {t("quarantine.restoreTrust")}
          </Button>
          <Button size="sm" variant="danger" icon={<Trash2 size={14} />} disabled={busy} onClick={remove}>
            {t("quarantine.deleteForever")}
          </Button>
        </div>
      )}
    </div>
  );
}
