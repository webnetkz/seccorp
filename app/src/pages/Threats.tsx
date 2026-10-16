import { ShieldCheck } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { api, on } from "../api/backend";
import type { ThreatEntry } from "../api/types";
import { ThreatCard } from "../components/ThreatCard";
import { Button, Card, Empty, PageHeader } from "../components/ui";
import { useThreatActions } from "../components/useThreatActions";
import { useI18n } from "../i18n";
import { useStore } from "../store";

export function ThreatsPage() {
  const { t } = useI18n();
  const { info, navigate } = useStore();
  const [items, setItems] = useState<ThreatEntry[] | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const load = useCallback(() => api.threats().then(setItems), []);
  const { run, busy } = useThreatActions(() => {
    setSelected(new Set());
    load();
  });

  useEffect(() => {
    load();
    return on("status://changed", () => load());
  }, [load]);

  const files = (items ?? []).filter((x) => !x.packageName);
  const chosen = (items ?? []).filter((x) => selected.has(x.id));

  return (
    <div className="page">
      <PageHeader
        title={t("threats.title")}
        subtitle={t("threats.subtitle")}
        right={
          files.length > 1 ? (
            <Button variant="primary" onClick={() => run(files, "quarantine")}>
              {t("threats.quarantineAll")}
            </Button>
          ) : undefined
        }
      />
      {items && items.length === 0 ? (
        <Card>
          <Empty
            icon={<ShieldCheck size={30} />}
            tone="ok"
            title={t("threats.empty")}
            desc={t("threats.emptyDesc")}
            action={<Button onClick={() => navigate("dashboard")}>{t("nav.dashboard")}</Button>}
          />
        </Card>
      ) : (
        <div>
          {(items ?? []).map((e) => (
            <ThreatCard
              key={e.id}
              entry={e}
              busy={busy.has(e.id)}
              canReveal={info?.features.folderPicker}
              onAction={(a) => run([e], a)}
              selected={selected.has(e.id)}
              onSelect={(v) =>
                setSelected((s) => {
                  const n = new Set(s);
                  if (v) n.add(e.id);
                  else n.delete(e.id);
                  return n;
                })
              }
            />
          ))}
          {chosen.length > 0 && (
            <div className="selection-bar">
              <span className="grow" style={{ fontWeight: 600 }}>
                {t("common.selected", { n: chosen.length })}
              </span>
              <Button size="sm" variant="primary" onClick={() => run(chosen.filter((c) => !c.packageName), "quarantine")}>
                {t("threats.quarantine")}
              </Button>
              <Button size="sm" onClick={() => run(chosen.filter((c) => !c.packageName), "delete")}>
                {t("threats.delete")}
              </Button>
              <Button size="sm" variant="ghost" onClick={() => run(chosen, "ignore")}>
                {t("threats.ignore")}
              </Button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
