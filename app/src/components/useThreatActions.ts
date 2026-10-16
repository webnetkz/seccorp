import { useCallback, useState } from "react";
import { api, errorText } from "../api/backend";
import type { ThreatEntry } from "../api/types";
import { useI18n } from "../i18n";
import { useStore } from "../store";
import type { ThreatAction } from "./ThreatCard";

/** Executes threat actions with confirmations, toasts and refreshes. */
export function useThreatActions(onDone?: () => void) {
  const { t } = useI18n();
  const { confirm, toast, refresh } = useStore();
  const [busy, setBusy] = useState<Set<string>>(new Set());

  const run = useCallback(
    async (entries: ThreatEntry[], action: ThreatAction) => {
      if (!entries.length) return;
      const first = entries[0];
      try {
        if (action === "reveal") return await api.revealPath(first.verdict.path);
        if (action === "appSettings" && first.packageName) return await api.openAppSettings(first.packageName);
        if (action === "delete") {
          const ok = await confirm({ title: t("threats.delete"), text: t("threats.confirmDelete"), confirm: t("common.delete"), danger: true });
          if (!ok) return;
        }
        if (action === "allow") {
          const ok = await confirm({ title: t("threats.allow"), text: t("threats.confirmAllow"), confirm: t("common.confirm") });
          if (!ok) return;
        }
        const ids = entries.map((e) => e.id);
        setBusy((b) => new Set([...b, ...ids]));
        const results = await api.resolveThreats(ids, action === "appSettings" ? "ignore" : action);
        const failed = results.filter((r) => !r.ok);
        const okCount = results.length - failed.length;
        if (okCount && action !== "ignore") toast(t("threats.resolved", { n: okCount }), "success");
        if (failed.length) toast(t("threats.failed", { msg: failed[0].error ?? "" }), "error");
      } catch (e) {
        toast(errorText(e), "error");
      } finally {
        setBusy(new Set());
        refresh();
        onDone?.();
      }
    },
    [confirm, toast, refresh, t, onDone],
  );

  return { run, busy };
}
