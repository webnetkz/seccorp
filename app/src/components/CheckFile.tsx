import { ShieldCheck } from "lucide-react";
import { useState } from "react";
import { api, errorText } from "../api/backend";
import type { FileVerdict } from "../api/types";
import { useI18n } from "../i18n";
import { useStore } from "../store";
import { pickFiles } from "../utils/pick";
import { ThreatCard } from "./ThreatCard";
import { Button, Modal, ModalHeader, Spinner } from "./ui";

/** "Check a file" flow: pick → scan → show the verdict. */
export function useCheckFile() {
  const { info, toast, refresh } = useStore();
  const [state, setState] = useState<{ open: boolean; loading: boolean; verdict: FileVerdict | null }>({
    open: false,
    loading: false,
    verdict: null,
  });

  const start = async () => {
    try {
      const files = await pickFiles(info, false);
      if (!files.length) return;
      setState({ open: true, loading: true, verdict: null });
      const v = await api.scanFileNow(files[0]);
      setState({ open: true, loading: false, verdict: v });
      refresh();
    } catch (e) {
      setState({ open: false, loading: false, verdict: null });
      toast(errorText(e), "error");
    }
  };

  const close = () => setState({ open: false, loading: false, verdict: null });
  return { start, state, close };
}

export function CheckFileModal({ state, onClose }: { state: ReturnType<typeof useCheckFile>["state"]; onClose: () => void }) {
  const { t } = useI18n();
  const { navigate } = useStore();
  const v = state.verdict;
  return (
    <Modal open={state.open} onClose={onClose}>
      <ModalHeader title={t("dashboard.checkFile")} onClose={onClose} />
      {state.loading && (
        <div className="empty">
          <Spinner size={28} />
          <div className="muted">{t("scan.checking")}</div>
        </div>
      )}
      {v && v.verdict === "clean" && (
        <div className="empty">
          <span className="icon-tile ok">
            <ShieldCheck size={30} />
          </span>
          <div className="empty-title">{t("scan.fileClean")}</div>
          <div className="empty-desc mono break">{v.path.split(/[\\/]/).pop()}</div>
        </div>
      )}
      {v && v.verdict !== "clean" && (
        <div style={{ marginTop: 12 }}>
          <div className="callout warn" style={{ marginBottom: 12 }}>
            {t("scan.fileThreat")}
          </div>
          <ThreatCard verdict={v} />
        </div>
      )}
      {v && (
        <div className="modal-actions">
          {v.verdict !== "clean" && (
            <Button
              variant="primary"
              onClick={() => {
                onClose();
                navigate("threats");
              }}
            >
              {t("dashboard.resolveThreats")}
            </Button>
          )}
          <Button onClick={onClose}>{t("common.close")}</Button>
        </div>
      )}
    </Modal>
  );
}
