import { CircleAlert, CircleCheck, HardDrive, Info, RotateCcw, ScanSearch, Settings2, Usb } from "lucide-react";
import { api, errorText } from "../api/backend";
import { useI18n } from "../i18n";
import { useStore } from "../store";
import { Button, Modal } from "./ui";

export function Toasts() {
  const { toasts } = useStore();
  return (
    <div className="toasts" aria-live="polite">
      {toasts.map((t) => (
        <div key={t.id} className={`toast ${t.kind}`}>
          {t.kind === "success" ? <CircleCheck size={18} /> : t.kind === "error" ? <CircleAlert size={18} /> : <Info size={18} />}
          <span className="selectable" style={{ wordBreak: "break-word" }}>
            {t.text}
          </span>
        </div>
      ))}
    </div>
  );
}

export function ConfirmDialog() {
  const { t } = useI18n();
  const { confirmState, closeConfirm } = useStore();
  return (
    <Modal open={!!confirmState} onClose={() => closeConfirm(false)}>
      {confirmState && (
        <>
          <div className="modal-title">{confirmState.title}</div>
          {confirmState.text && <p className="modal-text">{confirmState.text}</p>}
          <div className="modal-actions">
            <Button variant="ghost" onClick={() => closeConfirm(false)}>
              {t("common.cancel")}
            </Button>
            <Button variant={confirmState.danger ? "danger" : "primary"} onClick={() => closeConfirm(true)} autoFocus>
              {confirmState.confirm}
            </Button>
          </div>
        </>
      )}
    </Modal>
  );
}

/**
 * macOS: explains Full Disk Access instead of letting the system ask for every
 * protected folder during a scan. Offers to open the settings, to restart (the
 * grant applies only after a restart) or to scan without protected folders.
 */
export function DiskAccessDialog() {
  const { t } = useI18n();
  const { diskAccess, closeDiskAccess, startScan, toast } = useStore();
  const req = diskAccess;
  const fail = (e: unknown) => toast(errorText(e), "error");
  return (
    <Modal open={!!req} onClose={closeDiskAccess} wide>
      {req && (
        <>
          <div className="row" style={{ gap: 12, alignItems: "center" }}>
            <span className="icon-tile warn">
              <HardDrive size={20} />
            </span>
            <div className="modal-title">{t("diskAccess.title")}</div>
          </div>
          <p className="modal-text">{t("diskAccess.text")}</p>
          <ol className="steps-list">
            <li>{t("diskAccess.step1")}</li>
            <li>{t("diskAccess.step2")}</li>
          </ol>
          <div className="callout" style={{ marginTop: 14 }}>
            <Info size={16} />
            <div>{t("diskAccess.stale")}</div>
          </div>
          <div className="modal-actions wrap">
            {req.kind && (
              <Button
                variant="ghost"
                className="push-left"
                onClick={() => {
                  const { kind, paths } = req;
                  closeDiskAccess();
                  if (kind) startScan(kind, paths ?? [], { limited: true });
                }}
              >
                {t("diskAccess.scanLimited")}
              </Button>
            )}
            <Button icon={<RotateCcw size={15} />} onClick={() => api.restartApp().catch(fail)}>
              {t("diskAccess.restart")}
            </Button>
            <Button variant="primary" icon={<Settings2 size={15} />} onClick={() => api.openPrivacySettings().catch(fail)}>
              {t("diskAccess.openSettings")}
            </Button>
          </div>
        </>
      )}
    </Modal>
  );
}

/** Asks before reading a newly attached USB drive, SD card or disk image. */
export function RemovableMediaDialog() {
  const { t } = useI18n();
  const { mediaPrompt, dismissMedia, scanMedia, scan } = useStore();
  return (
    <Modal open={!!mediaPrompt} onClose={dismissMedia} wide>
      {mediaPrompt && (
        <>
          <div className="row" style={{ gap: 12, alignItems: "center" }}>
            <span className="icon-tile">
              <Usb size={20} />
            </span>
            <div className="modal-title">{t("media.title")}</div>
          </div>
          <p className="modal-text">{t("media.text", { name: mediaPrompt.name })}</p>
          <div className="current-file selectable mono">{mediaPrompt.path}</div>
          {scan.running && (
            <div className="callout" style={{ marginTop: 14 }}>
              <Info size={16} />
              <div>{t("media.busy")}</div>
            </div>
          )}
          <div className="modal-actions">
            <Button variant="ghost" onClick={dismissMedia}>
              {t("media.later")}
            </Button>
            <Button variant="primary" icon={<ScanSearch size={16} />} disabled={scan.running} onClick={scanMedia} autoFocus>
              {t("media.scan")}
            </Button>
          </div>
        </>
      )}
    </Modal>
  );
}
