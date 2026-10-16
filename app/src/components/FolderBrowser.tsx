import { ChevronLeft, File, Folder, HardDrive } from "lucide-react";
import { useEffect, useState } from "react";
import { api, errorText } from "../api/backend";
import type { DirEntry, DirListing } from "../api/types";
import { useI18n } from "../i18n";
import { bytes } from "../utils/format";
import { Button, Modal, ModalHeader, Spinner } from "./ui";

/** In-app folder browser (Android has no native folder picker that returns paths). */
export function FolderBrowser({ open, onClose, onPick }: { open: boolean; onClose: () => void; onPick: (path: string) => void }) {
  const i18n = useI18n();
  const { t } = i18n;
  const [roots, setRoots] = useState<DirEntry[]>([]);
  const [listing, setListing] = useState<DirListing | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    setListing(null);
    api.browseRoots().then(setRoots).catch((e) => setError(errorText(e)));
  }, [open]);

  const go = async (path: string) => {
    setLoading(true);
    setError(null);
    try {
      setListing(await api.listDir(path));
    } catch (e) {
      setError(errorText(e));
    } finally {
      setLoading(false);
    }
  };

  const isRoot = listing && roots.some((r) => r.path === listing.path);

  return (
    <Modal open={open} onClose={onClose}>
      <ModalHeader title={t("scan.chooseFolders")} onClose={onClose} />
      {listing && (
        <div className="row" style={{ marginTop: 6 }}>
          <Button size="sm" variant="ghost" icon={<ChevronLeft size={16} />} onClick={() => (isRoot || !listing.parent ? setListing(null) : go(listing.parent))}>
            {t("common.back")}
          </Button>
          <span className="mono faint ellipsis grow">{listing.path}</span>
        </div>
      )}
      <div className="browser-list">
        {loading && (
          <div className="row" style={{ justifyContent: "center", padding: 20 }}>
            <Spinner />
          </div>
        )}
        {error && <div className="callout warn">{error}</div>}
        {!listing &&
          roots.map((r) => (
            <div key={r.path} className="list-item clickable" onClick={() => go(r.path)}>
              <span className="icon-tile sm">
                <HardDrive size={16} />
              </span>
              <div className="grow">
                <div className="list-title">{r.name}</div>
                <div className="list-sub mono">{r.path}</div>
              </div>
            </div>
          ))}
        {listing &&
          !loading &&
          listing.entries.map((e) => (
            <div key={e.path} className={`list-item ${e.isDir ? "clickable" : ""}`} onClick={() => e.isDir && go(e.path)}>
              <span className={`icon-tile sm ${e.isDir ? "" : "muted"}`}>{e.isDir ? <Folder size={16} /> : <File size={16} />}</span>
              <div className="grow ellipsis">{e.name}</div>
              {!e.isDir && <span className="faint num" style={{ fontSize: 12 }}>{bytes(e.size, i18n)}</span>}
            </div>
          ))}
      </div>
      <div className="modal-actions">
        <Button variant="ghost" onClick={onClose}>
          {t("common.cancel")}
        </Button>
        <Button variant="primary" disabled={!listing} onClick={() => listing && onPick(listing.path)}>
          {t("common.choose")}
        </Button>
      </div>
    </Modal>
  );
}
