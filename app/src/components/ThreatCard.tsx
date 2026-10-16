import { ChevronRight, FolderOpen, ShieldAlert, ShieldX } from "lucide-react";
import { useState } from "react";
import type { Detection, FileVerdict, ThreatEntry } from "../api/types";
import { useI18n, type I18n } from "../i18n";
import { bytes, dateTime, fileName } from "../utils/format";
import { Badge, Button } from "./ui";

export type ThreatAction = "quarantine" | "delete" | "ignore" | "allow" | "uninstall" | "appSettings" | "reveal";

export function describeDetection(d: Detection, i18n: I18n): string {
  const names = i18n.raw<Record<string, string>>("detections.names");
  if (names[d.name]) return names[d.name];
  if (i18n.lang === "en" && d.description) return d.description;
  return i18n.t(`detections.${d.kind}`);
}

export function primary(v: FileVerdict): Detection | undefined {
  const rank = (d: Detection) => ({ critical: 5, high: 4, medium: 3, low: 2, info: 1 })[d.severity] * 10 + (d.kind === "heuristic" ? 0 : 5);
  return [...v.detections].sort((a, b) => rank(b) - rank(a))[0];
}

export function VerdictBadge({ verdict }: { verdict: FileVerdict["verdict"] }) {
  const { t } = useI18n();
  const tone = verdict === "malicious" ? "danger" : verdict === "suspicious" ? "warn" : "ok";
  return (
    <Badge tone={tone} dot>
      {t(`threats.verdict.${verdict}`)}
    </Badge>
  );
}

export function ThreatCard({
  entry,
  verdict,
  busy,
  onAction,
  canReveal,
  selected,
  onSelect,
}: {
  entry?: ThreatEntry;
  verdict?: FileVerdict;
  busy?: boolean;
  onAction?: (a: ThreatAction) => void;
  canReveal?: boolean;
  selected?: boolean;
  onSelect?: (v: boolean) => void;
}) {
  const i18n = useI18n();
  const { t } = i18n;
  const v = entry?.verdict ?? verdict!;
  const [open, setOpen] = useState(false);
  const d = primary(v);
  const isApp = !!entry?.packageName;
  const title = entry?.appLabel ?? fileName(v.path);

  return (
    <div className={`threat ${v.verdict}`}>
      {onSelect && (
        <input type="checkbox" className="checkbox" checked={!!selected} onChange={(e) => onSelect(e.target.checked)} style={{ marginTop: 10 }} />
      )}
      <span className={`icon-tile ${v.verdict === "malicious" ? "danger" : "warn"}`}>
        {v.verdict === "malicious" ? <ShieldX size={20} /> : <ShieldAlert size={20} />}
      </span>
      <div className="grow">
        <div className="row wrap" style={{ gap: 8 }}>
          <span className="threat-name">{d?.name ?? "—"}</span>
          <VerdictBadge verdict={v.verdict} />
        </div>
        <div className="threat-path selectable">
          {isApp ? `${title} · ${entry?.packageName}` : v.path}
        </div>
        {d && <div className="threat-desc">{describeDetection(d, i18n)}</div>}
        {d?.location && (
          <div className="threat-desc faint">
            {t("threats.location")}: <span className="mono">{d.location}</span>
          </div>
        )}

        {open && (
          <div style={{ marginTop: 12 }}>
            <dl className="kv selectable">
              {entry && (
                <>
                  <dt>{t("threats.detectedAt")}</dt>
                  <dd>
                    {dateTime(entry.detectedAt, i18n)} · {t(`threats.sources.${entry.source}`)}
                  </dd>
                </>
              )}
              <dt>{t("threats.size")}</dt>
              <dd>{bytes(v.size, i18n)}</dd>
              <dt>{t("threats.fileType")}</dt>
              <dd>{v.fileType}</dd>
              {v.sha256 && (
                <>
                  <dt>{t("threats.sha256")}</dt>
                  <dd className="mono">{v.sha256}</dd>
                </>
              )}
              {v.score > 0 && (
                <>
                  <dt>{t("threats.why")}</dt>
                  <dd>{t("threats.score", { n: v.score })}</dd>
                </>
              )}
            </dl>
            {v.detections.length > 1 && (
              <ul style={{ margin: "10px 0 0", paddingLeft: 18, color: "var(--text-2)", fontSize: 13 }}>
                {v.detections.map((x, i) => (
                  <li key={i}>
                    <b>{x.name}</b> — {describeDetection(x, i18n)}
                    {x.location ? <span className="faint"> ({x.location})</span> : null}
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}

        <div className="threat-actions">
          {onAction && !isApp && (
            <>
              <Button size="sm" variant="primary" loading={busy} onClick={() => onAction("quarantine")}>
                {t("threats.quarantine")}
              </Button>
              <Button size="sm" onClick={() => onAction("delete")} disabled={busy}>
                {t("threats.delete")}
              </Button>
              <Button size="sm" variant="ghost" onClick={() => onAction("allow")} disabled={busy}>
                {t("threats.allow")}
              </Button>
              <Button size="sm" variant="ghost" onClick={() => onAction("ignore")} disabled={busy}>
                {t("threats.ignore")}
              </Button>
            </>
          )}
          {onAction && isApp && (
            <>
              <Button size="sm" variant="danger" loading={busy} onClick={() => onAction("uninstall")}>
                {t("threats.uninstall")}
              </Button>
              <Button size="sm" onClick={() => onAction("appSettings")}>
                {t("apps.appSettings")}
              </Button>
              <Button size="sm" variant="ghost" onClick={() => onAction("ignore")} disabled={busy}>
                {t("threats.ignore")}
              </Button>
            </>
          )}
          {canReveal && !isApp && onAction && (
            <Button size="sm" variant="ghost" icon={<FolderOpen size={15} />} onClick={() => onAction("reveal")}>
              {t("common.showInFolder")}
            </Button>
          )}
          <Button size="sm" variant="ghost" onClick={() => setOpen(!open)}>
            {t("common.details")}
            <ChevronRight size={15} style={{ transform: open ? "rotate(90deg)" : undefined, transition: "transform .15s" }} />
          </Button>
        </div>
      </div>
    </div>
  );
}
