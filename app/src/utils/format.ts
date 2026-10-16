import type { I18n } from "../i18n";

export function bytes(n: number, i18n: I18n): string {
  const units = i18n.lang === "ru" ? ["Б", "КБ", "МБ", "ГБ", "ТБ"] : ["B", "KB", "MB", "GB", "TB"];
  let v = n;
  let u = 0;
  while (v >= 1024 && u < units.length - 1) {
    v /= 1024;
    u++;
  }
  const digits = u === 0 || v >= 100 ? 0 : 1;
  return `${new Intl.NumberFormat(i18n.locale, { maximumFractionDigits: digits }).format(v)} ${units[u]}`;
}

export function compact(n: number, i18n: I18n): string {
  return new Intl.NumberFormat(i18n.locale, { notation: "compact", maximumFractionDigits: 1 }).format(n);
}

export function dateTime(ts: number, i18n: I18n): string {
  return new Intl.DateTimeFormat(i18n.locale, { dateStyle: "medium", timeStyle: "short" }).format(new Date(ts * 1000));
}

export function date(ts: number, i18n: I18n): string {
  return new Intl.DateTimeFormat(i18n.locale, { dateStyle: "medium" }).format(new Date(ts * 1000));
}

export function time(ts: number, i18n: I18n): string {
  return new Intl.DateTimeFormat(i18n.locale, { timeStyle: "short" }).format(new Date(ts * 1000));
}

export function relative(ts: number | null | undefined, i18n: I18n): string {
  if (!ts) return i18n.t("common.never");
  const diff = ts - Math.floor(Date.now() / 1000);
  const rtf = new Intl.RelativeTimeFormat(i18n.locale, { numeric: "auto" });
  const abs = Math.abs(diff);
  if (abs < 60) return rtf.format(Math.round(diff), "second");
  if (abs < 3600) return rtf.format(Math.round(diff / 60), "minute");
  if (abs < 86400) return rtf.format(Math.round(diff / 3600), "hour");
  if (abs < 86400 * 30) return rtf.format(Math.round(diff / 86400), "day");
  return date(ts, i18n);
}

export function duration(ms: number, i18n: I18n): string {
  const s = Math.max(0, Math.round(ms / 1000));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  const ru = i18n.lang === "ru";
  if (h > 0) return ru ? `${h} ч ${m} мин` : `${h}h ${m}m`;
  if (m > 0) return ru ? `${m} мин ${sec} с` : `${m}m ${sec}s`;
  return ru ? `${sec} с` : `${sec}s`;
}

export function fileName(path: string): string {
  return path.split(/[\\/]/).filter(Boolean).pop() ?? path;
}

export function dirName(path: string): string {
  const parts = path.split(/([\\/])/);
  return parts.slice(0, -2).join("") || path;
}

/** Keeps the start and the end of long paths: `C:\Users\…\file.exe`. */
export function middle(s: string, max = 64): string {
  if (s.length <= max) return s;
  const keep = max - 1;
  const head = Math.ceil(keep * 0.4);
  const tail = keep - head;
  return `${s.slice(0, head)}…${s.slice(s.length - tail)}`;
}

/** Converts `file://` URLs returned by mobile pickers to paths. */
export function toPath(p: string): string {
  if (p.startsWith("file://")) {
    try {
      return decodeURIComponent(p.slice(7));
    } catch {
      return p.slice(7);
    }
  }
  return p;
}

export function filesWord(n: number, i18n: I18n): string {
  return i18n.lang === "ru" ? i18n.plural(n, ["файл", "файла", "файлов"]) : n === 1 ? "file" : "files";
}
