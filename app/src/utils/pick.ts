import { open, save } from "@tauri-apps/plugin-dialog";
import { api, isTauri } from "../api/backend";
import type { AppInfo } from "../api/types";
import { toPath } from "./format";

function normalize(v: string | string[] | null): string[] {
  if (!v) return [];
  return (Array.isArray(v) ? v : [v]).map(toPath);
}

/** Native folder picker (desktop). */
export async function pickFolders(): Promise<string[]> {
  if (!isTauri) return ["/Users/user/Projects"];
  return normalize(await open({ directory: true, multiple: true }));
}

/** Picks files to scan or import, using the right mechanism per platform. */
export async function pickFiles(info: AppInfo | null, multiple = true): Promise<string[]> {
  if (!isTauri) return ["/Users/user/Downloads/document.pdf"];
  if (info?.platform === "android") {
    const r = await api.pickFileNative();
    return !r.cancelled && r.path ? [r.path] : [];
  }
  if (info?.platform === "ios") {
    return normalize(await open({ multiple: false }));
  }
  return normalize(await open({ multiple }));
}

/** Save dialog (desktop only; mobile reports go to Downloads/Documents). */
export async function pickSavePath(defaultName: string, ext: string, info: AppInfo | null): Promise<string | null | undefined> {
  if (!isTauri || info?.features.folderPicker !== true) return undefined;
  const p = await save({ defaultPath: defaultName, filters: [{ name: ext.toUpperCase(), extensions: [ext] }] });
  return p ? toPath(p) : null;
}
