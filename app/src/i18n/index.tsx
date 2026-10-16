import { createContext, useContext, useMemo, type ReactNode } from "react";
import { en } from "./en";
import { ru } from "./ru";

export type Lang = "ru" | "en";
const dictionaries = { ru, en };

export function detectLang(pref: string): Lang {
  if (pref === "ru" || pref === "en") return pref;
  const nav = (typeof navigator !== "undefined" ? navigator.language : "ru").toLowerCase();
  return nav.startsWith("ru") || nav.startsWith("kk") || nav.startsWith("uk") || nav.startsWith("be") ? "ru" : "en";
}

function lookup(dict: unknown, key: string): unknown {
  return key.split(".").reduce<unknown>((o, k) => (o && typeof o === "object" ? (o as Record<string, unknown>)[k] : undefined), dict);
}

export type Vars = Record<string, string | number>;

function format(s: string, vars?: Vars): string {
  if (!vars) return s;
  return s.replace(/\{(\w+)\}/g, (m, k) => (k in vars ? String(vars[k]) : m));
}

export interface I18n {
  lang: Lang;
  locale: string;
  t: (key: string, vars?: Vars) => string;
  /** Raw access for arrays / maps. */
  raw: <T = unknown>(key: string) => T;
  num: (n: number) => string;
  plural: (n: number, forms: [string, string, string]) => string;
}

const Ctx = createContext<I18n | null>(null);

export function makeI18n(lang: Lang): I18n {
  const dict = dictionaries[lang];
  const locale = lang === "ru" ? "ru-RU" : "en-US";
  const nf = new Intl.NumberFormat(locale);
  const pr = new Intl.PluralRules(locale);
  return {
    lang,
    locale,
    t: (key, vars) => {
      const v = lookup(dict, key) ?? lookup(en, key);
      return typeof v === "string" ? format(v, vars) : key;
    },
    raw: <T,>(key: string) => (lookup(dict, key) ?? lookup(en, key)) as T,
    num: (n) => nf.format(n),
    plural: (n, [one, few, many]) => {
      const rule = pr.select(n);
      if (lang === "ru") return rule === "one" ? one : rule === "few" ? few : many;
      return rule === "one" ? one : many;
    },
  };
}

export function I18nProvider({ lang, children }: { lang: Lang; children: ReactNode }) {
  const value = useMemo(() => makeI18n(lang), [lang]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useI18n(): I18n {
  const v = useContext(Ctx);
  if (!v) throw new Error("I18nProvider missing");
  return v;
}
