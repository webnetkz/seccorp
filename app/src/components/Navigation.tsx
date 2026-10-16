import {
  Archive,
  Database,
  Ellipsis,
  History,
  House,
  LayoutGrid,
  Radar,
  ScanSearch,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Smartphone,
} from "lucide-react";
import { useState, type ReactNode } from "react";
import { useI18n } from "../i18n";
import { useStore, type Route } from "../store";

interface Item {
  route: Route;
  label: string;
  icon: ReactNode;
  badge?: number;
  dot?: boolean;
}

function useItems() {
  const { t } = useI18n();
  const { info, dashboard, scan } = useStore();
  const f = info?.features;
  const threats = dashboard?.activeThreats ?? 0;
  const main: Item[] = [
    { route: "dashboard", label: t("nav.dashboard"), icon: <House size={19} /> },
    ...(threats > 0 ? [{ route: "threats" as Route, label: t("nav.threats"), icon: <ShieldAlert size={19} />, badge: threats }] : []),
    { route: "scan", label: t("nav.scan"), icon: <ScanSearch size={19} />, dot: scan.running },
    { route: "protection", label: t("nav.protection"), icon: <Radar size={19} /> },
    ...(f?.installedApps ? [{ route: "apps" as Route, label: t("nav.apps"), icon: <LayoutGrid size={19} /> }] : []),
    ...(f?.deviceCheck ? [{ route: "device" as Route, label: t("nav.device"), icon: <Smartphone size={19} /> }] : []),
    { route: "quarantine", label: t("nav.quarantine"), icon: <Archive size={19} />, badge: undefined },
  ];
  const tools: Item[] = [
    { route: "history", label: t("nav.history"), icon: <History size={19} /> },
    { route: "signatures", label: t("nav.signatures"), icon: <Database size={19} /> },
    { route: "settings", label: t("nav.settings"), icon: <Settings size={19} /> },
  ];
  return { main, tools, threats };
}

function NavButton({ item, active, onClick }: { item: Item; active: boolean; onClick: () => void }) {
  return (
    <button className={`nav-item ${active ? "active" : ""}`} onClick={onClick} aria-current={active ? "page" : undefined}>
      {item.icon}
      <span>{item.label}</span>
      {item.badge ? <span className="nav-badge">{item.badge}</span> : item.dot ? <span className="nav-dot" /> : null}
    </button>
  );
}

export function Sidebar() {
  const { t } = useI18n();
  const { route, navigate, dashboard, info } = useStore();
  const { main, tools } = useItems();
  const rt = dashboard?.realtime;
  return (
    <aside className="sidebar">
      <div className="brand" data-tauri-drag-region>
        <img className="brand-logo" src="/icon.svg" alt="" />
        <div>
          <div className="brand-name">SecCorp</div>
          <div className="brand-sub">{info?.platform === "ios" ? t("app.taglineIos") : t("app.tagline")}</div>
        </div>
      </div>
      <nav className="nav">
        {main.map((i) => (
          <NavButton key={i.route} item={i} active={route === i.route} onClick={() => navigate(i.route)} />
        ))}
        <div className="nav-section">{t("nav.more")}</div>
        {tools.map((i) => (
          <NavButton key={i.route} item={i} active={route === i.route} onClick={() => navigate(i.route)} />
        ))}
      </nav>
      {rt && (
        <div className="sidebar-footer">
          <div className="row">
            {rt.running ? <ShieldCheck size={16} color="var(--ok)" /> : <ShieldAlert size={16} color="var(--warn)" />}
            <span style={{ fontWeight: 600 }}>{rt.running ? t("protection.statusOn") : t("protection.statusOff")}</span>
          </div>
          <div className="faint" style={{ fontSize: 12, marginTop: 4 }}>
            {t("signatures.version")}: {dashboard?.db.version.startsWith("builtin") ? t("signatures.builtin") : dashboard?.db.version}
          </div>
        </div>
      )}
    </aside>
  );
}

export function BottomNav() {
  const { t } = useI18n();
  const { route, navigate, info } = useStore();
  const { main, tools, threats } = useItems();
  const [more, setMore] = useState(false);
  const f = info?.features;

  const primary: Item[] = [
    main.find((i) => i.route === "dashboard")!,
    { ...main.find((i) => i.route === "scan")!, badge: threats || undefined },
    main.find((i) => i.route === "protection")!,
    f?.installedApps ? main.find((i) => i.route === "apps")! : main.find((i) => i.route === "quarantine")!,
  ];
  const primaryRoutes = new Set(primary.map((i) => i.route));
  const rest = [...main, ...tools].filter((i) => !primaryRoutes.has(i.route) && i.route !== "threats");
  const moreActive = rest.some((i) => i.route === route);

  const go = (r: Route) => {
    setMore(false);
    navigate(r);
  };

  return (
    <>
      <nav className="bottom-nav">
        {primary.map((i) => (
          <button
            key={i.route}
            className={`bottom-nav-item ${route === i.route || (i.route === "scan" && route === "threats") ? "active" : ""}`}
            onClick={() => go(i.route)}
          >
            {i.icon}
            <span>{i.label}</span>
            {i.badge ? <span className="nav-badge">{i.badge}</span> : null}
          </button>
        ))}
        <button className={`bottom-nav-item ${moreActive ? "active" : ""}`} onClick={() => setMore(true)}>
          <Ellipsis size={19} />
          <span>{t("nav.more")}</span>
        </button>
      </nav>
      {more && (
        <>
          <div className="sheet-backdrop" onClick={() => setMore(false)} />
          <div className="sheet" role="dialog">
            <div className="sheet-handle" />
            <div className="sheet-grid">
              {rest.map((i) => (
                <button key={i.route} className="sheet-item" onClick={() => go(i.route)}>
                  {i.icon}
                  <span>{i.label}</span>
                </button>
              ))}
            </div>
          </div>
        </>
      )}
    </>
  );
}
