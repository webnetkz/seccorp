import { Onboarding } from "./components/Onboarding";
import { ConfirmDialog, DiskAccessDialog, RemovableMediaDialog, Toasts } from "./components/Overlays";
import { BottomNav, Sidebar } from "./components/Navigation";
import { AppsPage } from "./pages/Apps";
import { Dashboard } from "./pages/Dashboard";
import { DevicePage } from "./pages/Device";
import { HistoryPage } from "./pages/History";
import { ProtectionPage } from "./pages/Protection";
import { QuarantinePage } from "./pages/Quarantine";
import { ScanPage } from "./pages/Scan";
import { SettingsPage } from "./pages/Settings";
import { SignaturesPage } from "./pages/Signatures";
import { ThreatsPage } from "./pages/Threats";
import { useStore } from "./store";

function Page() {
  const { route } = useStore();
  switch (route) {
    case "scan":
      return <ScanPage />;
    case "threats":
      return <ThreatsPage />;
    case "protection":
      return <ProtectionPage />;
    case "quarantine":
      return <QuarantinePage />;
    case "history":
      return <HistoryPage />;
    case "signatures":
      return <SignaturesPage />;
    case "settings":
      return <SettingsPage />;
    case "apps":
      return <AppsPage />;
    case "device":
      return <DevicePage />;
    default:
      return <Dashboard />;
  }
}

export default function App() {
  const { route, info } = useStore();
  return (
    <div className="app">
      {info?.platform === "macos" && <div className="drag-region" data-tauri-drag-region />}
      <Sidebar />
      <main className="content">
        <Page key={route} />
      </main>
      <BottomNav />
      <Toasts />
      <ConfirmDialog />
      <DiskAccessDialog />
      <RemovableMediaDialog />
      <Onboarding />
    </div>
  );
}
