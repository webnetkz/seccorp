import { Activity, Database, Eye, Network, RefreshCw, Server, ShieldAlert, ShieldCheck, TriangleAlert, X } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { api, errorText, on } from "../api/backend";
import type { NetworkAlert, NetworkConnection, NetworkStatus } from "../api/types";
import { Badge, Button, Card, CardHeader, Empty, PageHeader, Setting, Toggle } from "../components/ui";
import { useI18n } from "../i18n";
import { useStore } from "../store";
import { dateTime, middle } from "../utils/format";

function endpoint(address: string | null, port: number | null): string {
  if (!address) return "—";
  const host = address.includes(":") ? `[${address}]` : address;
  return port ? `${host}:${port}` : host;
}

function alertTitle(alert: NetworkAlert, t: (key: string) => string): string {
  if (alert.kind === "known_c2") return t("network.knownC2");
  if (alert.kind === "infected_process") return t("network.infectedProcess");
  return t("network.possibleSpyware");
}

function ReasonList({ reasons }: { reasons: string[] }) {
  const { t } = useI18n();
  return (
    <ul className="network-reasons">
      {reasons.map((reason) => (
        <li key={reason}>{t(`network.reasons.${reason}`)}</li>
      ))}
    </ul>
  );
}

function ConnectionRow({ connection }: { connection: NetworkConnection }) {
  const { t } = useI18n();
  const flagged = connection.verdict !== "clean";
  return (
    <div className={`network-row ${flagged ? connection.verdict : ""}`}>
      <span className={`dot ${connection.verdict}`} />
      <div className="network-process">
        <div className="row" style={{ gap: 7 }}>
          <strong className="ellipsis">{connection.process || t("network.unknownProcess")}</strong>
          {connection.pid != null && <span className="faint num">PID {connection.pid}</span>}
        </div>
        {connection.executable && (
          <div className="mono faint ellipsis" title={connection.executable}>
            {middle(connection.executable, 72)}
          </div>
        )}
      </div>
      <div className="network-endpoint">
        <div className="mono">{endpoint(connection.remoteAddress, connection.remotePort)}</div>
        <div className="faint mono">
          {connection.protocol} · {connection.state}
        </div>
      </div>
      <div className="network-local mono faint">{endpoint(connection.localAddress, connection.localPort)}</div>
    </div>
  );
}

export function NetworkPage() {
  const i18n = useI18n();
  const { t } = i18n;
  const { settings, updateSettings, reloadSettings, refresh, toast } = useStore();
  const [status, setStatus] = useState<NetworkStatus | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      setStatus(await api.networkStatus());
    } catch (e) {
      toast(errorText(e), "error");
    }
  }, [toast]);

  useEffect(() => {
    void load();
    const offs = [on<NetworkStatus>("network://updated", setStatus), on<NetworkAlert>("network://alert", () => void load())];
    return () => offs.forEach((off) => off());
  }, [load]);

  if (!settings || !status) return null;

  const setEnabled = async (enabled: boolean) => {
    try {
      setStatus(await api.setNetworkProtection(enabled));
      await Promise.all([reloadSettings(), refresh()]);
    } catch (e) {
      toast(errorText(e), "error");
    }
  };

  const scan = async () => {
    setBusy(true);
    try {
      setStatus(await api.scanNetwork());
    } catch (e) {
      toast(errorText(e), "error");
    } finally {
      setBusy(false);
    }
  };

  const dismiss = async (id: string) => {
    try {
      setStatus(await api.dismissNetworkAlert(id));
      refresh();
    } catch (e) {
      toast(errorText(e), "error");
    }
  };

  const enabled = settings.networkMonitorEnabled;
  const connections = status.connections.slice(0, 200);

  return (
    <div className="page">
      <PageHeader
        title={t("network.title")}
        subtitle={t("network.subtitle")}
        right={
          <Button icon={<RefreshCw size={16} />} loading={busy || status.scanning} disabled={!enabled} onClick={scan}>
            {busy || status.scanning ? t("network.scanning") : t("network.scanNow")}
          </Button>
        }
      />

      <Card>
        <CardHeader
          icon={status.running ? <ShieldCheck size={22} /> : <ShieldAlert size={22} />}
          tone={status.running ? "ok" : "warn"}
          title={t("network.protectionTitle")}
          sub={t("network.protectionDesc")}
          right={<Toggle on={enabled} onChange={setEnabled} label={t("network.protectionTitle")} />}
        />
        <div className="row wrap" style={{ gap: 8 }}>
          <Badge tone={status.running ? "ok" : "warn"} dot>
            {status.running ? t("network.active") : t("network.inactive")}
          </Badge>
          {status.error && <span className="faint" style={{ fontSize: 13 }}>{status.error}</span>}
        </div>
        <div className="metrics network-metrics">
          <div className="metric">
            <div className="metric-label"><Activity size={14} /> {t("network.activeConnections")}</div>
            <div className="metric-value num">{i18n.num(status.activeConnections)}</div>
          </div>
          <div className="metric">
            <div className="metric-label"><Server size={14} /> {t("network.listeningPorts")}</div>
            <div className="metric-value num">{i18n.num(status.listeningPorts)}</div>
          </div>
          <div className="metric">
            <div className="metric-label"><Database size={14} /> {t("network.indicators")}</div>
            <div className="metric-value num">{i18n.num(status.indicatorCount)}</div>
          </div>
          <div className="metric">
            <div className="metric-label"><RefreshCw size={14} /> {t("network.lastScan")}</div>
            <div className="metric-value small">{status.lastScanAt ? dateTime(status.lastScanAt, i18n) : t("network.neverScanned")}</div>
          </div>
        </div>
      </Card>

      <div className="grid-2" style={{ marginTop: 16 }}>
        <Card>
          <CardHeader icon={<Database size={20} />} title={t("network.intelTitle")} sub={t("network.intelDesc")} />
          <Setting
            title={t("common.on")}
            desc={status.intelligenceUpdatedAt ? t("network.intelUpdated", { date: dateTime(status.intelligenceUpdatedAt, i18n) }) : undefined}
          >
            <Toggle on={settings.networkThreatIntel} onChange={(value) => updateSettings({ networkThreatIntel: value })} />
          </Setting>
        </Card>
        <Card>
          <CardHeader icon={<Eye size={20} />} title={t("network.spywareTitle")} sub={t("network.spywareDesc")} />
          <Setting title={t("common.on")}>
            <Toggle on={settings.networkSpywareHeuristics} onChange={(value) => updateSettings({ networkSpywareHeuristics: value })} />
          </Setting>
        </Card>
      </div>

      <div className="callout" style={{ marginTop: 16 }}>
        <Network size={18} />
        <div>{t("network.privacy")}</div>
      </div>

      <Card style={{ marginTop: 16 }}>
        <CardHeader
          icon={<TriangleAlert size={20} />}
          tone={status.alerts.some((alert) => alert.severity === "malicious") ? "danger" : status.alerts.length ? "warn" : "ok"}
          title={t("network.alerts")}
          right={status.alerts.length ? <Badge tone="danger">{i18n.num(status.alerts.length)}</Badge> : undefined}
        />
        {status.alerts.length === 0 ? (
          <Empty icon={<ShieldCheck size={22} />} tone="ok" title={t("network.noAlerts")} desc={t("network.noAlertsDesc")} />
        ) : (
          <div className="stack-sm">
            {status.alerts.map((alert) => (
              <div className={`network-alert ${alert.severity}`} key={alert.id}>
                <ShieldAlert size={19} />
                <div className="grow" style={{ minWidth: 0 }}>
                  <div className="row wrap" style={{ gap: 8 }}>
                    <strong>{alertTitle(alert, t)}</strong>
                    <Badge tone={alert.severity === "malicious" ? "danger" : "warn"}>{alert.process}</Badge>
                    <span className="faint">{dateTime(alert.detectedAt, i18n)}</span>
                  </div>
                  <div className="mono" style={{ marginTop: 5 }}>{endpoint(alert.remoteAddress, alert.remotePort)}</div>
                  {alert.executable && <div className="mono faint ellipsis" title={alert.executable}>{alert.executable}</div>}
                  <ReasonList reasons={alert.reasons} />
                </div>
                <button className="btn btn-ghost btn-icon" title={t("network.dismiss")} aria-label={t("network.dismiss")} onClick={() => dismiss(alert.id)}>
                  <X size={16} />
                </button>
              </div>
            ))}
            {status.alerts.some((alert) => alert.kind === "possible_spyware") && (
              <div className="callout warn"><TriangleAlert size={17} /><div>{t("network.heuristicNotice")}</div></div>
            )}
          </div>
        )}
      </Card>

      <Card style={{ marginTop: 16 }}>
        <CardHeader icon={<Activity size={20} />} title={t("network.connections")} right={<Badge>{i18n.num(status.connections.length)}</Badge>} />
        {connections.length === 0 ? (
          <Empty icon={<Network size={22} />} tone="muted" title={t("network.noConnections")} />
        ) : (
          <div className="network-table">
            <div className="network-head">
              <span />
              <span>{t("network.process")}</span>
              <span>{t("network.endpoint")}</span>
              <span>{t("network.localEndpoint")}</span>
            </div>
            {connections.map((connection, index) => (
              <ConnectionRow key={`${connection.protocol}-${connection.localAddress}-${connection.localPort}-${connection.pid ?? "x"}-${index}`} connection={connection} />
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}
