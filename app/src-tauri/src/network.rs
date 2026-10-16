//! Local network protection: socket inventory, C2 indicator matching and
//! conservative process/persistence correlation. Connection metadata never
//! leaves the device; only the public indicator list is downloaded.

use crate::model::{NetworkAlert, NetworkConnection, NetworkStatus};
use crate::state::AppState;
use seccom_engine::util::now_unix;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Emitter, Manager};

const FEODO_IP_BLOCKLIST: &str = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt";
const INTEL_MAX_AGE: Duration = Duration::from_secs(30 * 60);
const MONITOR_INTERVAL: Duration = Duration::from_secs(30);
const MAX_CONNECTIONS: usize = 2_000;
const MAX_ALERTS: usize = 200;

pub struct NetworkProtection {
    snapshot: Mutex<NetworkStatus>,
    stop: Mutex<Option<Arc<AtomicBool>>>,
    scanning: AtomicBool,
    dismissed: Mutex<HashSet<String>>,
}

impl Default for NetworkProtection {
    fn default() -> Self {
        Self {
            snapshot: Mutex::new(NetworkStatus {
                supported: cfg!(desktop),
                enabled: cfg!(desktop),
                running: false,
                scanning: false,
                last_scan_at: None,
                active_connections: 0,
                listening_ports: 0,
                indicator_count: 0,
                intelligence_updated_at: None,
                connections: Vec::new(),
                alerts: Vec::new(),
                error: None,
            }),
            stop: Mutex::new(None),
            scanning: AtomicBool::new(false),
            dismissed: Mutex::new(HashSet::new()),
        }
    }
}

pub fn status(app: &AppHandle) -> NetworkStatus {
    let state = app.state::<AppState>();
    let mut result = state.network.snapshot.lock().unwrap_or_else(|e| e.into_inner()).clone();
    result.supported = cfg!(desktop);
    result.enabled = cfg!(desktop) && state.settings().network_monitor_enabled;
    result.scanning = state.network.scanning.load(Ordering::Relaxed);
    result
}

/// Restarts the monitor after a settings change.
pub fn apply(app: &AppHandle) {
    let state = app.state::<AppState>();
    if let Some(old) = state.network.stop.lock().unwrap_or_else(|e| e.into_inner()).take() {
        old.store(true, Ordering::Relaxed);
    }

    let enabled = cfg!(desktop) && state.settings().network_monitor_enabled;
    {
        let mut snapshot = state.network.snapshot.lock().unwrap_or_else(|e| e.into_inner());
        snapshot.supported = cfg!(desktop);
        snapshot.enabled = enabled;
        snapshot.running = enabled;
        if !enabled {
            snapshot.scanning = false;
            snapshot.error = None;
        }
    }
    let _ = app.emit("network://updated", status(app));
    if !enabled {
        return;
    }

    let stop = Arc::new(AtomicBool::new(false));
    *state.network.stop.lock().unwrap_or_else(|e| e.into_inner()) = Some(stop.clone());
    let handle = app.clone();
    let _ = std::thread::Builder::new().name("seccorp-network".into()).spawn(move || {
        loop {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            if let Err(e) = scan_once(&handle) {
                set_error(&handle, e);
            }
            for _ in 0..MONITOR_INTERVAL.as_secs() {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    });
}

pub fn scan_now(app: &AppHandle) -> Result<NetworkStatus, String> {
    if !cfg!(desktop) {
        return Ok(status(app));
    }
    scan_once(app)?;
    Ok(status(app))
}

pub fn dismiss_alert(app: &AppHandle, id: &str) -> NetworkStatus {
    let state = app.state::<AppState>();
    state.network.dismissed.lock().unwrap_or_else(|e| e.into_inner()).insert(id.to_string());
    state.network.snapshot.lock().unwrap_or_else(|e| e.into_inner()).alerts.retain(|a| a.id != id);
    let result = status(app);
    let _ = app.emit("network://updated", &result);
    let _ = app.emit("status://changed", ());
    result
}

fn set_error(app: &AppHandle, error: String) {
    let state = app.state::<AppState>();
    let mut snapshot = state.network.snapshot.lock().unwrap_or_else(|e| e.into_inner());
    snapshot.running = state.settings().network_monitor_enabled;
    snapshot.scanning = false;
    snapshot.error = Some(error);
    drop(snapshot);
    let _ = app.emit("network://updated", status(app));
    let _ = app.emit("status://changed", ());
}

fn scan_once(app: &AppHandle) -> Result<(), String> {
    let state = app.state::<AppState>();
    if state.network.scanning.swap(true, Ordering::AcqRel) {
        return Ok(());
    }
    {
        let mut snapshot = state.network.snapshot.lock().unwrap_or_else(|e| e.into_inner());
        snapshot.scanning = true;
        snapshot.error = None;
    }
    let _ = app.emit("network://updated", status(app));

    let result = perform_scan(app);
    state.network.scanning.store(false, Ordering::Release);
    if result.is_err() {
        state.network.snapshot.lock().unwrap_or_else(|e| e.into_inner()).scanning = false;
    }
    result
}

#[cfg(desktop)]
fn perform_scan(app: &AppHandle) -> Result<(), String> {
    use netstat2::{AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, TcpState, get_sockets_info};
    use std::collections::HashMap;
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

    let state = app.state::<AppState>();
    let settings = state.settings();
    let intel_error = if settings.network_threat_intel { update_intelligence(&state).err() } else { None };
    let indicators = if settings.network_threat_intel { load_indicators(&state.paths.network_intel) } else { HashSet::new() };
    let intel_updated = modified_unix(&state.paths.network_intel);

    let sockets = get_sockets_info(AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6, ProtocolFlags::TCP | ProtocolFlags::UDP)
        .map_err(|e| format!("cannot inspect network sockets: {e}"))?;

    let mut system = System::new();
    system.refresh_processes_specifics(ProcessesToUpdate::All, true, ProcessRefreshKind::nothing().with_exe(UpdateKind::OnlyIfNotSet));
    let processes: HashMap<u32, (String, Option<String>)> = system
        .processes()
        .iter()
        .map(|(pid, process)| {
            (pid.as_u32(), (process.name().to_string_lossy().into_owned(), process.exe().map(|p| p.to_string_lossy().into_owned())))
        })
        .collect();

    let startup = crate::platform::startup_items();
    let startup_text: Vec<String> =
        startup.iter().flat_map(|item| [item.command.to_lowercase(), item.path.clone().unwrap_or_default().to_lowercase()]).collect();
    let mut scanned_executables: HashMap<String, Option<String>> = HashMap::new();
    let mut connections = Vec::new();
    let mut new_alerts = Vec::new();
    let mut active_connections = 0usize;
    let mut listening_ports = 0usize;

    for socket in sockets {
        let pid = socket.associated_pids.first().copied();
        let (process, executable) = pid.and_then(|p| processes.get(&p).cloned()).unwrap_or_else(|| ("Unknown".into(), None));
        let persisted = executable.as_ref().is_some_and(|exe| {
            let needle = exe.to_lowercase();
            startup_text.iter().any(|entry| !needle.is_empty() && entry.contains(&needle))
        });

        let (protocol, local_addr, local_port, remote_addr, remote_port, socket_state, connected, listening) = match socket
            .protocol_socket_info
        {
            ProtocolSocketInfo::Tcp(tcp) => {
                let connected = tcp.state == TcpState::Established;
                let listening = tcp.state == TcpState::Listen;
                (
                    "TCP".to_string(),
                    tcp.local_addr,
                    tcp.local_port,
                    (tcp.remote_port > 0).then_some(tcp.remote_addr),
                    (tcp.remote_port > 0).then_some(tcp.remote_port),
                    tcp.state.to_string(),
                    connected,
                    listening,
                )
            }
            ProtocolSocketInfo::Udp(udp) => ("UDP".to_string(), udp.local_addr, udp.local_port, None, None, "BOUND".into(), false, true),
        };
        if connected {
            active_connections += 1;
        }
        if listening {
            listening_ports += 1;
        }

        let mut reasons = Vec::new();
        let known_c2 = remote_addr.is_some_and(|ip| indicators.contains(&ip));
        if known_c2 {
            reasons.push("known_c2".into());
        }

        let suspicious_location = executable.as_deref().is_some_and(is_suspicious_executable_path);
        let risky_port = remote_port.is_some_and(is_risky_remote_port);
        if settings.network_spyware_heuristics {
            if suspicious_location {
                reasons.push("suspicious_location".into());
            }
            if persisted {
                reasons.push("startup_persistence".into());
            }
            if risky_port {
                reasons.push("risky_port".into());
            }
        }

        let public_remote = remote_addr.is_some_and(is_public_remote);
        let mut infected_name = None;
        let heuristic_score = u32::from(suspicious_location) * 35 + u32::from(persisted) * 30 + u32::from(risky_port) * 20;
        if public_remote
            && heuristic_score >= 35
            && let Some(exe) = executable.as_ref()
        {
            infected_name = scanned_executables
                .entry(exe.clone())
                .or_insert_with(|| {
                    let verdict = state.engine.scan_file(std::path::Path::new(exe), &state.scan_options());
                    (verdict.verdict == seccom_engine::Verdict::Malicious)
                        .then(|| verdict.threat_name().unwrap_or("known malware").to_string())
                })
                .clone();
            if infected_name.is_some() {
                reasons.push("infected_executable".into());
            }
        }

        let possible_spyware = settings.network_spyware_heuristics && public_remote && connected && heuristic_score >= 60;
        let verdict = if known_c2 || infected_name.is_some() {
            "malicious"
        } else if possible_spyware {
            "suspicious"
        } else {
            "clean"
        };

        if verdict != "clean" {
            let kind = if known_c2 {
                "known_c2"
            } else if infected_name.is_some() {
                "infected_process"
            } else {
                "possible_spyware"
            };
            new_alerts.push(NetworkAlert {
                id: alert_id(kind, pid, executable.as_deref(), remote_addr, remote_port),
                detected_at: now_unix(),
                severity: verdict.into(),
                kind: kind.into(),
                process: process.clone(),
                executable: executable.clone(),
                remote_address: remote_addr.map(|ip| ip.to_string()),
                remote_port,
                reasons: reasons.clone(),
            });
        }

        connections.push(NetworkConnection {
            protocol,
            local_address: local_addr.to_string(),
            local_port,
            remote_address: remote_addr.map(|ip| ip.to_string()),
            remote_port,
            state: socket_state,
            pid,
            process,
            executable,
            verdict: verdict.into(),
            reasons,
        });
    }

    connections.sort_by_key(|c| match c.verdict.as_str() {
        "malicious" => 0,
        "suspicious" => 1,
        _ if c.remote_address.is_some() => 2,
        _ => 3,
    });
    connections.truncate(MAX_CONNECTIONS);

    let dismissed = state.network.dismissed.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let mut snapshot = state.network.snapshot.lock().unwrap_or_else(|e| e.into_inner());
    let existing: HashSet<String> = snapshot.alerts.iter().map(|a| a.id.clone()).collect();
    let genuinely_new: Vec<NetworkAlert> =
        new_alerts.into_iter().filter(|alert| !existing.contains(&alert.id) && !dismissed.contains(&alert.id)).collect();
    for alert in genuinely_new.iter().rev() {
        snapshot.alerts.insert(0, alert.clone());
    }
    snapshot.alerts.truncate(MAX_ALERTS);
    snapshot.supported = true;
    snapshot.enabled = settings.network_monitor_enabled;
    snapshot.running = settings.network_monitor_enabled;
    snapshot.scanning = false;
    snapshot.last_scan_at = Some(now_unix());
    snapshot.active_connections = active_connections;
    snapshot.listening_ports = listening_ports;
    snapshot.indicator_count = indicators.len();
    snapshot.intelligence_updated_at = intel_updated;
    snapshot.connections = connections;
    snapshot.error = intel_error;
    drop(snapshot);

    for alert in &genuinely_new {
        let _ = app.emit("network://alert", alert);
    }
    if let Some(alert) = genuinely_new.first() {
        let ru = crate::i18n::lang(&state) == "ru";
        let title = if ru { "Сетевая угроза обнаружена" } else { "Network threat detected" };
        let body = if alert.kind == "known_c2" {
            if ru {
                "Соединение с известным сервером управления вредоносным ПО"
            } else {
                "Connection to a known malware command server"
            }
        } else if ru {
            "Обнаружен процесс с подозрительной сетевой активностью"
        } else {
            "A process with suspicious network activity was detected"
        };
        crate::notify::notify(app, title, body);
    }
    let _ = app.emit("network://updated", status(app));
    let _ = app.emit("status://changed", ());
    Ok(())
}

#[cfg(not(desktop))]
fn perform_scan(_app: &AppHandle) -> Result<(), String> {
    Ok(())
}

fn alert_id(kind: &str, pid: Option<u32>, executable: Option<&str>, remote: Option<IpAddr>, port: Option<u16>) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    kind.hash(&mut hasher);
    pid.hash(&mut hasher);
    executable.hash(&mut hasher);
    remote.hash(&mut hasher);
    port.hash(&mut hasher);
    format!("network-{:016x}", hasher.finish())
}

fn is_risky_remote_port(port: u16) -> bool {
    matches!(port, 1337 | 4444 | 5555 | 6666 | 6667 | 9001 | 9050 | 31337)
}

fn is_suspicious_executable_path(path: &str) -> bool {
    let p = path.replace('\\', "/").to_lowercase();
    p.starts_with("/tmp/")
        || p.starts_with("/private/tmp/")
        || p.starts_with("/var/tmp/")
        || p.contains("/appdata/local/temp/")
        || p.contains("/downloads/")
        || p.contains("/download/")
        || p.split('/').any(|part| part.starts_with('.') && part.len() > 1 && part != ".app")
}

fn is_public_remote(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_multicast()
                || o[0] == 0
                || o[0] >= 224
                || (o[0] == 100 && (64..=127).contains(&o[1]))
                || (o[0] == 192 && o[1] == 0 && o[2] == 2)
                || (o[0] == 198 && o[1] == 51 && o[2] == 100)
                || (o[0] == 203 && o[1] == 0 && o[2] == 113))
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                || (s[0] == 0x2001 && s[1] == 0x0db8))
        }
    }
}

fn load_indicators(path: &std::path::Path) -> HashSet<IpAddr> {
    std::fs::read_to_string(path).map(|text| parse_indicators(&text)).unwrap_or_default()
}

fn parse_indicators(text: &str) -> HashSet<IpAddr> {
    text.lines()
        .filter_map(|line| line.split('#').next())
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter_map(|line| line.parse::<IpAddr>().ok())
        .collect()
}

fn modified_unix(path: &std::path::Path) -> Option<u64> {
    path.metadata().ok()?.modified().ok()?.duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs())
}

fn intelligence_is_fresh(path: &std::path::Path) -> bool {
    path.metadata()
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|m| SystemTime::now().duration_since(m).ok())
        .is_some_and(|age| age <= INTEL_MAX_AGE)
}

#[cfg(feature = "online-update")]
fn update_intelligence(state: &AppState) -> Result<(), String> {
    if intelligence_is_fresh(&state.paths.network_intel) {
        return Ok(());
    }
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(15)))
        .user_agent(concat!("SecCorp/", env!("CARGO_PKG_VERSION")))
        .build()
        .new_agent();
    let mut response = agent.get(FEODO_IP_BLOCKLIST).call().map_err(|e| format!("cannot update C2 indicators: {e}"))?;
    let text =
        response.body_mut().with_config().limit(5 * 1024 * 1024).read_to_string().map_err(|e| format!("cannot read C2 indicators: {e}"))?;
    let parsed = parse_indicators(&text);
    if parsed.is_empty() {
        return Err("C2 indicator update was empty".into());
    }
    if let Some(parent) = state.paths.network_intel.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let tmp = state.paths.network_intel.with_extension("txt.tmp");
    std::fs::write(&tmp, text).map_err(|e| e.to_string())?;
    std::fs::rename(tmp, &state.paths.network_intel).map_err(|e| e.to_string())
}

#[cfg(not(feature = "online-update"))]
fn update_intelligence(_state: &AppState) -> Result<(), String> {
    Err("online network intelligence updates are disabled".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_ip_blocklist_and_comments() {
        let set = parse_indicators("# comment\n1.2.3.4\n2001:db8::1 # label\ninvalid\n");
        assert!(set.contains(&"1.2.3.4".parse().unwrap()));
        assert!(set.contains(&"2001:db8::1".parse().unwrap()));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn distinguishes_public_and_local_addresses() {
        assert!(is_public_remote("8.8.8.8".parse().unwrap()));
        assert!(!is_public_remote("127.0.0.1".parse().unwrap()));
        assert!(!is_public_remote("192.168.1.2".parse().unwrap()));
        assert!(!is_public_remote("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn recognizes_untrusted_process_locations() {
        assert!(is_suspicious_executable_path("/private/tmp/.agent/run"));
        assert!(is_suspicious_executable_path("C:\\Users\\me\\Downloads\\tool.exe"));
        assert!(!is_suspicious_executable_path("/Applications/Safari.app/Contents/MacOS/Safari"));
    }
}
