//! Executables of running processes (desktop quick scan).

use std::collections::BTreeSet;
use std::path::PathBuf;
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

pub fn running_executables() -> Vec<PathBuf> {
    let mut sys = System::new();
    sys.refresh_processes_specifics(ProcessesToUpdate::All, true, ProcessRefreshKind::nothing().with_exe(UpdateKind::OnlyIfNotSet));
    let exes: BTreeSet<PathBuf> =
        sys.processes().values().filter_map(|p| p.exe().map(|e| e.to_path_buf())).filter(|p| p.is_file()).collect();
    exes.into_iter().collect()
}
