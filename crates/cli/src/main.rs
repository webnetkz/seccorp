//! `seccom-cli` – command-line scanner built on the SecCorp engine.
//!
//! Exit codes: 0 = no threats, 1 = threats found, 2 = error.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use seccom_engine::quarantine::Quarantine;
use seccom_engine::realtime::RealtimeMonitor;
use seccom_engine::{Engine, HeuristicLevel, ScanControl, ScanEvent, ScanOptions, SignatureDb, Verdict};
use std::io::IsTerminal;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "seccom-cli", version, about = "SecCorp antivirus command-line scanner")]
struct Cli {
    /// Signature directories or files to load (in addition to built-in signatures).
    #[arg(long = "db", global = true)]
    db: Vec<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, ValueEnum)]
enum Level {
    Off,
    Low,
    Normal,
    High,
}

impl From<Level> for HeuristicLevel {
    fn from(l: Level) -> Self {
        match l {
            Level::Off => HeuristicLevel::Off,
            Level::Low => HeuristicLevel::Low,
            Level::Normal => HeuristicLevel::Normal,
            Level::High => HeuristicLevel::High,
        }
    }
}

#[derive(Subcommand)]
enum Command {
    /// Scan files and directories.
    Scan {
        paths: Vec<PathBuf>,
        /// Print results as JSON.
        #[arg(long)]
        json: bool,
        /// Do not unpack archives.
        #[arg(long)]
        no_archives: bool,
        #[arg(long, value_enum, default_value = "normal")]
        heuristics: Level,
        /// Worker threads (0 = automatic).
        #[arg(long, default_value_t = 0)]
        threads: usize,
        /// Exclude a path prefix or `*.ext` (repeatable).
        #[arg(long)]
        exclude: Vec<String>,
        /// Move threats into this quarantine vault.
        #[arg(long)]
        quarantine: Option<PathBuf>,
        /// Skip content analysis for files larger than this (MB).
        #[arg(long, default_value_t = 512)]
        max_size: u64,
        /// Print only threats.
        #[arg(long, short)]
        quiet: bool,
    },
    /// Show information about the loaded signature database.
    Info,
    /// Watch directories and scan new or changed files.
    Watch { paths: Vec<PathBuf> },
    /// Manage a quarantine vault.
    Quarantine {
        #[arg(long)]
        vault: PathBuf,
        #[command(subcommand)]
        action: QuarantineAction,
    },
}

#[derive(Subcommand)]
enum QuarantineAction {
    List,
    Restore { id: String },
    Delete { id: String },
}

struct Style {
    color: bool,
}

impl Style {
    fn paint(&self, code: &str, s: &str) -> String {
        if self.color { format!("\x1b[{code}m{s}\x1b[0m") } else { s.to_string() }
    }
    fn red(&self, s: &str) -> String {
        self.paint("1;31", s)
    }
    fn yellow(&self, s: &str) -> String {
        self.paint("1;33", s)
    }
    fn green(&self, s: &str) -> String {
        self.paint("1;32", s)
    }
    fn dim(&self, s: &str) -> String {
        self.paint("2", s)
    }
}

fn load_engine(dbs: &[PathBuf]) -> Result<Engine> {
    let db = SignatureDb::load_dirs(dbs).context("loading signature database")?;
    for w in db.info().warnings.iter().take(20) {
        eprintln!("warning: {w}");
    }
    Ok(Engine::new(db))
}

fn human_bytes(b: u64) -> String {
    const U: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    format!("{v:.1} {}", U[i])
}

fn main() {
    let code = match run() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e:#}");
            2
        }
    };
    std::process::exit(code);
}

fn run() -> Result<i32> {
    let cli = Cli::parse();
    let style = Style { color: std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none() };
    match cli.command {
        Command::Info => {
            let engine = load_engine(&cli.db)?;
            let info = engine.db_info();
            println!("Engine:           {}", seccom_engine::ENGINE_VERSION);
            println!("Database version: {}", info.version);
            println!("Hash signatures:  {}", info.hash_signatures);
            println!("Body signatures:  {}", info.body_signatures);
            println!("Rules:            {}", info.rules);
            println!("Skipped entries:  {}", info.skipped);
            for s in &info.sources {
                println!("  - {} [{}]: {} signatures", s.name, s.kind, s.signatures);
            }
            Ok(0)
        }
        Command::Scan { paths, json, no_archives, heuristics, threads, exclude, quarantine, max_size, quiet } => {
            if paths.is_empty() {
                anyhow::bail!("nothing to scan: pass one or more paths");
            }
            let engine = load_engine(&cli.db)?;
            let opts = ScanOptions {
                scan_archives: !no_archives,
                heuristics: heuristics.into(),
                threads,
                exclusions: exclude,
                max_file_size: max_size * 1024 * 1024,
                use_cache: false,
                ..Default::default()
            };
            let vault = quarantine.as_deref().map(Quarantine::open).transpose().context("opening quarantine")?;
            let control = ScanControl::new();
            let started = std::time::Instant::now();
            let summary = engine.scan_paths(&paths, &opts, &control, None, &|event| {
                if json {
                    return;
                }
                match event {
                    ScanEvent::Threat(v) => {
                        let d = v.primary_detection();
                        let label = match v.verdict {
                            Verdict::Malicious => style.red("FOUND     "),
                            _ => style.yellow("SUSPICIOUS"),
                        };
                        println!(
                            "{label} {}  {}{}",
                            v.path,
                            d.map(|d| d.name.as_str()).unwrap_or("?"),
                            d.and_then(|d| d.location.as_ref()).map(|l| style.dim(&format!("  [{l}]"))).unwrap_or_default()
                        );
                    }
                    ScanEvent::Error { path, message } => {
                        if !quiet {
                            eprintln!("{} {path}: {message}", style.dim("skip"));
                        }
                    }
                }
            });

            let mut quarantined = 0;
            if let Some(vault) = &vault {
                for t in &summary.threats {
                    match vault.add(std::path::Path::new(&t.path), t.threat_name().unwrap_or("Unknown")) {
                        Ok(item) => {
                            quarantined += 1;
                            if !json {
                                println!("{} {} -> {}", style.green("quarantined"), t.path, item.id);
                            }
                        }
                        Err(e) => eprintln!("cannot quarantine {}: {e}", t.path),
                    }
                }
            }

            if json {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                let secs = started.elapsed().as_secs_f64();
                println!();
                println!("Scanned:     {} files ({})", summary.files_scanned, human_bytes(summary.bytes_scanned));
                println!(
                    "Threats:     {}",
                    if summary.threats.is_empty() { style.green("0") } else { style.red(&summary.threats.len().to_string()) }
                );
                if quarantined > 0 {
                    println!("Quarantined: {quarantined}");
                }
                println!("Skipped:     {}  Errors: {}", summary.files_skipped, summary.errors);
                println!("Time:        {secs:.1}s ({:.0} files/s)", summary.files_scanned as f64 / secs.max(0.001));
            }
            Ok(if summary.threats.is_empty() { 0 } else { 1 })
        }
        Command::Watch { paths } => {
            let engine = Arc::new(load_engine(&cli.db)?);
            let color = style.color;
            let mon = RealtimeMonitor::start(
                engine,
                &paths,
                ScanOptions::default(),
                vec![],
                Arc::new(move |v| {
                    let s = Style { color };
                    if v.is_threat() {
                        println!("{} {} {}", s.red("THREAT"), v.path, v.threat_name().unwrap_or("?"));
                    } else {
                        println!("{} {}", s.dim("ok    "), v.path);
                    }
                }),
            )?;
            for p in mon.watched() {
                println!("watching {}", p.display());
            }
            println!("press Ctrl+C to stop");
            loop {
                std::thread::sleep(std::time::Duration::from_secs(3600));
            }
        }
        Command::Quarantine { vault, action } => {
            let q = Quarantine::open(&vault)?;
            match action {
                QuarantineAction::List => {
                    for i in q.list()? {
                        println!("{}  {}  {}  {}", i.id, i.threat, human_bytes(i.size), i.original_path);
                    }
                }
                QuarantineAction::Restore { id } => println!("restored to {}", q.restore(&id, None)?.display()),
                QuarantineAction::Delete { id } => {
                    q.delete(&id)?;
                    println!("deleted {id}");
                }
            }
            Ok(0)
        }
    }
}
