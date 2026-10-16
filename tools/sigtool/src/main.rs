//! `sigtool` – build, sign and verify SecCorp signature database updates.
//!
//! Typical release flow:
//!
//! ```text
//! sigtool keygen --out keys/                      # once; keep update_signing.key secret
//! sigtool build --input signatures/ --version 2026.10.13.1 --key keys/update_signing.key --out dist/
//! # upload dist/seccom-db-2026.10.13.1.tar.gz and dist/update.json to your update server
//! ```

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use seccom_engine::sigdb::{DbLoader, DbManifest};
use seccom_engine::update::{self, UpdateIndex};
use seccom_engine::{Engine, ScanOptions};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "sigtool", version, about = "SecCorp signature database tool")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate an Ed25519 key pair for signing updates.
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    /// Package and sign a signature directory.
    Build {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        version: String,
        /// Private key file created by `keygen`.
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value = "SecCorp signatures")]
        name: String,
        /// Minimal engine version required by this database.
        #[arg(long)]
        min_engine: Option<String>,
        /// Base URL where the bundle will be hosted (default: relative URL).
        #[arg(long)]
        url_base: Option<String>,
    },
    /// Verify a bundle against update.json and a public key.
    Verify {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        index: PathBuf,
        /// Public key as hex or a path to a .pub file.
        #[arg(long)]
        pubkey: String,
    },
    /// Load signature sources and print statistics / warnings.
    Stats { inputs: Vec<PathBuf> },
    /// Scan files using only the given signature sources.
    Test {
        #[arg(long)]
        input: Vec<PathBuf>,
        files: Vec<PathBuf>,
    },
}

fn read_key_file(path: &Path) -> Result<[u8; 32]> {
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut key = [0u8; 32];
    hex::decode_to_slice(text.trim(), &mut key).context("key file must contain 64 hex characters")?;
    Ok(key)
}

fn write_secret(path: &Path, content: &str) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("creating {}", path.display()))?;
        f.write_all(content.as_bytes())?;
    }
    #[cfg(not(unix))]
    {
        if path.exists() {
            bail!("{} already exists", path.display());
        }
        std::fs::write(path, content)?;
    }
    Ok(())
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Keygen { out } => {
            std::fs::create_dir_all(&out)?;
            let secret_path = out.join("update_signing.key");
            let public_path = out.join("update_signing.pub");
            if secret_path.exists() || public_path.exists() {
                bail!("keys already exist in {} – refusing to overwrite", out.display());
            }
            let (secret, public) = update::generate_keypair()?;
            write_secret(&secret_path, &hex::encode(secret))?;
            std::fs::write(&public_path, hex::encode(public))?;
            println!("Private key: {}  (keep it secret, never commit it)", secret_path.display());
            println!("Public key:  {}", public_path.display());
            println!("Embed the public key at build time:  SECCOM_UPDATE_PUBKEY=$(cat {})", public_path.display());
        }
        Command::Build { input, version, key, out, name, min_engine, url_base } => {
            let secret = read_key_file(&key)?;
            // Validate before packaging.
            let mut loader = DbLoader::new(false);
            loader.add_path(&input)?;
            let db = loader.build();
            let info = db.info();
            if info.total_signatures() == 0 {
                bail!("no signatures found in {}", input.display());
            }
            for w in info.warnings.iter().take(50) {
                eprintln!("warning: {w}");
            }
            let released = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
            let manifest = DbManifest { name, version: version.clone(), released, min_engine };
            let bundle = update::create_bundle(&input, &manifest)?;
            std::fs::create_dir_all(&out)?;
            let file_name = format!("seccom-db-{version}.tar.gz");
            let url = match url_base {
                Some(base) => format!("{}/{}", base.trim_end_matches('/'), file_name),
                None => file_name.clone(),
            };
            let index = update::build_index(&bundle, &manifest, &url, &secret);
            std::fs::write(out.join(&file_name), &bundle)?;
            std::fs::write(out.join("update.json"), serde_json::to_vec_pretty(&index)?)?;
            println!("Bundle:   {} ({} bytes)", out.join(&file_name).display(), bundle.len());
            println!("Index:    {}", out.join("update.json").display());
            println!("SHA-256:  {}", index.sha256);
            println!("Contents: {} hash, {} body signatures, {} rules", info.hash_signatures, info.body_signatures, info.rules);
        }
        Command::Verify { bundle, index, pubkey } => {
            let key_hex = if Path::new(&pubkey).exists() { std::fs::read_to_string(&pubkey)? } else { pubkey };
            let key = update::parse_public_key(&key_hex)?;
            let bytes = std::fs::read(&bundle)?;
            let idx: UpdateIndex = serde_json::from_slice(&std::fs::read(&index)?)?;
            update::verify_bundle(&bytes, &idx, &key)?;
            println!("OK: {} version {} is authentic", bundle.display(), idx.version);
        }
        Command::Stats { inputs } => {
            let mut loader = DbLoader::new(true);
            for i in &inputs {
                loader.add_path(i)?;
            }
            let t = std::time::Instant::now();
            let db = loader.build();
            let info = db.info();
            println!("Version:          {}", info.version);
            println!("Hash signatures:  {}", info.hash_signatures);
            println!("Body signatures:  {}", info.body_signatures);
            println!("Rules:            {}", info.rules);
            println!("Skipped entries:  {}", info.skipped);
            println!("Load time:        {:.2}s", t.elapsed().as_secs_f64());
            for s in &info.sources {
                println!("  - {} [{}]: {} (+{} skipped)", s.name, s.kind, s.signatures, s.skipped);
            }
            for w in &info.warnings {
                println!("warning: {w}");
            }
        }
        Command::Test { input, files } => {
            let mut loader = DbLoader::new(true);
            for i in &input {
                loader.add_path(i)?;
            }
            let engine = Engine::new(loader.build());
            let opts = ScanOptions::default();
            for f in files {
                let v = engine.scan_file(&f, &opts);
                println!("{:?}\t{}\t{}", v.verdict, f.display(), v.threat_name().unwrap_or("-"));
            }
        }
    }
    Ok(())
}
