//! Prepare a signed, versioned ClamAV-derived database feed for SecCorp.

use seccom_engine::sigdb::{DbLoader, DbManifest, clamav::read_cvd_header};
use seccom_engine::update::{build_index, create_bundle, generate_keypair};
use seccom_engine::util::now_unix;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

fn main() {
    if let Err(err) = run() {
        eprintln!("seccom-feed: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    match args.next().and_then(|s| s.into_string().ok()).as_deref() {
        Some("keygen") => {
            let path = PathBuf::from(args.next().ok_or("usage: seccom-feed keygen <private-seed-file>")?);
            if args.next().is_some() {
                return Err("usage: seccom-feed keygen <private-seed-file>".into());
            }
            let (seed, public) = generate_keypair()?;
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(path)?;
            writeln!(file, "{}", hex::encode(seed))?;
            file.sync_all()?;
            println!("{}", hex::encode(public));
        }
        Some("prepare") => {
            let db_dir = PathBuf::from(args.next().ok_or("usage: seccom-feed prepare <clamav-db-dir> <output-dir>")?);
            let output_dir = PathBuf::from(args.next().ok_or("usage: seccom-feed prepare <clamav-db-dir> <output-dir>")?);
            if args.next().is_some() {
                return Err("usage: seccom-feed prepare <clamav-db-dir> <output-dir>".into());
            }
            prepare(&db_dir, &output_dir)?;
        }
        _ => return Err("usage: seccom-feed <keygen|prepare> ...".into()),
    }
    Ok(())
}

fn prepare(db_dir: &Path, output_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let seed_text = std::env::var("SECCOM_UPDATE_SIGNING_SEED")?;
    let decoded = hex::decode(seed_text.trim())?;
    let seed: [u8; 32] = decoded.try_into().map_err(|_| "SECCOM_UPDATE_SIGNING_SEED must be 64 hex characters")?;
    let asset_base = std::env::var("SECCOM_UPDATE_ASSET_BASE_URL")?;
    let asset_base = asset_base.trim_end_matches('/');

    let mut sources = Vec::new();
    for stem in ["main", "daily", "bytecode"] {
        let source = ["cvd", "cld"]
            .into_iter()
            .map(|ext| db_dir.join(format!("{stem}.{ext}")))
            .find(|p| p.is_file())
            .ok_or_else(|| format!("FreshClam did not provide {stem}.cvd or {stem}.cld in {}", db_dir.display()))?;
        let bytes = fs::read(&source)?;
        let header = read_cvd_header(&bytes)?;
        sources.push((stem, source, bytes, header));
    }

    let version = format!("clamav-{}-{}-{}", sources[0].3.version, sources[1].3.version, sources[2].3.version);
    if sources.iter().any(|(_, _, _, h)| h.version == 0) {
        return Err("one or more ClamAV database headers have an invalid version".into());
    }

    let nonce = uuid::Uuid::new_v4().simple().to_string();
    let staged = std::env::temp_dir().join(format!("seccom-feed-{nonce}"));
    fs::create_dir_all(&staged)?;
    let stage_result = (|| -> Result<(), Box<dyn std::error::Error>> {
        for (stem, source, _, _) in &sources {
            let extension = source.extension().and_then(|s| s.to_str()).ok_or("invalid database filename")?;
            fs::copy(source, staged.join(format!("{stem}.{extension}")))?;
        }

        let mut loader = DbLoader::new(false);
        loader.add_path(&staged)?;
        let info = loader.build().info().clone();
        if info.total_signatures() == 0 {
            return Err("ClamAV data produced no signatures supported by SecCorp".into());
        }

        let released = now_unix();
        let manifest = DbManifest {
            name: "ClamAV signatures (SecCorp-supported formats)".into(),
            version: version.clone(),
            released,
            min_engine: None,
        };
        fs::write(staged.join("manifest.json"), serde_json::to_vec_pretty(&manifest)?)?;
        let bundle = create_bundle(&staged, &manifest)?;
        let bundle_name = format!("seccom-db-{version}.tar.gz");
        let bundle_path = output_dir.join(&bundle_name);
        fs::create_dir_all(output_dir)?;
        fs::write(&bundle_path, &bundle)?;
        let index = build_index(&bundle, &manifest, &format!("{asset_base}/{bundle_name}"), &seed);
        fs::write(output_dir.join("update.json"), serde_json::to_vec_pretty(&index)?)?;
        println!(
            "Prepared {version}: {} hash + {} body signatures; {} skipped; {} bytes",
            info.hash_signatures,
            info.body_signatures,
            info.skipped,
            bundle.len()
        );
        Ok(())
    })();
    let _ = fs::remove_dir_all(&staged);
    stage_result
}
