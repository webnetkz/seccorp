//! Integration tests for parallel directory scanning.

use seccom_engine::cache::ScanCache;
use seccom_engine::{Engine, ScanControl, ScanEvent, ScanOptions, Verdict};
use std::path::PathBuf;
use std::sync::Mutex;

fn eicar() -> Vec<u8> {
    "*H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE$}7)CC7)^P(45XZP\\4[PA@%P!O5X".bytes().rev().collect()
}

fn make_tree() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    for i in 0..200 {
        let sub = root.join(format!("d{}", i % 10));
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join(format!("file{i}.txt")), format!("ordinary content {i}\n")).unwrap();
    }
    std::fs::write(root.join("d3").join("test.com"), eicar()).unwrap();
    std::fs::create_dir_all(root.join("excluded")).unwrap();
    std::fs::write(root.join("excluded").join("also.com"), eicar()).unwrap();
    dir
}

#[test]
fn scans_tree_with_exclusions_and_cache() {
    let dir = make_tree();
    let engine = Engine::with_builtin();
    let opts =
        ScanOptions { exclusions: vec![dir.path().join("excluded").to_string_lossy().into_owned()], threads: 4, ..Default::default() };
    let cache = ScanCache::in_memory("test");
    let events = Mutex::new(Vec::new());
    let control = ScanControl::new();
    let summary = engine.scan_paths(&[dir.path().to_path_buf()], &opts, &control, Some(&cache), &|e| {
        if let ScanEvent::Threat(v) = e {
            events.lock().unwrap().push(v.path);
        }
    });
    assert_eq!(summary.files_scanned, 201);
    assert_eq!(summary.threats.len(), 1);
    assert_eq!(summary.threats[0].verdict, Verdict::Malicious);
    assert!(summary.threats[0].path.ends_with("test.com"));
    assert_eq!(events.lock().unwrap().len(), 1);
    assert!(!summary.cancelled);
    let p = control.progress();
    assert!(p.walk_done);
    assert_eq!(p.files_discovered, 201);

    // Second run: clean files come from the cache, the threat is re-scanned.
    let control2 = ScanControl::new();
    let summary2 = engine.scan_paths(&[dir.path().to_path_buf()], &opts, &control2, Some(&cache), &|_| {});
    assert_eq!(summary2.files_cached, 200);
    assert_eq!(summary2.threats.len(), 1);
}

#[test]
fn cancel_and_pause() {
    let dir = make_tree();
    let engine = Engine::with_builtin();
    let opts = ScanOptions { threads: 2, use_cache: false, ..Default::default() };

    // Cancel before start: nothing is scanned.
    let control = ScanControl::new();
    control.cancel();
    let s = engine.scan_paths(&[dir.path().to_path_buf()], &opts, &control, None, &|_| {});
    assert!(s.cancelled);
    assert!(s.files_scanned <= 2);

    // Pause, then resume from another thread.
    let control = std::sync::Arc::new(ScanControl::new());
    control.pause();
    let c2 = control.clone();
    let t = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(c2.progress().paused);
        assert_eq!(c2.progress().files_scanned, 0);
        c2.resume();
    });
    let roots: Vec<PathBuf> = vec![dir.path().to_path_buf()];
    let s = engine.scan_paths(&roots, &opts, &control, None, &|_| {});
    t.join().unwrap();
    assert_eq!(s.files_scanned, 202);
    assert_eq!(s.threats.len(), 2);
}

#[test]
fn overlapping_roots_scan_each_file_once() {
    let dir = make_tree();
    let engine = Engine::with_builtin();
    let opts =
        ScanOptions { exclusions: vec![dir.path().join("excluded").to_string_lossy().into_owned()], threads: 2, ..Default::default() };
    let root = dir.path().to_path_buf();
    // Same tree reached through several roots: itself, a sub-folder, a file inside it,
    // a duplicate spelled with a trailing separator.
    let roots = vec![root.join("d3"), root.clone(), root.join("d3").join("test.com"), PathBuf::from(format!("{}/", root.display()))];
    let control = ScanControl::new();
    let summary = engine.scan_paths(&roots, &opts, &control, None, &|_| {});
    assert_eq!(summary.files_scanned, 201);
    assert_eq!(summary.threats.len(), 1);
    assert_eq!(summary.roots.len(), 1);
}

#[test]
fn normalize_roots_keeps_order_and_drops_nested() {
    use seccom_engine::scanner::normalize_roots;
    let r = normalize_roots(&[
        PathBuf::from("/home/u/Downloads"),
        PathBuf::from("/tmp"),
        PathBuf::from("/tmp/x/app.bin"),
        PathBuf::from("/home/u/Downloads/"),
        PathBuf::from("/home/u/Desktop"),
        PathBuf::from("/tmpfiles"),
    ]);
    assert_eq!(
        r,
        vec![PathBuf::from("/home/u/Downloads"), PathBuf::from("/tmp"), PathBuf::from("/home/u/Desktop"), PathBuf::from("/tmpfiles"),]
    );
}
