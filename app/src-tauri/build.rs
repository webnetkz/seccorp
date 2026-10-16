fn main() {
    // The update signing key is compiled in; rebuild when it changes.
    println!("cargo:rerun-if-env-changed=SECCOM_UPDATE_PUBKEY");
    println!("cargo:rerun-if-env-changed=SECCOM_UPDATE_URL");
    tauri_build::build()
}
