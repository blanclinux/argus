use std::env;

fn main() {
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "windows" {
        return;
    }
    let mut res = winres::WindowsResource::new();
    res.set_manifest_file("app.manifest");
    // Icon embedding is optional; skip to keep cross-builds robust.

    if let Err(e) = res.compile() {
        // Icon may be missing in dev; manifest is the critical part.
        eprintln!("winres: {e}");
    }
}
