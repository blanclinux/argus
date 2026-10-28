use anyhow::Result;
use std::process::Command;

fn get_euid() -> Option<u32> {
    // Read /proc/self/status and parse the Uid line: real effective saved fs
    std::fs::read_to_string("/proc/self/status").ok().and_then(|content| {
        content.lines().find_map(|line| {
            if let Some(rest) = line.strip_prefix("Uid:") {
                let parts: Vec<&str> = rest.split_whitespace().collect();
                parts.get(1).and_then(|p| p.trim().parse::<u32>().ok())
            } else {
                None
            }
        })
    })
}

pub fn is_elevated() -> bool {
    get_euid() == Some(0)
}

pub fn ensure_elevated() -> Result<()> {
    if is_elevated() {
        return Ok(());
    }

    // Try pkexec first (GUI password prompt), then sudo.
    let exe = std::env::current_exe()?;
    let args: Vec<String> = std::env::args().skip(1).collect();

    if let Ok(status) = Command::new("pkexec").arg(&exe).args(&args).status() {
        if status.success() {
            std::process::exit(0);
        }
    }

    if let Ok(status) = Command::new("sudo").arg(&exe).args(&args).status() {
        if status.success() {
            std::process::exit(0);
        }
    }

    anyhow::bail!(
        "argus requires root privileges. Re-run with sudo or as root."
    );
}
