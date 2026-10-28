use anyhow::Result;
use crate::cli::KillArgs;

#[cfg(windows)]
pub fn kill_pid(pid: u32, _force: bool) -> String {
    // Try to stop a service owning this PID first.
    if let Some(name) = find_service_for_pid(pid) {
        if stop_service(&name).is_ok() {
            return format!("stopped service {} (pid {})", name, pid);
        }
    }
    unsafe {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
        let handle = OpenProcess(PROCESS_TERMINATE, 0, pid);
        if handle.is_null() {
            return format!("open process {} failed (access denied?)", pid);
        }
        let ok = TerminateProcess(handle, 1);
        CloseHandle(handle);
        if ok != 0 {
            format!("killed pid {}", pid)
        } else {
            format!("terminate pid {} failed", pid)
        }
    }
}

#[cfg(windows)]
fn find_service_for_pid(pid: u32) -> Option<String> {
    let services = crate::platform::windows::services::list_services().ok()?;
    for s in services {
        if s.pid == pid {
            return Some(s.name);
        }
    }
    None
}

#[cfg(windows)]
fn stop_service(name: &str) -> Result<()> {
    crate::platform::windows::services::stop_service(name)
}

#[cfg(not(windows))]
pub fn kill_pid(_pid: u32, _force: bool) -> String {
    "not supported on this platform".into()
}

pub fn run_cli_kill(args: KillArgs) -> Result<()> {
    #[cfg(windows)]
    {
        if !args.yes {
            use std::io::{self, Write};
            print!("Kill PID {}? [y/N] ", args.pid);
            io::stdout().flush().ok();
            let mut line = String::new();
            io::stdin().read_line(&mut line)?;
            if !line.trim().eq_ignore_ascii_case("y") {
                println!("cancelled");
                return Ok(());
            }
        }
        let msg = kill_pid(args.pid, args.force);
        println!("{}", msg);
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = args;
        anyhow::bail!("not supported on this platform")
    }
}
