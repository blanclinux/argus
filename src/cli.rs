use crate::model::PortEntry;
use crate::util;
use anyhow::Result;
use clap::{Args, Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "argus", version, about = "Inspect and manage localhost ports, processes, and services on Windows.")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// List ports once and exit.
    List(ListArgs),
    /// Kill a process by PID (with confirmation unless --yes).
    Kill(KillArgs),
    /// Check environment and privileges.
    Doctor,
}

#[derive(Args, Debug, Clone)]
pub struct ListArgs {
    /// Emit JSON instead of a table.
    #[arg(long)]
    pub json: bool,
    /// Include established connections, not just listeners.
    #[arg(long)]
    pub all: bool,
    /// Show only Node/Bun/Deno related processes.
    #[arg(long)]
    pub node: bool,
    /// Filter by a specific port.
    #[arg(long)]
    pub port: Option<u16>,
    /// Filter by protocol: tcp, tcp6, udp, udp6, or all.
    #[arg(long, default_value = "all")]
    pub proto: String,
    /// Refresh interval seconds for TUI (not used in list).
    #[arg(long, default_value_t = 2)]
    pub interval: u64,
}

#[derive(Args, Debug, Clone)]
pub struct KillArgs {
    pub pid: u32,
    #[arg(long)]
    pub force: bool,
    #[arg(long)]
    pub yes: bool,
}

#[cfg(windows)]
#[derive(Serialize)]
struct JsonEntry {
    protocol: String,
    local_addr: String,
    local_port: u16,
    state: Option<String>,
    pid: u32,
    process_name: String,
    image_path: String,
    command_line: String,
    start_time: Option<String>,
    memory_kb: Option<u64>,
    service_name: Option<String>,
    service_status: Option<String>,
    kind: String,
    status: String,
}

#[cfg(windows)]
impl From<&PortEntry> for JsonEntry {
    fn from(e: &PortEntry) -> Self {
        Self {
            protocol: e.protocol.to_string(),
            local_addr: e.local_addr.clone(),
            local_port: e.local_port,
            state: e.state.map(|s| s.to_string()),
            pid: e.pid,
            process_name: e.process_name.clone(),
            image_path: e.image_path.clone(),
            command_line: e.command_line.clone(),
            start_time: e.start_time.clone(),
            memory_kb: e.memory_kb,
            service_name: e.service_name.clone(),
            service_status: e.service_status.clone(),
            kind: e.kind.label().to_string(),
            status: e.status.label().to_string(),
        }
    }
}

#[cfg(windows)]
pub fn collect_entries(args: &ListArgs) -> Result<Vec<PortEntry>> {
    use crate::platform::windows::ports::scan;
    let mut entries = scan()?;
    // classify
    for e in &mut entries {
        e.status = crate::util::classify_status(e);
        e.kind = crate::util::classify_kind(&e.process_name, &e.command_line, e.local_port);
    }
    // filters
    if !args.all {
        entries.retain(|e| e.is_listener());
    }
    if args.node {
        entries.retain(|e| {
            let h = format!("{} {}", e.process_name, e.command_line).to_lowercase();
            h.contains("node") || h.contains("bun") || h.contains("deno")
        });
    }
    if let Some(p) = args.port {
        entries.retain(|e| e.local_port == p);
    }
    let proto = args.proto.to_lowercase();
    if proto != "all" {
        entries.retain(|e| e.protocol.to_string().to_lowercase() == proto);
    }
    entries.sort_by_key(|e| (e.local_port, e.pid));
    Ok(entries)
}

#[cfg(windows)]
pub fn run_list(args: ListArgs) -> Result<()> {
    let entries = collect_entries(&args)?;
    if args.json {
        let json: Vec<JsonEntry> = entries.iter().map(JsonEntry::from).collect();
        println!("{}", serde_json::to_string_pretty(&json)?);
        return Ok(());
    }
    // plain table
    print_table(&entries);
    Ok(())
}

#[cfg(windows)]
pub fn run_doctor() -> Result<()> {
    use crate::platform::windows::elevation::is_elevated;
    println!("argus doctor");
    println!("  OS: Windows");
    println!("  Elevated: {}", is_elevated());
    println!("  Note: port scan requires elevation for all processes.");
    Ok(())
}

#[cfg(windows)]
fn print_table(entries: &[PortEntry]) {
    // Simple aligned table (TUI uses richer rendering).
    let header = format!(
        "{:<6} {:<7} {:<9} {:<7} {:<22} {:<28} {:<20} {:<8}",
        "PORT", "PROTO", "STATE", "PID", "PROCESS", "SERVICE", "STARTED", "STATUS"
    );
    println!("{header}");
    println!("{}", "-".repeat(header.len()));
    for e in entries {
        println!(
            "{:<6} {:<7} {:<9} {:<7} {:<22} {:<28} {:<20} {:<8}",
            e.local_port,
            e.protocol,
            e.state.map(|s| s.to_string()).unwrap_or_else(|| "-".into()),
            e.pid,
            util::truncate(&e.process_name, 22),
            util::truncate(e.service_name.as_deref().unwrap_or("-"), 28),
            util::truncate(e.start_time.as_deref().unwrap_or("-"), 20),
            e.status,
        );
    }
    println!("\n{} entries", entries.len());
}

#[cfg(not(windows))]
pub fn collect_entries(_args: &ListArgs) -> Result<Vec<PortEntry>> {
    Ok(Vec::new())
}
