use crate::model::{PortEntry, ProcessKind, Status, TcpState};

pub fn classify_kind(name: &str, command_line: &str, port: u16) -> ProcessKind {
    let n = name.to_lowercase();
    let c = command_line.to_lowercase();
    let hay = format!("{n} {c}");

    // Databases
    if hay.contains("postgres")
        || hay.contains("mysqld")
        || hay.contains("mongod")
        || hay.contains("redis-server")
        || hay.contains("sqlservr")
        || hay.contains("oracle")
        || port == 5432
        || port == 3306
        || port == 27017
        || port == 6379
        || port == 1433
    {
        return ProcessKind::Database;
    }

    // Frontend dev servers / frameworks
    if hay.contains("vite")
        || hay.contains("next")
        || hay.contains("webpack")
        || hay.contains("react-scripts")
        || hay.contains("angular")
        || hay.contains("svelte")
        || hay.contains("astro")
        || hay.contains("remix")
        || hay.contains("gatsby")
        || hay.contains("vite preview")
        || (hay.contains("node") && (port == 3000 || port == 5173 || port == 4200 || port == 8080))
    {
        return ProcessKind::Frontend;
    }

    // Backend / APIs
    if hay.contains("uvicorn")
        || hay.contains("gunicorn")
        || hay.contains("flask")
        || hay.contains("django")
        || hay.contains("spring")
        || hay.contains("tomcat")
        || hay.contains("kestrel")
        || hay.contains("dotnet")
        || hay.contains("java")
        || hay.contains("go run")
        || hay.contains("cargo run")
        || hay.contains("rails")
        || hay.contains("express")
        || hay.contains("fastify")
        || hay.contains("nestjs")
        || hay.contains("node")
    {
        return ProcessKind::Backend;
    }

    // System services
    if n.contains("svchost")
        || n.contains("system")
        || n.contains("services.exe")
        || n.contains("lsass")
        || n.contains("spoolsv")
    {
        return ProcessKind::System;
    }

    ProcessKind::Unknown
}

pub fn classify_status(entry: &PortEntry) -> Status {
    // Paused service or suspended process takes priority.
    if entry.service_status.as_deref() == Some("Paused") || entry.suspended {
        return Status::Paused;
    }
    // Stale TCP states without a live owner.
    match entry.state {
        Some(TcpState::TimeWait) | Some(TcpState::CloseWait) | Some(TcpState::Closing) => {
            if entry.pid == 0 {
                return Status::Stale;
            }
        }
        _ => {}
    }
    // Dead: no live process.
    if entry.pid != 0 && entry.process_name.is_empty() && entry.image_path.is_empty() {
        return Status::Dead;
    }
    if entry.pid == 0 {
        return Status::Stale;
    }
    Status::Active
}

pub fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = bytes as f64;
    let mut i = 0usize;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{bytes} {}", UNITS[i])
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{PortEntry, ProcessKind, Status, TcpState};

    fn entry() -> PortEntry {
        PortEntry {
            protocol: crate::model::Protocol::Tcp,
            local_addr: "127.0.0.1".into(),
            local_port: 3000,
            remote_addr: None,
            state: Some(TcpState::Listen),
            pid: 1234,
            process_name: "node.exe".into(),
            image_path: "C:\\node.exe".into(),
            command_line: "node server.js".into(),
            start_time: None,
            start_time_raw: None,
            memory_kb: None,
            service_name: None,
            service_display: None,
            service_status: None,
            suspended: false,
            kind: ProcessKind::Unknown,
            status: Status::Unknown,
        }
    }

    #[test]
    fn classify_frontend() {
        let k = classify_kind("node.exe", "vite dev", 5173);
        assert_eq!(k, ProcessKind::Frontend);
    }

    #[test]
    fn classify_database() {
        let k = classify_kind("postgres.exe", "", 5432);
        assert_eq!(k, ProcessKind::Database);
    }

    #[test]
    fn classify_active() {
        let mut e = entry();
        e.status = classify_status(&e);
        assert_eq!(e.status, Status::Active);
    }

    #[test]
    fn classify_stale_no_pid() {
        let mut e = entry();
        e.pid = 0;
        e.state = Some(TcpState::TimeWait);
        assert_eq!(classify_status(&e), Status::Stale);
    }

    #[test]
    fn classify_paused_service() {
        let mut e = entry();
        e.service_status = Some("Paused".into());
        assert_eq!(classify_status(&e), Status::Paused);
    }

    #[test]
    fn truncate_works() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("hello world!!", 6), "hello…");
    }

    #[test]
    fn format_bytes_works() {
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(2048), "2.0 KB");
    }
}
