use crate::model::{PortEntry, ProcessKind, Protocol, Status, TcpState};
use anyhow::Result;
use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub fn scan() -> Result<Vec<PortEntry>> {
    let inode_to_pid = build_inode_map();
    let mut entries: Vec<PortEntry> = Vec::new();

    if let Ok(content) = fs::read_to_string("/proc/net/tcp") {
        parse_tcp_line(&content, false, &inode_to_pid, &mut entries)?;
    }
    if let Ok(content) = fs::read_to_string("/proc/net/tcp6") {
        parse_tcp_line(&content, true, &inode_to_pid, &mut entries)?;
    }
    if let Ok(content) = fs::read_to_string("/proc/net/udp") {
        parse_udp_line(&content, false, &inode_to_pid, &mut entries)?;
    }
    if let Ok(content) = fs::read_to_string("/proc/net/udp6") {
        parse_udp_line(&content, true, &inode_to_pid, &mut entries)?;
    }

    for e in &mut entries {
        if let Some(info) = crate::platform::linux::process::get_process_info(e.pid) {
            e.process_name = info.name;
            e.image_path = info.image_path;
            e.command_line = info.command_line;
            e.start_time = info.start_time;
            e.start_time_raw = info.start_raw;
            e.memory_kb = info.memory_kb;
            e.suspended = info.suspended;
        }
        if let Some(svc) = crate::platform::linux::services::get_service_for_pid(e.pid) {
            e.service_name = Some(svc.name);
            e.service_display = Some(svc.display);
            e.service_status = Some(svc.status);
        }
        e.status = crate::util::classify_status(e);
        e.kind = crate::util::classify_kind(&e.process_name, &e.command_line, e.local_port);
    }

    Ok(entries)
}

fn parse_tcp_line(
    content: &str,
    is_v6: bool,
    inode_to_pid: &HashMap<u64, u32>,
    entries: &mut Vec<PortEntry>,
) -> Result<()> {
    for line in content.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            continue;
        }
        let local_addr = parts[1];
        let state_str = parts[3];
        let inode_str = parts[9];

        let local_ip_port = parse_addr(local_addr, is_v6)?;
        let state = u16::from_str_radix(state_str, 16).unwrap_or(0);
        let inode: u64 = inode_str.parse().unwrap_or(0);

        let pid = inode_to_pid.get(&inode).copied().unwrap_or(0);

        entries.push(PortEntry {
            protocol: if is_v6 { Protocol::Tcp6 } else { Protocol::Tcp },
            local_addr: local_ip_port.0.to_string(),
            local_port: local_ip_port.1,
            remote_addr: None,
            state: Some(TcpState::from_raw(state as u32)),
            pid,
            process_name: String::new(),
            image_path: String::new(),
            command_line: String::new(),
            start_time: None,
            start_time_raw: None,
            memory_kb: None,
            service_name: None,
            service_display: None,
            service_status: None,
            suspended: false,
            kind: ProcessKind::Unknown,
            status: Status::Unknown,
        });
    }
    Ok(())
}

fn parse_udp_line(
    content: &str,
    is_v6: bool,
    inode_to_pid: &HashMap<u64, u32>,
    entries: &mut Vec<PortEntry>,
) -> Result<()> {
    for line in content.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            continue;
        }
        let local_addr = parts[1];
        let inode_str = parts[9];

        let local_ip_port = parse_addr(local_addr, is_v6)?;
        let inode: u64 = inode_str.parse().unwrap_or(0);

        let pid = inode_to_pid.get(&inode).copied().unwrap_or(0);

        entries.push(PortEntry {
            protocol: if is_v6 { Protocol::Udp6 } else { Protocol::Udp },
            local_addr: local_ip_port.0.to_string(),
            local_port: local_ip_port.1,
            remote_addr: None,
            state: None,
            pid,
            process_name: String::new(),
            image_path: String::new(),
            command_line: String::new(),
            start_time: None,
            start_time_raw: None,
            memory_kb: None,
            service_name: None,
            service_display: None,
            service_status: None,
            suspended: false,
            kind: ProcessKind::Unknown,
            status: Status::Unknown,
        });
    }
    Ok(())
}

fn parse_addr(addr: &str, is_v6: bool) -> Result<(IpAddr, u16)> {
    if is_v6 {
        let colon = addr.rfind(':').ok_or_else(|| anyhow::anyhow!("no colon in {addr}"))?;
        let ip_hex = &addr[..colon];
        let port_hex = &addr[colon + 1..];
        let port = u16::from_str_radix(port_hex, 16)?;
        let chunks: Vec<u32> = (0..4)
            .map(|i| u32::from_str_radix(&ip_hex[i * 8..(i + 1) * 8], 16))
            .collect::<Result<Vec<_>, _>>()?;
        let ip = Ipv6Addr::from([
            u32::from_be(chunks[0]),
            u32::from_be(chunks[1]),
            u32::from_be(chunks[2]),
            u32::from_be(chunks[3]),
        ]);
        Ok((IpAddr::V6(ip), port))
    } else {
        let colon = addr.rfind(':').ok_or_else(|| anyhow::anyhow!("no colon in {addr}"))?;
        let ip_hex = &addr[..colon];
        let port_hex = &addr[colon + 1..];
        let port = u16::from_str_radix(port_hex, 16)?;
        let ip_val = u32::from_str_radix(ip_hex, 16)?;
        let ip = Ipv4Addr::from([
            (ip_val & 0xFF) as u8,
            ((ip_val >> 8) & 0xFF) as u8,
            ((ip_val >> 16) & 0xFF) as u8,
            ((ip_val >> 24) & 0xFF) as u8,
        ]);
        Ok((IpAddr::V4(ip), port))
    }
}

fn build_inode_map() -> HashMap<u64, u32> {
    let mut map = HashMap::new();

    if let Ok(proc_entries) = fs::read_dir("/proc") {
        for entry in proc_entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let pid_str = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let pid: u32 = match pid_str.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };

            let fd_dir = path.join("fd");
            if let Ok(fd_entries) = fs::read_dir(&fd_dir) {
                for fd_entry in fd_entries.flatten() {
                    if let Ok(link) = fs::read_link(fd_entry.path()) {
                        let link_str = link.to_string_lossy();
                        if let Some(inode_str) =
                            link_str.strip_prefix("socket:[").and_then(|s| s.strip_suffix(']'))
                        {
                            if let Ok(inode) = inode_str.parse::<u64>() {
                                map.insert(inode, pid);
                            }
                        }
                    }
                }
            }
        }
    }
    map
}
