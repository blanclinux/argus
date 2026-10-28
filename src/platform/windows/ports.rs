use crate::model::{PortEntry, ProcessKind, Protocol, Status, TcpState};
use crate::platform::windows::process::get_process_info;
use crate::platform::windows::services::{list_services, ServiceInfo};
use anyhow::Result;
use std::net::Ipv6Addr;

pub fn scan() -> Result<Vec<PortEntry>> {
    let services = list_services().unwrap_or_default();
    let mut service_map: std::collections::HashMap<u32, ServiceInfo> =
        std::collections::HashMap::new();
    for s in services {
        service_map.insert(s.pid, s);
    }

    let mut entries: Vec<PortEntry> = Vec::new();

    // TCP IPv4
    scan_tcp4(&mut entries, &service_map);
    // TCP IPv6
    scan_tcp6(&mut entries, &service_map);
    // UDP IPv4
    scan_udp4(&mut entries, &service_map);
    // UDP IPv6
    scan_udp6(&mut entries, &service_map);

    // Fill process info
    for e in &mut entries {
        if let Some(info) = get_process_info(e.pid) {
            if !info.name.is_empty() {
                e.process_name = info.name;
            }
            e.image_path = info.image_path;
            e.command_line = info.command_line;
            e.start_time = info.start_time;
            e.start_time_raw = info.start_raw;
            e.memory_kb = info.memory_kb;
            e.suspended = info.suspended;
        }
        if let Some(svc) = service_map.get(&e.pid) {
            e.service_name = Some(svc.name.clone());
            e.service_display = Some(svc.display.clone());
            e.service_status = Some(svc.status.clone());
        }
        e.status = crate::util::classify_status(e);
        e.kind = crate::util::classify_kind(&e.process_name, &e.command_line, e.local_port);
    }

    Ok(entries)
}

fn scan_tcp4(entries: &mut Vec<PortEntry>, _svc: &std::collections::HashMap<u32, crate::platform::windows::services::ServiceInfo>) {
    use windows_sys::Win32::NetworkManagement::IpHelper::{GetExtendedTcpTable, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL};
    const AF_INET: u32 = 2;
    unsafe {
        let mut size = 0u32;
        GetExtendedTcpTable(std::ptr::null_mut(), &mut size, 0, AF_INET as u32, TCP_TABLE_OWNER_PID_ALL, 0);
        if size == 0 { return; }
        let mut buf = vec![0u8; size as usize];
        let ret = GetExtendedTcpTable(buf.as_mut_ptr() as *mut std::ffi::c_void, &mut size, 0, AF_INET as u32, TCP_TABLE_OWNER_PID_ALL, 0);
        if ret != 0 { return; }
        let table = buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID;
        let num = (*table).dwNumEntries as usize;
        let first = (*table).table.as_ptr();
        for i in 0..num {
            let row: MIB_TCPROW_OWNER_PID = *first.add(i);
            let port = u16::from_be(row.dwLocalPort as u16);
            let addr = row.dwLocalAddr;
            let ip = format!("{}.{}.{}.{}", addr & 0xFF, (addr >> 8) & 0xFF, (addr >> 16) & 0xFF, (addr >> 24) & 0xFF);
            entries.push(PortEntry {
                protocol: Protocol::Tcp,
                local_addr: ip,
                local_port: port,
                remote_addr: None,
                state: Some(TcpState::from_raw(row.dwState)),
                pid: row.dwOwningPid,
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
    }
}

fn scan_tcp6(entries: &mut Vec<PortEntry>, _svc: &std::collections::HashMap<u32, crate::platform::windows::services::ServiceInfo>) {
    use windows_sys::Win32::NetworkManagement::IpHelper::{GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL};
    const AF_INET6: u32 = 23;
    unsafe {
        let mut size = 0u32;
        GetExtendedTcpTable(std::ptr::null_mut(), &mut size, 0, AF_INET6 as u32, TCP_TABLE_OWNER_PID_ALL, 0);
        if size == 0 { return; }
        let mut buf = vec![0u8; size as usize];
        let ret = GetExtendedTcpTable(buf.as_mut_ptr() as *mut std::ffi::c_void, &mut size, 0, AF_INET6 as u32, TCP_TABLE_OWNER_PID_ALL, 0);
        if ret != 0 { return; }
        let table = buf.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID;
        let num = (*table).dwNumEntries as usize;
        let first = (*table).table.as_ptr();
        for i in 0..num {
            let row: MIB_TCP6ROW_OWNER_PID = *first.add(i);
            let port = u16::from_be(row.dwLocalPort as u16);
            let ip = Ipv6Addr::from(row.ucLocalAddr).to_string();
            entries.push(PortEntry {
                protocol: Protocol::Tcp6,
                local_addr: ip,
                local_port: port,
                remote_addr: None,
                state: Some(TcpState::from_raw(row.dwState)),
                pid: row.dwOwningPid,
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
    }
}

fn scan_udp4(entries: &mut Vec<PortEntry>, _svc: &std::collections::HashMap<u32, crate::platform::windows::services::ServiceInfo>) {
    use windows_sys::Win32::NetworkManagement::IpHelper::{GetExtendedUdpTable, MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, UDP_TABLE_OWNER_PID};
    const AF_INET: u32 = 2;
    unsafe {
        let mut size = 0u32;
        GetExtendedUdpTable(std::ptr::null_mut(), &mut size, 0, AF_INET as u32, UDP_TABLE_OWNER_PID, 0);
        if size == 0 { return; }
        let mut buf = vec![0u8; size as usize];
        let ret = GetExtendedUdpTable(buf.as_mut_ptr() as *mut std::ffi::c_void, &mut size, 0, AF_INET as u32, UDP_TABLE_OWNER_PID, 0);
        if ret != 0 { return; }
        let table = buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID;
        let num = (*table).dwNumEntries as usize;
        let first = (*table).table.as_ptr();
        for i in 0..num {
            let row: MIB_UDPROW_OWNER_PID = *first.add(i);
            let port = u16::from_be(row.dwLocalPort as u16);
            let addr = row.dwLocalAddr;
            let ip = format!("{}.{}.{}.{}", addr & 0xFF, (addr >> 8) & 0xFF, (addr >> 16) & 0xFF, (addr >> 24) & 0xFF);
            entries.push(PortEntry {
                protocol: Protocol::Udp,
                local_addr: ip,
                local_port: port,
                remote_addr: None,
                state: None,
                pid: row.dwOwningPid,
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
    }
}

fn scan_udp6(entries: &mut Vec<PortEntry>, _svc: &std::collections::HashMap<u32, crate::platform::windows::services::ServiceInfo>) {
    use windows_sys::Win32::NetworkManagement::IpHelper::{GetExtendedUdpTable, MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID, UDP_TABLE_OWNER_PID};
    const AF_INET6: u32 = 23;
    unsafe {
        let mut size = 0u32;
        GetExtendedUdpTable(std::ptr::null_mut(), &mut size, 0, AF_INET6 as u32, UDP_TABLE_OWNER_PID, 0);
        if size == 0 { return; }
        let mut buf = vec![0u8; size as usize];
        let ret = GetExtendedUdpTable(buf.as_mut_ptr() as *mut std::ffi::c_void, &mut size, 0, AF_INET6 as u32, UDP_TABLE_OWNER_PID, 0);
        if ret != 0 { return; }
        let table = buf.as_ptr() as *const MIB_UDP6TABLE_OWNER_PID;
        let num = (*table).dwNumEntries as usize;
        let first = (*table).table.as_ptr();
        for i in 0..num {
            let row: MIB_UDP6ROW_OWNER_PID = *first.add(i);
            let port = u16::from_be(row.dwLocalPort as u16);
            let ip = Ipv6Addr::from(row.ucLocalAddr).to_string();
            entries.push(PortEntry {
                protocol: Protocol::Udp6,
                local_addr: ip,
                local_port: port,
                remote_addr: None,
                state: None,
                pid: row.dwOwningPid,
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
    }
}
