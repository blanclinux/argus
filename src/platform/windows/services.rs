use anyhow::Result;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::System::Services::{
    ControlService, EnumServicesStatusExW, OpenSCManagerW, OpenServiceW, SC_ENUM_PROCESS_INFO,
    SC_MANAGER_ENUMERATE_SERVICE, SERVICE_CONTROL_STOP, SERVICE_QUERY_STATUS, SERVICE_STATE_ALL,
    SERVICE_STATUS, SERVICE_STOP, SERVICE_WIN32, ENUM_SERVICE_STATUS_PROCESSW,
};

#[derive(Debug, Clone)]
pub struct ServiceInfo {
    pub name: String,
    pub display: String,
    pub status: String,
    pub pid: u32,
}

pub fn list_services() -> Result<Vec<ServiceInfo>> {
    unsafe {
        let scm = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_ENUMERATE_SERVICE);
        if scm.is_null() {
            anyhow::bail!("OpenSCManager failed");
        }
        let mut bytes_needed = 0u32;
        let mut services_returned = 0u32;
        let mut resume_handle = 0u32;
        // first call
        EnumServicesStatusExW(
            scm,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            std::ptr::null_mut(),
            0,
            &mut bytes_needed,
            &mut services_returned,
            &mut resume_handle,
            std::ptr::null(),
        );
        if bytes_needed == 0 {
            let _ = CloseHandle(scm);
            return Ok(Vec::new());
        }
        let mut buf = vec![0u8; bytes_needed as usize];
        let ok = EnumServicesStatusExW(
            scm,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            buf.as_mut_ptr(),
            bytes_needed,
            &mut bytes_needed,
            &mut services_returned,
            &mut resume_handle,
            std::ptr::null(),
        );
        if ok == 0 {
            let _ = CloseHandle(scm);
            anyhow::bail!("EnumServicesStatusEx failed");
        }
        let mut out = Vec::new();
        let arr = buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW;
        for i in 0..services_returned as usize {
            let s = &*arr.add(i);
            let name = pwstr_to_string(s.lpServiceName);
            let display = pwstr_to_string(s.lpDisplayName);
            let state = match s.ServiceStatusProcess.dwCurrentState {
                1 => "Stopped",
                2 => "StartPending",
                3 => "StopPending",
                4 => "Running",
                5 => "ContinuePending",
                6 => "PausePending",
                7 => "Paused",
                _ => "Unknown",
            };
            out.push(ServiceInfo {
                name,
                display,
                status: state.to_string(),
                pid: s.ServiceStatusProcess.dwProcessId,
            });
        }
        let _ = CloseHandle(scm);
        Ok(out)
    }
}

pub fn stop_service(name: &str) -> Result<()> {
    unsafe {
        let scm = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_ENUMERATE_SERVICE);
        if scm.is_null() {
            anyhow::bail!("OpenSCManager failed");
        }
        let name_w: Vec<u16> = OsStr::new(name).encode_wide().chain(std::iter::once(0)).collect();
        let svc = OpenServiceW(scm, name_w.as_ptr(), SERVICE_STOP | SERVICE_QUERY_STATUS);
        if svc.is_null() {
            let _ = CloseHandle(scm);
            anyhow::bail!("OpenService failed");
        }
        let mut status: SERVICE_STATUS = std::mem::zeroed();
        let ok = ControlService(svc, SERVICE_CONTROL_STOP, &mut status);
        let _ = CloseHandle(svc);
        let _ = CloseHandle(scm);
        if ok == 0 {
            anyhow::bail!("ControlService stop failed");
        }
        Ok(())
    }
}

fn pwstr_to_string(p: *mut u16) -> String {
    if p.is_null() {
        return String::new();
    }
    unsafe {
        let mut len = 0usize;
        while *p.add(len) != 0 {
            len += 1;
            if len > 32768 {
                break;
            }
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
    }
}
