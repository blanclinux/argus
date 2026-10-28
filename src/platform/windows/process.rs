use windows_sys::Win32::Foundation::{CloseHandle, FILETIME};
use windows_sys::Win32::System::ProcessStatus::K32GetProcessMemoryInfo;
use windows_sys::Win32::System::ProcessStatus::PROCESS_MEMORY_COUNTERS;
use windows_sys::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_INFORMATION,
    PROCESS_VM_READ,
};

pub struct ProcessInfo {
    pub name: String,
    pub image_path: String,
    pub command_line: String,
    pub start_time: Option<String>,
    pub start_raw: Option<u64>,
    pub memory_kb: Option<u64>,
    pub suspended: bool,
}

pub fn get_process_info(pid: u32) -> Option<ProcessInfo> {
    if pid == 0 {
        return None;
    }
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
        if handle.is_null() {
            return None;
        }

        // image path
        let mut buf = vec![0u16; 32768];
        let mut size = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(handle, 0, buf.as_mut_ptr(), &mut size);
        let image_path = if ok != 0 {
            String::from_utf16_lossy(&buf[..size as usize])
        } else {
            String::new()
        };
        let name = image_path
            .rsplit('\\')
            .next()
            .unwrap_or("")
            .to_string();

        // start time
        let mut creation = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        let mut exit = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        let mut kernel = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        let mut user = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        let (start_time, start_raw) = if GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) != 0 {
            let raw = ((creation.dwHighDateTime as u64) << 32) | creation.dwLowDateTime as u64;
            (filetime_to_string(creation), Some(raw))
        } else {
            (None, None)
        };

        // memory
        let mut pmc: PROCESS_MEMORY_COUNTERS = std::mem::zeroed();
        pmc.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
        let memory_kb = if K32GetProcessMemoryInfo(handle, &mut pmc, pmc.cb) != 0 {
            Some(pmc.WorkingSetSize as u64 / 1024)
        } else {
            None
        };

        // command line (best effort)
        let command_line = read_command_line(handle).unwrap_or_default();

        // suspended
        let suspended = is_suspended(pid);

        CloseHandle(handle);

        Some(ProcessInfo {
            name,
            image_path,
            command_line,
            start_time,
            start_raw,
            memory_kb,
            suspended,
        })
    }
}

fn filetime_to_string(ft: FILETIME) -> Option<String> {
    use windows_sys::Win32::Foundation::SYSTEMTIME;
    use windows_sys::Win32::System::Time::FileTimeToSystemTime;
    unsafe {
        let mut st: SYSTEMTIME = std::mem::zeroed();
        if FileTimeToSystemTime(&ft, &mut st) == 0 {
            return None;
        }
        // Convert FILETIME (UTC) to local? Keep UTC ISO-like.
        Some(format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond
        ))
    }
}

fn is_suspended(_pid: u32) -> bool {
    false
}

fn read_command_line(handle: windows_sys::Win32::Foundation::HANDLE) -> Option<String> {
    use windows_sys::Win32::System::Threading::PROCESS_BASIC_INFORMATION;
    type NtQueryInformationProcessFn = unsafe extern "system" fn(
        *mut std::ffi::c_void,
        u32,
        *mut std::ffi::c_void,
        u32,
        *mut u32,
    ) -> i32;
    unsafe {
        let name: Vec<u16> = "ntdll.dll\0".encode_utf16().collect();
        let ntdll = windows_sys::Win32::System::LibraryLoader::GetModuleHandleW(name.as_ptr());
        if ntdll.is_null() {
            return None;
        }
        let proc = windows_sys::Win32::System::LibraryLoader::GetProcAddress(
            ntdll, "NtQueryInformationProcess\0".as_ptr(),
        );
        if proc.is_null() {
            return None;
        }
        let ntqip: NtQueryInformationProcessFn = std::mem::transmute(proc);

        let mut pbi: PROCESS_BASIC_INFORMATION = std::mem::zeroed();
        let mut ret_len = 0u32;
        let status = ntqip(
            handle,
            0,
            &mut pbi as *mut _ as *mut _,
            std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut ret_len,
        );
        if status != 0 || pbi.PebBaseAddress.is_null() {
            return None;
        }

        let mut peb_params_ptr: *mut std::ffi::c_void = std::ptr::null_mut();
        let ok = windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory(
            handle,
            (pbi.PebBaseAddress as usize + 0x20) as *const _,
            &mut peb_params_ptr as *mut _ as *mut _,
            std::mem::size_of::<*mut std::ffi::c_void>(),
            std::ptr::null_mut(),
        );
        if ok == 0 || peb_params_ptr.is_null() {
            return None;
        }

        let mut length: u16 = 0;
        let mut buffer_ptr: *mut u16 = std::ptr::null_mut();
        let _ = windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory(
            handle,
            peb_params_ptr as *const _,
            &mut length as *mut _ as *mut _,
            2,
            std::ptr::null_mut(),
        );
        let _ = windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory(
            handle,
            (peb_params_ptr as usize + 0x78) as *const _,
            &mut buffer_ptr as *mut _ as *mut _,
            std::mem::size_of::<*mut u16>(),
            std::ptr::null_mut(),
        );
        if buffer_ptr.is_null() || length == 0 {
            return None;
        }
        let char_count = (length / 2) as usize;
        let mut buf = vec![0u16; char_count];
        let ok = windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory(
            handle,
            buffer_ptr as *const _,
            buf.as_mut_ptr() as *mut _,
            length as usize,
            std::ptr::null_mut(),
        );
        if ok == 0 {
            return None;
        }
        Some(String::from_utf16_lossy(&buf))
    }
}
