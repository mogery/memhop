use std::{ffi::{CString, c_void}, alloc::Layout};

use windows_sys::Win32::{Foundation::{HANDLE, HINSTANCE, MAX_PATH}, System::{SystemInformation::{GetSystemInfo, SYSTEM_INFO}, Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_READONLY, PAGE_READWRITE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_WRITECOPY, PAGE_EXECUTE, MEM_PRIVATE}, ProcessStatus::{K32EnumProcessModules, K32GetModuleFileNameExA, MODULEINFO, K32GetModuleInformation}, Threading::{OpenProcess, PROCESS_VM_READ, PROCESS_QUERY_INFORMATION}, Diagnostics::Debug::ReadProcessMemory}};

use super::{MemoryMap, MemoryPermissions, MemoryPrivacy, MemoryPath, Process, ProcessModule};
use crate::error::{Result, Error};

fn get_maps(handle: HANDLE) -> Result<Vec<MemoryMap>> {
    let mut vec = vec! [];

    let system_info = unsafe {
        let ptr = std::alloc::alloc_zeroed(Layout::new::<SYSTEM_INFO>()) as *mut SYSTEM_INFO;
        GetSystemInfo(ptr);
        *ptr
    };

    let mut address = system_info.lpMinimumApplicationAddress as usize;
    let max_address = system_info.lpMaximumApplicationAddress as usize;

    while address < max_address {
        let (res, info) = unsafe {
            let layout = Layout::new::<MEMORY_BASIC_INFORMATION>();
            let ptr = std::alloc::alloc_zeroed(layout) as *mut MEMORY_BASIC_INFORMATION;
            let res = VirtualQueryEx(
                handle,
                address as *const c_void,
                ptr,
                layout.size()
            );
            (res, *ptr)
        };

        if res == 0 {
            return Err(Error::Io(std::io::Error::last_os_error()))
        }

        address += info.RegionSize;

        if info.State != MEM_COMMIT {
            continue;
        }

        vec.push(MemoryMap {
            base: info.BaseAddress as usize,
            ceiling: info.BaseAddress as usize + info.RegionSize,
            perms: MemoryPermissions {
                readable: info.Protect == PAGE_READONLY ||
                    info.Protect == PAGE_READWRITE ||
                    info.Protect == PAGE_WRITECOPY ||
                    info.Protect == PAGE_EXECUTE_READ ||
                    info.Protect == PAGE_EXECUTE_READWRITE ||
                    info.Protect == PAGE_EXECUTE_WRITECOPY,
                writable: info.Protect == PAGE_READWRITE ||
                    info.Protect == PAGE_WRITECOPY ||
                    info.Protect == PAGE_EXECUTE_READWRITE ||
                    info.Protect == PAGE_EXECUTE_WRITECOPY,
                executable: info.Protect == PAGE_EXECUTE ||
                    info.Protect == PAGE_EXECUTE_READ ||
                    info.Protect == PAGE_EXECUTE_READWRITE ||
                    info.Protect == PAGE_EXECUTE_WRITECOPY,
                privacy: if info.Type == MEM_PRIVATE {
                    MemoryPrivacy::Private
                } else {
                    MemoryPrivacy::Shared
                }
            },
            pathname: MemoryPath::Unknown,
        });

    }

    Ok(vec)
}

fn get_modules(handle: HANDLE) -> Result<Vec<ProcessModule>> {
    let mut vec = vec! [];

    let (res, modules_ptr, cb_needed) = unsafe {
        let layout = Layout::array::<HINSTANCE>(1024).map_err(Error::Layout)?;
        let ptr = std::alloc::alloc_zeroed(layout) as *mut [HINSTANCE; 1024];
        let mut cb_needed = 0u32;
        
        let res = K32EnumProcessModules(
            handle,
            ptr as *mut HINSTANCE,
            layout.size() as u32,
            &mut cb_needed as *mut u32
        );

        (res, ptr, cb_needed)
    };

    if res == 0 {
        return Err(Error::Io(std::io::Error::last_os_error()))
    }

    let hmodule_size = Layout::new::<HINSTANCE>().size() as u32;
    let len = cb_needed / hmodule_size;

    for i in 0..len {
        let module: HINSTANCE = unsafe {
            (*modules_ptr)[i as usize]
        };

        let mut name_arr: [u8; MAX_PATH as usize] = unsafe { std::mem::zeroed() };

        let res = unsafe {
            K32GetModuleFileNameExA(
                handle,
                module,
                &mut name_arr as *mut u8,
                MAX_PATH as u32
            )
        };

        let name_arr = &name_arr[..res as usize + 1];

        if res == 0 {
            return Err(Error::Io(std::io::Error::last_os_error()))
        }

        let name = CString::from_vec_with_nul(name_arr.to_vec()).map_err(Error::FromVecWithNul)?.to_str().map_err(Error::Utf8)?.to_string();

        let (res, modinfo) = unsafe {
            let layout = Layout::new::<MODULEINFO>();
            let ptr = std::alloc::alloc_zeroed(layout) as *mut MODULEINFO;
            let res = K32GetModuleInformation(
                handle,
                module,
                ptr,
                layout.size() as u32
            );
            (res, *ptr)
        };

        if res == 0 {
            return Err(Error::Io(std::io::Error::last_os_error()))
        }

        vec.push(ProcessModule {
            name,
            base_address: modinfo.lpBaseOfDll as usize
        });
    }

    Ok(vec)
}

impl Process {
    /// Creates a Process from the target PID
    pub fn from_pid<'b>(pid: u32) -> Result<Process> {
        let handle: HANDLE = unsafe {
            OpenProcess(
                PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                0, // false
                pid
            )
        };
    
        if handle == 0 {
            return Err(Error::Io(std::io::Error::last_os_error()))
        }
    
        Ok(Process {
            pid,
            maps: get_maps(handle)?,
            modules: get_modules(handle)?,
            handle,
        })
    }

    /// Retrieves the path of the process executable
    pub fn get_executable_path(&self) -> Result<String> {
        let module = self.modules.first().map_or(Err(Error::InvalidData), Ok)?;
        Ok(module.name.clone())
    }

    /// Reads a buffer from the process
    pub fn read_buf(&self, ptr: usize, len: usize) -> Result<Vec<u8>> {
        let buf = &mut vec![0u8; len][..];
        let mut bytes_read: usize = 0;

        let res = unsafe {
            ReadProcessMemory(
                self.handle,
                ptr as *const c_void,
                buf as *mut [u8] as *mut c_void,
                len,
                &mut bytes_read as *mut usize
            )
        };

        if res == 0 {
            return Err(Error::Io(std::io::Error::last_os_error()))
        }

        Ok(buf[..bytes_read].to_vec())
    }
}
