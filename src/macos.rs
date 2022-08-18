use std::ffi::CString;

use darwin_libproc_sys::proc_pidpath;
use libc::c_void;
use mach2::{traps::{task_for_pid, mach_task_self}, port::{mach_port_t, MACH_PORT_NULL}, kern_return::KERN_SUCCESS, vm_types::{mach_vm_address_t, mach_vm_size_t}, vm::mach_vm_read_overwrite};
use regex::Regex;

use super::{MemoryMap, MemoryPermissions, MemoryPrivacy, MemoryPath, Process};
use crate::error::{Error, Result};

fn get_maps(pid: u32) -> Result<Vec<MemoryMap>> {
    let mut vec = vec! [];

    let vmmap = String::from_utf8(
            std::process::Command::new("vmmap")
            .args(["-wide".to_string(), pid.to_string()])
            .output()
            .map_err(Error::Io)?
            .stdout
        )
        .map_err(Error::FromUtf8)?;

    let mut in_block = false;
    for line in vmmap.lines() {
        if in_block {
            let data = line.trim();

            if data.starts_with("REGION TYPE") {
                continue;
            }

            if data.is_empty() {
                in_block = false;
            } else {
                let captures = Regex::new(r"^(.+)\s+([0-9abcdef]+)-([0-9abcdef]+)\s+.+\s+([r-][w-][x-])/([r-][w-][x-]) SM=(.{3}) (?:(?:PURGE=(.)|.+))? (.*)$")
                    .expect("VMMAP regex is invalid")
                    .captures_iter(line).next().map_or(Err(Error::InvalidData), Ok)?;
                let permissions = &mut captures[4].chars();

                vec.push(MemoryMap {
                    base: usize::from_str_radix(&captures[2], 16).map_err(Error::ParseInt)?,
                    ceiling: usize::from_str_radix(&captures[3], 16).map_err(Error::ParseInt)?,
                    perms: MemoryPermissions {
                        readable: permissions.next().map_or(Err(Error::InvalidData), Ok)? == 'r',
                        writable: permissions.next().map_or(Err(Error::InvalidData), Ok)? == 'w',
                        executable: permissions.next().map_or(Err(Error::InvalidData), Ok)? == 'x',
                        privacy: if &captures[6] == "PRV" || &captures[6] == "COW" {
                            MemoryPrivacy::Private
                        } else {
                            MemoryPrivacy::Shared
                        },
                    },
                    pathname: MemoryPath::MappedFile(captures[8].trim().to_string()),
                })
            }
        } else if line.starts_with("==== Writable regions for process") || line.starts_with("==== Non-writable regions for process") {
            in_block = true;
        }
    }

    Ok(vec)
}

fn get_task(pid: u32) -> Result<mach_port_t> {
    unsafe {
        let mut task = MACH_PORT_NULL;
        let res = task_for_pid(mach_task_self(), pid as i32, &mut task as *mut mach_port_t);
        if res != KERN_SUCCESS {
            Err(Error::Mach(res))
        } else {
            Ok(task)
        }
    }
}

impl Process {
    /// Creates a Process from the target PID
    pub fn from_pid(pid: u32) -> Result<Process> {
        Ok(Process {
            pid,
            maps: get_maps(pid)?,
        })
    }

    /// Retrieves the path of the process executable
    pub fn get_executable_path(&self) -> Result<String> {
        let (len, _arr) = unsafe {
            let mut path: [u8; 2048] = std::mem::zeroed();
    
            let len = proc_pidpath(
                self.pid as i32,
                std::mem::transmute::<*mut u8, *mut c_void>(&mut path as *mut u8),
                2048
            );
    
            (len, path)
        };
    
        if len == -1 {
            return Err(Error::Libproc);
        }
    
        let arr = &_arr[..len as usize + 1];
    
        Ok(CString::from_vec_with_nul(arr.to_vec()).map_err(Error::FromVecWithNul)?.to_str().map_err(Error::Utf8)?.to_string())
    }

    /// Reads a buffer from the process
    pub fn read_buf(&self, ptr: usize, len: usize) -> Result<Vec<u8>> {
        let task: mach_port_t = get_task(self.pid)?;

        let buf = &mut vec![0u8; len][..];
        let mut size = len as u64;

        let kr = unsafe {
            mach_vm_read_overwrite(
                task,
                ptr as mach_vm_address_t,
                len as mach_vm_size_t,
                buf as *mut [u8] as *const () as u64,
                &mut size as *mut u64
            )
        };

        if kr != KERN_SUCCESS {
            return Err(Error::Mach(kr))
        }

        Ok(buf.to_vec())
    }
}
