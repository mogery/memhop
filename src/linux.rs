use procmaps::{self, Mappings, Map};
use std::{fs::{OpenOptions, read_link}, io::{Seek, Read}};

use crate::error::{Error, Result};

use super::{MemoryMap, MemoryPath, MemoryPermissions, MemoryPrivacy, Process};

impl From<&Map> for MemoryMap {
    fn from(map: &Map) -> MemoryMap {
        MemoryMap {
            base: map.base,
            ceiling: map.ceiling,
            perms: MemoryPermissions {
                readable: map.perms.readable,
                writable: map.perms.writable,
                executable: map.perms.executable,
                privacy: match map.perms.privacy {
                    procmaps::Privacy::Shared => MemoryPrivacy::Shared,
                    procmaps::Privacy::Private => MemoryPrivacy::Private,
                }
            },
            pathname: match &map.pathname {
                procmaps::Path::MappedFile(x) => MemoryPath::MappedFile(x.to_string()),
                procmaps::Path::Stack => MemoryPath::Stack,
                procmaps::Path::ThreadStack(x) => MemoryPath::ThreadStack(*x),
                procmaps::Path::Vdso => MemoryPath::Vdso,
                procmaps::Path::Heap => MemoryPath::Heap,
                procmaps::Path::Vvar => MemoryPath::Vvar,
                procmaps::Path::Vsyscall => MemoryPath::Vsyscall,
            },
        }
    }
}

impl Process {
    /// Creates a Process from the target PID
    pub fn from_pid(pid: u32) -> Result<Process> {
        let mappings = Mappings::from_pid(pid as i32).map_err(Error::Procmaps)?;

        Ok(Process {
            pid,
            maps: mappings.iter().map(|x| x.into()).collect(),
        })
    }

    /// Retrieves the path of the process executable
    pub fn get_executable_path(&self) -> Result<String> {
        let path = read_link(format!("/proc/{}/exe", self.pid)).map_err(Error::Io)?;
        Ok(path.to_str().map_or(Err(Error::InvalidData), Ok)?.to_string())
    }

    /// Reads a buffer from the process
    pub fn read_buf(&self, ptr: usize, len: usize) -> Result<Vec<u8>> {
        let mut mem = OpenOptions::new().read(true).open(format!("/proc/{}/mem", self.pid)).map_err(Error::Io)?;

        mem.seek(std::io::SeekFrom::Start(ptr as u64)).map_err(Error::Io)?;
        let mut buf: Vec<u8> = vec![0; len];
        mem.read_exact(&mut buf).map_err(Error::Io)?;
    
        Ok(buf)
    }
}
