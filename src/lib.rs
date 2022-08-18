#![warn(missing_docs)]
#![doc = include_str!("../README.md")]

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::*;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::*;

/// memhop's Error wrapper
pub mod error;

use std::{io::Cursor, ffi::CString};

use byteorder::{ReadBytesExt, NativeEndian};

use crate::error::{Error, Result};

/// Represents the privacy of a mapping.
#[derive(PartialEq, Eq, Debug)]
pub enum MemoryPrivacy {
    /// This mapping is shared
    Shared,
    /// This mapping is private (copy on write)
    Private,
}

/// Represents the permissions of a mapping.
#[derive(Debug)]
pub struct MemoryPermissions {
    /// Is the memory mapping readable?
    pub readable: bool,
    /// Is the memory mapping writable?
    pub writable: bool,
    /// Is the memory mapping executable?
    pub executable: bool,
    /// Privacy of the memory mapping
    pub privacy: MemoryPrivacy,
}

/// Represents the pathname associated with the memory mapping.
#[derive(PartialEq, Eq, Debug)]
pub enum MemoryPath {
    /// A file backs up this mapping
    MappedFile(String),
    /// This mapping is the main thread stack
    Stack,
    /// This mapping is a thread's stack
    ThreadStack(usize),
    /// This mapping is the virtual dynamically linked shared object
    Vdso,
    /// This mapping is the process's heap
    Heap,
    /// This mapping holds variables updated by the kernel
    Vvar,
    /// This region is the vsyscall mapping
    Vsyscall,
    /// Platform does not support memory mapping pathnames
    Unknown,
}

/// Represents a mapped region of memory.
#[derive(Debug)]
pub struct MemoryMap {
    /// Base address of the memory mapping
    pub base: usize,
    /// Ceiling address of the memory mapping
    pub ceiling: usize,
    /// Permissions of the memory mapping
    pub perms: MemoryPermissions,
    /// Pathname of the memory mapping
    pub pathname: MemoryPath,
}

impl MemoryMap {
    /// Calculate the size of the mapping in bytes
    pub fn size_of_mapping(&self) -> usize {
        self.ceiling - self.base
    }
}

#[cfg(any(doc, target_os = "windows"))]
#[derive(Debug)]
/// Represents a Windows process module. [More info here.](https://docs.microsoft.com/en-us/windows/win32/psapi/module-information)
pub struct ProcessModule {
    /// Name of module
    pub name: String,
    /// Base address of module
    pub base_address: usize,
}

/// Represents a process
pub struct Process {
    /// PID of process
    pub pid: u32,
    /// Memory mappings of process
    pub maps: Vec<MemoryMap>,

    #[cfg(any(doc, target_os = "windows"))]
    /// Modules of process
    pub modules: Vec<ProcessModule>,

    #[cfg(target_os = "windows")]
    /// WinAPI handle to process
    handle: windows_sys::Win32::Foundation::HANDLE,
}

#[cfg(any(doc, target_os = "windows"))]
unsafe impl Send for Process {}
#[cfg(any(doc, target_os = "windows"))]
unsafe impl Sync for Process {}

impl Process {
    /// Reads an unsigned byte from the process
    pub fn read_u8(&self, ptr: usize) -> Result<u8> {
        Cursor::new(self.read_buf(ptr, 1)?).read_u8().map_err(Error::Io)
    }

    /// Reads a signed byte from the process
    pub fn read_i8(&self, ptr: usize) -> Result<i8> {
        Cursor::new(self.read_buf(ptr, 1)?).read_i8().map_err(Error::Io)
    }
    
    /// Reads an unsigned short from the process
    pub fn read_u16(&self, ptr: usize) -> Result<u16> {
        Cursor::new(self.read_buf(ptr, 2)?).read_u16::<NativeEndian>().map_err(Error::Io)
    }

    /// Reads a signed short from the process
    pub fn read_i16(&self, ptr: usize) -> Result<i16> {
        Cursor::new(self.read_buf(ptr, 2)?).read_i16::<NativeEndian>().map_err(Error::Io)
    }
    
    /// Reads an unsigned int from the process
    pub fn read_u32(&self, ptr: usize) -> Result<u32> {
        Cursor::new(self.read_buf(ptr, 4)?).read_u32::<NativeEndian>().map_err(Error::Io)
    }
    
    /// Reads a signed int from the process
    pub fn read_i32(&self, ptr: usize) -> Result<i32> {
        Cursor::new(self.read_buf(ptr, 4)?).read_i32::<NativeEndian>().map_err(Error::Io)
    }

    /// Reads an unsigned long from the process
    pub fn read_u64(&self, ptr: usize) -> Result<u64> {
        Cursor::new(self.read_buf(ptr, 8)?).read_u64::<NativeEndian>().map_err(Error::Io)
    }
    
    /// Reads a signed long from the process
    pub fn read_i64(&self, ptr: usize) -> Result<u64> {
        Cursor::new(self.read_buf(ptr, 8)?).read_u64::<NativeEndian>().map_err(Error::Io)
    }

    /// Reads a pointer from the process (width is platform-dependent)
    pub fn read_ptr(&self, ptr: usize) -> Result<usize> {
        Ok(if cfg!(target_pointer_width = "64") {
            Cursor::new(self.read_buf(ptr, 8)?).read_u64::<NativeEndian>().map_err(Error::Io)? as usize
        } else {
            Cursor::new(self.read_buf(ptr, 4)?).read_u32::<NativeEndian>().map_err(Error::Io)? as usize
        })
    }
    
    /// Reads a C-style string from the process
    pub fn read_cstring(&self, ptr: usize) -> Result<String> {
        let mut buf: Vec<u8> = vec![];
        let mut i: usize = 0;
    
        loop {
            let x = self.read_u8(ptr + i)?;
            buf.push(x);
            i += 1;
            if x == 0 {
                break Ok(CString::from_vec_with_nul(buf).map_err(Error::FromVecWithNul)?.to_str().map_err(Error::Utf8)?.to_string());
            }
        }
    }
    
    /// Walks a memory mapping for a pointer.
    /// Returns found addresses.
    pub fn walk_ptr(&self, map: &MemoryMap, query: usize) -> Result<Vec<usize>> {
        let mut vec = Vec::new();
    
        let buf = self.read_buf(map.base, map.size_of_mapping())?;
    
        let size = std::mem::size_of::<usize>();
        let len = map.size_of_mapping() / size;
        
        for i in 0..len {
            let mut cur = Cursor::new(&buf[i * size .. i * size + std::mem::size_of::<usize>()]);
            
            let x = if cfg!(target_pointer_width = "64") {
                cur.read_u64::<NativeEndian>().map_err(Error::Io)? as usize
            } else {
                cur.read_u32::<NativeEndian>().map_err(Error::Io)? as usize
            };
    
            if x == query {
                vec.push(map.base + i * size);
            }
        }
    
        Ok(vec)
    }
}