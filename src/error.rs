use std::fmt;

/// memhop's generic Result wrapper
pub type Result<T> = std::result::Result<T, Error>;

/// memhop's generic Error wrapper
#[derive(Debug)]
pub enum Error {
    /// IO error. May include errors such as EACCES on some platforms
    Io(std::io::Error),
    /// CString parsing error
    FromVecWithNul(std::ffi::FromVecWithNulError),
    /// CString parsing error
    Utf8(std::str::Utf8Error),
    /// CString parsing error
    FromUtf8(std::string::FromUtf8Error),
    /// Int parsing error
    ParseInt(std::num::ParseIntError),
    /// Invalid data/state encountered when parsing OS-specific data
    InvalidData,

    #[cfg(target_os = "linux")]
    /// Procmaps error
    Procmaps(procmaps::Error),

    #[cfg(target_os = "macos")]
    /// Regex error while parsing memory maps
    Regex(regex::Error),
    #[cfg(target_os = "macos")]
    /// Mach kernel error
    Mach(i32),
    #[cfg(target_os = "macos")]
    /// Libproc error
    Libproc,

    #[cfg(target_os = "windows")]
    /// Layout error
    Layout(std::alloc::LayoutError),
}

// Generation of an error is completely separate from how it is displayed.
// There's no need to be concerned about cluttering complex logic with the display style.
//
// Note that we don't store any extra info about the errors. This means we can't state
// which string failed to parse without modifying our types to carry that information.
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Io(x) => write!(f, "IO error; err = {:?}", x),
            Self::FromVecWithNul(x) => write!(f, "FromVecWithNul error; err = {:?}", x),
            Self::Utf8(x) => write!(f, "UTF8 error; err = {:?}", x),
            Self::FromUtf8(x) => write!(f, "FromUTF8 error; err = {:?}", x),
            Self::ParseInt(x) => write!(f, "ParseInt error; err = {:?}", x),
            Self::InvalidData => write!(f, "invalid data encountered"),

            #[cfg(target_os = "linux")]
            Self::Procmaps(x) => write!(f, "procmaps error; err = {:?}", x),

            #[cfg(target_os = "macos")]
            Self::Regex(x) => write!(f, "regex error; err = {:?}", x),
            #[cfg(target_os = "macos")]
            Self::Mach(x) => write!(f, "mach error code {}", x),
            #[cfg(target_os = "macos")]
            Self::Libproc => write!(f, "libproc error"),

            #[cfg(target_os = "windows")]
            Self::Layout(x) => write!(f, "Layout error; err = {:?}", x),
        }
    }
}