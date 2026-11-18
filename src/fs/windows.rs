//! Reparse points and short names through the Win32 API.

use std::ffi::OsString;
use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_NOT_A_REPARSE_POINT, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, GetLongPathNameW, OPEN_EXISTING,
};
use windows_sys::Win32::System::IO::DeviceIoControl;
use windows_sys::Win32::System::Ioctl::FSCTL_GET_REPARSE_POINT;

use super::resolve::canonical;
use crate::Os;

const TAG_MOUNT_POINT: u32 = 0xA000_0003;
const TAG_SYMLINK: u32 = 0xA000_000C;
const TAG_NAME_SURROGATE: u32 = 0x2000_0000;
const SYMLINK_FLAG_RELATIVE: u32 = 1;
const MAX_REPARSE_BUFFER: usize = 16 * 1024;

fn wide(p: &Path) -> Vec<u16> {
    let s = p.as_os_str();
    let text = s.to_string_lossy();
    let mut v: Vec<u16> = if text.len() > 240 && !text.starts_with(r"\\") {
        OsString::from(format!(r"\\?\{text}"))
            .encode_wide()
            .collect()
    } else if text.len() > 240 && !text.starts_with(r"\\?\") {
        OsString::from(format!(r"\\?\UNC\{}", &text[2..]))
            .encode_wide()
            .collect()
    } else {
        s.encode_wide().collect()
    };
    v.push(0);
    v
}

struct Handle(HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

/// The target of a symbolic link, junction or mount point, read with `FSCTL_GET_REPARSE_POINT`.
pub fn link_target(p: &Path) -> io::Result<Option<PathBuf>> {
    let name = wide(p);
    // SAFETY: `name` is NUL-terminated and outlives the call.
    let h = unsafe {
        CreateFileW(
            name.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let h = Handle(h);
    let mut buf = vec![0u8; MAX_REPARSE_BUFFER];
    let mut got = 0u32;
    // SAFETY: the buffer is writable for its full length; `got` receives the bytes written.
    let ok = unsafe {
        DeviceIoControl(
            h.0,
            FSCTL_GET_REPARSE_POINT,
            std::ptr::null(),
            0,
            buf.as_mut_ptr().cast(),
            buf.len() as u32,
            &mut got,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(ERROR_NOT_A_REPARSE_POINT as i32) {
            return Ok(None);
        }
        return Err(e);
    }
    buf.truncate(got as usize);
    parse_reparse(&buf, p)
}

fn u16_at(b: &[u8], at: usize) -> io::Result<u16> {
    b.get(at..at + 2)
        .map(|x| u16::from_le_bytes([x[0], x[1]]))
        .ok_or_else(|| io::Error::other("short reparse buffer"))
}

fn u32_at(b: &[u8], at: usize) -> io::Result<u32> {
    b.get(at..at + 4)
        .map(|x| u32::from_le_bytes([x[0], x[1], x[2], x[3]]))
        .ok_or_else(|| io::Error::other("short reparse buffer"))
}

/// The absolute target held in a `REPARSE_DATA_BUFFER`; `None` for a reparse point that is no
/// link (a cloud placeholder, a dedup file), an error for a link kind it cannot read.
pub(crate) fn parse_reparse(buf: &[u8], link: &Path) -> io::Result<Option<PathBuf>> {
    let tag = u32_at(buf, 0)?;
    let (path_at, relative) = match tag {
        TAG_MOUNT_POINT => (16, false),
        TAG_SYMLINK => (20, u32_at(buf, 16)? & SYMLINK_FLAG_RELATIVE != 0),
        t if t & TAG_NAME_SURROGATE != 0 => {
            return Err(io::Error::other(format!("unreadable link kind {t:#x}")));
        }
        _ => return Ok(None),
    };
    let off = path_at + usize::from(u16_at(buf, 8)?);
    let len = usize::from(u16_at(buf, 10)?);
    let bytes = buf
        .get(off..off + len)
        .ok_or_else(|| io::Error::other("short reparse buffer"))?;
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let name = String::from_utf16(&units).map_err(io::Error::other)?;
    if name.is_empty() {
        return Err(io::Error::other("empty link target"));
    }
    let target = if relative {
        let parent = link.parent().unwrap_or(link);
        format!(r"{}\{name}", parent.to_string_lossy())
    } else {
        nt_to_win32(&name)
    };
    Ok(Some(PathBuf::from(canonical(&target, Os::Windows))))
}

/// `\??\C:\x` → `C:\x`, `\??\UNC\s\h` → `\\s\h`, `\??\Volume{…}\` → `\\?\Volume{…}\`.
fn nt_to_win32(name: &str) -> String {
    let Some(rest) = name.strip_prefix(r"\??\") else {
        return name.to_string();
    };
    let b = rest.as_bytes();
    if b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':' {
        rest.to_string()
    } else if rest.len() >= 4 && rest[..4].eq_ignore_ascii_case(r"UNC\") {
        format!(r"\\{}", &rest[4..])
    } else {
        format!(r"\\?\{rest}")
    }
}

/// `p` with every 8.3 short name expanded, by `GetLongPathNameW`.
pub fn long_path(p: &Path) -> io::Result<PathBuf> {
    let name = wide(p);
    let mut buf = vec![0u16; 512];
    loop {
        // SAFETY: `name` is NUL-terminated; `buf` is writable for the length passed.
        let n = unsafe { GetLongPathNameW(name.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
        if n == 0 {
            return Err(io::Error::last_os_error());
        }
        if (n as usize) < buf.len() {
            buf.truncate(n as usize);
            return Ok(PathBuf::from(OsString::from_wide(&buf)));
        }
        buf.resize(n as usize + 1, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    /// A `REPARSE_DATA_BUFFER` with the substitute name first and the print name after it.
    fn buffer(tag: u32, flags: Option<u32>, sub: &str) -> Vec<u8> {
        let sub = utf16(sub);
        let print = utf16("print");
        let mut b = tag.to_le_bytes().to_vec();
        b.extend(0u32.to_le_bytes()); // data length + reserved, unread
        b.extend(0u16.to_le_bytes());
        b.extend((sub.len() as u16).to_le_bytes());
        b.extend((sub.len() as u16).to_le_bytes());
        b.extend((print.len() as u16).to_le_bytes());
        if let Some(f) = flags {
            b.extend(f.to_le_bytes());
        }
        b.extend(sub);
        b.extend(print);
        b
    }

    #[test]
    fn reparse_buffers_yield_win32_targets() {
        let link = Path::new(r"C:\w\root\l");
        let cases: &[(Vec<u8>, Option<&str>)] = &[
            (
                buffer(TAG_MOUNT_POINT, None, r"\??\D:\data\"),
                Some(r"D:\data"),
            ),
            (
                buffer(
                    TAG_MOUNT_POINT,
                    None,
                    r"\??\Volume{0b1c2d3e-0000-4000-8000-000000000001}\",
                ),
                Some(r"\\?\Volume{0b1c2d3e-0000-4000-8000-000000000001}\"),
            ),
            (
                buffer(TAG_SYMLINK, Some(0), r"\??\UNC\srv\share\x"),
                Some(r"\\srv\share\x"),
            ),
            (buffer(TAG_SYMLINK, Some(0), r"\??\C:\x"), Some(r"C:\x")),
            (buffer(TAG_SYMLINK, Some(1), r"..\up"), Some(r"C:\w\up")),
            (buffer(0x9000_001A, None, ""), None),
        ];
        for (buf, want) in cases {
            let got = parse_reparse(buf, link).unwrap();
            assert_eq!(got.as_deref(), want.map(Path::new), "{want:?}");
        }
        assert!(parse_reparse(&buffer(0xA000_001D, None, "x"), link).is_err());
        assert!(parse_reparse(&buffer(TAG_SYMLINK, Some(0), ""), link).is_err());
        assert!(parse_reparse(&[0x03, 0, 0, 0xA0], link).is_err());
    }
}
