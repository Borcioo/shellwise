//! A fake shellwise release in a local folder, laid out as the release workflow publishes it:
//! `<base>/download/v<version>/<archive>`, `<base>/download/v<version>/SHA256SUMS` and
//! `<base>/latest/download/SHA256SUMS`. Each archive holds the folder
//! `shellwise-v<version>-<target>/` with the fake binary and a `VERSION` marker file inside.

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};

/// The target the install script picks on this machine when nothing overrides it.
pub fn host_target() -> &'static str {
    if cfg!(windows) {
        "x86_64-pc-windows-msvc"
    } else if cfg!(target_os = "macos") {
        if cfg!(target_arch = "aarch64") {
            "aarch64-apple-darwin"
        } else {
            "x86_64-apple-darwin"
        }
    } else if cfg!(target_arch = "aarch64") {
        "aarch64-unknown-linux-musl"
    } else {
        "x86_64-unknown-linux-musl"
    }
}

/// The binary's file name on this OS.
pub fn bin_name() -> &'static str {
    if cfg!(windows) {
        "shellwise.exe"
    } else {
        "shellwise"
    }
}

pub fn archive_name(version: &str, target: &str) -> String {
    let ext = if target.contains("windows") {
        "zip"
    } else {
        "tar.gz"
    };
    format!("shellwise-v{version}-{target}.{ext}")
}

/// The fake binary of one version and target: the test binary with a tag appended, so it still
/// runs and each version and target has its own bytes.
pub fn fake_binary(version: &str, target: &str) -> Vec<u8> {
    let mut bytes = std::fs::read(env!("CARGO_BIN_EXE_shellwise")).expect("read the test binary");
    bytes.extend_from_slice(format!("\nshellwise-fake {version} {target}\n").as_bytes());
    bytes
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A fresh folder under the system temp folder, unique to this process and call.
pub fn temp_folder(label: &str) -> PathBuf {
    static NEXT: Mutex<u32> = Mutex::new(0);
    let n = {
        let mut next = NEXT.lock().unwrap();
        *next += 1;
        *next
    };
    let dir = std::env::temp_dir()
        .join("shellwise-install-tests")
        .join(format!("{}-{n}-{label}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create a temp folder");
    dir
}

/// Each archive is built once per test process, kept in memory (its build folder is removed) and
/// written into every release that needs it.
fn cached_archive(version: &str, target: &str) -> Vec<u8> {
    static CACHE: OnceLock<Mutex<HashMap<String, Vec<u8>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut built = cache.lock().unwrap();
    let name = archive_name(version, target);
    if let Some(bytes) = built.get(&name) {
        return bytes.clone();
    }
    let work = temp_folder("archive");
    let folder = format!("shellwise-v{version}-{target}");
    let inner = work.join("stage").join(&folder);
    std::fs::create_dir_all(&inner).unwrap();
    let exe = if target.contains("windows") {
        "shellwise.exe"
    } else {
        "shellwise"
    };
    std::fs::write(inner.join(exe), fake_binary(version, target)).unwrap();
    std::fs::write(inner.join("VERSION"), version).unwrap();
    let out = work.join(&name);
    if name.ends_with(".zip") {
        zip_folder(&inner, &out, &work);
    } else {
        let status = Command::new("tar")
            .arg("-czf")
            .arg(&out)
            .arg("-C")
            .arg(work.join("stage"))
            .arg(&folder)
            .status()
            .expect("run tar");
        assert!(status.success(), "tar -czf {out:?}: {status}");
    }
    let bytes = std::fs::read(&out).unwrap_or_else(|e| panic!("no archive at {out:?}: {e}"));
    let _ = std::fs::remove_dir_all(&work);
    built.insert(name, bytes.clone());
    bytes
}

/// `Compress-Archive` of `folder` (kept as the top-level entry) into `out`. The paths go through
/// the environment, so no quote or glob character is passed as an argument.
fn zip_folder(folder: &Path, out: &Path, work: &Path) {
    let script = work.join("zip.ps1");
    std::fs::write(
        &script,
        "$ErrorActionPreference = 'Stop'\n\
         Compress-Archive -LiteralPath $env:ZIP_SRC -DestinationPath $env:ZIP_DST\n",
    )
    .unwrap();
    let shell = powershell_for_tools().expect("pwsh or powershell to build a .zip");
    let out_put = Command::new(shell)
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ])
        .arg(&script)
        .env("ZIP_SRC", folder)
        .env("ZIP_DST", out)
        .env("POWERSHELL_TELEMETRY_OPTOUT", "1")
        .stdin(Stdio::null())
        .output()
        .expect("run Compress-Archive");
    assert!(
        out_put.status.success(),
        "Compress-Archive failed: {}",
        String::from_utf8_lossy(&out_put.stderr)
    );
}

fn powershell_for_tools() -> Option<&'static str> {
    ["pwsh", "powershell"].into_iter().find(|p| {
        Command::new(p)
            .args(["-NoProfile", "-NonInteractive", "-Command", "exit"])
            .env("POWERSHELL_TELEMETRY_OPTOUT", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    })
}

pub struct Release {
    pub base: PathBuf,
}

impl Release {
    pub fn new(root: &Path) -> Self {
        let base = root.join("release");
        std::fs::create_dir_all(&base).unwrap();
        Release { base }
    }

    pub fn version_dir(&self, version: &str) -> PathBuf {
        self.base.join("download").join(format!("v{version}"))
    }

    pub fn archive_path(&self, version: &str, target: &str) -> PathBuf {
        self.version_dir(version)
            .join(archive_name(version, target))
    }

    pub fn sums_path(&self, version: &str) -> PathBuf {
        self.version_dir(version).join("SHA256SUMS")
    }

    pub fn latest_sums_path(&self) -> PathBuf {
        self.base.join("latest").join("download").join("SHA256SUMS")
    }

    /// Lays out the archives of `version` for `targets` and its `SHA256SUMS`, in the format
    /// `sha256sum` writes (`<hex>  <name>`).
    pub fn publish(&self, version: &str, targets: &[&str]) {
        let dir = self.version_dir(version);
        std::fs::create_dir_all(&dir).unwrap();
        let mut sums = String::new();
        for target in targets {
            let dest = self.archive_path(version, target);
            std::fs::write(&dest, cached_archive(version, target)).unwrap();
            let hex = sha256_hex(&std::fs::read(&dest).unwrap());
            sums.push_str(&format!("{hex}  {}\n", archive_name(version, target)));
        }
        std::fs::write(self.sums_path(version), sums).unwrap();
    }

    /// Makes `version` the latest release.
    pub fn mark_latest(&self, version: &str) {
        let latest = self.latest_sums_path();
        std::fs::create_dir_all(latest.parent().unwrap()).unwrap();
        std::fs::copy(self.sums_path(version), latest).unwrap();
    }

    /// Writes `text` as the `SHA256SUMS` of `version` and, when it is the latest, there too.
    pub fn write_sums(&self, version: &str, text: &str) {
        let latest = self.latest_sums_path();
        let is_latest = std::fs::read(&latest).ok() == std::fs::read(self.sums_path(version)).ok();
        std::fs::write(self.sums_path(version), text).unwrap();
        if is_latest {
            std::fs::write(latest, text).unwrap();
        }
    }

    pub fn sums(&self, version: &str) -> String {
        std::fs::read_to_string(self.sums_path(version)).unwrap()
    }
}
