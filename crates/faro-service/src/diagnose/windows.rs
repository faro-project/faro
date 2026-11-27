//! The Windows parts of a problem report: the service's state in the
//! Service Control Manager, the login sessions and each signed-in account's
//! agent log, the installed product (the MSI's Uninstall entry), the
//! Windows version and hardware, and the member's Desktop.
//!
//! The command runs in an elevated terminal, so its token is an
//! administrator's: it reads `C:\ProgramData\Faro` (SYSTEM and
//! Administrators only) and, since administrators can open other accounts'
//! profile folders, the agent logs there. It cannot ask for a session's
//! token (that needs LocalSystem), so an account's profile folder is found
//! from the registry's profile list by the account's name.

use super::{LogSource, Member};
use faro_platform_windows::{layout, scm, service};
use std::fmt::Write as _;
use std::io;
use std::path::PathBuf;
use windows::core::{HSTRING, PCWSTR, PWSTR};
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
use windows::Win32::System::Registry::{
    RegCloseKey, RegEnumKeyExW, RegGetValueW, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ,
    RRF_RT_REG_DWORD, RRF_RT_REG_SZ,
};
use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
use windows::Win32::UI::Shell::{FOLDERID_Desktop, SHGetKnownFolderPath, KF_FLAG_DEFAULT};

const UNINSTALL: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
const PROFILE_LIST: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
const WINDOWS_NT: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";

/// A string value under `HKEY_LOCAL_MACHINE`.
fn reg_string(subkey: &str, value: &str) -> Option<String> {
    let (k, v) = (HSTRING::from(subkey), HSTRING::from(value));
    let mut buf = [0u16; 1024];
    let mut bytes = std::mem::size_of_val(&buf) as u32;
    // SAFETY: `buf` is valid for `bytes` bytes; the strings are NUL-terminated.
    let err = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(k.as_ptr()),
            PCWSTR(v.as_ptr()),
            RRF_RT_REG_SZ,
            None,
            Some(buf.as_mut_ptr().cast()),
            Some(&mut bytes),
        )
    };
    if err != ERROR_SUCCESS {
        return None;
    }
    let n = (bytes as usize / 2).min(buf.len());
    let end = buf[..n].iter().position(|&c| c == 0).unwrap_or(n);
    Some(String::from_utf16_lossy(&buf[..end]))
}

fn reg_dword(subkey: &str, value: &str) -> Option<u32> {
    let (k, v) = (HSTRING::from(subkey), HSTRING::from(value));
    let mut data = 0u32;
    let mut bytes = 4u32;
    // SAFETY: `data` is valid for 4 bytes.
    let err = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(k.as_ptr()),
            PCWSTR(v.as_ptr()),
            RRF_RT_REG_DWORD,
            None,
            Some((&raw mut data).cast()),
            Some(&mut bytes),
        )
    };
    (err == ERROR_SUCCESS).then_some(data)
}

/// The names of the subkeys of `subkey` under `HKEY_LOCAL_MACHINE`.
fn reg_subkeys(subkey: &str) -> Vec<String> {
    let k = HSTRING::from(subkey);
    let mut key = HKEY::default();
    // SAFETY: a NUL-terminated name and a valid out pointer; closed below.
    let err = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(k.as_ptr()),
            None,
            KEY_READ,
            &mut key,
        )
    };
    if err != ERROR_SUCCESS {
        return Vec::new();
    }
    let mut names = Vec::new();
    for i in 0.. {
        let mut buf = [0u16; 256];
        let mut len = buf.len() as u32;
        // SAFETY: `buf` holds `len` units; the optional outputs are unused.
        let err = unsafe {
            RegEnumKeyExW(
                key,
                i,
                Some(PWSTR(buf.as_mut_ptr())),
                &mut len,
                None,
                None,
                None,
                None,
            )
        };
        if err != ERROR_SUCCESS {
            break;
        }
        names.push(String::from_utf16_lossy(&buf[..len as usize]));
    }
    // SAFETY: `key` was opened above and is closed once.
    let _ = unsafe { RegCloseKey(key) };
    names
}

/// The account running this elevated command, for its Desktop. `None` when
/// it runs as LocalSystem (whose Desktop nobody sees).
pub fn member() -> Option<Member> {
    if faro_platform_windows::acl::running_as_system() {
        return None;
    }
    let name = std::env::var("USERNAME").ok().filter(|n| !n.is_empty())?;
    Some(Member {
        name,
        uid: 0,
        gid: 0,
        home: std::env::var_os("USERPROFILE")
            .map(PathBuf::from)
            .unwrap_or_default(),
    })
}

/// The Desktop folder of the account whose token this process has.
pub fn desktop_folder() -> io::Result<PathBuf> {
    // SAFETY: a known folder id; the result is freed below.
    let p = unsafe { SHGetKnownFolderPath(&FOLDERID_Desktop, KF_FLAG_DEFAULT, None) }
        .map_err(|e| io::Error::other(format!("SHGetKnownFolderPath: {e}")))?;
    // SAFETY: a NUL-terminated string allocated by the call.
    let s = unsafe { p.to_string() };
    // SAFETY: allocated by SHGetKnownFolderPath, freed once, not used after.
    unsafe { windows::Win32::System::Com::CoTaskMemFree(Some(p.0.cast())) };
    s.map(PathBuf::from).map_err(io::Error::other)
}

/// A path as the OS reports it for a handle, made comparable: no verbatim
/// prefix, `\` separators, no trailing separator, lowercase.
fn comparable(p: &str) -> String {
    let p = p.replace('/', "\\");
    let p = if let Some(r) = p.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{r}")
    } else {
        p.strip_prefix(r"\\?\").unwrap_or(&p).to_owned()
    };
    p.trim_end_matches('\\').to_lowercase()
}

/// `path` with any 8.3 short names (`ZIMMER~1`) spelled out, which the OS
/// does for a handle's path too. Does not follow links.
fn long_path(path: &std::path::Path) -> std::path::PathBuf {
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Storage::FileSystem::GetLongPathNameW;
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    let mut buf = vec![0u16; 4096];
    // SAFETY: NUL-terminated input and an output buffer of the stated length.
    let n =
        unsafe { GetLongPathNameW(windows::core::PCWSTR(wide.as_ptr()), Some(&mut buf)) } as usize;
    if n == 0 || n > buf.len() {
        return path.to_path_buf();
    }
    String::from_utf16_lossy(&buf[..n]).into()
}

/// Refuses `handle` (opened from `requested`) when it is not at exactly
/// that path: some folder on the way is a junction or symbolic link, which
/// a user can plant in their own profile to aim the elevated command
/// somewhere else. Checks every component, on the handle that is read, so
/// there is no gap to race (the last component is also refused by the
/// caller's reparse-point test on the open itself).
pub fn verify_no_links(
    handle: &impl std::os::windows::io::AsRawHandle,
    requested: &std::path::Path,
) -> io::Result<()> {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{
        GetFinalPathNameByHandleW, FILE_NAME_NORMALIZED, GETFINALPATHNAMEBYHANDLE_FLAGS,
    };
    let mut buf = vec![0u16; 4096];
    // SAFETY: a live handle and a buffer of the stated length.
    let n = unsafe {
        GetFinalPathNameByHandleW(
            HANDLE(handle.as_raw_handle()),
            &mut buf,
            GETFINALPATHNAMEBYHANDLE_FLAGS(FILE_NAME_NORMALIZED.0),
        )
    } as usize;
    if n == 0 || n > buf.len() {
        return Err(io::Error::other("cannot resolve the path"));
    }
    let actual = String::from_utf16_lossy(&buf[..n]);
    let wanted = long_path(&std::path::absolute(requested)?);
    if comparable(&actual) != comparable(&wanted.to_string_lossy()) {
        return Err(io::Error::other(
            "a folder on the way is a link (junction or symbolic link)",
        ));
    }
    Ok(())
}

/// Opens a directory without following links and checks its whole path
/// with [`verify_no_links`].
pub fn check_dir_no_links(dir: &std::path::Path) -> io::Result<()> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(dir)?;
    // A handle on a link itself reports the link's own path, so the last
    // component is refused by its attribute.
    if f.metadata()?.file_attributes() & 0x400 != 0 {
        return Err(io::Error::other("it is a link (junction or symbolic link)"));
    }
    verify_no_links(&f, dir)
}

/// Each signed-in account's agent log (and the folder to list), and notes
/// on the ones that can't be reached.
pub fn agent_logs() -> (Vec<(String, LogSource)>, Vec<PathBuf>, String) {
    let mut logs = Vec::new();
    let mut dirs = Vec::new();
    let mut notes = String::new();
    let sessions = match service::enumerate_sessions() {
        Ok(s) => s,
        Err(e) => {
            let _ = writeln!(notes, "agent logs skipped: cannot list the sessions: {e}");
            return (logs, dirs, notes);
        }
    };
    let own = std::env::var("USERNAME").unwrap_or_default();
    let own_local = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    let profiles: Vec<PathBuf> = reg_subkeys(PROFILE_LIST)
        .into_iter()
        .filter_map(|sid| reg_string(&format!(r"{PROFILE_LIST}\{sid}"), "ProfileImagePath"))
        .map(PathBuf::from)
        .collect();
    let mut seen: Vec<String> = Vec::new();
    for s in sessions {
        if seen.contains(&s.user) {
            continue;
        }
        seen.push(s.user.clone());
        let local = if s.user.eq_ignore_ascii_case(&own) && own_local.is_some() {
            own_local.clone()
        } else {
            profiles
                .iter()
                .find(|p| profile_matches(p, &s.user))
                .map(|p| p.join("AppData").join("Local"))
        };
        match local {
            Some(local) => {
                let path = layout::agent_log(&local);
                if let Some(dir) = path.parent() {
                    // The account owns this folder: a junction anywhere on
                    // the way would aim this elevated command elsewhere.
                    if let Err(e) = check_dir_no_links(dir) {
                        if e.kind() != io::ErrorKind::NotFound {
                            let _ = writeln!(
                                notes,
                                "{}'s agent log skipped: {}: {e}",
                                s.user,
                                dir.display()
                            );
                            continue;
                        }
                    }
                    dirs.push(dir.to_path_buf());
                }
                logs.push((
                    s.user.clone(),
                    LogSource {
                        path,
                        keep: layout::LOG_KEEP,
                        owner: None,
                    },
                ));
            }
            None => {
                let _ = writeln!(
                    notes,
                    "{}'s agent log skipped: no profile folder found for the account",
                    s.user
                );
            }
        }
    }
    (logs, dirs, notes)
}

/// `C:\Users\alex` (or `alex.DOMAIN`, which Windows makes when the name is
/// taken) is the profile of the account `alex`.
fn profile_matches(profile: &std::path::Path, user: &str) -> bool {
    let Some(leaf) = profile.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let (leaf, user) = (leaf.to_ascii_lowercase(), user.to_ascii_lowercase());
    leaf == user || leaf.strip_prefix(&user).is_some_and(|r| r.starts_with('.'))
}

/// Windows version, hardware, memory and disk space.
pub fn system(o: &mut String) {
    let _ = writeln!(o);
    let get = |v| reg_string(WINDOWS_NT, v).unwrap_or_else(|| "unknown".into());
    // Windows 11 still says "Windows 10" in ProductName; the build tells.
    let build = get("CurrentBuildNumber");
    let mut product = get("ProductName");
    if build.parse::<u32>().is_ok_and(|b| b >= 22000) {
        product = product.replace("Windows 10", "Windows 11");
    }
    let _ = writeln!(
        o,
        "Windows: {product} {} (build {build}.{})",
        get("DisplayVersion"),
        reg_dword(WINDOWS_NT, "UBR").map_or_else(|| "?".into(), |n| n.to_string()),
    );
    let (maker, model) = faro_platform_windows::tamper::bios_strings();
    let _ = writeln!(o, "Computer: {maker} {model}");
    let mut mem = MEMORYSTATUSEX {
        dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
        ..Default::default()
    };
    // SAFETY: `dwLength` is set; a valid out pointer.
    if unsafe { GlobalMemoryStatusEx(&mut mem) }.is_ok() {
        let _ = writeln!(o, "Memory (bytes): {}", mem.ullTotalPhys);
    }
    for dir in [layout::DATA_DIR, layout::PROGRAM_DIR] {
        let (mut free, mut total) = (0u64, 0u64);
        let w = HSTRING::from(dir);
        // SAFETY: a NUL-terminated path and valid out pointers.
        let ok = unsafe {
            GetDiskFreeSpaceExW(PCWSTR(w.as_ptr()), Some(&mut free), Some(&mut total), None)
        };
        if ok.is_ok() {
            let _ = writeln!(o, "Disk of {dir}: {free} bytes free of {total}");
        }
    }
}

/// The Faro service in the Service Control Manager, and the login sessions.
pub fn service_text() -> String {
    let mut o = String::new();
    let _ = write!(o, "Service {}: ", layout::SERVICE_NAME);
    match scm::service_state(layout::SERVICE_NAME) {
        Ok(Some(state)) => {
            let _ = writeln!(o, "{state:?}");
        }
        Ok(None) => {
            let _ = writeln!(o, "not installed");
        }
        Err(e) => {
            let _ = writeln!(o, "cannot be queried: {e}");
        }
    }
    let _ = writeln!(o);
    let _ = writeln!(
        o,
        "Login sessions (id, account, state, protocol, Faro agent):"
    );
    match service::enumerate_sessions() {
        Ok(sessions) if sessions.is_empty() => {
            let _ = writeln!(o, "  none");
        }
        Ok(sessions) => {
            let agents = agent_sessions();
            for s in sessions {
                let _ = writeln!(
                    o,
                    "  {}  {}  {:?}  {:?}  agent {}",
                    service::session_id(s.id).0,
                    s.user,
                    s.state,
                    s.protocol,
                    if agents.contains(&s.id) {
                        "running"
                    } else {
                        "not running"
                    },
                );
            }
        }
        Err(e) => {
            let _ = writeln!(o, "  cannot list them: {e}");
        }
    }
    o
}

/// The sessions with a `faro-agent.exe` process in them.
fn agent_sessions() -> Vec<u32> {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    let mut out = Vec::new();
    // SAFETY: a snapshot handle closed below; entries are filled by the calls.
    unsafe {
        let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else {
            return out;
        };
        let mut e = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut ok = Process32FirstW(snap, &mut e).is_ok();
        while ok {
            let n = e
                .szExeFile
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(e.szExeFile.len());
            if String::from_utf16_lossy(&e.szExeFile[..n]).eq_ignore_ascii_case("faro-agent.exe") {
                if let Some(id) = crate::win::process_session_id(e.th32ProcessID) {
                    out.push(id);
                }
            }
            ok = Process32NextW(snap, &mut e).is_ok();
        }
        let _ = windows::Win32::Foundation::CloseHandle(snap);
    }
    out
}

/// The installed product (the MSI's Uninstall entry) and the programs.
pub fn package() -> String {
    let mut o = String::new();
    let mut found = false;
    for key in reg_subkeys(UNINSTALL) {
        let path = format!(r"{UNINSTALL}\{key}");
        if reg_string(&path, "DisplayName").as_deref() != Some("Faro") {
            continue;
        }
        found = true;
        let _ = writeln!(o, "Installed product (Windows Installer, {key}):");
        for (label, value) in [
            ("Version", "DisplayVersion"),
            ("Publisher", "Publisher"),
            ("Install location", "InstallLocation"),
            ("Install date", "InstallDate"),
        ] {
            if let Some(v) = reg_string(&path, value) {
                let _ = writeln!(o, "  {label}: {v}");
            }
        }
    }
    if !found {
        let _ = writeln!(o, "No installed product named Faro in the Uninstall list.");
    }
    let _ = writeln!(o);
    for p in [layout::SERVICE_PROGRAM, layout::AGENT_PROGRAM] {
        let _ = write!(o, "{p}: ");
        match std::fs::metadata(p) {
            Ok(m) => {
                let _ = write!(o, "{} bytes; ", m.len());
            }
            Err(e) => {
                let _ = writeln!(o, "{e}");
                continue;
            }
        }
        match faro_platform_windows::authenticode::signer_of(std::path::Path::new(p)) {
            Ok(s) => {
                let _ = writeln!(o, "signed by {} ({})", s.subject, s.thumbprint_sha256);
            }
            Err(e) => {
                let _ = writeln!(o, "signature: {e}");
            }
        }
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_paths_compare_without_prefixes_or_case() {
        assert_eq!(
            comparable(r"\\?\C:\Users\Alex\"),
            comparable("c:/users/alex")
        );
        assert_eq!(comparable(r"\\?\UNC\srv\share"), r"\\srv\share");
    }

    fn junction(link: &std::path::Path, target: &std::path::Path) {
        let st = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .output()
            .unwrap();
        assert!(st.status.success(), "mklink: {st:?}");
    }

    #[test]
    fn a_junction_anywhere_on_the_path_is_refused() {
        let t = tempfile::tempdir().unwrap();
        let real = t.path().join("real");
        std::fs::create_dir_all(real.join("Faro")).unwrap();
        std::fs::write(real.join("Faro").join("agent.log"), "x").unwrap();
        let plain = real.join("Faro");
        check_dir_no_links(&plain).expect("a plain folder passes");
        // A junction in the middle of the path (not the last component).
        let link = t.path().join("Local");
        junction(&link, &real);
        let through = link.join("Faro");
        let e = check_dir_no_links(&through).expect_err("junction in the middle");
        assert!(e.to_string().contains("link"), "{e}");
        // ...and as the last component.
        let leaf = t.path().join("leaf");
        junction(&leaf, &plain);
        assert!(check_dir_no_links(&leaf).is_err());
        // The file read refuses it too.
        let f = std::fs::File::open(through.join("agent.log")).unwrap();
        assert!(verify_no_links(&f, &through.join("agent.log")).is_err());
        let f = std::fs::File::open(plain.join("agent.log")).unwrap();
        verify_no_links(&f, &plain.join("agent.log")).unwrap();
    }

    #[test]
    fn a_profile_folder_belongs_to_its_account() {
        let p = |s| std::path::PathBuf::from(s);
        assert!(profile_matches(&p(r"C:\Users\Alex"), "alex"));
        assert!(profile_matches(&p(r"C:\Users\alex.PC1"), "alex"));
        assert!(!profile_matches(&p(r"C:\Users\alexandra"), "alex"));
    }
}
