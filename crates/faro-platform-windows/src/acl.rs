//! File and directory ACLs, and the privilege of the current process.
//!
//! The service keeps its state (config, device keys, outbox, journal) in
//! `%ProgramData%\Faro` ([`crate::layout::DATA_DIR`]). `%ProgramData%`
//! itself lets every user create folders there and owns what they create,
//! so the service must not trust whatever it finds: it gives the directory
//! a **protected** DACL (no ACEs inherited from `%ProgramData%`) naming only
//! SYSTEM and Administrators, resets every existing child to inherit just
//! that, and takes ownership (an owner can always rewrite a DACL, so a
//! directory a user pre-created and still owns would not stay protected).
//!
//! The directories are set with SDDL ([`STATE_DIR_SDDL`], [`LOG_DIR_SDDL`])
//! through `ConvertStringSecurityDescriptorToSecurityDescriptorW` and
//! `SetNamedSecurityInfoW` with `PROTECTED_DACL_SECURITY_INFORMATION`.
//!
//! **Call order:** [`protect_state_dir`] first, then [`protect_log_dir`]
//! (the log directory sits inside the state directory, and protecting the
//! state directory resets its children to inherit).
//!
//! **Reparse points** (symbolic links, junctions, mount points) are refused
//! anywhere in the tree: a privileged process rewriting ACLs through a link
//! a user planted is a classic way to have it lock down, or hand over, a
//! file of the attacker's choosing.

use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    GetNamedSecurityInfoW, SetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    AclSizeInformation, CheckTokenMembership, CreateWellKnownSid, GetAce, GetAclInformation,
    GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, GetTokenInformation, IsWellKnownSid,
    TokenElevation, TokenUser, WinBuiltinAdministratorsSid, WinLocalSystemSid, ACE_HEADER, ACL,
    ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION, INHERIT_ONLY_ACE, OBJECT_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SECURITY_MAX_SID_SIZE, TOKEN_ELEVATION, TOKEN_QUERY, UNPROTECTED_DACL_SECURITY_INFORMATION,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// The state directory's DACL: protected (`P`), auto-inherited (`AI`),
/// SYSTEM and Administrators full control, inherited by subfolders and
/// files (`OICI`). Nobody else, not even read: the directory holds the
/// device's private keys.
pub const STATE_DIR_SDDL: &str = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

/// The log directory's DACL: SYSTEM full control, Administrators read
/// (`FR`), so an ally with the admin password can read the service log
/// without being able to quietly edit it.
pub const LOG_DIR_SDDL: &str = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FR;;;BA)";

/// Accounts whose write access to Faro's files is expected.
const TRUSTED_SIDS: [&str; 3] = [
    "S-1-5-18",     // LocalSystem
    "S-1-5-32-544", // BUILTIN\Administrators
    // NT SERVICE\TrustedInstaller (owns the OS's own files).
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
];

/// SIDs that appear in ACEs but never match a token: CREATOR OWNER and
/// CREATOR GROUP (placeholders for inheritance), and OWNER RIGHTS (applies
/// to the owner, which is checked separately).
const INERT_SIDS: [&str; 3] = ["S-1-3-0", "S-1-3-1", "S-1-3-4"];

/// Access rights that let a holder change what a file or directory holds,
/// or change who may: write/append data (for a directory: add files and
/// subdirectories), delete it or its children, rewrite its DACL or owner,
/// and the generic rights that include those.
const WRITE_RIGHTS: u32 = 0x0000_0002 // FILE_WRITE_DATA / FILE_ADD_FILE
    | 0x0000_0004 // FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
    | 0x0000_0040 // FILE_DELETE_CHILD
    | 0x0001_0000 // DELETE
    | 0x0004_0000 // WRITE_DAC
    | 0x0008_0000 // WRITE_OWNER
    | 0x1000_0000 // GENERIC_ALL
    | 0x4000_0000; // GENERIC_WRITE

/// Give `dir` a protected (non-inherited) DACL granting full control to
/// SYSTEM and Administrators only, applied to it and inherited by children.
///
/// Also: the owner becomes SYSTEM when running as SYSTEM (Administrators
/// when running as an elevated administrator; unchanged otherwise, which
/// only happens in tests), and every existing child loses its explicit
/// ACEs and inherits only from `dir`. Fails if `dir` or anything under it
/// is a reparse point.
pub fn protect_state_dir(dir: &Path) -> std::io::Result<()> {
    protect_tree(dir, STATE_DIR_SDDL)
}

/// Give a log directory SYSTEM full control and Administrators read.
/// Same treatment of owner, children and reparse points as
/// [`protect_state_dir`].
pub fn protect_log_dir(dir: &Path) -> std::io::Result<()> {
    protect_tree(dir, LOG_DIR_SDDL)
}

fn protect_tree(dir: &Path, dacl_sddl: &str) -> std::io::Result<()> {
    let meta = std::fs::symlink_metadata(dir)?;
    if is_reparse(&meta) {
        return Err(reparse_error(dir));
    }
    if !meta.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} is not a directory", dir.display()),
        ));
    }
    // List the tree before locking it down: afterwards a test running as a
    // plain user (the owner) could no longer list it. In production the
    // service runs as SYSTEM, and once the root is protected nobody else
    // can add entries, so nothing is missed.
    let mut children = Vec::new();
    collect_children(dir, &mut children)?;

    let owner = owner_sddl();
    let root = SecurityDescriptor::from_sddl(&format!("{owner}{dacl_sddl}"))?;
    let mut info = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
    if !owner.is_empty() {
        info |= OWNER_SECURITY_INFORMATION;
    }
    set_named(dir, info, &root)?;

    // Children: an empty, unprotected DACL means "only what is inherited".
    let child = SecurityDescriptor::from_sddl(&format!("{owner}D:AI"))?;
    let mut info = DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION;
    if !owner.is_empty() {
        info |= OWNER_SECURITY_INFORMATION;
    }
    for c in &children {
        set_named(c, info, &child)?;
    }
    Ok(())
}

/// The owner part of the SDDL for what this process may set as owner.
fn owner_sddl() -> &'static str {
    if running_as_system() {
        "O:SY"
    } else if running_elevated() {
        "O:BA"
    } else {
        ""
    }
}

fn is_reparse(meta: &std::fs::Metadata) -> bool {
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

fn reparse_error(p: &Path) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!(
            "{} is a reparse point (link or junction); refusing to change its ACL",
            p.display()
        ),
    )
}

fn collect_children(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        let meta = std::fs::symlink_metadata(&path)?;
        if is_reparse(&meta) {
            return Err(reparse_error(&path));
        }
        out.push(path.clone());
        if meta.is_dir() {
            collect_children(&path, out)?;
        }
    }
    Ok(())
}

fn wide(p: &Path) -> Vec<u16> {
    p.as_os_str().encode_wide().chain(Some(0)).collect()
}

/// A self-relative security descriptor from `LocalAlloc`, freed on drop.
struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

impl SecurityDescriptor {
    fn from_sddl(sddl: &str) -> std::io::Result<Self> {
        let w: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
        let mut sd = PSECURITY_DESCRIPTOR::default();
        // SAFETY: `w` is NUL-terminated; `sd` is a valid out pointer.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(w.as_ptr()),
                SDDL_REVISION_1,
                &mut sd,
                None,
            )
        }
        .map_err(std::io::Error::from)?;
        Ok(SecurityDescriptor(sd))
    }

    /// The owner SID, if the descriptor has one.
    fn owner(&self) -> std::io::Result<Option<PSID>> {
        let mut owner = PSID::default();
        let mut defaulted = Default::default();
        // SAFETY: `self.0` is a valid descriptor; out pointers are valid.
        unsafe { GetSecurityDescriptorOwner(self.0, &mut owner, &mut defaulted) }
            .map_err(std::io::Error::from)?;
        Ok((!owner.0.is_null()).then_some(owner))
    }

    /// The DACL: `Ok(None)` when absent or NULL (which grants everyone
    /// everything), otherwise a pointer into the descriptor.
    fn dacl(&self) -> std::io::Result<Option<*const ACL>> {
        let mut present = Default::default();
        let mut defaulted = Default::default();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        // SAFETY: `self.0` is a valid descriptor; out pointers are valid.
        unsafe { GetSecurityDescriptorDacl(self.0, &mut present, &mut dacl, &mut defaulted) }
            .map_err(std::io::Error::from)?;
        Ok((present.as_bool() && !dacl.is_null()).then_some(dacl.cast_const()))
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: allocated by LocalAlloc (SDDL conversion or
        // GetNamedSecurityInfoW), freed once.
        unsafe { LocalFree(Some(HLOCAL(self.0 .0))) };
    }
}

fn set_named(
    path: &Path,
    info: OBJECT_SECURITY_INFORMATION,
    sd: &SecurityDescriptor,
) -> std::io::Result<()> {
    let w = wide(path);
    let owner = if info.contains(OWNER_SECURITY_INFORMATION) {
        sd.owner()?
    } else {
        None
    };
    let dacl = sd.dacl()?;
    // SAFETY: `w` is NUL-terminated; owner and DACL point into `sd`, which
    // outlives the call.
    let err = unsafe {
        SetNamedSecurityInfoW(
            PCWSTR(w.as_ptr()),
            SE_FILE_OBJECT,
            info,
            owner,
            None,
            dacl,
            None,
        )
    };
    if err.is_err() {
        return Err(std::io::Error::other(format!(
            "SetNamedSecurityInfoW({}): {}",
            path.display(),
            std::io::Error::from_raw_os_error(err.0 as i32)
        )));
    }
    Ok(())
}

fn get_named(
    path: &Path,
    info: OBJECT_SECURITY_INFORMATION,
) -> std::io::Result<SecurityDescriptor> {
    let w = wide(path);
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `w` is NUL-terminated; we ask only for the whole descriptor
    // (`sd`, freed by `SecurityDescriptor`) and read parts from it.
    let err = unsafe {
        GetNamedSecurityInfoW(
            PCWSTR(w.as_ptr()),
            SE_FILE_OBJECT,
            info,
            None,
            None,
            None,
            None,
            &mut sd,
        )
    };
    if err.is_err() {
        return Err(std::io::Error::from_raw_os_error(err.0 as i32));
    }
    Ok(SecurityDescriptor(sd))
}

/// A SID as `S-1-…` text.
fn sid_string(sid: PSID) -> std::io::Result<String> {
    let mut s = PWSTR::null();
    // SAFETY: `sid` is a valid SID; `s` receives a LocalAlloc'd string.
    unsafe { ConvertSidToStringSidW(sid, &mut s) }.map_err(std::io::Error::from)?;
    // SAFETY: `s` is a valid NUL-terminated string until freed below.
    let out = unsafe { s.to_string() }.map_err(|e| std::io::Error::other(e.to_string()));
    // SAFETY: allocated by ConvertSidToStringSidW, freed once.
    unsafe { LocalFree(Some(HLOCAL(s.0.cast()))) };
    out
}

/// Whether `path`'s DACL grants write to anyone but SYSTEM, Administrators
/// or TrustedInstaller (a tamper check on Faro's own files).
///
/// "Write" means any right that lets the holder change the object's
/// contents or who may change them: write/append data (add files or
/// subdirectories, for a directory), delete it or its children, rewrite
/// its DACL or owner, and `GENERIC_WRITE`/`GENERIC_ALL`. Also `true`:
///
/// * the owner is anyone else (an owner can always rewrite the DACL);
/// * the DACL is NULL (everyone has full access).
///
/// Inherit-only ACEs (which apply only to children) and placeholder SIDs
/// (CREATOR OWNER/GROUP, OWNER RIGHTS) are ignored. Deny ACEs are not
/// credited, so the answer errs towards "writable". The check reads the
/// object's own DACL, not effective access through its parents (except
/// that renaming needs `DELETE` here or `FILE_DELETE_CHILD` on the parent:
/// check the parent too when that matters, as `verify_process` does).
pub fn writable_by_others(path: &Path) -> std::io::Result<bool> {
    let sd = get_named(path, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION)?;
    match sd.owner()? {
        Some(owner) if TRUSTED_SIDS.contains(&sid_string(owner)?.as_str()) => {}
        _ => return Ok(true),
    }
    let Some(dacl) = sd.dacl()? else {
        return Ok(true);
    };
    let mut size = ACL_SIZE_INFORMATION::default();
    // SAFETY: `dacl` points into `sd`; `size` is a correctly sized buffer.
    unsafe {
        GetAclInformation(
            dacl,
            (&raw mut size).cast(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    }
    .map_err(std::io::Error::from)?;
    for i in 0..size.AceCount {
        let mut ace: *mut core::ffi::c_void = std::ptr::null_mut();
        // SAFETY: `i` < AceCount; `ace` points into `sd`.
        unsafe { GetAce(dacl, i, &mut ace) }.map_err(std::io::Error::from)?;
        // SAFETY: every ACE starts with an ACE_HEADER.
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        // ACCESS_ALLOWED_ACE_TYPE (0) and ACCESS_ALLOWED_CALLBACK_ACE_TYPE
        // (9) share the layout header, mask, SID. Object ACEs (5, 0xB) only
        // appear on directory-service objects, never on files; other types
        // are deny or audit entries.
        if !matches!(header.AceType, 0 | 9) {
            continue;
        }
        if u32::from(header.AceFlags) & INHERIT_ONLY_ACE.0 != 0 {
            continue;
        }
        // SAFETY: for these types the header is followed by the u32 mask
        // and the SID starts right after it (ACCESS_ALLOWED_ACE layout).
        let (mask, sid) = unsafe {
            let p = ace.cast::<u8>().add(size_of::<ACE_HEADER>());
            (p.cast::<u32>().read_unaligned(), PSID(p.add(4).cast()))
        };
        if mask & WRITE_RIGHTS == 0 {
            continue;
        }
        let sid = sid_string(sid)?;
        if TRUSTED_SIDS.contains(&sid.as_str()) || INERT_SIDS.contains(&sid.as_str()) {
            continue;
        }
        return Ok(true);
    }
    Ok(false)
}

/// The current process token, closed on drop.
struct Token(HANDLE);

impl Token {
    fn current() -> Option<Token> {
        let mut h = HANDLE::default();
        // SAFETY: the pseudo-handle from GetCurrentProcess needs no closing;
        // `h` is a valid out pointer.
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut h) }.ok()?;
        Some(Token(h))
    }

    /// Fixed- or variable-size token information into an aligned buffer.
    fn info(&self, class: windows::Win32::Security::TOKEN_INFORMATION_CLASS) -> Option<Vec<u64>> {
        let mut len = 0u32;
        // SAFETY: a size query with no buffer.
        let _ = unsafe { GetTokenInformation(self.0, class, None, 0, &mut len) };
        if len == 0 {
            return None;
        }
        let mut buf = vec![0u64; (len as usize).div_ceil(8)];
        // SAFETY: `buf` holds at least `len` bytes, 8-byte aligned.
        unsafe { GetTokenInformation(self.0, class, Some(buf.as_mut_ptr().cast()), len, &mut len) }
            .ok()?;
        Some(buf)
    }
}

impl Drop for Token {
    fn drop(&mut self) {
        // SAFETY: we own the token handle.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

/// Whether the current process token is LocalSystem.
pub fn running_as_system() -> bool {
    let Some(token) = Token::current() else {
        return false;
    };
    let Some(buf) = token.info(TokenUser) else {
        return false;
    };
    // SAFETY: TokenUser fills a TOKEN_USER whose SID points into `buf`.
    unsafe {
        let user = &*buf.as_ptr().cast::<windows::Win32::Security::TOKEN_USER>();
        IsWellKnownSid(user.User.Sid, WinLocalSystemSid).as_bool()
    }
}

/// Whether the current process token is an elevated administrator: the
/// token is elevated (UAC full token, or SYSTEM) **and** Administrators is
/// an enabled group in it. Elevation alone is not enough (some non-admin
/// tokens, such as Backup Operators', are also "elevated").
pub fn running_elevated() -> bool {
    let Some(token) = Token::current() else {
        return false;
    };
    let elevated = token.info(TokenElevation).is_some_and(|b| {
        // SAFETY: TokenElevation fills a TOKEN_ELEVATION.
        unsafe { (*b.as_ptr().cast::<TOKEN_ELEVATION>()).TokenIsElevated != 0 }
    });
    if !elevated {
        return false;
    }
    let mut sid = [0u8; SECURITY_MAX_SID_SIZE as usize];
    let mut len = sid.len() as u32;
    let psid = PSID(sid.as_mut_ptr().cast());
    // SAFETY: `sid` has room for any SID; `len` is its size.
    if unsafe { CreateWellKnownSid(WinBuiltinAdministratorsSid, None, Some(psid), &mut len) }
        .is_err()
    {
        return false;
    }
    let mut member = Default::default();
    // SAFETY: a None token means "the calling thread's effective token";
    // `psid` is a valid SID.
    unsafe { CheckTokenMembership(None, psid, &mut member) }.is_ok() && member.as_bool()
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Security::Authorization::ConvertSecurityDescriptorToStringSecurityDescriptorW;

    /// The DACL of `path` as SDDL.
    fn dacl_sddl(path: &Path) -> String {
        let sd = get_named(path, DACL_SECURITY_INFORMATION).unwrap();
        let mut s = PWSTR::null();
        // SAFETY: valid descriptor and out pointer.
        unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd.0,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut s,
                None,
            )
        }
        .unwrap();
        // SAFETY: NUL-terminated LocalAlloc'd string, freed once.
        let out = unsafe { s.to_string() }.unwrap();
        unsafe { LocalFree(Some(HLOCAL(s.0.cast()))) };
        out
    }

    /// Give the tree back to everyone so the temp dir can be deleted (the
    /// test user still owns it, and an owner may always rewrite the DACL).
    fn loosen(dir: &Path) {
        let sd = SecurityDescriptor::from_sddl("D:P(A;OICI;FA;;;WD)").unwrap();
        set_named(
            dir,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            &sd,
        )
        .unwrap();
    }

    #[test]
    fn sddl_constants_parse() {
        for s in [STATE_DIR_SDDL, LOG_DIR_SDDL] {
            let sd = SecurityDescriptor::from_sddl(s).unwrap();
            assert!(sd.dacl().unwrap().is_some());
        }
    }

    #[test]
    fn state_dir_is_protected_and_children_reset() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("Faro");
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("config.toml"), b"x").unwrap();
        std::fs::write(dir.join("sub").join("key"), b"k").unwrap();
        // A child that a user pre-created with its own, permissive DACL.
        let open = SecurityDescriptor::from_sddl("D:P(A;;FA;;;WD)").unwrap();
        set_named(
            &dir.join("config.toml"),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            &open,
        )
        .unwrap();
        assert!(dacl_sddl(&dir.join("config.toml")).contains(";;;WD)"));

        protect_state_dir(&dir).unwrap();

        assert_eq!(dacl_sddl(&dir), STATE_DIR_SDDL);
        for child in [
            dir.join("config.toml"),
            dir.join("sub"),
            dir.join("sub").join("key"),
        ] {
            let s = dacl_sddl(&child);
            // Only inherited ACEs (`ID`), from SYSTEM and Administrators.
            assert!(s.starts_with("D:AI("), "{}: {s}", child.display());
            assert!(!s.contains("WD"), "{}: {s}", child.display());
            for ace in s
                .trim_start_matches("D:AI")
                .split(')')
                .filter(|a| !a.is_empty())
            {
                assert!(ace.contains("ID"), "{}: {s}", child.display());
                assert!(
                    ace.ends_with(";;;SY") || ace.ends_with(";;;BA"),
                    "{}: {s}",
                    child.display()
                );
            }
        }
        // Owned by the (non-admin) test user, so still "writable by others"
        // unless this test runs elevated, where ownership moved to BA/SY.
        assert_eq!(
            writable_by_others(&dir).unwrap(),
            !(running_elevated() || running_as_system())
        );

        loosen(&dir);
    }

    #[test]
    fn log_dir_gives_admins_read_only() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("logs");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("faro-service.log"), b"").unwrap();
        protect_log_dir(&dir).unwrap();
        assert_eq!(dacl_sddl(&dir), LOG_DIR_SDDL);
        assert!(dacl_sddl(&dir.join("faro-service.log")).contains("FR;;;BA"));
        loosen(&dir);
    }

    #[test]
    fn reparse_points_and_files_are_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let file = tmp.path().join("f");
        std::fs::write(&file, b"").unwrap();
        assert!(protect_state_dir(&file).is_err());
        assert!(protect_state_dir(&tmp.path().join("missing")).is_err());

        // A junction inside the tree (junctions need no privilege, unlike
        // symlinks). Created with `mklink /J`.
        let dir = tmp.path().join("state");
        let target = tmp.path().join("elsewhere");
        std::fs::create_dir(&dir).unwrap();
        std::fs::create_dir(&target).unwrap();
        let link = dir.join("link");
        let ok = std::process::Command::new("cmd.exe")
            .arg("/c")
            .arg("mklink")
            .arg("/J")
            .arg(&link)
            .arg(&target)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !ok {
            eprintln!("skipped junction case: mklink /J failed");
            return;
        }
        let err = protect_state_dir(&dir).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "{err}");
        // Refused before anything changed.
        assert!(!dacl_sddl(&dir).starts_with("D:PAI(A;OICI;FA;;;SY)"));
        // The junction itself as the root.
        assert_eq!(
            protect_state_dir(&link).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
        std::fs::remove_dir(&link).unwrap();
    }

    #[test]
    fn writable_by_others_on_system_and_user_paths() {
        for p in [
            r"C:\Windows\System32",
            r"C:\Windows\System32\cmd.exe",
            r"C:\Program Files",
        ] {
            assert!(!writable_by_others(Path::new(p)).unwrap(), "{p}");
        }
        let tmp = tempfile::tempdir().unwrap();
        assert!(writable_by_others(tmp.path()).unwrap());
        assert!(writable_by_others(&std::env::current_exe().unwrap()).unwrap());
        assert!(writable_by_others(&tmp.path().join("missing")).is_err());
    }

    #[test]
    fn privilege_queries_are_consistent() {
        let system = running_as_system();
        let elevated = running_elevated();
        eprintln!("running_as_system={system} running_elevated={elevated}");
        if system {
            assert!(elevated, "SYSTEM is an elevated administrator");
        }
        // A test runner is never SYSTEM unless started as a service.
        let user = std::env::var("USERNAME").unwrap_or_default();
        if !user.ends_with('$') && !user.eq_ignore_ascii_case("SYSTEM") {
            assert!(!system);
        }
    }
}
