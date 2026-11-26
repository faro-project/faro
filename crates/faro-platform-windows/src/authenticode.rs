//! Authenticode verification of a file or of a running process's image.
//!
//! The Windows counterpart of macOS's code-signing requirement
//! (`ipc.agent_requirement`, `faro-service`'s `source::codesign`): the
//! service checks that the process at the other end of an agent pipe runs
//! an image signed by Faro's publisher, and the updater checks a downloaded
//! MSI the same way.
//!
//! # What is checked
//!
//! 1. **The signature and its chain** (`WinVerifyTrust` with
//!    `WINTRUST_ACTION_GENERIC_VERIFY_V2`, the policy Explorer and
//!    SmartScreen use): the embedded PKCS#7 signature matches the file's
//!    hash, the signing certificate carries the code-signing EKU and chains
//!    to a root in the machine's trusted root store, and every certificate
//!    was valid when the file was signed (an RFC 3161 timestamp extends
//!    this past the signing certificate's expiry). No UI is ever shown.
//! 2. **The signer** (`WTHelperProvDataFromStateData` and friends): the leaf
//!    certificate of the primary signer, whose subject Common Name must equal
//!    [`SignerRequirement::subject`] exactly and whose SHA-256 thumbprint, if
//!    the requirement pins any, must be one of them; the requirement can
//!    instead (or also) pin the thumbprint of the certificate that issued the
//!    leaf (`issuer_sha256`, for services such as Azure Trusted Signing that
//!    rotate leaf certificates under a stable issuing CA). A trusted chain
//!    alone proves only that *somebody* with a code-signing certificate
//!    signed the file, and a subject name alone is satisfied by any CA that
//!    will issue a certificate with that Common Name: the pin is what makes
//!    it Faro's. Release builds must carry one (`build-msi.ps1` refuses
//!    otherwise); the subject-only form exists for development.
//!
//! Only **embedded** signatures count (`WTD_CHOICE_FILE`). A catalog-signed
//! file (most of `System32`) reports [`AuthenticodeError::Unsigned`]: Faro's
//! own binaries and MSIs are always embedded-signed, and accepting catalogs
//! would let any file the OS has a catalog entry for stand in for them.
//!
//! # Revocation (off-line tolerant)
//!
//! The first pass checks revocation for the whole chain except the root
//! (`WTD_REVOKE_WHOLECHAIN` + `WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT`),
//! fetching CRLs/OCSP over the network when CryptoAPI has nothing cached.
//! A certificate that **is** revoked is always refused. When the revocation
//! status merely **cannot be determined** (`CERT_E_REVOCATION_FAILURE`,
//! `CRYPT_E_REVOCATION_OFFLINE`, `CRYPT_E_NO_REVOCATION_CHECK`: the
//! computer is off-line or the responder is down), the check is repeated
//! without revocation and accepted if everything else holds, with a
//! warning in the log. Faro must keep working on a laptop with no network
//! (the agent connects at every login), and Windows itself does not check
//! revocation when it starts a program. The cost is that someone who can
//! block the computer's network can make a revoked-but-unexpired Faro
//! certificate pass; with the subject (and ideally the thumbprint) pinned
//! that needs Faro's own stolen and revoked key, not just any code-signing
//! certificate. CryptoAPI caches CRLs and OCSP responses, so repeated checks
//! (one per agent connection) do not each go to the network.
//!
//! # Processes
//!
//! [`verify_process`] verifies the file the process was started from and
//! pins the process instance with a handle (see its docs for why it also
//! insists the image lives where only administrators can write).

use std::fmt;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};

use windows::core::{GUID, HRESULT, PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    GetLastError, CERT_E_REVOCATION_FAILURE, CERT_E_REVOKED, CRYPT_E_NO_REVOCATION_CHECK,
    CRYPT_E_REVOCATION_OFFLINE, CRYPT_E_REVOKED, HANDLE, HWND, TRUST_E_NOSIGNATURE,
    TRUST_E_PROVIDER_UNKNOWN, TRUST_E_SUBJECT_FORM_UNKNOWN, WAIT_TIMEOUT,
};
use windows::Win32::Security::Cryptography::{
    szOID_COMMON_NAME, CertGetCertificateContextProperty, CertGetNameStringW, CERT_CONTEXT,
    CERT_NAME_ATTR_TYPE, CERT_SHA256_HASH_PROP_ID,
};
use windows::Win32::Security::WinTrust::{
    WTHelperGetProvCertFromChain, WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData,
    WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0,
    WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE,
    WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, WTD_REVOKE_NONE, WTD_REVOKE_WHOLECHAIN,
    WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
};
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, WaitForSingleObject, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
};

/// What a signature must satisfy. `subject` is matched against the leaf
/// signing certificate's subject Common Name exactly (for example
/// `"Faro Project"`); `thumbprints`, when non-empty, pins the leaf
/// certificate's SHA-256 thumbprint (lowercase hex), any one of which
/// matches; `issuer_thumbprints`, when non-empty, pins the SHA-256
/// thumbprint of the certificate that issued the leaf (the next one in its
/// chain). When both are given, both must match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerRequirement {
    pub subject: String,
    pub thumbprints: Vec<String>,
    pub issuer_thumbprints: Vec<String>,
}

impl SignerRequirement {
    /// Parse the `ipc.agent_requirement` text on Windows:
    /// `subject="Faro Project"` optionally followed by
    /// `; sha256=<hex>[,<hex>...]` and/or `; issuer_sha256=<hex>[,<hex>...]`.
    ///
    /// The grammar, precisely (whitespace around tokens is ignored):
    ///
    /// ```text
    /// requirement := clause ( ";" clause )*
    /// clause      := "subject" "=" quoted
    ///              | "sha256" "=" hex64 ( "," hex64 )*
    ///              | "issuer_sha256" "=" hex64 ( "," hex64 )*
    /// quoted      := '"' ( any char but '"' and '\' | '\"' | '\\' )* '"'
    /// hex64       := 64 hex digits (any case; stored lowercase)
    /// ```
    ///
    /// `subject` is required and must not be blank, each key may appear
    /// once, and unknown keys are an error (a typo must not silently weaken
    /// the check). [`fmt::Display`] prints the canonical form, which parses
    /// back to the same value.
    pub fn parse(text: &str) -> Result<Self, AuthenticodeError> {
        let bad = |m: &str| AuthenticodeError::Requirement(m.to_owned());
        let mut subject: Option<String> = None;
        let mut thumbprints: Option<Vec<String>> = None;
        let mut issuers: Option<Vec<String>> = None;
        let mut rest = text;
        loop {
            rest = rest.trim_start();
            let eq = rest.find('=').ok_or_else(|| bad("expected `key=value`"))?;
            let key = rest[..eq].trim();
            rest = rest[eq + 1..].trim_start();
            match key {
                "subject" => {
                    if subject.is_some() {
                        return Err(bad("`subject` given twice"));
                    }
                    let (value, after) = parse_quoted(rest)?;
                    if value.trim().is_empty() {
                        return Err(bad("`subject` is empty"));
                    }
                    subject = Some(value);
                    rest = after;
                }
                "sha256" | "issuer_sha256" => {
                    let slot = if key == "sha256" {
                        &mut thumbprints
                    } else {
                        &mut issuers
                    };
                    if slot.is_some() {
                        return Err(bad(&format!("`{key}` given twice")));
                    }
                    let end = rest.find(';').unwrap_or(rest.len());
                    let mut list = Vec::new();
                    for item in rest[..end].split(',') {
                        let item = item.trim();
                        if item.len() != 64 || !item.bytes().all(|b| b.is_ascii_hexdigit()) {
                            return Err(bad(&format!(
                                "`{key}` needs 64 hex digits per thumbprint"
                            )));
                        }
                        list.push(item.to_ascii_lowercase());
                    }
                    *slot = Some(list);
                    rest = &rest[end..];
                }
                "" => return Err(bad("missing key before `=`")),
                other => return Err(bad(&format!("unknown key `{other}`"))),
            }
            rest = rest.trim_start();
            if rest.is_empty() {
                break;
            }
            rest = rest
                .strip_prefix(';')
                .ok_or_else(|| bad("expected `;` between clauses"))?;
        }
        Ok(SignerRequirement {
            subject: subject.ok_or_else(|| bad("`subject` is required"))?,
            thumbprints: thumbprints.unwrap_or_default(),
            issuer_thumbprints: issuers.unwrap_or_default(),
        })
    }

    /// Whether the requirement pins a certificate (leaf or issuer) and so
    /// is not satisfied by just any CA-issued certificate with the subject.
    pub fn is_pinned(&self) -> bool {
        !self.thumbprints.is_empty() || !self.issuer_thumbprints.is_empty()
    }

    /// Whether `signer` satisfies this requirement (exact subject CN, one of
    /// the pinned leaf thumbprints and one of the pinned issuer thumbprints
    /// when any are pinned).
    pub fn check(&self, signer: &SignerInfo) -> Result<(), AuthenticodeError> {
        if signer.subject != self.subject {
            return Err(AuthenticodeError::WrongSigner(format!(
                "signed by {:?}, not {:?}",
                signer.subject, self.subject
            )));
        }
        if !self.thumbprints.is_empty()
            && !self
                .thumbprints
                .iter()
                .any(|t| t.eq_ignore_ascii_case(&signer.thumbprint_sha256))
        {
            return Err(AuthenticodeError::WrongSigner(format!(
                "certificate {} is not pinned",
                signer.thumbprint_sha256
            )));
        }
        if !self.issuer_thumbprints.is_empty() {
            let issuer = signer.issuer_thumbprint_sha256.as_deref();
            if !issuer.is_some_and(|i| {
                self.issuer_thumbprints
                    .iter()
                    .any(|t| t.eq_ignore_ascii_case(i))
            }) {
                return Err(AuthenticodeError::WrongSigner(format!(
                    "issuing certificate {} is not pinned",
                    issuer.unwrap_or("(none)")
                )));
            }
        }
        Ok(())
    }
}

impl fmt::Display for SignerRequirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("subject=\"")?;
        for c in self.subject.chars() {
            if c == '"' || c == '\\' {
                f.write_str("\\")?;
            }
            write!(f, "{c}")?;
        }
        f.write_str("\"")?;
        if !self.thumbprints.is_empty() {
            write!(f, "; sha256={}", self.thumbprints.join(","))?;
        }
        if !self.issuer_thumbprints.is_empty() {
            write!(f, "; issuer_sha256={}", self.issuer_thumbprints.join(","))?;
        }
        Ok(())
    }
}

/// Parse a `"..."` string at the start of `s` (backslash escapes `"` and
/// `\`); returns the value and the text after the closing quote.
fn parse_quoted(s: &str) -> Result<(String, &str), AuthenticodeError> {
    let bad = |m: &str| AuthenticodeError::Requirement(m.to_owned());
    let body = s
        .strip_prefix('"')
        .ok_or_else(|| bad("`subject` must be a double-quoted string"))?;
    let mut out = String::new();
    let mut chars = body.char_indices();
    while let Some((i, c)) = chars.next() {
        match c {
            '"' => return Ok((out, &body[i + 1..])),
            '\\' => match chars.next() {
                Some((_, e @ ('"' | '\\'))) => out.push(e),
                _ => return Err(bad("only `\\\"` and `\\\\` escapes are allowed")),
            },
            c => out.push(c),
        }
    }
    Err(bad("unterminated quoted string"))
}

/// The verified signer of a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerInfo {
    pub subject: String,
    pub thumbprint_sha256: String,
    /// SHA-256 thumbprint of the certificate that issued the leaf (the next
    /// in the signer's chain), if the chain has one.
    pub issuer_thumbprint_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthenticodeError {
    #[error("invalid requirement: {0}")]
    Requirement(String),
    #[error("file is not signed")]
    Unsigned,
    #[error("signature is not trusted: {0}")]
    Untrusted(String),
    #[error("signer does not satisfy the requirement: {0}")]
    WrongSigner(String),
    #[error("os error: {0}")]
    Os(String),
}

/// Verify `path`'s Authenticode signature chains to a trusted root (with
/// revocation checks off-line tolerant) and its signer satisfies `req`.
///
/// The file is opened once, without `FILE_SHARE_WRITE` or
/// `FILE_SHARE_DELETE`, and `WinVerifyTrust` reads it through that handle,
/// so it cannot be modified, replaced or renamed while it is being checked.
/// What happens to it afterwards is the caller's business: the updater
/// should install from a location only SYSTEM can write, or keep its own
/// handle open from verification to installation.
pub fn verify_file(path: &Path, req: &SignerRequirement) -> Result<SignerInfo, AuthenticodeError> {
    verify_file_with(path, req, Fetch::Network)
}

/// Where revocation data may come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fetch {
    /// CRLs and OCSP responses are fetched from the network when the cache
    /// has nothing (an update package, a one-off check).
    Network,
    /// Only what CryptoAPI has cached (`WTD_CACHE_ONLY_URL_RETRIEVAL`): no
    /// network wait, for checks on a hot path such as every agent
    /// connection. Revocation data that is not cached counts as
    /// undeterminable, which is accepted as off-line below.
    CacheOnly,
}

fn verify_file_with(
    path: &Path,
    req: &SignerRequirement,
    fetch: Fetch,
) -> Result<SignerInfo, AuthenticodeError> {
    let file = open_locked(path).map_err(|e| AuthenticodeError::Os(format!("open: {e}")))?;
    let signer = verify_handle(path, HANDLE(file.as_raw_handle()), fetch)?;
    req.check(&signer)?;
    Ok(signer)
}

/// Read `path`'s signer without checking it against a requirement (the
/// signature and chain are still fully verified). For diagnostics and for
/// learning the thumbprint to pin.
pub fn signer_of(path: &Path) -> Result<SignerInfo, AuthenticodeError> {
    let file = open_locked(path).map_err(|e| AuthenticodeError::Os(format!("open: {e}")))?;
    verify_handle(path, HANDLE(file.as_raw_handle()), Fetch::Network)
}

/// Open `path` for reading, sharing read access only, so nobody can write,
/// delete or rename it while the handle is open. A running program's image
/// can still be opened like this.
fn open_locked(path: &Path) -> std::io::Result<std::fs::File> {
    const FILE_SHARE_READ: u32 = 0x1;
    std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(path)
}

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

/// The outcome of one `WinVerifyTrust` pass.
enum Pass {
    Ok(SignerInfo),
    Failed {
        status: HRESULT,
        last_error: u32,
    },
    /// Trusted, but the signer could not be read (should not happen).
    NoSigner(String),
}

fn verify_handle(path: &Path, file: HANDLE, fetch: Fetch) -> Result<SignerInfo, AuthenticodeError> {
    let path_w = wide(path);
    let finish = |pass: Pass| match pass {
        Pass::Ok(s) => Ok(s),
        Pass::NoSigner(m) => Err(AuthenticodeError::Os(m)),
        Pass::Failed { status, last_error } => Err(classify(status, last_error)),
    };
    match verify_pass(&path_w, file, true, fetch) {
        Pass::Failed { status, .. } if revocation_unknown(status) => {
            let second = verify_pass(&path_w, file, false, fetch);
            if matches!(second, Pass::Ok(_)) {
                tracing::warn!(
                    status = format_args!("{:#010x}", status.0),
                    "revocation status unavailable (off-line?); accepted the signature without it"
                );
            }
            finish(second)
        }
        first => finish(first),
    }
}

/// The revocation status could not be determined (as opposed to "revoked").
fn revocation_unknown(status: HRESULT) -> bool {
    status == CERT_E_REVOCATION_FAILURE
        || status == CRYPT_E_REVOCATION_OFFLINE
        || status == CRYPT_E_NO_REVOCATION_CHECK
}

/// Map a failed `WinVerifyTrust` to an error, following Microsoft's
/// documented sample: `TRUST_E_NOSIGNATURE` means "unsigned" only when the
/// last error says so; otherwise a signature is present but broken.
fn classify(status: HRESULT, last_error: u32) -> AuthenticodeError {
    let le = HRESULT(last_error as i32);
    if status == TRUST_E_NOSIGNATURE {
        if last_error == 0
            || le == TRUST_E_NOSIGNATURE
            || le == TRUST_E_SUBJECT_FORM_UNKNOWN
            || le == TRUST_E_PROVIDER_UNKNOWN
        {
            return AuthenticodeError::Unsigned;
        }
        return AuthenticodeError::Untrusted(format!("invalid signature ({last_error:#010x})"));
    }
    if status == TRUST_E_SUBJECT_FORM_UNKNOWN || status == TRUST_E_PROVIDER_UNKNOWN {
        return AuthenticodeError::Unsigned;
    }
    if status == CERT_E_REVOKED || status == CRYPT_E_REVOKED {
        return AuthenticodeError::Untrusted("a certificate in the chain is revoked".into());
    }
    AuthenticodeError::Untrusted(format!(
        "{} ({:#010x})",
        windows::core::Error::from_hresult(status).message(),
        status.0
    ))
}

/// One `WinVerifyTrust` verify + read signer + close cycle.
fn verify_pass(path_w: &[u16], file: HANDLE, check_revocation: bool, fetch: Fetch) -> Pass {
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(path_w.as_ptr()),
        hFile: file,
        pgKnownSubject: std::ptr::null_mut(),
    };
    let mut data = WINTRUST_DATA {
        cbStruct: size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: if check_revocation {
            WTD_REVOKE_WHOLECHAIN
        } else {
            WTD_REVOKE_NONE
        },
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &mut file_info,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: {
            let mut flags = if check_revocation {
                WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT
            } else {
                Default::default()
            };
            if fetch == Fetch::CacheOnly {
                flags |= WTD_CACHE_ONLY_URL_RETRIEVAL;
            }
            flags
        },
        ..Default::default()
    };
    let mut action: GUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // SAFETY: `data` and `file_info` are fully initialised, outlive both
    // calls, and point at `path_w` (NUL-terminated) and an open file
    // handle. A null HWND means "no parent window"; WTD_UI_NONE shows none.
    let status =
        HRESULT(unsafe { WinVerifyTrust(HWND::default(), &mut action, (&raw mut data).cast()) });
    // SAFETY: GetLastError has no preconditions; read before anything else.
    let last_error = unsafe { GetLastError() }.0;
    let result = if status.is_ok() {
        // SAFETY: after a successful VERIFY the state data is valid until
        // the CLOSE below.
        match unsafe { leaf_signer(data.hWVTStateData) } {
            Ok(s) => Pass::Ok(s),
            Err(m) => Pass::NoSigner(m),
        }
    } else {
        Pass::Failed { status, last_error }
    };
    // Always release the state WinVerifyTrust allocated for VERIFY, on
    // failure too.
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    // SAFETY: as above; CLOSE with the same data frees hWVTStateData.
    unsafe { WinVerifyTrust(HWND::default(), &mut action, (&raw mut data).cast()) };
    result
}

/// Read the primary signer's leaf certificate out of WinVerifyTrust state.
///
/// # Safety
/// `state` must be the `hWVTStateData` of a successful, not yet closed
/// `WTD_STATEACTION_VERIFY` call.
unsafe fn leaf_signer(state: HANDLE) -> Result<SignerInfo, String> {
    // SAFETY: per the function contract; each pointer is checked for null
    // before it is dereferenced, and all of it is owned by the state data.
    unsafe {
        let prov = WTHelperProvDataFromStateData(state);
        if prov.is_null() {
            return Err("no provider data".into());
        }
        let sgnr = WTHelperGetProvSignerFromChain(prov, 0, false, 0);
        if sgnr.is_null() {
            return Err("no signer".into());
        }
        // Index 0 of the signer's chain is the signing (leaf) certificate.
        let cert = WTHelperGetProvCertFromChain(sgnr, 0);
        if cert.is_null() || (*cert).pCert.is_null() {
            return Err("no signer certificate".into());
        }
        let mut info = cert_signer((*cert).pCert)?;
        if (*sgnr).csCertChain > 1 {
            let issuer = WTHelperGetProvCertFromChain(sgnr, 1);
            if !issuer.is_null() && !(*issuer).pCert.is_null() {
                info.issuer_thumbprint_sha256 = Some(cert_thumbprint((*issuer).pCert)?);
            }
        }
        Ok(info)
    }
}

/// SHA-256 thumbprint of a certificate, lowercase hex.
///
/// # Safety
/// `cert` must be a valid certificate context.
unsafe fn cert_thumbprint(cert: *const CERT_CONTEXT) -> Result<String, String> {
    // SAFETY: `cert` is valid per the contract; the buffer is sized from the
    // length the first call reports.
    unsafe {
        let mut len = 0u32;
        CertGetCertificateContextProperty(cert, CERT_SHA256_HASH_PROP_ID, None, &mut len)
            .map_err(|e| format!("thumbprint size: {e}"))?;
        let mut hash = vec![0u8; len as usize];
        CertGetCertificateContextProperty(
            cert,
            CERT_SHA256_HASH_PROP_ID,
            Some(hash.as_mut_ptr().cast()),
            &mut len,
        )
        .map_err(|e| format!("thumbprint: {e}"))?;
        hash.truncate(len as usize);
        Ok(hash.iter().map(|b| format!("{b:02x}")).collect())
    }
}

/// Subject CN and SHA-256 thumbprint of a certificate.
///
/// # Safety
/// `cert` must be a valid certificate context.
unsafe fn cert_signer(cert: *const CERT_CONTEXT) -> Result<SignerInfo, String> {
    // SAFETY: `cert` is valid per the contract; the buffers are sized from
    // the length the first call of each pair reports.
    unsafe {
        let oid = Some(szOID_COMMON_NAME.0 as *const core::ffi::c_void);
        let n = CertGetNameStringW(cert, CERT_NAME_ATTR_TYPE, 0, oid, None);
        let mut buf = vec![0u16; n.max(1) as usize];
        let n = CertGetNameStringW(cert, CERT_NAME_ATTR_TYPE, 0, oid, Some(&mut buf));
        // `n` counts the terminating NUL; 1 means "no CN" (empty subject,
        // which no requirement can match since parse rejects blank ones).
        let subject = String::from_utf16_lossy(&buf[..(n as usize).saturating_sub(1)]);

        let thumbprint_sha256 = cert_thumbprint(cert)?;
        Ok(SignerInfo {
            subject,
            thumbprint_sha256,
            issuer_thumbprint_sha256: None,
        })
    }
}

/// The full image path of process `pid` (`QueryFullProcessImageNameW`).
///
/// This is the path the process was **started from**, recorded by the
/// kernel at creation; if the file was renamed since, the path may now
/// name a different file (see [`verify_process`]).
pub fn process_image_path(pid: u32) -> std::io::Result<PathBuf> {
    let process = open_process(pid)?;
    image_path_of(&process)
}

/// The image path of the process behind an already-open handle (opened with
/// `PROCESS_QUERY_LIMITED_INFORMATION`), so the answer cannot be about a
/// different process that reused the pid.
pub fn process_image_of(process: &OwnedHandle) -> std::io::Result<PathBuf> {
    image_path_of(process)
}

fn open_process(pid: u32) -> std::io::Result<OwnedHandle> {
    // SAFETY: OpenProcess has no memory-safety preconditions; on success we
    // own the returned handle.
    let h = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            false,
            pid,
        )
    }
    .map_err(std::io::Error::from)?;
    // SAFETY: `h` is a fresh, valid handle nobody else owns.
    Ok(unsafe { OwnedHandle::from_raw_handle(h.0) })
}

fn image_path_of(process: &OwnedHandle) -> std::io::Result<PathBuf> {
    // Long paths can exceed MAX_PATH; 32 Ki UTF-16 units is the NT limit.
    let mut buf = vec![0u16; 32 * 1024];
    let mut len = buf.len() as u32;
    // SAFETY: `buf` has `len` writable units and the handle is open with
    // PROCESS_QUERY_LIMITED_INFORMATION.
    unsafe {
        QueryFullProcessImageNameW(
            HANDLE(process.as_raw_handle()),
            PROCESS_NAME_WIN32,
            PWSTR(buf.as_mut_ptr()),
            &mut len,
        )
    }
    .map_err(std::io::Error::from)?;
    buf.truncate(len as usize);
    Ok(PathBuf::from(String::from_utf16_lossy(&buf)))
}

/// Verify the image of running process `pid`. Implementations open the
/// process first and re-check it is still alive after verifying, so a pid
/// reused in between is not accepted.
///
/// In order:
///
/// 1. **Pin the process.** A handle is opened before anything else. While
///    it is open the kernel keeps the process object, so its pid cannot be
///    handed to a new process; every later step reads *that* process.
/// 2. **Verify its image** ([`verify_file`]) at the path the kernel recorded
///    at creation, with the file locked against change during the check.
/// 3. **Refuse images an ordinary user could have swapped.** The recorded
///    path is the creation-time name: a user can start `evil.exe`, rename it
///    while it runs (Windows allows renaming a running image) and copy the
///    genuine signed `faro-agent.exe` to the old name, which would then
///    verify. That needs write access to the image's directory, so the
///    image file and its directory must not be writable by anyone but
///    SYSTEM, Administrators or TrustedInstaller
///    ([`crate::acl::writable_by_others`]). Faro's agent lives in
///    `C:\Program Files\Faro`, which passes; a copy in a user's folder
///    fails with [`AuthenticodeError::Untrusted`].
/// 4. **Re-check the process is still running** (the handle is not
///    signalled). An exited process can no longer be the peer the caller
///    is talking to.
///
/// Callers verifying a pipe client should get the pid from
/// `GetNamedPipeClientProcessId` and still compare the client's token user
/// with the session's: a signed image only proves *which program* is on the
/// other end, not on whose behalf it runs.
pub fn verify_process(pid: u32, req: &SignerRequirement) -> Result<SignerInfo, AuthenticodeError> {
    verify_process_with(pid, req, Fetch::Network)
}

/// [`verify_process`] with a choice of where revocation data may come from.
/// The service's agent-pipe check uses [`Fetch::CacheOnly`], so a slow
/// responder cannot stall every agent connection.
pub fn verify_process_with(
    pid: u32,
    req: &SignerRequirement,
    fetch: Fetch,
) -> Result<SignerInfo, AuthenticodeError> {
    let os = |what: &str, e: std::io::Error| AuthenticodeError::Os(format!("{what}: {e}"));
    let process = open_process(pid).map_err(|e| os("open process", e))?;
    let path = image_path_of(&process).map_err(|e| os("image path", e))?;
    let signer = verify_file_with(&path, req, fetch)?;
    // The image, its directory and every directory above it up to the
    // volume root: anyone who can write (or rename, or replace) any of them
    // can put another file under the verified path.
    let dir = path
        .parent()
        .ok_or_else(|| AuthenticodeError::Os("image path has no directory".into()))?;
    let mut checked: Vec<(&Path, bool)> = vec![(path.as_path(), false), (dir, false)];
    checked.extend(dir.ancestors().skip(1).map(|a| (a, true)));
    for (p, above) in checked {
        let writable = if above {
            crate::acl::replaceable_by_others(p)
        } else {
            crate::acl::writable_by_others(p)
        };
        match writable {
            Ok(false) => {}
            Ok(true) => {
                return Err(AuthenticodeError::Untrusted(format!(
                    "{} is writable by non-administrators, so the image could have been swapped",
                    p.display()
                )))
            }
            Err(e) => return Err(os("image ACL", e)),
        }
    }
    // SAFETY: the handle is open with SYNCHRONIZE; a zero timeout only polls.
    let wait = unsafe { WaitForSingleObject(HANDLE(process.as_raw_handle()), 0) };
    if wait != WAIT_TIMEOUT {
        return Err(AuthenticodeError::Os(format!(
            "process {pid} exited during verification"
        )));
    }
    Ok(signer)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(subject: &str) -> SignerRequirement {
        SignerRequirement {
            subject: subject.into(),
            thumbprints: vec![],
            issuer_thumbprints: vec![],
        }
    }

    #[test]
    fn parse_requirements() {
        assert_eq!(
            SignerRequirement::parse(r#"subject="Faro Project""#).unwrap(),
            req("Faro Project")
        );
        let hex = "AB".repeat(32);
        let r = SignerRequirement::parse(&format!(
            r#"  subject = "Faro; \"Project\"" ;sha256= {hex} , {} "#,
            "01".repeat(32)
        ))
        .unwrap();
        assert_eq!(r.subject, r#"Faro; "Project""#);
        assert_eq!(r.thumbprints, vec!["ab".repeat(32), "01".repeat(32)]);
        // The canonical form round-trips.
        assert_eq!(SignerRequirement::parse(&r.to_string()).unwrap(), r);
        // Clause order does not matter.
        let r2 = SignerRequirement::parse(&format!(r#"sha256={hex}; subject="X""#)).unwrap();
        assert_eq!(r2.subject, "X");
    }

    #[test]
    fn parse_rejects_bad_requirements() {
        let zeros = "0".repeat(64);
        let bad_hex = "g".repeat(64);
        for bad in [
            "".to_string(),
            "subject=Faro".into(),
            r#"subject="""#.into(),
            r#"subject="  ""#.into(),
            r#"subject="Faro"#.into(),
            r#"subject="a\b""#.into(),
            r#"subject="a"; subject="b""#.into(),
            r#"subject="a" sha256=00"#.into(),
            r#"subject="a"; sha256=00"#.into(),
            format!(r#"subject="a"; sha256={bad_hex}"#),
            format!(r#"subject="a"; sha256={zeros},"#),
            format!(r#"subject="a"; sha256={zeros}; sha256={zeros}"#),
            format!("sha256={zeros}"),
            r#"subjekt="a""#.into(),
            r#"subject="a";"#.into(),
            "anchor apple generic".into(),
        ] {
            assert!(
                matches!(
                    SignerRequirement::parse(&bad),
                    Err(AuthenticodeError::Requirement(_))
                ),
                "{bad:?} should not parse"
            );
        }
    }

    #[test]
    fn check_matches_subject_and_pins() {
        let s = SignerInfo {
            subject: "Faro Project".into(),
            thumbprint_sha256: "aa".repeat(32),
            issuer_thumbprint_sha256: Some("cc".repeat(32)),
        };
        req("Faro Project").check(&s).unwrap();
        assert!(matches!(
            req("Faro project").check(&s),
            Err(AuthenticodeError::WrongSigner(_))
        ));
        let mut pinned = req("Faro Project");
        pinned.thumbprints = vec!["bb".repeat(32)];
        assert!(matches!(
            pinned.check(&s),
            Err(AuthenticodeError::WrongSigner(_))
        ));
        pinned.thumbprints.push("aa".repeat(32));
        pinned.check(&s).unwrap();
    }

    #[test]
    fn issuer_pins_parse_and_check() {
        let leaf = "aa".repeat(32);
        let ca = "CC".repeat(32);
        let r = SignerRequirement::parse(&format!(r#"subject="Faro Project"; issuer_sha256={ca}"#))
            .unwrap();
        assert_eq!(r.issuer_thumbprints, vec!["cc".repeat(32)]);
        assert!(r.thumbprints.is_empty());
        assert!(r.is_pinned());
        assert!(!req("Faro Project").is_pinned());
        assert_eq!(SignerRequirement::parse(&r.to_string()).unwrap(), r);
        let both = SignerRequirement::parse(&format!(
            r#"issuer_sha256={ca}; subject="X"; sha256={leaf}"#
        ))
        .unwrap();
        assert_eq!(SignerRequirement::parse(&both.to_string()).unwrap(), both);
        assert!(SignerRequirement::parse(&format!(
            r#"subject="X"; issuer_sha256={ca}; issuer_sha256={ca}"#
        ))
        .is_err());
        assert!(SignerRequirement::parse(r#"subject="X"; issuer_sha256=00"#).is_err());

        let signer = |issuer: Option<&str>| SignerInfo {
            subject: "Faro Project".into(),
            thumbprint_sha256: leaf.clone(),
            issuer_thumbprint_sha256: issuer.map(str::to_owned),
        };
        // A rotated leaf under the pinned issuer passes.
        r.check(&signer(Some(&"cc".repeat(32)))).unwrap();
        // Another CA that issues the same subject, or no issuer, does not.
        for s in [signer(Some(&"dd".repeat(32))), signer(None)] {
            assert!(matches!(
                r.check(&s),
                Err(AuthenticodeError::WrongSigner(_))
            ));
        }
        // Both pins must hold.
        both.check(&signer(Some(&"cc".repeat(32)))).unwrap_err(); // subject X
        let mut both = r.clone();
        both.thumbprints = vec!["bb".repeat(32)];
        assert!(both.check(&signer(Some(&"cc".repeat(32)))).is_err());
        both.thumbprints.push(leaf.clone());
        both.check(&signer(Some(&"cc".repeat(32)))).unwrap();
    }

    #[test]
    fn ancestors_above_the_image_are_checked_for_replacement_only() {
        // The stock volume root lets Users add subdirectories; that must
        // not count, or no install could ever verify.
        let sys = std::env::var_os("SystemRoot").map(PathBuf::from).unwrap();
        let root = sys.ancestors().last().unwrap().to_path_buf();
        assert!(!crate::acl::replaceable_by_others(&root).unwrap());
        assert!(!crate::acl::replaceable_by_others(&sys).unwrap());
    }

    #[test]
    fn unsigned_exe_is_unsigned() {
        // The test binary itself is an unsigned PE; copy it so the check
        // runs on a plain temp file.
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("unsigned.exe");
        std::fs::copy(std::env::current_exe().unwrap(), &exe).unwrap();
        assert_eq!(
            verify_file(&exe, &req("Faro Project")),
            Err(AuthenticodeError::Unsigned)
        );
        // Not a PE at all: also "unsigned".
        let txt = dir.path().join("plain.exe");
        std::fs::write(&txt, b"not a program").unwrap();
        assert_eq!(
            verify_file(&txt, &req("Faro Project")),
            Err(AuthenticodeError::Unsigned)
        );
        assert!(matches!(
            verify_file(&dir.path().join("missing.exe"), &req("x")),
            Err(AuthenticodeError::Os(_))
        ));
    }

    /// An embedded-signed (not only catalog-signed) Microsoft binary present
    /// on stock Windows 10/11 (Defender's and MRT's stubs) or on machines
    /// with Edge / OneDrive.
    fn embedded_signed_microsoft_binary() -> Option<PathBuf> {
        [
            r"C:\Windows\System32\MpSigStub.exe",
            r"C:\Windows\System32\MRT.exe",
            r"C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe",
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Microsoft OneDrive\OneDrive.exe",
        ]
        .into_iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
    }

    #[test]
    fn embedded_signed_microsoft_binary_verifies() {
        let Some(path) = embedded_signed_microsoft_binary() else {
            eprintln!("skipped: no embedded-signed Microsoft binary on this machine");
            return;
        };
        let info = signer_of(&path).unwrap();
        assert!(
            info.subject.starts_with("Microsoft "),
            "{}: {info:?}",
            path.display()
        );
        assert_eq!(info.thumbprint_sha256.len(), 64);
        assert!(info
            .thumbprint_sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        assert_eq!(verify_file(&path, &req(&info.subject)).unwrap(), info);
        // Somebody else's valid signature is the wrong signer.
        let err = verify_file(
            &path,
            &SignerRequirement::parse(r#"subject="Faro Project""#).unwrap(),
        )
        .unwrap_err();
        assert!(
            matches!(&err, AuthenticodeError::WrongSigner(m) if m.contains("Microsoft")),
            "{err}"
        );
        // Pinning the right thumbprint passes, a wrong one fails.
        let mut pinned = req(&info.subject);
        pinned.thumbprints = vec![info.thumbprint_sha256.clone()];
        assert_eq!(verify_file(&path, &pinned).unwrap(), info);
        pinned.thumbprints = vec!["00".repeat(32)];
        assert!(matches!(
            verify_file(&path, &pinned),
            Err(AuthenticodeError::WrongSigner(_))
        ));
    }

    #[test]
    fn tampered_signed_exe_is_untrusted() {
        let Some(signed) = embedded_signed_microsoft_binary() else {
            eprintln!("skipped: no embedded-signed Microsoft binary on this machine");
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let copy = dir.path().join("tampered.exe");
        let mut bytes = std::fs::read(&signed).unwrap();
        // Flip a byte inside the hashed image, well before the signature
        // (which sits at the end of the file).
        let at = bytes.len() / 3;
        bytes[at] ^= 0xff;
        std::fs::write(&copy, &bytes).unwrap();
        let err = verify_file(&copy, &req("Microsoft Corporation")).unwrap_err();
        assert!(matches!(err, AuthenticodeError::Untrusted(_)), "{err}");
    }

    #[test]
    fn catalog_signed_system_binary_is_unsigned() {
        // cmd.exe is catalog-signed only: embedded-only verification treats
        // it as unsigned (see the module docs).
        let cmd = Path::new(r"C:\Windows\System32\cmd.exe");
        assert_eq!(
            verify_file(cmd, &req("Microsoft Windows")),
            Err(AuthenticodeError::Unsigned)
        );
    }

    #[test]
    fn own_process_is_unsigned_and_dead_pids_fail() {
        let me = std::process::id();
        let path = process_image_path(me).unwrap();
        assert_eq!(
            std::fs::canonicalize(&path).unwrap(),
            std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap()
        );
        assert_eq!(
            verify_process(me, &req("Faro Project")),
            Err(AuthenticodeError::Unsigned)
        );
        // A process that has exited and been reaped.
        let mut child = std::process::Command::new("cmd.exe")
            .args(["/c", "exit"])
            .spawn()
            .unwrap();
        let pid = child.id();
        child.wait().unwrap();
        drop(child);
        // The pid may in theory be reused already; then it is some other
        // process, which must not verify either.
        assert!(verify_process(pid, &req("Faro Project")).is_err());
        // Pid 0 (the idle process) cannot be opened.
        assert!(matches!(
            verify_process(0, &req("x")),
            Err(AuthenticodeError::Os(_))
        ));
    }
}
