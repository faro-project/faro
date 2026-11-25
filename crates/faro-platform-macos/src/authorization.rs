//! An administrator's approval for enrolling the computer, through
//! Authorization Services (issue #62; the pattern of Apple's
//! EvenBetterAuthorizationSample).
//!
//! ```text
//! agent (user)                         service (root)                 authd / SecurityAgent
//!   Authorization::new_empty()
//!   external_form() ── 32 bytes ──────▶ from_external_form()
//!                                       ensure_enroll_rule()  ──────▶ read (and fix) the rule
//!                                       copy_rights(no dialog) ─────▶ must be refused
//!                                       copy_rights(org.faro.enroll,
//!                                         prompt naming the instance) ▶ admin name + password
//!                                       ◀───────────────────────────── yes / no
//!                                       drop: DestroyRights
//!   drop: DestroyRights
//! ```
//!
//! **Why a right of our own.** `system.privilege.admin` has
//! `allow-root: true`, so a root caller could be granted it with no prompt
//! at all. `org.faro.enroll` is defined with [`enroll_rule`]: an
//! administrator must authenticate every time (`group: admin`,
//! `shared: false`, `timeout: 0`, `allow-root: false`), and nothing is
//! cached for a later request.
//!
//! **Why the rule is checked before every prompt.** The authorization
//! database lets anyone *add* a right that doesn't exist yet
//! (`config.add.` is `class: allow`), so a user could plant
//! `org.faro.enroll` as "allow" before Faro defines it. Changing a right
//! that exists needs root or an administrator (`config.modify.`). So the
//! service reads the right before every prompt and accepts it only if
//! [`definition_ok`] says it is exactly Faro's rule. A root service
//! rewrites a missing or different right and reads it back; a non-root
//! service never writes it and refuses. Anything unexpected fails closed,
//! including a more specific `config.*` right for it ([`GUARD_RIGHTS`])
//! that could let someone else change it.
//!
//! **Why the agent's authorization is checked first.** It must not carry
//! the right already (asked without a dialog, authd must refuse), so an
//! approval given in some other program's dialog, with that program's
//! words, is never accepted.
//!
//! The FFI is raw `extern "C"` against Security.framework, like the
//! service's code-signature check.

use std::collections::BTreeMap;
use std::ffi::{c_char, c_void, CString};
use std::ptr::{self, NonNull};

use objc2_core_foundation::{CFBoolean, CFDictionary, CFNumber, CFRetained, CFString, CFType};

/// The right that approves enrolling this computer.
pub const ENROLL_RIGHT: &str = "org.faro.enroll";

/// The rule's comment in the authorization database.
const RULE_COMMENT: &str = "Used by Faro to let an administrator approve enrolling this \
    computer. Faro checks this rule before every use and refuses if it was changed.";

/// The default prompt stored with the rule (the service always passes its
/// own, naming the instance).
const RULE_PROMPT: &str = "Faro wants to enroll this computer.";

/// `kAuthorizationExternalFormLength`.
pub const EXTERNAL_FORM_LEN: usize = 32;

type OSStatus = i32;
type AuthorizationRef = *mut c_void;

#[repr(C)]
struct AuthorizationItem {
    name: *const c_char,
    value_length: usize,
    value: *mut c_void,
    flags: u32,
}

#[repr(C)]
struct AuthorizationItemSet {
    count: u32,
    items: *mut AuthorizationItem,
}

#[repr(C)]
struct AuthorizationExternalForm {
    bytes: [c_char; EXTERNAL_FORM_LEN],
}

const FLAG_DEFAULTS: u32 = 0;
const FLAG_INTERACTION_ALLOWED: u32 = 1 << 0;
const FLAG_EXTEND_RIGHTS: u32 = 1 << 1;
const FLAG_DESTROY_RIGHTS: u32 = 1 << 3;

const ERR_SUCCESS: OSStatus = 0;
const ERR_DENIED: OSStatus = -60005;
const ERR_CANCELED: OSStatus = -60006;
const ERR_INTERACTION_NOT_ALLOWED: OSStatus = -60007;

/// `kAuthorizationEnvironmentPrompt`.
const ENV_PROMPT: &[u8] = b"prompt\0";

#[link(name = "Security", kind = "framework")]
extern "C" {
    fn AuthorizationCreate(
        rights: *const AuthorizationItemSet,
        environment: *const AuthorizationItemSet,
        flags: u32,
        authorization: *mut AuthorizationRef,
    ) -> OSStatus;
    fn AuthorizationFree(authorization: AuthorizationRef, flags: u32) -> OSStatus;
    fn AuthorizationCopyRights(
        authorization: AuthorizationRef,
        rights: *const AuthorizationItemSet,
        environment: *const AuthorizationItemSet,
        flags: u32,
        authorized_rights: *mut *mut AuthorizationItemSet,
    ) -> OSStatus;
    fn AuthorizationMakeExternalForm(
        authorization: AuthorizationRef,
        ext_form: *mut AuthorizationExternalForm,
    ) -> OSStatus;
    fn AuthorizationCreateFromExternalForm(
        ext_form: *const AuthorizationExternalForm,
        authorization: *mut AuthorizationRef,
    ) -> OSStatus;
    fn AuthorizationRightGet(right_name: *const c_char, definition: *mut *const c_void)
        -> OSStatus;
    fn AuthorizationRightSet(
        authorization: AuthorizationRef,
        right_name: *const c_char,
        definition: *const c_void,
        description_key: *const c_void,
        bundle: *const c_void,
        locale_table_name: *const c_void,
    ) -> OSStatus;
}

/// What went wrong.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    /// The administrator's name or password was wrong, or the rule refused.
    #[error("not approved")]
    Denied,
    /// Someone pressed Cancel.
    #[error("cancelled")]
    Canceled,
    /// Approval needs a dialog and none may be shown (or nobody is at the
    /// screen of the session that asked).
    #[error("approval needs a dialog, and none can be shown")]
    InteractionNotAllowed,
    /// `org.faro.enroll` is not in the authorization database, and this
    /// process may not add it.
    #[error("the `{ENROLL_RIGHT}` rule is not set up (the Faro service sets it up when it runs as root)")]
    RuleMissing,
    /// `org.faro.enroll` is not exactly Faro's rule.
    #[error("the `{ENROLL_RIGHT}` rule was changed: {0}")]
    RuleAltered(String),
    /// The authorization handed over already carried the right: approved
    /// somewhere else, not in Faro's own prompt.
    #[error("the authorization was approved before Faro asked")]
    AlreadyAuthorized,
    /// Any other Authorization Services failure.
    #[error("{call} failed (OSStatus {status})")]
    Os {
        call: &'static str,
        status: OSStatus,
    },
}

fn check(call: &'static str, status: OSStatus) -> Result<(), AuthError> {
    match status {
        ERR_SUCCESS => Ok(()),
        ERR_DENIED => Err(AuthError::Denied),
        ERR_CANCELED => Err(AuthError::Canceled),
        ERR_INTERACTION_NOT_ALLOWED => Err(AuthError::InteractionNotAllowed),
        status => Err(AuthError::Os { call, status }),
    }
}

/// An authorization reference, freed with `kAuthorizationFlagDestroyRights`
/// on drop, so no right obtained through it outlives it.
#[derive(Debug)]
pub struct Authorization(AuthorizationRef);

impl Authorization {
    /// A reference with no rights, for the agent to hand to the service.
    /// Never prompts.
    pub fn new_empty() -> Result<Authorization, AuthError> {
        let mut r: AuthorizationRef = ptr::null_mut();
        // SAFETY: null rights and environment are allowed; `r` is a valid
        // out-pointer.
        let status =
            unsafe { AuthorizationCreate(ptr::null(), ptr::null(), FLAG_DEFAULTS, &mut r) };
        check("AuthorizationCreate", status)?;
        if r.is_null() {
            return Err(AuthError::Os {
                call: "AuthorizationCreate",
                status: 0,
            });
        }
        Ok(Authorization(r))
    }

    /// The 32 bytes another process can turn back into this reference.
    pub fn external_form(&self) -> Result<[u8; EXTERNAL_FORM_LEN], AuthError> {
        let mut ext = AuthorizationExternalForm {
            bytes: [0; EXTERNAL_FORM_LEN],
        };
        // SAFETY: `self.0` is a live reference; `ext` is a valid out-pointer.
        let status = unsafe { AuthorizationMakeExternalForm(self.0, &mut ext) };
        check("AuthorizationMakeExternalForm", status)?;
        Ok(ext.bytes.map(|b| b as u8))
    }

    /// The reference another process exported with
    /// [`external_form`](Self::external_form).
    pub fn from_external_form(bytes: &[u8; EXTERNAL_FORM_LEN]) -> Result<Authorization, AuthError> {
        let ext = AuthorizationExternalForm {
            bytes: bytes.map(|b| b as c_char),
        };
        let mut r: AuthorizationRef = ptr::null_mut();
        // SAFETY: `ext` is a fully initialized external form and `r` a valid
        // out-pointer.
        let status = unsafe { AuthorizationCreateFromExternalForm(&ext, &mut r) };
        check("AuthorizationCreateFromExternalForm", status)?;
        if r.is_null() {
            return Err(AuthError::Os {
                call: "AuthorizationCreateFromExternalForm",
                status: 0,
            });
        }
        Ok(Authorization(r))
    }

    /// Ask for `right`. With `interactive`, authd may show its dialog, with
    /// `prompt` as the explanation, and this blocks until it closes.
    pub fn copy_rights(
        &self,
        right: &str,
        prompt: Option<&str>,
        interactive: bool,
    ) -> Result<(), AuthError> {
        let name = CString::new(right).map_err(|_| AuthError::Os {
            call: "AuthorizationCopyRights",
            status: 0,
        })?;
        let mut item = AuthorizationItem {
            name: name.as_ptr(),
            value_length: 0,
            value: ptr::null_mut(),
            flags: 0,
        };
        let rights = AuthorizationItemSet {
            count: 1,
            items: &mut item,
        };
        // The prompt is plain text: no NUL (it is passed with its length).
        let prompt: Option<Vec<u8>> = prompt.map(|p| p.bytes().filter(|&b| b != 0).collect());
        let mut env_item = prompt.as_ref().map(|p| AuthorizationItem {
            name: ENV_PROMPT.as_ptr().cast(),
            value_length: p.len(),
            value: p.as_ptr().cast_mut().cast(),
            flags: 0,
        });
        let env = AuthorizationItemSet {
            count: u32::from(env_item.is_some()),
            items: env_item
                .as_mut()
                .map_or(ptr::null_mut(), |i| i as *mut AuthorizationItem),
        };
        let mut flags = FLAG_EXTEND_RIGHTS;
        if interactive {
            flags |= FLAG_INTERACTION_ALLOWED;
        }
        // SAFETY: `self.0` is live; `rights` and `env` point to item arrays
        // (and NUL-terminated names and value buffers) that outlive the
        // call; a null `authorized_rights` asks for no copy.
        let status =
            unsafe { AuthorizationCopyRights(self.0, &rights, &env, flags, ptr::null_mut()) };
        check("AuthorizationCopyRights", status)
    }
}

impl Drop for Authorization {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a live reference, freed exactly once.
        unsafe {
            AuthorizationFree(self.0, FLAG_DESTROY_RIGHTS);
        }
    }
}

/// One value of a rule definition, as far as [`definition_ok`] needs it.
#[derive(Debug, Clone, PartialEq)]
pub enum RuleValue {
    Bool(bool),
    Int(i64),
    Real(f64),
    Text(String),
    /// A dictionary, array or anything else.
    Other,
}

/// A rule definition from the authorization database.
pub type RuleDefinition = BTreeMap<String, RuleValue>;

/// Faro's rule for [`ENROLL_RIGHT`]: an administrator authenticates every
/// time, root gets no shortcut, and nothing is shared or cached.
pub fn enroll_rule() -> Vec<(&'static str, RuleValue)> {
    vec![
        ("class", RuleValue::Text("user".into())),
        ("group", RuleValue::Text("admin".into())),
        ("shared", RuleValue::Bool(false)),
        ("timeout", RuleValue::Int(0)),
        ("allow-root", RuleValue::Bool(false)),
        ("authenticate-user", RuleValue::Bool(true)),
        ("session-owner", RuleValue::Bool(false)),
    ]
}

/// Keys authd adds or that only carry text: allowed with any value.
const METADATA_KEYS: &[&str] = &[
    "comment",
    "created",
    "modified",
    "version",
    "tries",
    "default-prompt",
    "default-button",
];

/// Whether `def` is exactly Faro's rule ([`enroll_rule`]) plus metadata.
///
/// Every required key must be there with exactly its value, and any other
/// key except the metadata authd keeps (comment, dates, version, tries,
/// prompts) makes it fail: `rule`, `mechanisms`, `k-of-n`,
/// `extract-password` and anything unknown could change who passes.
pub fn definition_ok(def: &RuleDefinition) -> Result<(), String> {
    let required = enroll_rule();
    for (key, want) in &required {
        match def.get(*key) {
            Some(have) if have == want => {}
            Some(have) => return Err(format!("`{key}` is {have:?}, expected {want:?}")),
            None => return Err(format!("`{key}` is missing")),
        }
    }
    for key in def.keys() {
        let known = required.iter().any(|(k, _)| k == key) || METADATA_KEYS.contains(&key.as_str());
        if !known {
            return Err(format!("unexpected key `{key}`"));
        }
    }
    Ok(())
}

fn to_rule_value(v: &CFType) -> RuleValue {
    if let Some(b) = v.downcast_ref::<CFBoolean>() {
        return RuleValue::Bool(b.as_bool());
    }
    if let Some(n) = v.downcast_ref::<CFNumber>() {
        // Lossless integer reads succeed only for integral values.
        if let Some(i) = n.as_i64() {
            return RuleValue::Int(i);
        }
        return n.as_f64().map_or(RuleValue::Other, RuleValue::Real);
    }
    if let Some(s) = v.downcast_ref::<CFString>() {
        return RuleValue::Text(s.to_string());
    }
    RuleValue::Other
}

/// Read a right's definition. `None` if the right does not exist.
pub fn read_rule(right: &str) -> Result<Option<RuleDefinition>, AuthError> {
    let name = CString::new(right).map_err(|_| AuthError::Os {
        call: "AuthorizationRightGet",
        status: 0,
    })?;
    let mut out: *const c_void = ptr::null();
    // SAFETY: `name` is NUL-terminated; `out` is a valid out-pointer that
    // receives a +1 CFDictionaryRef on success.
    let status = unsafe { AuthorizationRightGet(name.as_ptr(), &mut out) };
    if status == ERR_DENIED {
        // What authd answers for a right that isn't defined.
        return Ok(None);
    }
    check("AuthorizationRightGet", status)?;
    let Some(dict) = NonNull::new(out.cast_mut().cast::<CFDictionary>()) else {
        return Err(AuthError::Os {
            call: "AuthorizationRightGet",
            status: 0,
        });
    };
    // SAFETY: a successful AuthorizationRightGet returns a retained
    // CFDictionary, which we now own.
    let dict: CFRetained<CFDictionary> = unsafe { CFRetained::from_raw(dict) };
    // SAFETY: every key and value of a property-list dictionary is a CF
    // object; keys are type-checked before use.
    let dict = unsafe { dict.cast_unchecked::<CFType, CFType>() };
    let (keys, values) = dict.to_vecs();
    let mut def = RuleDefinition::new();
    for (k, v) in keys.iter().zip(values.iter()) {
        let Some(k) = k.downcast_ref::<CFString>() else {
            return Err(AuthError::RuleAltered("a key is not a string".into()));
        };
        def.insert(k.to_string(), to_rule_value(v));
    }
    Ok(Some(def))
}

/// A CF value for [`write_enroll_rule`].
enum Owned {
    Bool(&'static CFBoolean),
    Number(CFRetained<CFNumber>),
    Text(CFRetained<CFString>),
}

impl Owned {
    fn as_type(&self) -> &CFType {
        match self {
            Owned::Bool(b) => b,
            Owned::Number(n) => n,
            Owned::Text(s) => s,
        }
    }
}

/// Write Faro's rule for [`ENROLL_RIGHT`]. Needs root (or an
/// administrator): `config.modify.` for a right that exists.
fn write_enroll_rule() -> Result<(), AuthError> {
    let mut entries: Vec<(CFRetained<CFString>, Owned)> = enroll_rule()
        .into_iter()
        .map(|(k, v)| {
            let v = match v {
                RuleValue::Bool(b) => Owned::Bool(CFBoolean::new(b)),
                RuleValue::Int(i) => Owned::Number(CFNumber::new_i64(i)),
                RuleValue::Text(s) => Owned::Text(CFString::from_str(&s)),
                RuleValue::Real(_) | RuleValue::Other => {
                    unreachable!("enroll_rule has no such values")
                }
            };
            (CFString::from_str(k), v)
        })
        .collect();
    entries.push((
        CFString::from_str("comment"),
        Owned::Text(CFString::from_str(RULE_COMMENT)),
    ));
    let keys: Vec<&CFString> = entries.iter().map(|(k, _)| &**k).collect();
    let values: Vec<&CFType> = entries.iter().map(|(_, v)| v.as_type()).collect();
    let dict = CFDictionary::<CFString, CFType>::from_slices(&keys, &values);
    let prompt = CFString::from_str(RULE_PROMPT);
    let auth = Authorization::new_empty()?;
    let name = CString::new(ENROLL_RIGHT).map_err(|_| AuthError::Os {
        call: "AuthorizationRightSet",
        status: 0,
    })?;
    let dict_ptr: *const CFDictionary<CFString, CFType> = &*dict;
    let prompt_ptr: *const CFString = &*prompt;
    // SAFETY: `auth` is live, `name` NUL-terminated, `dict` and `prompt`
    // are valid CF objects that outlive the call; a null bundle and table
    // name are allowed.
    let status = unsafe {
        AuthorizationRightSet(
            auth.0,
            name.as_ptr(),
            dict_ptr.cast(),
            prompt_ptr.cast(),
            ptr::null(),
            ptr::null(),
        )
    };
    check("AuthorizationRightSet", status)
}

/// Rights that decide who may add, change or remove [`ENROLL_RIGHT`] more
/// specifically than Apple's `config.add.`, `config.modify.` and
/// `config.remove.`. None of them should ever exist; one that does could
/// let someone other than root or an administrator rewrite Faro's rule
/// between the check and the prompt, so the check fails closed.
pub const GUARD_RIGHTS: &[&str] = &[
    "config.add.org.faro.enroll",
    "config.modify.org.faro.enroll",
    "config.remove.org.faro.enroll",
    "config.modify.org.faro.",
    "config.modify.org.",
    "config.remove.org.faro.",
    "config.remove.org.",
];

/// What [`ensure_enroll_rule`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleCheck {
    /// The rule was already exactly Faro's.
    Correct,
    /// It was missing (`None`) or different (why), and was rewritten.
    Rewritten(Option<String>),
}

/// Make sure [`ENROLL_RIGHT`] is exactly Faro's rule. With `may_write`
/// (a root service) a missing or different rule is rewritten and read back;
/// without it, it is refused.
pub fn ensure_enroll_rule(may_write: bool) -> Result<RuleCheck, AuthError> {
    for guard in GUARD_RIGHTS {
        if read_rule(guard)?.is_some() {
            return Err(AuthError::RuleAltered(format!(
                "`{guard}` exists, so the rule may be changed without an administrator"
            )));
        }
    }
    let problem = match read_rule(ENROLL_RIGHT)? {
        Some(def) => match definition_ok(&def) {
            Ok(()) => return Ok(RuleCheck::Correct),
            Err(why) => Some(why),
        },
        None => None,
    };
    if !may_write {
        return Err(match problem {
            Some(why) => AuthError::RuleAltered(why),
            None => AuthError::RuleMissing,
        });
    }
    write_enroll_rule()?;
    match read_rule(ENROLL_RIGHT)? {
        Some(def) => definition_ok(&def).map_err(AuthError::RuleAltered)?,
        None => return Err(AuthError::RuleMissing),
    }
    Ok(RuleCheck::Rewritten(problem))
}

/// The service's side: check (and, with `may_write_rule`, fix) the rule,
/// then ask for [`ENROLL_RIGHT`] through the agent's authorization,
/// showing `prompt`. Blocks until an administrator answers, and destroys
/// the rights before it returns. `Ok` carries what was found about the
/// rule, for the log.
///
/// The agent's authorization must not carry the right already: asked
/// without a dialog first, it must be refused. Otherwise another program
/// could have shown the dialog with words of its own, got an
/// administrator's approval into an authorization, and handed that over.
/// Faro's rule should make this impossible anyway (`timeout: 0`,
/// `shared: false`); the check costs nothing.
pub fn approve_enrollment(
    external_form: &[u8; EXTERNAL_FORM_LEN],
    prompt: &str,
    may_write_rule: bool,
) -> Result<RuleCheck, AuthError> {
    let rule = ensure_enroll_rule(may_write_rule)?;
    let auth = Authorization::from_external_form(external_form)?;
    match auth.copy_rights(ENROLL_RIGHT, None, false) {
        Err(AuthError::InteractionNotAllowed | AuthError::Denied) => {}
        Ok(()) => return Err(AuthError::AlreadyAuthorized),
        Err(e) => return Err(e),
    }
    auth.copy_rights(ENROLL_RIGHT, Some(prompt), true)?;
    Ok(rule)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn faro_rule() -> RuleDefinition {
        let mut d: RuleDefinition = enroll_rule()
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect();
        // What authd adds on read-back.
        d.insert("comment".into(), RuleValue::Text(RULE_COMMENT.into()));
        d.insert("created".into(), RuleValue::Real(817183863.2));
        d.insert("modified".into(), RuleValue::Real(817183863.2));
        d.insert("version".into(), RuleValue::Int(0));
        d.insert("tries".into(), RuleValue::Int(10000));
        d.insert("default-prompt".into(), RuleValue::Other);
        d
    }

    #[test]
    fn faros_rule_is_accepted() {
        assert_eq!(definition_ok(&faro_rule()), Ok(()));
    }

    #[test]
    fn any_change_is_refused() {
        let changes: &[(&str, RuleValue)] = &[
            ("class", RuleValue::Text("allow".into())),
            ("class", RuleValue::Text("rule".into())),
            ("group", RuleValue::Text("staff".into())),
            ("shared", RuleValue::Bool(true)),
            ("timeout", RuleValue::Int(300)),
            ("timeout", RuleValue::Real(0.5)),
            ("allow-root", RuleValue::Bool(true)),
            ("authenticate-user", RuleValue::Bool(false)),
            ("session-owner", RuleValue::Bool(true)),
            ("shared", RuleValue::Int(0)),
        ];
        for (k, v) in changes {
            let mut d = faro_rule();
            d.insert((*k).to_owned(), v.clone());
            assert!(definition_ok(&d).is_err(), "{k} = {v:?} accepted");
        }
        for (k, _) in enroll_rule() {
            let mut d = faro_rule();
            d.remove(k);
            assert!(definition_ok(&d).is_err(), "missing {k} accepted");
        }
        for extra in [
            "rule",
            "mechanisms",
            "k-of-n",
            "extract-password",
            "entitled",
            "password-only",
            "something-new",
        ] {
            let mut d = faro_rule();
            d.insert(extra.to_owned(), RuleValue::Other);
            assert!(definition_ok(&d).is_err(), "extra {extra} accepted");
        }
    }

    /// Read-only: an Apple right reads back with the keys this module
    /// expects authd to add, and is (rightly) not Faro's rule.
    #[test]
    fn reads_an_existing_right() {
        let def = read_rule("system.preferences")
            .expect("readable")
            .expect("system.preferences exists");
        assert_eq!(def.get("class"), Some(&RuleValue::Text("user".into())));
        assert!(matches!(def.get("timeout"), Some(RuleValue::Int(_))));
        assert!(matches!(def.get("shared"), Some(RuleValue::Bool(_))));
        assert!(definition_ok(&def).is_err());
        assert_eq!(read_rule("org.faro.test.does-not-exist"), Ok(None));
    }

    /// The no-GUI check of the whole path: create a reference, export and
    /// import it as the service does, and ask for the right without
    /// allowing a dialog. It must not be granted.
    ///
    /// If an administrator authenticated in this login session in the last
    /// few minutes and `org.faro.enroll` is not defined yet, authd's default
    /// rule could reuse that credential; Faro's own rule never would
    /// (`shared: false`, `timeout: 0`), which is why the service checks the
    /// rule before every prompt.
    #[test]
    fn no_approval_without_a_dialog() {
        let agent = Authorization::new_empty().expect("create");
        let ext = agent.external_form().expect("export");
        let service = Authorization::from_external_form(&ext).expect("import");
        let r = service.copy_rights(ENROLL_RIGHT, Some("test"), false);
        assert!(
            matches!(r, Err(AuthError::InteractionNotAllowed | AuthError::Denied)),
            "{r:?}"
        );
    }

    /// Read-only: on a normal Mac no right overrides who may change
    /// Faro's rule.
    #[test]
    fn no_guard_right_exists() {
        for g in GUARD_RIGHTS {
            assert_eq!(read_rule(g), Ok(None), "{g}");
        }
    }

    #[test]
    fn non_root_never_writes_the_rule() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        // Read-only when `may_write` is false: missing or not Faro's.
        match ensure_enroll_rule(false) {
            Ok(RuleCheck::Correct) => {} // a root service on this Mac set it up
            Ok(RuleCheck::Rewritten(_)) => panic!("wrote the rule without root"),
            Err(AuthError::RuleMissing | AuthError::RuleAltered(_)) => {}
            Err(e) => panic!("{e}"),
        }
    }

    /// Writes `org.faro.enroll` into this Mac's authorization database.
    /// Run it on a test Mac only:
    /// `sudo -E cargo test -p faro-platform-macos authorization -- --ignored`.
    #[test]
    #[ignore = "modifies the system authorization database; run as root on a test Mac"]
    fn root_writes_and_reads_back_the_rule() {
        ensure_enroll_rule(true).expect("rule set up");
        let def = read_rule(ENROLL_RIGHT).unwrap().unwrap();
        assert_eq!(definition_ok(&def), Ok(()), "{def:?}");
    }
}
