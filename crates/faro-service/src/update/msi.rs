//! The Windows update package: an MSI, checked before it is installed.
//!
//! The Windows counterpart of [`super::signature`] (#66) and
//! [`super::package_version`] (#71). The update metadata says which bytes
//! to install (PROTOCOL.md §8.2); someone who holds both online keys and
//! controls a mirror could still list a package that isn't Faro's, or an
//! old one Faro really signed under a higher version. So before the
//! install starts, the service checks the downloaded `.msi` itself:
//!
//! 1. **Signed by Faro.** Its Authenticode signature must chain to a
//!    trusted root and its signer must satisfy the requirement compiled in
//!    from `FARO_WINDOWS_SIGNER` ([`BUILD_SIGNER`]; the
//!    `faro_platform_windows::authenticode::SignerRequirement` syntax,
//!    `subject="…"` optionally followed by `; sha256=<thumbprint>,…`). It
//!    never comes from the update, its metadata, the mirror or the config
//!    file. `installers/windows/build-msi.ps1` passes the same value to
//!    `cargo` and writes it as the default `ipc.agent_requirement`.
//! 2. **Faro's product.** The MSI's `UpgradeCode` must be Faro's
//!    ([`UPGRADE_CODE`], fixed in `installers/windows/Faro.wxs`). This
//!    matters most when the signer is shared: the SignPath Foundation signs
//!    many projects under one name, so a subject-only requirement would
//!    accept any of their MSIs.
//! 3. **The version the metadata says.** An MSI's `ProductVersion` is
//!    numeric only (`major.minor.build`, at most 255.255.65535), so it can't
//!    carry a pre-release: `0.1.0-beta.1` is `0.1.0`. The build writes the
//!    full semver version into the private property [`VERSION_PROPERTY`]
//!    (`FaroVersion`), and this module reads both from the `Property`
//!    table. `FaroVersion` must be the target's and above the installed
//!    version (semver precedence, [`super::package_version::judge_version`]),
//!    and `ProductVersion` must be its numeric part.
//!
//! **How it is read.** With the pure-Rust `msi` crate: the file is a
//! compound document, and the `Property` table is read straight from its
//! streams. Nothing is run and nothing is unpacked to disk. The table is
//! part of what the Authenticode signature of an MSI covers (every stream
//! and storage except the signature's own), and the signature is checked
//! first, so the version read is the one Faro signed. The file lives in the
//! state directory (`%ProgramData%\Faro\updates`), which only SYSTEM and
//! Administrators can write, between the check and the install.
//!
//! **Outcomes**, as on macOS: [`Rejected`] is positive evidence (unsigned,
//! another signer, an untrusted chain, another product, another version);
//! the service records it, never retries that package and reports a
//! tamper-class integrity failure. [`Unconfirmed`] means the check couldn't
//! conclude (the file can't be read, a property is missing or malformed,
//! the two versions disagree, an OS error, this build has no signer).
//!
//! **Development builds.** A `-Dev` MSI is unsigned and its service has the
//! `dev` feature and no signer: it skips step 1 (steps 2 and 3 still
//! apply), so development packages can update each other. A build without
//! the `dev` feature and without a signer refuses every package. The
//! decision is made at compile time ([`BUILD_POLICY`]).

use super::package_version::judge_version;
use super::signature::PackageCheckError::{self, Rejected, Unconfirmed};
use faro_platform_windows::authenticode::{AuthenticodeError, SignerInfo, SignerRequirement};
use faro_update::Version;
use std::io::{Read, Seek};
use std::path::Path;

/// Faro's MSI `UpgradeCode`. Never change it: Windows Installer finds the
/// installed Faro to upgrade by it (`installers/windows/Faro.wxs`).
pub const UPGRADE_CODE: &str = "{07FB4D24-3048-4FE8-AFCF-2C9549BC9982}";
/// The private MSI property holding the full semver version.
pub const VERSION_PROPERTY: &str = "FaroVersion";

/// The signer requirement this service was built with
/// (`FARO_WINDOWS_SIGNER`), if any. An empty value counts as none.
pub const BUILD_SIGNER: Option<&str> = non_empty(option_env!("FARO_WINDOWS_SIGNER"));

/// What this build requires of an update package, fixed at compile time.
pub const BUILD_POLICY: SignerPolicy = policy_for(BUILD_SIGNER, cfg!(feature = "dev"));

/// What an update package's signature must be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerPolicy {
    /// Authenticode-signed by a signer satisfying this requirement.
    Require { requirement: &'static str },
    /// No signer and not a development build: nothing can be installed.
    RefuseAll,
    /// A development build without a signer: no signature check. Only a
    /// build with the `dev` feature acts on it.
    Unchecked,
}

/// The policy for a build. A signer always wins, also in a development
/// build. Without one, only the `dev` feature skips the check.
pub const fn policy_for(signer: Option<&'static str>, dev: bool) -> SignerPolicy {
    match signer {
        Some(requirement) => SignerPolicy::Require { requirement },
        None if dev => SignerPolicy::Unchecked,
        None => SignerPolicy::RefuseAll,
    }
}

const fn non_empty(v: Option<&'static str>) -> Option<&'static str> {
    match v {
        Some(s) if !s.is_empty() => Some(s),
        _ => None,
    }
}

/// A package whose signature passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignerAccepted {
    Verified(SignerInfo),
    /// A development build: not checked.
    Unchecked,
}

/// Check `msi`'s Authenticode signature against this build's policy.
pub fn check_signature(msi: &Path) -> Result<SignerAccepted, PackageCheckError> {
    check_signature_with(BUILD_POLICY, msi, &mut |p, r| {
        faro_platform_windows::authenticode::verify_file(p, r)
    })
}

/// [`check_signature`] with the policy and the verifier given (tests).
pub fn check_signature_with(
    policy: SignerPolicy,
    msi: &Path,
    verify: &mut dyn FnMut(&Path, &SignerRequirement) -> Result<SignerInfo, AuthenticodeError>,
) -> Result<SignerAccepted, PackageCheckError> {
    let requirement = match policy {
        SignerPolicy::Require { requirement } => requirement,
        SignerPolicy::RefuseAll => {
            return Err(Unconfirmed(
                "this build has no signer requirement (FARO_WINDOWS_SIGNER), so it can't check packages"
                    .into(),
            ))
        }
        SignerPolicy::Unchecked if cfg!(feature = "dev") => return Ok(SignerAccepted::Unchecked),
        SignerPolicy::Unchecked => {
            return Err(Unconfirmed(
                "only a development build may skip the signature check".into(),
            ))
        }
    };
    let req = SignerRequirement::parse(requirement).map_err(|e| {
        Unconfirmed(format!(
            "this build's signer requirement (FARO_WINDOWS_SIGNER) is invalid: {e}"
        ))
    })?;
    verify(msi, &req)
        .map(SignerAccepted::Verified)
        .map_err(judge_authenticode)
}

/// Which verification failures are evidence that the package isn't Faro's.
pub fn judge_authenticode(e: AuthenticodeError) -> PackageCheckError {
    match e {
        AuthenticodeError::Unsigned
        | AuthenticodeError::Untrusted(_)
        | AuthenticodeError::WrongSigner(_) => {
            Rejected(format!("the MSI's Authenticode signature: {e}"))
        }
        AuthenticodeError::Requirement(_) | AuthenticodeError::Os(_) => Unconfirmed(format!(
            "cannot check the MSI's Authenticode signature: {e}"
        )),
    }
}

/// What the updater reads from an MSI's `Property` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsiFacts {
    pub upgrade_code: Option<String>,
    pub product_version: Option<String>,
    pub faro_version: Option<String>,
}

/// Read [`MsiFacts`] from the MSI at `path`.
pub fn read_facts(path: &Path) -> Result<MsiFacts, PackageCheckError> {
    let f = std::fs::File::open(path)
        .map_err(|e| Unconfirmed(format!("cannot open {}: {e}", path.display())))?;
    read_facts_from(f)
}

/// Read [`MsiFacts`] from an MSI. A property given twice can't be judged.
pub fn read_facts_from<R: Read + Seek>(r: R) -> Result<MsiFacts, PackageCheckError> {
    let bad = |e: std::io::Error| Unconfirmed(format!("not a readable MSI: {e}"));
    let mut pkg = msi::Package::open(r).map_err(bad)?;
    if pkg.package_type() != msi::PackageType::Installer {
        return Err(Unconfirmed("not an installer database".into()));
    }
    let rows = pkg
        .select_rows(msi::Select::table("Property").columns(&["Property", "Value"]))
        .map_err(bad)?;
    let mut facts = MsiFacts {
        upgrade_code: None,
        product_version: None,
        faro_version: None,
    };
    for row in rows {
        let (Some(name), Some(value)) = (row[0].as_str(), row[1].as_str()) else {
            continue;
        };
        let slot = match name {
            "UpgradeCode" => &mut facts.upgrade_code,
            "ProductVersion" => &mut facts.product_version,
            VERSION_PROPERTY => &mut facts.faro_version,
            _ => continue,
        };
        if slot.replace(value.to_owned()).is_some() {
            return Err(Unconfirmed(format!("the MSI sets {name} twice")));
        }
    }
    Ok(facts)
}

/// The `ProductVersion` an MSI of `v` carries: `major.minor.patch`, with
/// Windows Installer's limits. `None` if `v` doesn't fit.
pub fn product_version_of(v: &Version) -> Option<String> {
    (v.major <= 255 && v.minor <= 255 && v.patch <= 65_535)
        .then(|| format!("{}.{}.{}", v.major, v.minor, v.patch))
}

/// Judge what an MSI says about itself. Returns its full version.
pub fn judge_facts(
    facts: &MsiFacts,
    target: &Version,
    installed: &Version,
) -> Result<Version, PackageCheckError> {
    let upgrade = facts
        .upgrade_code
        .as_deref()
        .ok_or_else(|| Unconfirmed("the MSI has no UpgradeCode".into()))?;
    if !upgrade.eq_ignore_ascii_case(UPGRADE_CODE) {
        return Err(Rejected(format!(
            "the MSI's UpgradeCode is {upgrade}, not Faro's {UPGRADE_CODE}"
        )));
    }
    let text = facts
        .faro_version
        .as_deref()
        .ok_or_else(|| Unconfirmed(format!("the MSI has no {VERSION_PROPERTY} property")))?;
    let found = Version::parse(text).map_err(|e| {
        Unconfirmed(format!(
            "the MSI's {VERSION_PROPERTY} {text:?} is not semver: {e}"
        ))
    })?;
    let numeric = facts
        .product_version
        .as_deref()
        .ok_or_else(|| Unconfirmed("the MSI has no ProductVersion".into()))?;
    if product_version_of(&found).as_deref() != Some(numeric) {
        return Err(Unconfirmed(format!(
            "the MSI's ProductVersion {numeric} doesn't match its {VERSION_PROPERTY} {found}"
        )));
    }
    judge_version(&found, target, installed)?;
    Ok(found)
}

/// Read `msi`'s version and check it against the target's and the
/// installed one. Returns the version read.
pub fn check_version(
    msi: &Path,
    target: &Version,
    installed: &Version,
) -> Result<Version, PackageCheckError> {
    judge_facts(&read_facts(msi)?, target, installed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }

    /// A minimal installer database with a `Property` table, as WiX writes
    /// one (the crate builds it in memory: no binary is committed).
    fn msi_with(props: &[(&str, &str)]) -> Vec<u8> {
        let mut pkg =
            msi::Package::create(msi::PackageType::Installer, Cursor::new(Vec::new())).unwrap();
        pkg.create_table(
            "Property",
            vec![
                msi::Column::build("Property").primary_key().id_string(72),
                msi::Column::build("Value").text_string(0),
            ],
        )
        .unwrap();
        let rows = props
            .iter()
            .map(|(k, val)| vec![msi::Value::from(*k), msi::Value::from(*val)])
            .collect();
        pkg.insert_rows(msi::Insert::into("Property").rows(rows))
            .unwrap();
        pkg.into_inner().unwrap().into_inner()
    }

    fn faro_msi(version: &str, product: &str) -> Vec<u8> {
        msi_with(&[
            ("ProductName", "Faro"),
            ("UpgradeCode", UPGRADE_CODE),
            ("ProductVersion", product),
            (VERSION_PROPERTY, version),
        ])
    }

    fn facts(bytes: Vec<u8>) -> Result<MsiFacts, PackageCheckError> {
        read_facts_from(Cursor::new(bytes))
    }

    #[test]
    fn reads_the_version_from_a_generated_msi() {
        let f = facts(faro_msi("0.2.0-beta.1", "0.2.0")).unwrap();
        assert_eq!(f.faro_version.as_deref(), Some("0.2.0-beta.1"));
        assert_eq!(f.product_version.as_deref(), Some("0.2.0"));
        assert_eq!(f.upgrade_code.as_deref(), Some(UPGRADE_CODE));
        let got = judge_facts(&f, &v("0.2.0-beta.1"), &v("0.1.0")).unwrap();
        assert_eq!(got, v("0.2.0-beta.1"));
    }

    #[test]
    fn reads_from_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("Faro.msi");
        std::fs::write(&p, faro_msi("1.0.0", "1.0.0")).unwrap();
        assert_eq!(
            check_version(&p, &v("1.0.0"), &v("0.9.0")).unwrap(),
            v("1.0.0")
        );
        let missing = dir.path().join("nope.msi");
        assert!(matches!(
            check_version(&missing, &v("1.0.0"), &v("0.9.0")),
            Err(Unconfirmed(_))
        ));
    }

    #[test]
    fn another_version_or_a_downgrade_is_rejected() {
        let f = facts(faro_msi("0.1.0-beta.1", "0.1.0")).unwrap();
        // An old release listed as a newer one.
        assert!(matches!(
            judge_facts(&f, &v("99.0.0"), &v("0.1.0-beta.1")),
            Err(Rejected(_))
        ));
        // The target's version, but not above the running one.
        assert!(matches!(
            judge_facts(&f, &v("0.1.0-beta.1"), &v("0.1.0-beta.1")),
            Err(Rejected(_))
        ));
        assert!(matches!(
            judge_facts(&f, &v("0.1.0-beta.1"), &v("0.1.0")),
            Err(Rejected(_))
        ));
    }

    #[test]
    fn another_product_is_rejected() {
        let f = facts(msi_with(&[
            ("UpgradeCode", "{00000000-0000-0000-0000-000000000000}"),
            ("ProductVersion", "1.0.0"),
            (VERSION_PROPERTY, "1.0.0"),
        ]))
        .unwrap();
        assert!(matches!(
            judge_facts(&f, &v("1.0.0"), &v("0.1.0")),
            Err(Rejected(_))
        ));
        // GUIDs compare without regard to case.
        let lower = facts(msi_with(&[
            ("UpgradeCode", &UPGRADE_CODE.to_ascii_lowercase()),
            ("ProductVersion", "1.0.0"),
            (VERSION_PROPERTY, "1.0.0"),
        ]))
        .unwrap();
        assert!(judge_facts(&lower, &v("1.0.0"), &v("0.1.0")).is_ok());
    }

    #[test]
    fn missing_or_inconsistent_properties_are_unconfirmed() {
        let cases: Vec<Vec<(&str, &str)>> = vec![
            vec![("ProductVersion", "1.0.0"), (VERSION_PROPERTY, "1.0.0")],
            vec![("UpgradeCode", UPGRADE_CODE), ("ProductVersion", "1.0.0")],
            vec![("UpgradeCode", UPGRADE_CODE), (VERSION_PROPERTY, "1.0.0")],
            vec![
                ("UpgradeCode", UPGRADE_CODE),
                ("ProductVersion", "1.0.0"),
                (VERSION_PROPERTY, "one"),
            ],
            // The numeric version must be the semver one's.
            vec![
                ("UpgradeCode", UPGRADE_CODE),
                ("ProductVersion", "1.0.1"),
                (VERSION_PROPERTY, "1.0.0"),
            ],
        ];
        for props in cases {
            let f = facts(msi_with(&props)).unwrap();
            assert!(
                matches!(
                    judge_facts(&f, &v("1.0.0"), &v("0.1.0")),
                    Err(Unconfirmed(_))
                ),
                "{props:?}"
            );
        }
        assert!(matches!(
            facts(b"not an msi at all".to_vec()),
            Err(Unconfirmed(_))
        ));
    }

    #[test]
    fn product_versions() {
        assert_eq!(product_version_of(&v("0.1.0-beta.1")).unwrap(), "0.1.0");
        assert_eq!(
            product_version_of(&v("255.255.65535")).unwrap(),
            "255.255.65535"
        );
        assert_eq!(product_version_of(&v("256.0.0")), None);
        assert_eq!(product_version_of(&v("1.0.65536")), None);
    }

    fn info() -> SignerInfo {
        SignerInfo {
            subject: "Faro Project".into(),
            thumbprint_sha256: "ab".repeat(32),
            issuer_thumbprint_sha256: None,
        }
    }

    #[test]
    fn policies() {
        assert_eq!(
            policy_for(Some("subject=\"Faro\""), false),
            SignerPolicy::Require {
                requirement: "subject=\"Faro\""
            }
        );
        assert_eq!(
            policy_for(Some("subject=\"Faro\""), true),
            SignerPolicy::Require {
                requirement: "subject=\"Faro\""
            }
        );
        assert_eq!(policy_for(None, true), SignerPolicy::Unchecked);
        assert_eq!(policy_for(None, false), SignerPolicy::RefuseAll);
        assert_eq!(non_empty(Some("")), None);
        assert_eq!(
            BUILD_POLICY,
            policy_for(BUILD_SIGNER, cfg!(feature = "dev"))
        );
    }

    #[cfg(not(feature = "dev"))]
    #[test]
    fn a_release_build_never_skips_the_signature() {
        assert_ne!(BUILD_POLICY, SignerPolicy::Unchecked);
        let mut called = false;
        let r = check_signature_with(SignerPolicy::Unchecked, Path::new("x.msi"), &mut |_, _| {
            called = true;
            Ok(info())
        });
        assert!(matches!(r, Err(Unconfirmed(_))));
        assert!(!called);
    }

    #[cfg(feature = "dev")]
    #[test]
    fn a_dev_build_without_a_signer_skips_it() {
        let r = check_signature_with(SignerPolicy::Unchecked, Path::new("x.msi"), &mut |_, _| {
            panic!("must not verify")
        });
        assert_eq!(r.unwrap(), SignerAccepted::Unchecked);
    }

    #[test]
    fn refuse_all_never_verifies() {
        let r = check_signature_with(SignerPolicy::RefuseAll, Path::new("x.msi"), &mut |_, _| {
            panic!("must not verify")
        });
        assert!(matches!(r, Err(Unconfirmed(_))));
    }

    #[test]
    fn verification_failures() {
        // The verifier is faro_platform_windows::authenticode::verify_file in
        // the service; here it is a stand-in, and the requirement parser is
        // the real one.
        let parsed = SignerRequirement::parse("subject=\"Faro Project\"");
        let policy = SignerPolicy::Require {
            requirement: "subject=\"Faro Project\"",
        };
        let Ok(want) = parsed else {
            // The parser is not implemented yet (it is a stub returning an
            // error): the check can't conclude, and must not verify.
            let r = check_signature_with(policy, Path::new("x.msi"), &mut |_, _| {
                panic!("must not verify with an unparsed requirement")
            });
            assert!(matches!(r, Err(Unconfirmed(_))));
            return;
        };
        let ok = check_signature_with(policy, Path::new("x.msi"), &mut |p, r| {
            assert_eq!(p, Path::new("x.msi"));
            assert_eq!(r, &want);
            Ok(info())
        });
        assert_eq!(ok.unwrap(), SignerAccepted::Verified(info()));
        for (e, rejected) in [
            (AuthenticodeError::Unsigned, true),
            (AuthenticodeError::Untrusted("expired".into()), true),
            (AuthenticodeError::WrongSigner("Someone Else".into()), true),
            (AuthenticodeError::Os("access denied".into()), false),
            (AuthenticodeError::Requirement("bad".into()), false),
        ] {
            let r = check_signature_with(policy, Path::new("x.msi"), &mut |_, _| Err(e.clone()));
            match r {
                Err(Rejected(_)) => assert!(rejected, "{e:?}"),
                Err(Unconfirmed(_)) => assert!(!rejected, "{e:?}"),
                other => panic!("{e:?}: {other:?}"),
            }
        }
    }

    #[test]
    fn an_invalid_build_requirement_is_unconfirmed() {
        let r = check_signature_with(
            SignerPolicy::Require {
                requirement: "not a requirement",
            },
            Path::new("x.msi"),
            &mut |_, _| panic!("must not verify"),
        );
        assert!(matches!(r, Err(Unconfirmed(_))));
    }
}
