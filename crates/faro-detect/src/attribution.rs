//! What a licence asks to travel with third-party data (§11): the rules
//! shared by model manifests ([`ModelInfo`](crate::ModelInfo)) and the
//! domain bundle compiler (`domains-compile`).
//!
//! Every licence on [`ALLOWED_MODEL_LICENSES`](crate::ALLOWED_MODEL_LICENSES)
//! except the public-domain dedications asks for attribution. The
//! permissive software licences (MIT, BSD, ISC, Zlib, Apache-2.0) also ask
//! for the copyright notice and the licence text to go with every copy,
//! binaries included. CC BY 4.0 needs attribution and a link to the
//! licence, but not its text.

use serde::{Deserialize, Serialize};

/// Allowlisted licences that ask for nothing to travel with the work.
pub const NO_ATTRIBUTION_LICENSES: &[&str] = &["CC0-1.0", "Unlicense"];

/// Allowlisted licences whose text must accompany copies, together with
/// the copyright notice.
pub const TEXT_REQUIRED_LICENSES: &[&str] = &[
    "Apache-2.0",
    "MIT",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "Zlib",
];

/// Who made a work, under what terms, and what Faro changed. Copied
/// verbatim into every manifest that ships the work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attribution {
    /// The creators, as the upstream names them.
    pub author: String,
    /// The upstream's copyright notices, verbatim. Required for licences
    /// in [`TEXT_REQUIRED_LICENSES`]; may be empty for CC-BY-4.0 when the
    /// upstream gives none.
    #[serde(default)]
    pub copyright: Vec<String>,
    /// Where the upstream publishes the work.
    pub source_url: String,
    /// The licence the work is used under.
    pub license_url: String,
    /// What was changed (CC BY 4.0 §3(a)(1)(B); also good practice for
    /// everything else).
    pub changes: String,
}

/// Why an attribution doesn't satisfy its licence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttributionError {
    /// The licence asks for attribution and there is none.
    Missing,
    /// This field is empty.
    EmptyField(&'static str),
    /// One of the copyright lines is empty.
    EmptyCopyrightLine,
    /// This licence needs the copyright notice, and there is none.
    NoCopyright(String),
    /// This licence needs its text to travel with the work, and it doesn't.
    NoLicenseText(String),
}

impl std::fmt::Display for AttributionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttributionError::Missing => {
                write!(f, "the licence requires attribution, but there is none")
            }
            AttributionError::EmptyField(field) => write!(f, "attribution.{field} is empty"),
            AttributionError::EmptyCopyrightLine => write!(f, "empty attribution.copyright line"),
            AttributionError::NoCopyright(id) => {
                write!(
                    f,
                    "{id} requires the copyright notice, but attribution.copyright is empty"
                )
            }
            AttributionError::NoLicenseText(id) => {
                write!(
                    f,
                    "{id} requires its text to travel with the work, but it is missing"
                )
            }
        }
    }
}

impl std::error::Error for AttributionError {}

/// Check that `attribution` carries everything the licences `ids` (SPDX
/// identifiers) ask for. `has_text(id)` says whether the full text of
/// licence `id` travels with the work.
pub fn check_attribution<'a>(
    ids: impl IntoIterator<Item = &'a str>,
    attribution: Option<&Attribution>,
    has_text: impl Fn(&str) -> bool,
) -> Result<(), AttributionError> {
    let ids: Vec<&str> = ids.into_iter().collect();
    if ids.iter().all(|id| NO_ATTRIBUTION_LICENSES.contains(id)) {
        return Ok(());
    }
    let a = attribution.ok_or(AttributionError::Missing)?;
    for (field, value) in [
        ("author", &a.author),
        ("source_url", &a.source_url),
        ("license_url", &a.license_url),
        ("changes", &a.changes),
    ] {
        if value.trim().is_empty() {
            return Err(AttributionError::EmptyField(field));
        }
    }
    if a.copyright.iter().any(|c| c.trim().is_empty()) {
        return Err(AttributionError::EmptyCopyrightLine);
    }
    for id in ids.iter().filter(|id| TEXT_REQUIRED_LICENSES.contains(id)) {
        if a.copyright.is_empty() {
            return Err(AttributionError::NoCopyright((*id).to_owned()));
        }
        if !has_text(id) {
            return Err(AttributionError::NoLicenseText((*id).to_owned()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full() -> Attribution {
        Attribution {
            author: "A".into(),
            copyright: vec!["Copyright (c) 2026 A".into()],
            source_url: "https://example.org/a".into(),
            license_url: "https://example.org/a/LICENSE".into(),
            changes: "Converted.".into(),
        }
    }

    #[test]
    fn rules() {
        let yes = |_: &str| true;
        let no = |_: &str| false;
        assert_eq!(check_attribution(["MIT"], Some(&full()), yes), Ok(()));
        assert_eq!(
            check_attribution(["MIT"], None, yes),
            Err(AttributionError::Missing)
        );
        assert_eq!(
            check_attribution(["BSD-2-Clause"], Some(&full()), no),
            Err(AttributionError::NoLicenseText("BSD-2-Clause".into()))
        );
        let mut a = full();
        a.copyright.clear();
        assert_eq!(
            check_attribution(["MIT"], Some(&a), yes),
            Err(AttributionError::NoCopyright("MIT".into()))
        );
        // CC BY 4.0 needs attribution but no copyright line or text.
        assert_eq!(check_attribution(["CC-BY-4.0"], Some(&a), no), Ok(()));
        assert_eq!(
            check_attribution(["CC-BY-4.0"], None, no),
            Err(AttributionError::Missing)
        );
        a.copyright.push(" ".into());
        assert_eq!(
            check_attribution(["CC-BY-4.0"], Some(&a), no),
            Err(AttributionError::EmptyCopyrightLine)
        );
        let mut a = full();
        a.changes = " ".into();
        assert_eq!(
            check_attribution(["MIT"], Some(&a), yes),
            Err(AttributionError::EmptyField("changes"))
        );
        // Public-domain dedications need nothing, alone or together.
        assert_eq!(check_attribution(["CC0-1.0"], None, no), Ok(()));
        assert_eq!(
            check_attribution(["CC0-1.0", "Unlicense"], None, no),
            Ok(())
        );
        assert_eq!(
            check_attribution(["CC0-1.0", "MIT"], None, no),
            Err(AttributionError::Missing)
        );
    }
}
