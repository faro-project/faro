//! Choosing which verified target to install.

use crate::metadata::{
    is_valid_channel_name, parse_os_version, TargetCustom, TargetKind, Targets, STABLE_CHANNEL,
};
use faro_proto::Hash32;
use semver::Version;
use std::fmt;
use std::str::FromStr;

/// An update channel, as configured by the member or pinned by the
/// instance admin.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Channel {
    /// Newest release in the named channel (`stable`, `beta`, ...).
    Named(String),
    /// `stable-1`: the newest release on the minor line immediately below
    /// the newest stable line. See [`VerifiedTargets::select_with`].
    StableMinusOne,
}

impl Channel {
    pub fn stable() -> Self {
        Channel::Named(STABLE_CHANNEL.to_owned())
    }
}

/// The string is neither a valid channel name nor `stable-1`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid channel {0:?}: expected a channel name like \"stable\" or the pin \"stable-1\"")]
pub struct InvalidChannel(pub String);

impl FromStr for Channel {
    type Err = InvalidChannel;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "stable-1" {
            Ok(Channel::StableMinusOne)
        } else if is_valid_channel_name(s) {
            Ok(Channel::Named(s.to_owned()))
        } else {
            Err(InvalidChannel(s.to_owned()))
        }
    }
}

impl fmt::Display for Channel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Channel::Named(n) => f.write_str(n),
            Channel::StableMinusOne => f.write_str("stable-1"),
        }
    }
}

/// A selected target: everything needed to download and verify it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetInfo {
    /// Name / mirror path.
    pub name: String,
    pub length: u64,
    pub blake3: Hash32,
    pub custom: TargetCustom,
}

/// Full selection query. [`VerifiedTargets::select`] covers the common case.
#[derive(Debug, Clone)]
pub struct Selection<'a> {
    pub channel: &'a Channel,
    pub kind: TargetKind,
    /// The client's platform (`macos`, `windows`, `linux`). Targets with
    /// platform `any` match every platform.
    pub platform: &'a str,
    /// The client's arch (`aarch64`, `x86_64`). Targets with arch `any`
    /// match every arch.
    pub arch: &'a str,
    /// Installed version, if any. `None` means "nothing installed".
    pub current_version: Option<&'a Version>,
    /// The running OS version; targets whose `min_os` is above it are
    /// skipped. `None` disables the check (e.g. OS version unknown).
    pub os_version: Option<&'a Version>,
    /// Permit selecting a version *below* `current_version` (an admin
    /// rolling a fleet back to `stable-1`). Off by default: without it, a
    /// pin can only hold clients where they are, never push them back.
    pub allow_downgrade: bool,
}

/// A targets document that passed [`crate::Updater::verify_targets`].
///
/// Only obtainable through verification, so holding one is proof the
/// listing is authentic, fresh and consistent with the trusted timestamp.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTargets {
    targets: Targets,
}

impl VerifiedTargets {
    pub(crate) fn new(targets: Targets) -> Self {
        VerifiedTargets { targets }
    }

    /// The verified document (e.g. for the server mirror to fetch every
    /// listed artifact).
    pub fn targets(&self) -> &Targets {
        &self.targets
    }

    /// All targets as [`TargetInfo`], in name order.
    pub fn iter(&self) -> impl Iterator<Item = TargetInfo> + '_ {
        self.targets.targets.iter().map(|(name, f)| TargetInfo {
            name: name.clone(),
            length: f.length,
            blake3: f.blake3,
            custom: f.custom.clone(),
        })
    }

    /// Look up one target by name.
    pub fn get(&self, name: &str) -> Option<TargetInfo> {
        self.targets.targets.get(name).map(|f| TargetInfo {
            name: name.to_owned(),
            length: f.length,
            blake3: f.blake3,
            custom: f.custom.clone(),
        })
    }

    /// The update to install for `kind` on `platform`/`arch` in `channel`,
    /// or `None` if there is nothing newer than `current_version`.
    pub fn select(
        &self,
        channel: &Channel,
        kind: TargetKind,
        platform: &str,
        arch: &str,
        current_version: Option<&Version>,
    ) -> Option<TargetInfo> {
        self.select_with(&Selection {
            channel,
            kind,
            platform,
            arch,
            current_version,
            os_version: None,
            allow_downgrade: false,
        })
    }

    /// Selection with every knob.
    ///
    /// Candidates are targets of the requested `kind` whose platform and
    /// arch match (or are `any`) and whose `min_os` is satisfied.
    ///
    /// * `Channel::Named(c)`: the highest semver among candidates listed in
    ///   channel `c`.
    /// * `Channel::StableMinusOne`: let `N` be the highest semver among
    ///   `stable` candidates. Collect the distinct `(major, minor)` lines of
    ///   all `stable` candidates and take the greatest line strictly below
    ///   `(N.major, N.minor)`; select the highest version on that line. This
    ///   handles major bumps naturally: with stable lines 1.8, 1.9 and 2.0,
    ///   `stable-1` is the newest 1.9.x. If no such line exists (only one
    ///   stable line has ever shipped for this platform), nothing is
    ///   selected — a pin never falls through to the newest release.
    ///
    /// Then, against `current_version`: a selection equal to the installed
    /// version is always `None`; a lower one is `None` unless
    /// `allow_downgrade`. Ties between equal versions (differing only in
    /// build metadata ordering) resolve to the semver-greatest, then the
    /// last name in order, so the result is deterministic.
    ///
    /// `min_client` is not checked here (the mirror selects for every
    /// client). A client uses [`select_for`](Self::select_for).
    pub fn select_with(&self, q: &Selection<'_>) -> Option<TargetInfo> {
        self.select_filtered(q, None)
    }

    /// [`select_with`](Self::select_with) for a client running version
    /// `client`: a target whose `min_client` is above it is not a
    /// candidate, so an older target this client can use wins instead.
    pub fn select_for(&self, q: &Selection<'_>, client: &Version) -> Option<TargetInfo> {
        self.select_filtered(q, Some(client))
    }

    fn select_filtered(&self, q: &Selection<'_>, client: Option<&Version>) -> Option<TargetInfo> {
        let candidates = self.iter().filter(|t| {
            let c = &t.custom;
            c.kind == q.kind
                && (c.platform == q.platform || c.platform == "any")
                && (c.arch == q.arch || c.arch == "any")
                && os_ok(c.min_os.as_deref(), q.os_version)
                && client_ok(c.min_client.as_ref(), client)
        });

        let in_channel = |t: &TargetInfo, ch: &str| t.custom.channels.iter().any(|c| c == ch);

        let chosen = match q.channel {
            Channel::Named(ch) => candidates
                .filter(|t| in_channel(t, ch))
                .max_by(|a, b| a.custom.version.cmp(&b.custom.version)),
            Channel::StableMinusOne => {
                let stable: Vec<TargetInfo> = candidates
                    .filter(|t| in_channel(t, STABLE_CHANNEL))
                    .collect();
                let newest_line = stable.iter().map(|t| line(&t.custom.version)).max()?;
                let prev_line = stable
                    .iter()
                    .map(|t| line(&t.custom.version))
                    .filter(|l| *l < newest_line)
                    .max()?;
                stable
                    .into_iter()
                    .filter(|t| line(&t.custom.version) == prev_line)
                    .max_by(|a, b| a.custom.version.cmp(&b.custom.version))
            }
        }?;

        match q.current_version {
            Some(cur) if chosen.custom.version == *cur => None,
            Some(cur) if chosen.custom.version < *cur && !q.allow_downgrade => None,
            _ => Some(chosen),
        }
    }
}

fn line(v: &Version) -> (u64, u64) {
    (v.major, v.minor)
}

fn client_ok(min: Option<&Version>, client: Option<&Version>) -> bool {
    match (min, client) {
        (Some(min), Some(client)) => client >= min,
        _ => true,
    }
}

/// A target with an unparseable `min_os` can't be shown to be compatible, so
/// it is skipped whenever the OS version is known. (Validation already
/// rejects such documents; this is defence in depth.)
fn os_ok(min_os: Option<&str>, os: Option<&Version>) -> bool {
    match (min_os, os) {
        (None, _) | (_, None) => true,
        (Some(min), Some(os)) => parse_os_version(min).is_some_and(|min| *os >= min),
    }
}
