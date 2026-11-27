//! [`FaroCore`]: enrollment, events, heartbeats and uploads.

use crate::error::FaroError;
use crate::keys::{self, KeyStore, DEVICE_KEY, DEVICE_TOKEN};
use crate::store::{self, Store, BUSY_TIMEOUT, CLOCK_SKEW, ENDORSEMENT, ENROLLMENT, LEAVING};
use crate::types::{
    AllyRecord, Approval, BlockedSummaryRecord, Context, CoreStatus, EnrolledDevice,
    GoodbyeOutcome, HeartbeatAnswer, HeartbeatState, InstancePreview, PendingLoosening,
    RecipientsInfo, SettingChangeRecord, ShieldSummaryRecord, Tamper, UploadOutcome,
    MAX_SETTING_CHANGES, PLATFORM,
};
use faro_client::enroll::{self as shared, EndorsementPoll, Enrollment, Registration};
use faro_client::link::parse_enroll_link;
use faro_client::uplink::{self, EventsDrained, OutboxAccess};
use faro_client::{ClientOptions, InstanceClient};
use faro_core::outbox::PendingReport;
use faro_core::urgency::{route_signal, SignalRoute};
use faro_core::{Clock, ClockGuard, EventWriter, Outbox, OutboxError, PrunePolicy, SystemClock};
use faro_crypto::{ChainHead, SigningKey};
use faro_proto::body::{EventBody, GoodbyeReason, TamperSignal};
use faro_proto::keys::{key_id, safety_code, DeviceEndorsement, Signed};
use faro_proto::report::TamperRecord;
use faro_proto::{SignedEvent, Urgency};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicI64;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

/// How often, at most, one process re-checks the instance's pinned identity
/// before talking to it (monotonic time).
pub const IDENTITY_RECHECK_MS: u64 = 60 * 60 * 1000;

/// Leave Faro's progress, in `mobile_state` ([`LEAVING`]). Stored before
/// the goodbye is written, so no other process records anything after it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct Leaving {
    /// The goodbye event, once written.
    goodbye_seq: Option<u64>,
    /// The instance acknowledged it, or had retired the phone already.
    delivered: bool,
}

/// Faro's core for one data directory (the app group container). Each
/// process that records events or talks to the instance (the app, the
/// packet tunnel) makes its own; they share the database and the key store.
///
/// Every method blocks the calling thread (network calls run on the core's
/// own Tokio runtime): call them from a background queue, never the main
/// thread.
#[derive(uniffi::Object)]
pub struct FaroCore {
    pub(crate) dir: PathBuf,
    pub(crate) keys: Arc<dyn KeyStore>,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) opts: ClientOptions,
    pub(crate) rt: Rt,
    pub(crate) store: Mutex<Store>,
    outbox: Mutex<Option<Outbox>>,
    /// Monotonic time of the last identity check that passed.
    identity_checked: Mutex<Option<u64>>,
    /// The instance's clock minus this phone's, as the last answer's
    /// `Date` header showed it (`faro_client`), shared by every client this
    /// core makes: each call makes its own, and a phone whose clock is off
    /// would otherwise sign every call with the wrong time.
    clock_offset: Arc<AtomicI64>,
}

/// The core's own runtime. Dropped with `shutdown_background`, so a core
/// can be dropped anywhere, an async context included.
pub(crate) struct Rt(Option<tokio::runtime::Runtime>);

impl Rt {
    pub(crate) fn block_on<F: Future>(&self, f: F) -> F::Output {
        self.0
            .as_ref()
            .expect("the runtime lives as long as the core")
            .block_on(f)
    }
}

impl Drop for Rt {
    fn drop(&mut self) {
        if let Some(rt) = self.0.take() {
            rt.shutdown_background();
        }
    }
}

pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

#[uniffi::export]
impl FaroCore {
    /// Open the core on `data_dir` (created if missing), with the
    /// platform's key store.
    #[uniffi::constructor]
    pub fn new(data_dir: String, keys: Arc<dyn KeyStore>) -> Result<Arc<Self>, FaroError> {
        Self::with_options(
            PathBuf::from(data_dir),
            keys,
            Arc::new(SystemClock::new()),
            ClientOptions {
                product: "faro-ios",
                ..ClientOptions::default()
            },
        )
    }

    /// Parse an enrollment link and ask its instance who it is, for the
    /// member to confirm.
    pub fn preview_enrollment(&self, link: String) -> Result<InstancePreview, FaroError> {
        let link = parse_enroll_link(&link)?;
        let client = InstanceClient::new(link.instance.clone(), self.clock.clone(), &self.opts)?
            .with_shared_clock_offset(self.clock_offset.clone());
        let info = self.rt.block_on(shared::discover(&client))?;
        Ok(InstancePreview {
            url: info.url.to_string(),
            name: info.name,
            instance_id: info.well_known.instance_id.to_string(),
            identity_fingerprint: key_id(info.well_known.identity_pubkey.as_bytes()),
            link_names_member_key: link.member_key.is_some(),
        })
    }

    /// Enroll this device with the instance the member confirmed:
    /// `identity_fingerprint` is [`InstancePreview::identity_fingerprint`],
    /// and the instance must still answer with that key. Generates the
    /// device key, registers it (as [`crate::types::PLATFORM`]) and pins the
    /// member key, refusing one the link's `m` doesn't name. The device then
    /// waits for the member's approval ([`FaroCore::poll_approval`]).
    pub fn enroll(
        &self,
        link: String,
        device_name: String,
        identity_fingerprint: String,
    ) -> Result<EnrolledDevice, FaroError> {
        let link = parse_enroll_link(&link)?;
        let name = shared::clean_device_name(&device_name);
        if name.is_empty() || name != device_name {
            return Err(FaroError::invalid(
                "a device name is 1-64 printable characters without surrounding spaces",
            ));
        }
        if let Some(e) = lock(&self.store).get::<Enrollment>(ENROLLMENT)? {
            return Err(FaroError::AlreadyEnrolled {
                instance: e.instance_url.clone(),
            });
        }
        let client = InstanceClient::new(link.instance.clone(), self.clock.clone(), &self.opts)?
            .with_shared_clock_offset(self.clock_offset.clone());
        let info = self.rt.block_on(shared::discover(&client))?;
        let shown = key_id(info.well_known.identity_pubkey.as_bytes());
        if !shown.eq_ignore_ascii_case(identity_fingerprint.trim()) {
            return Err(FaroError::Integrity {
                message: "the instance answered with another identity than the one shown; \
                          enroll again from the start"
                    .into(),
            });
        }
        let key = keys::create_device_key(self.keys.as_ref())?;
        let enrollment = self.rt.block_on(shared::register(
            &client,
            &info,
            &Registration {
                code: &link.code,
                device_pubkey: key.public(),
                platform: PLATFORM,
                device_name: &name,
                client_version: env!("CARGO_PKG_VERSION"),
                member_key: link.member_key.as_deref(),
                now_ms: self.clock.wall_ms(),
            },
        ))?;
        self.keys.store(
            DEVICE_TOKEN.to_owned(),
            enrollment.device_token.as_bytes().to_vec(),
        )?;
        // The record keeps everything but the token, which is a secret and
        // lives in the key store.
        let mut record = enrollment.clone();
        zeroize::Zeroize::zeroize(&mut record.device_token);
        if !lock(&self.store).put_new(ENROLLMENT, &record)? {
            return Err(FaroError::AlreadyEnrolled {
                instance: enrollment.instance_url.clone(),
            });
        }
        tracing::info!(device = %enrollment.device_id, instance = %enrollment.instance_id,
            "enrolled; waiting for the member to approve this device");
        Ok(EnrolledDevice {
            device_id: enrollment.device_id.to_string(),
            device_fingerprint: shared::device_fingerprint(&key.public()),
            member_fingerprint: shared::member_fingerprint(&enrollment.member_sign_pubkey),
            instance_name: enrollment.instance_name.clone(),
        })
    }

    /// Ask the instance once whether the member has approved this device.
    /// On approval the endorsement is verified against the pinned member
    /// key, and the recipient list is bootstrapped no lower than the anchor
    /// the member signed into it.
    pub fn poll_approval(&self) -> Result<Approval, FaroError> {
        let e = self.enrollment()?;
        if self.is_approved(&e)? {
            return Ok(Approval::Approved);
        }
        let key = Arc::new(self.device_key()?);
        let device_pubkey = key.public();
        let client = self.device_client(&e, key)?;
        let signed =
            match self
                .rt
                .block_on(shared::poll_endorsement(&client, &e, &device_pubkey))?
            {
                EndorsementPoll::Pending => return Ok(Approval::Pending),
                EndorsementPoll::Endorsed(signed) => signed,
            };
        let endorsement = shared::verify_endorsement(&signed, &e, &device_pubkey)
            .map_err(shared::EnrollError::from)?;
        lock(&self.store).put(ENDORSEMENT, &*signed)?;
        let mut guard = self.open_outbox(&e)?;
        let outbox = guard.as_mut().expect("opened");
        self.rt.block_on(shared::bootstrap_if_needed(
            &client,
            outbox,
            &e,
            &endorsement,
        ))?;
        Ok(Approval::Approved)
    }

    /// Where this device stands. Needs no key and no network.
    pub fn status(&self) -> Result<CoreStatus, FaroError> {
        let Some(e) = lock(&self.store).get::<Enrollment>(ENROLLMENT)? else {
            return Ok(CoreStatus {
                enrolled: false,
                approved: false,
                instance_name: None,
                instance_url: None,
                device_id: None,
                member_fingerprint: None,
                next_seq: 0,
                pending_events: 0,
                manifest_version: None,
                leaving: false,
                goodbye_delivered: false,
            });
        };
        let leaving = self.leaving()?;
        let approved = self.is_approved(&e)?;
        let (head, stats, manifest) = self.with_outbox(&e, |o| {
            Ok((o.head()?, o.stats()?, o.manifest_checkpoint()?))
        })?;
        Ok(CoreStatus {
            enrolled: true,
            approved,
            instance_name: Some(e.instance_name.clone()),
            instance_url: Some(e.instance_url.clone()),
            device_id: Some(e.device_id.to_string()),
            member_fingerprint: Some(shared::member_fingerprint(&e.member_sign_pubkey)),
            next_seq: head.next_seq,
            pending_events: stats.events,
            manifest_version: manifest.map(|m| m.version),
            leaving: leaving.is_some(),
            goodbye_delivered: leaving.is_some_and(|l| l.delivered),
        })
    }

    /// Who this phone reports to: the recipient manifest the member signed,
    /// as the device verified and stored it (no network). Each ally comes
    /// with the safety code of the member's key and theirs, which the
    /// member's web app shows next to each ally's name, and, from a format 2
    /// manifest, the name the member signed (sanitized again here), so the
    /// instance can't put a false name next to a real key. A format 1
    /// manifest names no one. Call [`FaroCore::upload_pending`] first to
    /// pick up a newer manifest.
    pub fn allies(&self) -> Result<RecipientsInfo, FaroError> {
        let e = self.enrollment_record()?;
        let set = self
            .with_outbox(&e, |o| {
                Ok(o.current_recipients(&e.member_sign_pubkey, &e.member_id)?)
            })?
            .ok_or(FaroError::NotApproved)?;
        let member = e.member_sign_pubkey.as_bytes();
        Ok(RecipientsInfo {
            instance_name: e.instance_name.clone(),
            instance_url: e.instance_url.clone(),
            member_fingerprint: shared::member_fingerprint(&e.member_sign_pubkey),
            manifest_version: set.manifest_ref().version,
            signed_at_ms: set.issued_at_ms(),
            allies: set
                .allies()
                .iter()
                .map(|a| AllyRecord {
                    ally_id: a.ally_id.to_string(),
                    name: a.display_name(),
                    safety_code: safety_code(member, a.enc_pubkey.as_bytes()),
                })
                .collect(),
        })
    }

    /// Leave Faro (docs/IOS.md §12): tell the allies with an urgent
    /// `goodbye`, and wait up to `deliver_within_secs` for the instance to
    /// acknowledge it. The order keeps every failure visible:
    ///
    /// 1. Reach the instance (its pinned identity and the latest recipient
    ///    manifest, so the goodbye reaches the current allies). If it can't
    ///    be reached, **nothing changes**: the error is returned and the
    ///    phone stays protected, for the member to try again.
    /// 2. Mark the phone as leaving: from here on no other event and no
    ///    heartbeat is recorded or sent ([`FaroError::Left`]), because
    ///    anything after the goodbye would tell the instance the phone is
    ///    back.
    /// 3. Write the goodbye and upload it. Not acknowledged in time is
    ///    [`GoodbyeOutcome::Queued`]; calling this again retries the
    ///    delivery and never writes a second goodbye.
    /// 4. Delivered: the device's keys are deleted from the key store.
    ///
    /// Only after [`GoodbyeOutcome::Delivered`] (or `AlreadyRetired`,
    /// `NotActivated`, `NotEnrolled`) should the app lift the protection.
    pub fn goodbye(&self, deliver_within_secs: u64) -> Result<GoodbyeOutcome, FaroError> {
        let Some(e) = lock(&self.store).get::<Enrollment>(ENROLLMENT)? else {
            return Ok(GoodbyeOutcome::NotEnrolled);
        };
        let leaving = self.leaving()?;
        if let Some(Leaving {
            delivered: true,
            goodbye_seq,
        }) = leaving
        {
            return Ok(match goodbye_seq {
                Some(seq) => GoodbyeOutcome::Delivered { seq },
                None if self.is_approved(&e)? => GoodbyeOutcome::AlreadyRetired,
                None => GoodbyeOutcome::NotActivated,
            });
        }
        if !self.is_approved(&e)? {
            self.set_leaving(Leaving {
                goodbye_seq: None,
                delivered: true,
            })?;
            return Ok(GoodbyeOutcome::NotActivated);
        }
        let e = self.enrollment()?;
        let key = Arc::new(self.device_key()?);
        let client = self.device_client(&e, key)?;
        let seq = match leaving.and_then(|l| l.goodbye_seq) {
            Some(seq) => seq,
            None => {
                // 1. Reach the instance before anything is written.
                let reached = match self
                    .rt
                    .block_on(client.check_identity(&e.instance_id, &e.instance_identity_pubkey))
                {
                    Ok(_) => self.rt.block_on(client.recipient_manifest(&e.member_id)),
                    Err(err) => Err(err),
                };
                let manifest = match reached {
                    Ok(m) => m,
                    Err(err) if err.retired().is_some() => return self.retired_already(),
                    Err(err) => return Err(err.into()),
                };
                *lock(&self.identity_checked) = Some(self.clock.mono_ms());
                self.with_outbox(&e, |o| {
                    match o.accept_manifest(&manifest, &e.member_sign_pubkey, &e.member_id) {
                        Ok(_) => Ok(()),
                        Err(OutboxError::Manifest(err)) => {
                            tracing::warn!(error = %err, "refused the instance's recipient manifest; the goodbye goes to the current one");
                            Ok(())
                        }
                        Err(err) => Err(err.into()),
                    }
                })?;
                // 2. Nothing else from here on.
                self.set_leaving(Leaving {
                    goodbye_seq: None,
                    delivered: false,
                })?;
                // 3. The goodbye.
                let body = EventBody::Goodbye {
                    reason: GoodbyeReason::Uninstalled,
                };
                let seq = self.append_any(&body, Urgency::Urgent)?;
                self.set_leaving(Leaving {
                    goodbye_seq: Some(seq),
                    delivered: false,
                })?;
                tracing::info!(seq, "goodbye written");
                seq
            }
        };
        match self.deliver(&client, &e, seq, Duration::from_secs(deliver_within_secs)) {
            Delivery::Acked => {
                self.set_leaving(Leaving {
                    goodbye_seq: Some(seq),
                    delivered: true,
                })?;
                self.forget_keys();
                tracing::info!(seq, "goodbye delivered");
                Ok(GoodbyeOutcome::Delivered { seq })
            }
            Delivery::Retired => self.retired_already(),
            Delivery::NotYet(error) => Ok(GoodbyeOutcome::Queued { seq, error }),
        }
    }

    /// Record an active tamper signal as an urgent `tamper` event. Returns
    /// its `seq`.
    pub fn record_tamper(&self, signal: Tamper) -> Result<u64, FaroError> {
        let signal = TamperSignal::from(signal);
        if route_signal(&signal) != SignalRoute::TamperEvent {
            return Err(FaroError::invalid("a context signal is not tamper"));
        }
        let seq = self.append(&EventBody::tamper(signal.clone()), Urgency::Urgent)?;
        self.log_tamper(TamperRecord {
            seq: Some(seq),
            ts_ms: self.clock.wall_ms(),
            signal,
            account: None,
        });
        Ok(seq)
    }

    /// Record a settings change that allies are told about, with the
    /// pending loosening it announces, applies or cancels, if any. Returns
    /// its `seq`.
    pub fn record_settings_change(
        &self,
        changes: Vec<SettingChangeRecord>,
        pending: Option<PendingLoosening>,
    ) -> Result<u64, FaroError> {
        if changes.is_empty() || changes.len() > MAX_SETTING_CHANGES {
            return Err(FaroError::invalid(format!(
                "a settings change has 1-{MAX_SETTING_CHANGES} changes"
            )));
        }
        let changes = changes
            .into_iter()
            .map(SettingChangeRecord::into_proto)
            .collect::<Result<Vec<_>, _>>()
            .map_err(FaroError::invalid)?;
        let p = pending.unwrap_or(PendingLoosening {
            requested_at_ms: None,
            takes_effect_at_ms: None,
            cancelled_at_ms: None,
            delay_secs: None,
        });
        let logged = pending.map(|_| changes.clone());
        let body = EventBody::SettingsChange {
            changes,
            requested_at: p.requested_at_ms,
            takes_effect_at: p.takes_effect_at_ms,
            cancelled_at: p.cancelled_at_ms,
            delay_secs: p.delay_secs,
        };
        let seq = self.append(&body, Urgency::Normal)?;
        if let Some(changes) = logged {
            self.log_loosening(&changes, &p);
        }
        Ok(seq)
    }

    /// Record the DNS filter's blocked lookups for one bucket
    /// (`blocked_summary`, a `capture`-class event: urgency `none`). Hosts
    /// travel only inside the sealed body. Returns its `seq`.
    pub fn record_blocked_summary(&self, summary: BlockedSummaryRecord) -> Result<u64, FaroError> {
        let body = summary.into_body().map_err(FaroError::invalid)?;
        let seq = self.append(&body, Urgency::None)?;
        self.log_summary(&body, seq);
        Ok(seq)
    }

    /// Record the shields' counts for one bucket (`shield_summary`, a
    /// `capture`-class event). Returns its `seq`.
    pub fn record_shield_summary(&self, summary: ShieldSummaryRecord) -> Result<u64, FaroError> {
        let body = summary.into_body().map_err(FaroError::invalid)?;
        let seq = self.append(&body, Urgency::None)?;
        self.log_summary(&body, seq);
        Ok(seq)
    }

    /// Record a context signal for the daily report. It is never an event
    /// and never an alert.
    pub fn record_context(&self, signal: Context) -> Result<(), FaroError> {
        let signal = TamperSignal::from(signal);
        if route_signal(&signal) != SignalRoute::ReportContext {
            return Err(FaroError::invalid("not a context signal"));
        }
        let mut store = lock(&self.store);
        if store.get::<Enrollment>(ENROLLMENT)?.is_none() {
            return Err(FaroError::NotEnrolled);
        }
        if store.get::<Leaving>(LEAVING)?.is_some() {
            return Err(FaroError::Left);
        }
        let ts_ms = self.clock.wall_ms();
        let rec = TamperRecord {
            seq: None,
            ts_ms,
            signal,
            account: None,
        };
        let json = serde_json::to_string(&rec).map_err(FaroError::storage)?;
        store.add_context(ts_ms, &json)
    }

    /// Send one signed heartbeat (PROTOCOL.md §7). Works while the device
    /// waits for approval too. The instance's acknowledgement prunes the
    /// outbox.
    ///
    /// The instance's clock in the answer is checked against this phone's
    /// (ARCHITECTURE.md §3.6): a skew beyond `faro_core`'s threshold is
    /// recorded once as an urgent `clock_manipulation`, and again only
    /// after the clock was seen back in range. Refused with
    /// [`FaroError::Left`] once the member started Leave Faro.
    pub fn heartbeat(&self, state: HeartbeatState) -> Result<HeartbeatAnswer, FaroError> {
        if self.leaving()?.is_some() {
            return Err(FaroError::Left);
        }
        let e = self.enrollment()?;
        let key = Arc::new(self.device_key()?);
        let client = self.device_client(&e, key.clone())?;
        self.check_identity(&client, &e)?;
        let access = Access { core: self, e: &e };
        let resp = self.rt.block_on(uplink::send_heartbeat(
            &client,
            &access,
            &key,
            &e,
            self.clock.as_ref(),
            state.into(),
        ))?;
        self.observe_server_clock(self.clock.wall_ms(), resp.server_time_ms, true);
        Ok(HeartbeatAnswer {
            server_time_ms: resp.server_time_ms,
            next_in_secs: resp.next_in_secs,
            acked_through: resp.acked_through,
        })
    }

    /// Upload everything pending: refresh the recipient manifest (a
    /// newer one the member signed is adopted, anything else is refused and
    /// the current one kept), then events in `seq` order, then reports.
    pub fn upload_pending(&self) -> Result<UploadOutcome, FaroError> {
        let e = self.enrollment()?;
        if !self.is_approved(&e)? {
            return Err(FaroError::NotApproved);
        }
        let key = Arc::new(self.device_key()?);
        let client = self.device_client(&e, key)?;
        self.check_identity(&client, &e)?;
        let mut warnings = Vec::new();
        let manifest = self.rt.block_on(client.recipient_manifest(&e.member_id))?;
        let judged = self.with_outbox(&e, |o| {
            match o.accept_manifest(&manifest, &e.member_sign_pubkey, &e.member_id) {
                Ok(_) => Ok(None),
                Err(OutboxError::Manifest(err)) => Ok(Some(err.to_string())),
                Err(err) => Err(err.into()),
            }
        })?;
        if let Some(w) = judged {
            tracing::warn!(error = %w, "refused the instance's recipient manifest; keeping the current one");
            warnings.push(format!("recipient manifest refused: {w}"));
        }
        let access = Access { core: self, e: &e };
        let mut acked = None;
        let drained = self
            .rt
            .block_on(uplink::drain_events(&client, &access, |a| acked = Some(a)))?;
        if let EventsDrained::AckBeyondHead { acked, .. } = drained {
            warnings.push(format!(
                "instance acknowledged seq {acked} beyond the local head"
            ));
        }
        let mut reports = 0u32;
        self.rt.block_on(uplink::drain_reports(
            &client,
            &access,
            |_| reports += 1,
            |err| warnings.push(format!("report dropped: {err}")),
        ))?;
        let now = self.clock.wall_ms();
        // The `Date` header of the instance's answers: `faro_client` keeps
        // an offset only when it is over a minute, so only a skew is judged
        // here; the heartbeat's exact time is what clears one.
        let offset = client.clock_offset_ms();
        if offset != 0 && self.leaving()?.is_none() {
            self.observe_server_clock(now, now.saturating_add(offset), false);
        }
        let (stats, checkpoint) = self.with_outbox(&e, |o| {
            o.prune(now, PrunePolicy::default())?;
            Ok((o.stats()?, o.manifest_checkpoint()?))
        })?;
        Ok(UploadOutcome {
            acked_through: acked,
            pending_events: stats.events,
            reports_uploaded: reports,
            manifest_version: checkpoint.map(|c| c.version),
            warnings,
        })
    }
}

/// Rust-only API (tests, and the crates built on this one).
impl FaroCore {
    /// As [`FaroCore::new`], with the clock and client options chosen.
    pub fn with_options(
        dir: PathBuf,
        keys: Arc<dyn KeyStore>,
        clock: Arc<dyn Clock>,
        opts: ClientOptions,
    ) -> Result<Arc<Self>, FaroError> {
        let store = Store::open(&dir)?;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(FaroError::storage)?;
        Ok(Arc::new(FaroCore {
            dir,
            keys,
            clock,
            opts,
            rt: Rt(Some(rt)),
            store: Mutex::new(store),
            outbox: Mutex::new(None),
            identity_checked: Mutex::new(None),
            clock_offset: Arc::new(AtomicI64::new(0)),
        }))
    }

    pub fn data_dir(&self) -> &Path {
        &self.dir
    }

    /// The database file every process shares.
    pub fn database_path(&self) -> PathBuf {
        store::database_path(&self.dir)
    }

    /// Context signals recorded at or after `since_ms`, oldest first, for
    /// the daily report (`faro_core::ReportBuilder::record_context`).
    pub fn context_since(&self, since_ms: i64) -> Result<Vec<TamperRecord>, FaroError> {
        lock(&self.store)
            .context_since(since_ms)?
            .into_iter()
            .map(|(_, json)| serde_json::from_str(&json).map_err(FaroError::storage))
            .collect()
    }

    /// Pending events, oldest first, as the outbox holds them.
    pub fn pending_events(&self, limit: usize) -> Result<Vec<SignedEvent>, FaroError> {
        let e = self.enrollment_record()?;
        self.with_outbox(&e, |o| Ok(o.pending(limit)?))
    }

    /// Append `body` to the chain in one exclusive transaction
    /// (`Outbox::append_exclusive`), sealed to the current recipients.
    /// Returns its `seq`. Refused with [`FaroError::Left`] once the member
    /// started Leave Faro.
    pub fn append(&self, body: &EventBody, urgency: Urgency) -> Result<u64, FaroError> {
        if self.leaving()?.is_some() {
            return Err(FaroError::Left);
        }
        self.append_any(body, urgency)
    }

    /// [`FaroCore::append`] without the Leave Faro check: the goodbye.
    fn append_any(&self, body: &EventBody, urgency: Urgency) -> Result<u64, FaroError> {
        let e = self.enrollment_record()?;
        let key = self.device_key()?;
        // The head is read again inside the transaction; genesis is only a
        // placeholder. The key is wiped when the writer drops.
        let mut writer = EventWriter::new(
            key,
            e.instance_id.clone(),
            e.device_id.clone(),
            ChainHead::genesis(&e.instance_id, &e.device_id),
            self.clock.clone(),
        );
        let ev = self.with_outbox(&e, |o| {
            Ok(o.append_exclusive(
                &mut writer,
                body,
                urgency,
                &e.member_sign_pubkey,
                &e.member_id,
            )?)
        })?;
        Ok(ev.header.seq)
    }

    fn leaving(&self) -> Result<Option<Leaving>, FaroError> {
        lock(&self.store).get::<Leaving>(LEAVING)
    }

    fn set_leaving(&self, l: Leaving) -> Result<(), FaroError> {
        lock(&self.store).put(LEAVING, &l)
    }

    /// The instance had retired this phone: its allies were told then.
    fn retired_already(&self) -> Result<GoodbyeOutcome, FaroError> {
        let seq = self.leaving()?.and_then(|l| l.goodbye_seq);
        self.set_leaving(Leaving {
            goodbye_seq: seq,
            delivered: true,
        })?;
        self.forget_keys();
        tracing::info!("the instance had already retired this phone; its allies know");
        Ok(GoodbyeOutcome::AlreadyRetired)
    }

    /// Delete the device key and token once nothing is left to sign. A
    /// failure is logged: the phone is leaving either way.
    fn forget_keys(&self) {
        for name in [DEVICE_KEY, DEVICE_TOKEN] {
            if let Err(err) = self.keys.delete(name.to_owned()) {
                tracing::warn!(%err, name, "could not delete a key after leaving");
            }
        }
    }

    /// Upload until the instance holds `seq` or `within` runs out.
    fn deliver(
        &self,
        client: &InstanceClient,
        e: &Enrollment,
        seq: u64,
        within: Duration,
    ) -> Delivery {
        // Real time, not the core's clock: this bounds how long the member waits.
        let deadline = std::time::Instant::now() + within;
        let mut wait = Duration::from_millis(500);
        loop {
            let access = Access { core: self, e };
            let error = match self
                .rt
                .block_on(uplink::drain_events(client, &access, |_| {}))
            {
                Ok(_) => None,
                Err(err) => {
                    let err = FaroError::from(err);
                    if matches!(err, FaroError::Retired { .. }) {
                        return Delivery::Retired;
                    }
                    Some(err.to_string())
                }
            };
            match self.with_outbox(e, |o| Ok(o.pending(1)?)) {
                Ok(first) if first.first().is_none_or(|ev| ev.header.seq > seq) => {
                    return Delivery::Acked;
                }
                Ok(_) => {}
                Err(err) => return Delivery::NotYet(err.to_string()),
            }
            let error = error.unwrap_or_else(|| "the instance did not acknowledge it".into());
            let now = std::time::Instant::now();
            if now >= deadline {
                return Delivery::NotYet(error);
            }
            tracing::info!(%error, "goodbye not delivered yet; retrying");
            self.rt
                .block_on(tokio::time::sleep(wait.min(deadline - now)));
            wait = (wait * 2).min(Duration::from_secs(5));
        }
    }

    /// Compare this phone's wall clock with the instance's (ARCHITECTURE.md
    /// §3.6, `faro_core::ClockGuard`'s threshold). A skew is recorded once,
    /// whichever process sees it first, until a reading in range (`clears`,
    /// the heartbeat's exact time) re-arms it. Never fails the caller.
    fn observe_server_clock(&self, local_wall_ms: i64, server_wall_ms: i64, clears: bool) {
        let signal = ClockGuard::default().check_server_wall(local_wall_ms, server_wall_ms);
        let Some(signal) = signal else {
            if clears {
                if let Err(err) = lock(&self.store).swap_flag(CLOCK_SKEW, false) {
                    tracing::warn!(%err, "clock check not saved");
                }
            }
            return;
        };
        let claimed = match lock(&self.store).swap_flag(CLOCK_SKEW, true) {
            Ok(was) => !was,
            Err(err) => {
                tracing::warn!(%err, "clock check not saved");
                return;
            }
        };
        if !claimed {
            return;
        }
        tracing::warn!(
            local_wall_ms,
            server_wall_ms,
            "the phone's clock is off the instance's"
        );
        if let Err(err) = self.append(&EventBody::tamper(signal), Urgency::Urgent) {
            // Not recorded (not approved yet, keys locked): try next time.
            tracing::warn!(%err, "clock skew not recorded yet");
            let _ = lock(&self.store).swap_flag(CLOCK_SKEW, false);
        }
    }

    /// The stored enrollment, without its token.
    pub(crate) fn enrollment_record(&self) -> Result<Enrollment, FaroError> {
        lock(&self.store)
            .get::<Enrollment>(ENROLLMENT)?
            .ok_or(FaroError::NotEnrolled)
    }

    /// The stored enrollment with its token from the key store.
    fn enrollment(&self) -> Result<Enrollment, FaroError> {
        let mut e = self.enrollment_record()?;
        let token = keys::device_token(self.keys.as_ref())?.ok_or_else(|| FaroError::KeyStore {
            message: "the device token is missing from the key store".into(),
        })?;
        e.device_token = token.as_str().to_owned();
        Ok(e)
    }

    pub(crate) fn device_key(&self) -> Result<SigningKey, FaroError> {
        keys::device_key(self.keys.as_ref())?.ok_or_else(|| FaroError::KeyStore {
            message: "the device key is missing from the key store".into(),
        })
    }

    fn device_client(
        &self,
        e: &Enrollment,
        key: Arc<SigningKey>,
    ) -> Result<InstanceClient, FaroError> {
        Ok(
            shared::device_client(e, key, self.clock.clone(), &self.opts, None)?
                .with_shared_clock_offset(self.clock_offset.clone()),
        )
    }

    /// Approved: a verified endorsement is stored and the recipient
    /// checkpoint is bootstrapped.
    fn is_approved(&self, e: &Enrollment) -> Result<bool, FaroError> {
        if lock(&self.store)
            .get::<Signed<DeviceEndorsement>>(ENDORSEMENT)?
            .is_none()
        {
            return Ok(false);
        }
        Ok(self
            .with_outbox(e, |o| Ok(o.manifest_checkpoint()?))?
            .is_some())
    }

    /// Re-check the instance's identity against the pin, at most every
    /// [`IDENTITY_RECHECK_MS`] per process. A mismatch stops the call
    /// before any device request is made.
    fn check_identity(&self, client: &InstanceClient, e: &Enrollment) -> Result<(), FaroError> {
        let now = self.clock.mono_ms();
        if lock(&self.identity_checked).is_some_and(|t| now >= t && now - t < IDENTITY_RECHECK_MS) {
            return Ok(());
        }
        self.rt
            .block_on(client.check_identity(&e.instance_id, &e.instance_identity_pubkey))?;
        *lock(&self.identity_checked) = Some(now);
        Ok(())
    }

    fn open_outbox(&self, e: &Enrollment) -> Result<MutexGuard<'_, Option<Outbox>>, OutboxError> {
        let mut g = lock(&self.outbox);
        if g.is_none() {
            let o = Outbox::open(&self.dir, &e.instance_id, &e.device_id)?;
            o.set_busy_timeout(BUSY_TIMEOUT)?;
            *g = Some(o);
        }
        Ok(g)
    }

    pub(crate) fn with_outbox_raw<T>(
        &self,
        e: &Enrollment,
        f: impl FnOnce(&mut Outbox) -> Result<T, OutboxError>,
    ) -> Result<T, OutboxError> {
        let mut g = self.open_outbox(e)?;
        f(g.as_mut().expect("opened"))
    }

    pub(crate) fn with_outbox<T>(
        &self,
        e: &Enrollment,
        f: impl FnOnce(&mut Outbox) -> Result<T, FaroError>,
    ) -> Result<T, FaroError> {
        let mut g = self.open_outbox(e)?;
        f(g.as_mut().expect("opened"))
    }
}

/// How a goodbye's delivery ended.
enum Delivery {
    Acked,
    Retired,
    NotYet(String),
}

/// The outbox for `faro_client::uplink`: each call takes the lock briefly
/// and runs synchronously (the database is local).
struct Access<'a> {
    core: &'a FaroCore,
    e: &'a Enrollment,
}

impl OutboxAccess for Access<'_> {
    fn head(&self) -> impl Future<Output = Result<ChainHead, OutboxError>> + Send {
        std::future::ready(self.core.with_outbox_raw(self.e, |o| o.head()))
    }
    fn pending(
        &self,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<SignedEvent>, OutboxError>> + Send {
        std::future::ready(self.core.with_outbox_raw(self.e, |o| o.pending(limit)))
    }
    fn ack_through(&self, acked: u64) -> impl Future<Output = Result<u64, OutboxError>> + Send {
        std::future::ready(self.core.with_outbox_raw(self.e, |o| o.ack_through(acked)))
    }
    fn pending_reports(
        &self,
    ) -> impl Future<Output = Result<Vec<PendingReport>, OutboxError>> + Send {
        std::future::ready(self.core.with_outbox_raw(self.e, |o| o.pending_reports()))
    }
    fn ack_report(&self, id: i64) -> impl Future<Output = Result<bool, OutboxError>> + Send {
        std::future::ready(self.core.with_outbox_raw(self.e, |o| o.ack_report(id)))
    }
}
