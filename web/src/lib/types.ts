import type { WrappedSecret } from './crypto/passphrase.ts';
import type {
	AllyEndorsement,
	DeviceEndorsement,
	ManifestRef,
	MemberEncKeyBinding,
	RecipientManifest,
	Signed
} from './crypto/proto.ts';
import type { EncryptedItem } from './crypto/seal.ts';

export type { EncryptedItem, ManifestRef, RecipientManifest, Signed };

// Wire types for the JSON API the web app uses. Hand-written for now; they
// mirror the serde types in server/src/api and crates/faro-proto (the plan in
// docs/ARCHITECTURE.md is to generate them with typeshare).

/** `GET /v1/setup` */
export interface SetupStatus {
	needs_setup: boolean;
}

/** `POST /v1/setup` body */
export interface SetupRequest {
	setup_token: string;
	email: string;
	display_name: string;
}

export interface Roles {
	admin: boolean;
	member: boolean;
	ally: boolean;
}

export interface User {
	id: string;
	email: string;
	display_name: string;
	roles: Roles;
	created_at_ms: number;
}

/** `POST /v1/setup` response */
export interface SetupResponse {
	user: User;
}

/** `GET /v1/me` */
export interface Me {
	user: User;
	has_member_keys: boolean;
	/** When this session signed in: deleting the account needs a recent sign-in. */
	session_started_at_ms: number;
	/** The pending deletion of this account, if the person asked for one. */
	deletion: PendingDeletion | null;
}

// ---- Account deletion ------------------------------------------------------

/** A requested account deletion: nothing is removed until `purge_after_ms`. */
export interface PendingDeletion {
	requested_at_ms: number;
	/** The end of the 7-day hold. */
	purge_after_ms: number;
	/** When the purge started; it can no longer be cancelled. */
	started_at_ms: number | null;
	/** An admin asked for it, not the person. The person or any admin may cancel. */
	by_admin: boolean;
}

/** Who a deletion notice (or its cancellation) went to. */
export interface DeletionTold {
	/** The person's own allies. */
	allies: number;
	/** Members the person is an ally for. */
	members: number;
}

/** `DELETE /v1/me` body */
export interface DeleteMe {
	confirm_email: string;
}

/** `DELETE /v1/me` response */
export interface DeletionRequested {
	deletion: PendingDeletion;
	told: DeletionTold;
}

/** `DELETE /admin/api/users/{id}` body: an admin asks for someone's account to be deleted. */
export interface DeleteUser {
	confirm_email: string;
}

/** `POST /v1/me/deletion/cancel` and `POST /admin/api/users/{id}/deletion/cancel` response */
export interface DeletionCancelled {
	requested_at_ms: number;
	cancelled_at_ms: number;
	told: DeletionTold;
}

export type RegistrationMode = 'invite-only' | 'open' | 'closed';

export interface InstanceSettings {
	registration: {
		mode: RegistrationMode;
		/** Lowercase domains without `@`; `["*"]` allows any domain. */
		allowed_email_domains: string[];
	};
	retention: {
		event_header_days: number;
		blob_days: number;
		alert_days: number;
	};
	liveness: {
		grace_secs: number;
	};
	updates: {
		/** `stable`, `beta`, … or the pin `stable-1`. */
		channel: string;
	};
	/** Groups (docs/GROUPS.md §13). */
	groups: GroupSettings;
}

/** `GET /v1/updates`: what the instance's update mirror offers. */
export interface UpdatesInfo {
	/** The mirror has verified release metadata to serve. */
	available: boolean;
	channel: string;
}

/** `PATCH /admin/api/settings` body: any subset. */
export interface SettingsPatch {
	registration_mode?: RegistrationMode;
	allowed_email_domains?: string[];
	retention?: {
		event_header_days?: number;
		blob_days?: number;
		alert_days?: number;
	};
	liveness_grace_secs?: number;
	update_channel?: string;
	groups?: Partial<GroupSettings>;
}

/** `GET /admin/api/overview`: configuration and aggregate counts only. */
export interface Overview {
	instance_name: string;
	server_version: string;
	users: {
		total: number;
		admins: number;
		members: number;
		allies: number;
		disabled: number;
	};
	devices: {
		pending_endorsement: number;
		active: number;
		removed: number;
	};
	/** Active devices by time since their last check-in. */
	last_seen: {
		within_1h: number;
		within_24h: number;
		within_7d: number;
		older: number;
		never: number;
	};
	storage: {
		/** Ciphertext blob bytes. */
		blobs: number;
		blob_count: number;
		/** Database size in bytes, if the backend can tell. */
		database: number | null;
	};
	/** Notification delivery, counts only. */
	notifications: {
		failed: number;
		retrying: number;
		pending: number;
		sent: number;
	};
	/** Accounts waiting to be deleted, and purges held up a week past their hold. */
	deletions: {
		pending: number;
		overdue: number;
	};
	smtp_configured: boolean;
	settings: InstanceSettings;
}

/** One row of `GET /admin/api/users`: account metadata, no relationships. */
export interface AdminUserRow {
	id: string;
	email: string;
	display_name: string;
	roles: Roles;
	disabled: boolean;
	created_at_ms: number;
	last_login_at_ms: number | null;
	/** Devices not removed. */
	device_count: number;
	/** Most recent check-in of any of the user's devices. */
	devices_last_seen_at_ms: number | null;
	/** When the account will be deleted, if it is being deleted. */
	deletion_purge_after_ms: number | null;
	/** An admin asked for the deletion (any admin may cancel it), not the person. */
	deletion_by_admin: boolean;
}

/** `PUT /admin/api/users/{id}/admin` response. */
export interface AdminRole {
	user_id: string;
	admin: boolean;
	/** How many people are emailed: the person and every other admin. */
	told: number;
}

/** An account named in the admin log. */
export interface AdminLogAccount {
	id: string;
	display_name: string;
	email: string;
}

/** One entry of `GET /admin/api/log`, newest first. */
export interface AdminLogEntry {
	id: string;
	action:
		| 'admin_granted'
		| 'admin_revoked'
		| 'deletion_requested'
		| 'deletion_cancelled'
		| 'account_created'
		| 'account_disabled'
		| 'account_enabled';
	/** The account it was about; null once that account is deleted. */
	user: AdminLogAccount | null;
	/**
	 * Who did it; null from the command line or once deleted. For
	 * `deletion_cancelled`, the person themself if they cancelled.
	 */
	actor: AdminLogAccount | null;
	via: 'console' | 'command_line';
	at_ms: number;
}

/** `POST /admin/api/invites` (and member ally invites) response. */
export interface InviteCreated {
	email: string;
	expires_at_ms: number;
	invite_url: string;
}

/** `GET /v1/invites/{token}` */
export interface InviteInfo {
	kind: 'member' | 'ally';
	inviter_display_name: string;
	instance_name: string;
	/** The address that must sign in to accept. */
	email: string;
	expires_at_ms: number;
}

/** `GET /v1/privacy-notice` (the fields the web app reads). */
export interface PrivacyNotice {
	instance_name: string;
	public_url: string;
	operator_can_see: string[];
	operator_cannot_see: string[];
	caveats: string[];
	retention: { event_header_days: number; blob_days: number; alert_days: number };
	registration_mode: string;
}

/** `POST /admin/api/smtp-test` */
export interface SmtpTestResult {
	ok: boolean;
	/** Short error code on failure, e.g. `rejected`, `connection`, `tls`. */
	error: string | null;
	sent_to: string;
}

/** Every API error body. */
export interface ApiErrorBody {
	error: string;
	message: string;
}

/** `POST /v1/auth/magic-link` (202, the same whether or not an account exists). */
export interface MagicLinkResponse {
	status: string;
}

/** `POST /v1/auth/magic-link/verify` */
export interface VerifyResponse {
	user: User;
	/** True if this sign-in created the account (open registration or an invite). */
	created: boolean;
}

/** `GET /.well-known/faro` (the fields the web app reads). */
export interface WellKnown {
	instance_id: string;
	name: string;
	identity_pubkey: string;
	server_version: string;
	protocol: number;
}

// ---- Instance branding (`/v1/branding`, `/admin/api/branding`) ----------
// Operator content: plain text, shown only in page chrome (see
// web/src/lib/branding.ts).

/** The logo is at `/v1/branding/logo/{id}.png`. */
export interface BrandingLogo {
	id: string;
	width: number;
	height: number;
}

export type SupportContact = { kind: 'email'; value: string } | { kind: 'url'; value: string };

/** `GET /v1/branding`: only what is switched on. */
export interface PublicBranding {
	instance_name: string;
	show_name: boolean;
	logo: BrandingLogo | null;
	welcome: string | null;
	support: SupportContact | null;
}

export interface BrandingSettings {
	show_logo: boolean;
	show_name: boolean;
	welcome_enabled: boolean;
	welcome: string;
	support_enabled: boolean;
	support: string;
}

export type BrandingPatch = Partial<BrandingSettings>;

/** `GET /admin/api/branding` */
export interface AdminBranding {
	instance_name: string;
	settings: BrandingSettings;
	logo: BrandingLogo | null;
}

// ---- Member keys (`/v1/me/keys`) ----------------------------------------

/**
 * How the web app stores the recovery copy of member keys: each secret
 * wrapped under the recovery code. Opaque to the server.
 */
export interface RecoveryWrapped {
	sign: WrappedSecret;
	enc: WrappedSecret;
}

/** `PUT /v1/me/keys` body. */
export interface PutMemberKeys {
	sign_pubkey: string;
	enc_binding: Signed<MemberEncKeyBinding>;
	wrapped_sign_key: WrappedSecret;
	wrapped_enc_key: WrappedSecret;
	recovery_wrapped: RecoveryWrapped;
}

/** `GET /v1/me/keys` */
export interface MemberKeysBlob {
	sign_pubkey: string;
	enc_binding: Signed<MemberEncKeyBinding>;
	wrapped_sign_key: unknown;
	wrapped_enc_key: unknown;
	recovery_wrapped: unknown;
	created_at_ms: number;
}

/**
 * An ally's wrapped private key as the web app uploads it: a
 * `WrappedSecret` under the passphrase, with the same secret wrapped under
 * the recovery code alongside (Rust readers ignore the extra field).
 */
export type AllyWrappedKey = WrappedSecret & { recovery?: WrappedSecret };

/** `GET /v1/me/ally-key` */
export interface AllyKeyBlob {
	enc_pubkey: string;
	key_id: string;
	wrapped_privkey: unknown;
	created_at_ms: number;
}

/**
 * `POST /v1/me/ally-key/challenge`: 32 bytes sealed to the ally key, for
 * proving `PUT /v1/me/ally-key/wrapped` (an `AllyKeyRewrap` with `proof`).
 */
export interface AllyKeyChallenge {
	enc_pubkey: string;
	issued_at_ms: number;
	sealed_challenge: string;
}

// ---- Devices -------------------------------------------------------------

export type Platform = 'macos' | 'windows' | 'linux' | 'ios' | 'android';

/** `GET /v1/me/devices` row. */
export interface DeviceSummary {
	device_id: string;
	name: string;
	platform: Platform;
	status: 'pending_endorsement' | 'active' | 'removed';
	sign_pubkey: string;
	key_id: string;
	enrolled_at_ms: number;
	last_seen_at_ms: number | null;
}

/** `POST /v1/me/enroll-codes` */
export interface EnrollCode {
	code: string;
	expires_at_ms: number;
	enroll_url: string;
}

export type DeviceEndorseRequest = Signed<DeviceEndorsement>;

// ---- Allies --------------------------------------------------------------

export type LinkState = 'pending' | 'active' | 'removed';

/** One of the member's allies (`GET /v1/me/allies`). */
export interface AllyLink {
	ally_id: string;
	display_name: string;
	email: string;
	state: LinkState;
	created_at_ms: number;
	activated_at_ms: number | null;
	ally_enc_pubkey: string | null;
	ally_key_id: string | null;
	member_sign_pubkey: string | null;
	/** When the ally's account will be deleted, if they asked for that. */
	deletion_purge_after_ms: number | null;
	/** The group this alliance was proposed in, if it came from a proposal. */
	origin_group_id: string | null;
}

export interface ManifestStatus {
	current: ManifestRef;
	needs_update: boolean;
	departed: string[];
}

export interface MyAllies {
	allies: AllyLink[];
	manifest: ManifestStatus | null;
}

export interface ApproveAlly {
	endorsement: Signed<AllyEndorsement>;
	manifest: Signed<RecipientManifest>;
}

export interface LinkStatus {
	ally_id: string;
	state: LinkState;
	manifest: ManifestRef;
}

/** A member the caller is an ally for (`GET /v1/ally/members`). */
export interface SupportedMember {
	member_id: string;
	display_name: string;
	state: LinkState;
	created_at_ms: number;
	activated_at_ms: number | null;
	member_sign_pubkey: string | null;
	ally_enc_pubkey: string | null;
	/** When the member's account will be deleted, if they asked for that. */
	deletion_purge_after_ms: number | null;
	/** The group this alliance was proposed in, if it came from a proposal. */
	origin_group_id: string | null;
}

/** `POST /v1/invites/{token}/accept` */
export interface InviteAccepted {
	member_id: string;
	state: LinkState;
	ally_key_id: string;
}

// ---- Feed ----------------------------------------------------------------

export type Urgency = 'none' | 'normal' | 'urgent';

export type EventKind =
	| 'capture'
	| 'flag'
	| 'tamper'
	| 'settings_change'
	| 'agent_restarted'
	| 'paused'
	| 'resumed'
	| 'goodbye'
	| 'boot'
	| 'shutdown';

export type ServerAlertKind =
	| 'missed_checkin'
	| 'chain_gap'
	| 'invalid_signature'
	| 'clock_skew'
	| 'device_removed'
	| 'ally_removed'
	| 'ally_added'
	| 'member_settings_changed'
	| 'upload_stalled'
	| 'account_disabled'
	| 'account_enabled'
	| 'ally_disabled'
	| 'ally_enabled'
	| 'account_deleted'
	| 'ally_deleted'
	| 'account_deletion_cancelled';

export type FeedItem =
	| {
			type: 'event';
			member_id: string;
			device_id: string;
			seq: number;
			ts_ms: number;
			kind: EventKind;
			urgency: Urgency;
			blob_id: string | null;
	  }
	| {
			type: 'report';
			member_id: string;
			device_id: string;
			report_id: string;
			period_start_ms: number;
			period_end_ms: number;
			blob_id: string;
	  }
	| {
			type: 'alert';
			member_id: string;
			device_id: string | null;
			alert_id: string;
			kind: ServerAlertKind;
			urgency: Urgency;
			ts_ms: number;
			detail: string | null;
	  };

export type FeedEntry = FeedItem & { received_at_ms: number };

/** `GET /v1/ally/feed` */
export interface FeedResponse {
	member_id: string;
	items: FeedEntry[];
	next_cursor: string | null;
	has_more: boolean;
	/**
	 * What each device in `items` is. Lets an ally, who has no device list,
	 * word an iPhone's alerts as an iPhone's. Absent from older instances.
	 */
	device_platforms?: Record<string, Platform>;
}

// ---- Decrypted bodies (faro_proto::body, faro_proto::report) --------------

export type Rating = 'clean' | 'low' | 'medium' | 'high';

export interface Reason {
	source: 'image' | 'domain' | 'title' | 'app' | 'ocr' | 'context' | 'dns';
	label: string;
	score?: number;
}

export interface BlurredThumbnail {
	width: number;
	height: number;
	transform: string;
	/** base64url PNG, blurred on the device before encryption. */
	png: string;
}

export interface AppInfo {
	id: string;
	name?: string;
}

export type TamperSignal =
	| { signal: 'permission_revoked'; permission: string; never_granted?: boolean }
	| { signal: 'agent_killed_repeatedly'; count: number; window_secs: number }
	| { signal: 'integrity_failure'; component: string }
	| { signal: 'clock_manipulation'; wall_delta_ms: number; mono_delta_ms: number }
	| { signal: 'wayland_token_lost' }
	| { signal: 'capture_failing'; consecutive_failures: number }
	| { signal: 'unmonitored_user_session'; user: string }
	| { signal: 'window_hidden_from_capture'; app: string }
	| { signal: 'browser_without_extension'; browser: string }
	| { signal: 'vpn_active' }
	| { signal: 'virtual_machine' }
	| { signal: 'remote_desktop' }
	// iPhone (docs/IOS.md §10.2). The first three are tamper events.
	| { signal: 'screen_time_revoked' }
	| { signal: 'filter_off'; cause: FilterOffCause }
	| { signal: 'settings_cleared' }
	// iPhone, context only: listed in the daily report.
	| { signal: 'doh_dropped' }
	| { signal: 'other_vpn' }
	| { signal: 'jailbreak_suspected' }
	// Android, context only (docs/ANDROID.md §8). Android's tamper events reuse
	// `permission_revoked` (`accessibility_service`, `device_admin`) and
	// `window_hidden_from_capture`.
	| { signal: 'battery_optimization_on' }
	| { signal: 'usb_debugging_on' };

/** Why an iPhone's DNS filter is off, as far as the phone could tell. */
export type FilterOffCause =
	'vpn_disconnected' | 'on_demand_off' | 'other_vpn' | 'profile_removed' | 'unknown';

/** One host in a `blocked_summary`: the host only, never a path or query. */
export interface BlockedHost {
	host: string;
	category: string;
	count: number;
}

export type EventBody =
	| { type: 'capture'; rating: Rating; count: number }
	| {
			type: 'flag';
			rating: Rating;
			reasons: Reason[];
			app?: AppInfo;
			window_title?: string;
			browser?: { url?: string; title?: string; incognito?: boolean };
			thumbnail?: BlurredThumbnail;
			burst?: boolean;
			account?: string;
	  }
	| { type: 'tamper'; signal: TamperSignal; account?: string }
	| {
			type: 'settings_change';
			changes: { key: string; old?: string; new?: string }[];
			// Pending loosening (docs/IOS.md §9), ms since the epoch; left out when not set.
			requested_at?: number;
			takes_effect_at?: number;
			cancelled_at?: number;
			/** The delay that was in force, in seconds. */
			delay_secs?: number;
	  }
	| {
			type: 'blocked_summary';
			bucket_start: number;
			bucket_secs: number;
			by_category: Record<string, number>;
			hosts: BlockedHost[];
			other_hosts: number;
	  }
	| {
			type: 'shield_summary';
			bucket_start: number;
			bucket_secs: number;
			shown: number;
			closed: number;
	  }
	| { type: 'agent_restarted'; count_last_hour: number }
	| { type: 'paused'; reason?: string; until_ms?: number }
	| { type: 'resumed' }
	| {
			type: 'goodbye';
			reason: 'uninstalled' | 'account_deleted' | { moved_instance: { new_instance_host: string } };
	  }
	| { type: 'boot'; os: string; client_version: string }
	| { type: 'shutdown' };

export type ActivityState =
	'active' | 'idle' | 'locked' | 'asleep' | 'paused' | 'off' | 'unmonitored';

export interface TamperRecord {
	seq: number | null;
	ts_ms: number;
	signal: TamperSignal;
	account?: string;
}

/**
 * The iPhone part of a daily report (docs/IOS.md §11). Present only in an
 * iPhone's report, which has no screen checks. The device builds it
 * (`faro_proto::report::IosReport`, `faro_core::IosReportBuilder`); the
 * fixture `crates/faro-core/tests/data/ios-reports.json` is written by that
 * code and read by `feed/ios.test.ts`, so the two can't drift.
 */
export interface IosReport {
	/** When each layer was on, in order. */
	protection: {
		start_ms: number;
		end_ms: number;
		/** `null` when the phone couldn't tell. */
		screen_time: boolean | null;
		filter: boolean;
	}[];
	/** Blocked lookups, one entry per day. */
	blocked: {
		day_start_ms: number;
		by_category: Record<string, number>;
		hosts: BlockedHost[];
		other_hosts: number;
	}[];
	/** Blocked apps opened, counts only, one entry per day. */
	shields: { day_start_ms: number; shown: number; closed: number }[];
	/** Loosenings asked for, applied or cancelled. */
	loosenings?: { ts_ms: number; text: string }[];
}

export interface DailyReport {
	v: number;
	device_id: string;
	device_name: string;
	period_start_ms: number;
	period_end_ms: number;
	first_seq: number | null;
	last_seq: number | null;
	timeline: { start_ms: number; end_ms: number; state: ActivityState; account?: string }[];
	counts: { clean: number; low: number; medium: number; high: number };
	flagged: {
		seq: number;
		ts_ms: number;
		rating: Rating;
		reasons: Reason[];
		app?: AppInfo;
		thumbnail?: BlurredThumbnail;
		member_note?: string;
		account?: string;
	}[];
	top_domains?: { name: string; count: number }[];
	top_apps?: { name: string; count: number }[];
	ios?: IosReport;
	health: {
		tamper: TamperRecord[];
		context: TamperRecord[];
		agent_restarts: number;
		capture_failures: number;
		unmonitored_secs: number;
	};
}

// ---- Preferences ---------------------------------------------------------

export type DeliveryMode = 'immediate' | 'digest' | 'off';

export interface QuietHours {
	start_min: number;
	end_min: number;
	tz_offset_min: number;
}

/** `GET /v1/me/notification-prefs?member_id=` */
export interface NotificationPrefs {
	member_id: string;
	urgent: DeliveryMode;
	normal: DeliveryMode;
	none: DeliveryMode;
	quiet_hours: QuietHours | null;
	tamper_minimum: DeliveryMode;
}

export interface RetentionWindows {
	event_header_days: number;
	blob_days: number;
	alert_days: number;
}

/** `GET /v1/me/retention` */
export interface RetentionView {
	instance: RetentionWindows;
	chosen: { event_header_days: number | null; blob_days: number | null; alert_days: number | null };
	effective: RetentionWindows;
	min_days: number;
}

// ---- Groups (docs/GROUPS.md; server/src/api/groups.rs) -----------------------

export type GroupRole = 'facilitator' | 'participant';
export type WhoCanInvite = 'facilitators' | 'participants';

/** The `groups` object of `GET|PATCH /admin/api/settings` (GROUPS.md §13). */
export interface GroupSettings {
	enabled: boolean;
	who_can_create: 'anyone' | 'admins';
	who_can_list: 'facilitators' | 'admins' | 'nobody';
	who_can_invite: WhoCanInvite;
	invites_create_accounts: boolean;
	max_groups_per_user: number;
}

export interface GroupPerson {
	user_id: string;
	display_name: string;
}

/** `GET /v1/groups` */
export interface GroupSummary {
	id: string;
	name: string;
	description: string;
	my_role: GroupRole;
	participant_count: number;
	meeting: Meeting | null;
	archived_at_ms: number | null;
	delete_after_ms: number | null;
	/** The last facilitator's account was deleted and this person is offered the role. */
	facilitator_offer: boolean;
}

/** `GET /v1/groups/{id}`, and the answer to creating, editing or joining */
export interface GroupView {
	id: string;
	name: string;
	description: string;
	created_at_ms: number;
	my_role: GroupRole;
	participant_count: number;
	facilitators: GroupPerson[];
	/** What is in effect: the instance's setting, narrowed by the group's. */
	who_can_invite: WhoCanInvite;
	/** What the facilitators chose; null until they choose. */
	group_who_can_invite: WhoCanInvite | null;
	/** The instance's limit: `facilitators` rules out "any participant". */
	instance_who_can_invite: WhoCanInvite;
	can_invite: boolean;
	max_participants: number | null;
	meeting: Meeting | null;
	/** The start of the next meeting (Unix ms), if there is a schedule. */
	next_meeting_at_ms: number | null;
	my_meeting_reminders: MeetingReminders;
	listed: boolean;
	listing: Listing | null;
	archived_at_ms: number | null;
	delete_after_ms: number | null;
	no_facilitator: boolean;
	facilitator_offer_until_ms: number | null;
	groups_disabled: boolean;
	my_sharing: MySharing;
}

/** A meeting schedule (GROUPS.md §8.4); the weekday counts from Monday as 0. */
export interface Meeting {
	cadence: 'weekly' | 'fortnightly';
	weekday: number;
	minute_of_day: number;
	/** Minutes east of UTC. */
	tz_offset_min: number;
	place?: string;
	anchor_ms?: number;
}

/** What a listing shows beyond the name, description and facilitators. */
export interface Listing {
	show_meeting_time: boolean;
	show_place: boolean;
}

/** The caller's reminder choices for one group. */
export interface MeetingReminders {
	reminders: boolean;
	email: boolean;
	/** What `email` is until the person chooses (off in large groups). */
	email_default: boolean;
}

/** How the viewer and another person are linked, from the viewer's side. */
export type RosterRelationship = 'partners' | 'your_ally' | 'their_ally' | 'waiting';

/** `GET /v1/groups/{id}/participants`. Never an email address. */
export interface RosterEntry {
	user_id: string;
	display_name: string;
	role: GroupRole;
	joined_at_ms: number;
	/** The account is disabled or being deleted: listed but unavailable. */
	unavailable: boolean;
	/** People you are linked with come first, whatever page they are on. */
	relationship: RosterRelationship | null;
	/** What they show the group; `not_shared` unless they chose to (GROUPS.md §8.2). */
	status: StatusDot;
}

/** The dot beside a name: only what the person chose to show. */
export type StatusDot =
	'monitoring_on' | 'paused' | 'not_checked_in' | 'no_computer' | 'not_shared';

/** What you show a group (`PUT /v1/groups/{id}/me/sharing`). */
export interface MySharing {
	share_status: boolean;
	share_allies: boolean;
}

/** `GET /v1/groups/{id}/participants/{user_id}/allies`. */
export interface SharedAllies {
	/** False when they don't show their allies to the group. */
	shared: boolean;
	allies: { user_id: string; display_name: string; side: 'ally' | 'supports' }[];
}

/** One pairing suggestion as you see it: your own card. */
export interface SuggestionCard {
	id: string;
	other: { user_id: string; display_name: string };
	created_at_ms: number;
}

/** A pairing a facilitator posted: never whether anyone acted on it. */
export interface PostedSuggestion {
	id: string;
	a: { user_id: string; display_name: string };
	b: { user_id: string; display_name: string };
	created_at_ms: number;
}

/** `GET /v1/groups/{id}/me/allies`: the people here you are linked with. */
export interface GroupAlly {
	user_id: string;
	display_name: string;
	relationship: RosterRelationship;
}

export interface Page<T> {
	items: T[];
	next_cursor: string | null;
}

export type HistoryKind =
	| 'joined'
	| 'left'
	| 'removed'
	| 'facilitator_added'
	| 'facilitator_removed'
	| 'renamed'
	| 'listed'
	| 'unlisted'
	| 'archived';

/** `GET /v1/groups/{id}/history`, newest first. `null` people are "someone". */
export interface HistoryEntry {
	id: string;
	at_ms: number;
	kind: HistoryKind;
	subject: GroupPerson | null;
	actor: GroupPerson | null;
}

/** `PATCH /v1/groups/{id}` body. `max_participants: null` removes the limit. */
export interface GroupPatch {
	name?: string;
	description?: string;
	who_can_invite?: WhoCanInvite;
	max_participants?: number | null;
	listed?: boolean;
	listing?: Partial<Listing>;
	/** `null` removes the meeting. */
	meeting?: MeetingInput | null;
}

/** A facilitator's meeting schedule, as sent. */
export interface MeetingInput {
	cadence: 'weekly' | 'fortnightly';
	weekday: number;
	minute_of_day: number;
	tz_offset_min: number;
	place?: string | null;
}

/** `POST /v1/groups/{id}/invites` body */
export interface GroupInvitesRequest {
	emails: string[];
	user_ids: string[];
}

export interface GroupInvitesCreated {
	invites: { invited: string; expires_at_ms: number; invite_url: string }[];
	/** Already in the group, already invited, or not a valid target. */
	skipped: number;
}

/** `GET /v1/groups/{id}/invites` */
export interface GroupInviteStatus {
	invited: string;
	invited_user_id: string | null;
	inviter: GroupPerson | null;
	created_at_ms: number;
	expires_at_ms: number;
	/** `not_accepted` covers declined and expired: the inviter is never told which. */
	state: 'pending' | 'accepted' | 'not_accepted';
}

/** `GET /v1/me/group-invites`, `GET /v1/group-invites/{token}` */
export interface GroupInviteInfo {
	/** Works in place of the emailed token in the invite endpoints' paths. */
	invite_ref: string;
	group_id: string;
	group_name: string;
	group_description: string;
	group_archived: boolean;
	inviter_display_name: string;
	/** The facilitators' display names. */
	facilitators: string[];
	meeting: Meeting | null;
	instance_name: string;
	expires_at_ms: number;
	/** People in the group now: who would see what you choose to share. */
	participant_count: number;
}

// ---- Alliance proposals (GROUPS.md §7; server/src/api/proposals.rs) ---------

export type ProposalKind = 'request' | 'offer' | 'partnership';

export interface ProposalPerson {
	user_id: string;
	display_name: string;
}

/** A proposal you sent, as you see it: a decline reads like an expiry. */
export interface OutgoingProposal {
	id: string;
	group_id: string;
	group_name: string | null;
	to: ProposalPerson;
	kind: ProposalKind;
	state: 'open' | 'accepted' | 'not_accepted' | 'withdrawn';
	created_at_ms: number;
	expires_at_ms: number;
	accepted_at_ms: number | null;
	withdrawn_at_ms: number | null;
	/** "You can ask again on" this date. */
	ask_again_at_ms: number | null;
	/** Your signed note (`GET /v1/group-messages/{id}`), if you wrote one. */
	note_id?: string | null;
}

/** A proposal sent to you. */
export interface IncomingProposal {
	id: string;
	group_id: string;
	group_name: string | null;
	from: ProposalPerson;
	kind: ProposalKind;
	state: 'open' | 'accepted' | 'declined' | 'expired' | 'withdrawn' | 'void';
	created_at_ms: number;
	expires_at_ms: number;
	decided_at_ms: number | null;
	/** The sender's signed note (`GET /v1/group-messages/{id}`), if any. */
	note_id?: string | null;
}

/** `GET /v1/me/proposals` */
export interface MyProposals {
	incoming: IncomingProposal[];
	outgoing: OutgoingProposal[];
}

/** `POST /v1/proposals/{id}/accept`: the links it started, all pending. */
export interface ProposalAccepted {
	proposal: IncomingProposal;
	links: { member_id: string; ally_id: string; state: 'pending'; ally_key_id: string }[];
}

/** `GET /v1/me/proposal-blocks` */
export interface ProposalBlock {
	user_id: string;
	display_name: string;
	created_at_ms: number;
}

/** What `POST …/proposals` and `…/accept` take for a first ally key. */
export interface AllyKeyUpload {
	enc_pubkey: string;
	wrapped_privkey: unknown;
}

// ---- The directory and join requests (GROUPS.md §8.8) ----------------------

/** `GET /v1/group-directory`: never who is in a group, or how many. */
export interface DirectoryEntry {
	id: string;
	name: string;
	description: string;
	facilitators: string[];
	meeting: Omit<Meeting, 'place' | 'anchor_ms'> | null;
	place: string | null;
	full: boolean;
	requested: boolean;
	joined: boolean;
}

/** `GET /v1/me/join-requests`: an ended one reads "not_accepted", always. */
export interface MyJoinRequest {
	id: string;
	group_id: string;
	state: 'open' | 'not_accepted';
	group_name?: string;
	created_at_ms?: number;
	expires_at_ms?: number;
}

/** `GET /admin/api/groups`: metadata only. */
export interface AdminGroupRow {
	id: string;
	name: string;
	participant_count: number;
	facilitators: GroupPerson[];
	no_facilitator: boolean;
	listed: boolean;
	created_at_ms: number;
	archived_at_ms: number | null;
	delete_after_ms: number | null;
}

/** `GET /v1/groups/{id}/join-requests` (facilitators): a name and a time. */
export interface JoinRequestEntry {
	id: string;
	display_name: string;
	created_at_ms: number;
	expires_at_ms: number;
	/** Their signed note to the facilitators, if they wrote one. */
	note_id?: string | null;
}
