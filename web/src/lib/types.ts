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
	operator_can_see: string[];
	operator_cannot_see: string[];
	caveats: string[];
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
	name: string;
	server_version: string;
}
