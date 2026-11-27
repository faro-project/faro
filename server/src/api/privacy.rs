//! `GET /v1/privacy-notice`: what this instance's operator can and cannot
//! see, in plain language (§5.3, §5.4 trade-off, §12 "operator privacy
//! notice"). Generated from the instance name and live settings. The list of
//! what the operator can see is written by hand: when a migration adds a
//! table that holds something readable by the operator, add a line here
//! and to `docs/operators/PRIVACY-NOTICE.md`. Public: members are shown it before
//! they sign up.

use crate::config::{RegistrationMode, RetentionConfig};
use crate::state::AppState;
use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyNotice {
    pub instance_name: String,
    pub public_url: String,
    pub operator_can_see: Vec<String>,
    pub operator_cannot_see: Vec<String>,
    /// Honest limits of the protection.
    pub caveats: Vec<String>,
    pub retention: RetentionConfig,
    pub registration_mode: String,
    /// The whole notice as plain text.
    pub text: String,
}

pub fn build(
    instance_name: &str,
    public_url: &str,
    retention: &RetentionConfig,
    mode: RegistrationMode,
) -> PrivacyNotice {
    let can_see = vec![
        "Account details: names, email addresses, roles (member, ally, admin) and when \
         people sign in."
            .to_owned(),
        "Who is connected to whom: which members have which allies.".to_owned(),
        "Devices (computers and phones): their names and platforms, when each one last checked in, and whether it \
         reported being asleep or shutting down."
            .to_owned(),
        "When events happen, what kind they are (for example a flagged capture, a tamper \
         signal, a settings change or a pause) and their urgency (none, normal or urgent). \
         The operator can see that an urgent event happened and when, but not what it was."
            .to_owned(),
        "Warnings the server raises itself: missed check-ins, gaps in a device's event log \
         and invalid signatures."
            .to_owned(),
        "When notifications are sent and whether delivery failed. Notification emails \
         never contain details: a member's name, a device name and an urgency, or that \
         someone is reaching out. They never name a group."
            .to_owned(),
        "The size and upload time of encrypted reports and attachments.".to_owned(),
        "Groups: each group's name and description, its facilitators and participants, its \
         history, and join requests and alliance proposals (who, to whom, when and the \
         outcome). Listed groups are visible to everyone signed in. The text of notes, \
         check-ins and reach outs is encrypted; the operator cannot read it."
            .to_owned(),
        "Reach outs: who sent one, to which people or group, when, and each person's answer \
         (\"I'll call\" or \"I'm here\") and when they answered. Also who has asked to hear \
         about whose reach outs differently or during quiet hours. Check-ins and replies: \
         who wrote them, in which group and when. Pairing suggestions: which two people a \
         facilitator suggested, in which group."
            .to_owned(),
        "Network addresses of devices and browsers, as any web server does. This server \
         keeps them only in memory, for rate limiting."
            .to_owned(),
    ];
    let cannot_see = vec![
        "Screenshots. Full screenshots never leave the device; only blurred thumbnails do, \
         and only encrypted."
            .to_owned(),
        "What check-ins, reach outs and notes say. They are encrypted for the people they \
         are addressed to."
            .to_owned(),
        "What reports and alerts say: ratings, reasons, websites, apps and thumbnails. \
         They are encrypted on the device for the member and the allies the member \
         approved, and only decrypted in their browsers."
            .to_owned(),
        "Passphrases and private keys. They are wrapped in your browser before upload, and \
         the server cannot unwrap them."
            .to_owned(),
        "A way to listen in. Devices only encrypt to keys the member has signed, so the \
         operator cannot add themselves (or anyone else) as an ally, and an admin account \
         gives no access to anyone's content."
            .to_owned(),
    ];
    let caveats = vec![
        "If you use the Faro web app, you trust the operator not to change the code this \
         server sends to your browser. Security-sensitive allies can use the Faro desktop \
         app when it is available."
            .to_owned(),
        "The operator can delete data or stop the server. Devices notice when the server \
         is unreachable, and gaps in a device's log are visible to the member and allies."
            .to_owned(),
        "An admin can disable an account, which stops that person signing in. Faro then \
         always emails the person and everyone in an accountability partnership with them, \
         and their computers keep being monitored and alerting their allies."
            .to_owned(),
        "Anyone can delete their account. Faro first emails everyone in an accountability \
         partnership with them, keeps everything for 7 days (they can cancel until then), \
         and then removes their data from this server. The operator's backups keep a copy \
         until they are rotated out."
            .to_owned(),
    ];
    let mode_text = match mode {
        RegistrationMode::InviteOnly => "by invitation only",
        RegistrationMode::Open => "open to allowed email domains",
        RegistrationMode::Closed => "closed to new accounts",
    };
    let bullet = |v: &[String]| {
        v.iter()
            .map(|l| format!("  - {l}"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let text = format!(
        "Privacy notice for {instance_name} ({public_url})\n\n\
         The people who run this server (the operator) CAN see:\n{}\n\n\
         The operator CANNOT see:\n{}\n\n\
         Limits:\n{}\n\n\
         How long data is kept: encrypted reports, attachments and check-ins {} days, event \
         metadata {} days, alerts and reach outs {} days. Members may choose shorter, never longer. \
         Deleted data is removed for good.\n\n\
         Registration on this instance is {mode_text}.\n",
        bullet(&can_see),
        bullet(&cannot_see),
        bullet(&caveats),
        retention.blob_days,
        retention.event_header_days,
        retention.alert_days,
    );
    PrivacyNotice {
        instance_name: instance_name.to_owned(),
        public_url: public_url.to_owned(),
        operator_can_see: can_see,
        operator_cannot_see: cannot_see,
        caveats,
        retention: retention.clone(),
        registration_mode: mode.as_str().to_owned(),
        text,
    }
}

/// `GET /v1/privacy-notice`
pub async fn get(State(state): State<AppState>) -> Json<PrivacyNotice> {
    let settings = state.settings();
    let cfg = state.config();
    Json(build(
        &cfg.instance.name,
        &cfg.public_url,
        &settings.retention,
        settings.registration.mode,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notice_reflects_settings() {
        let r = RetentionConfig {
            event_header_days: 60,
            blob_days: 14,
            alert_days: 45,
        };
        let n = build(
            "Grace Church Faro",
            "https://faro.example.org",
            &r,
            RegistrationMode::Open,
        );
        assert!(n.text.contains("Grace Church Faro"));
        assert!(n.text.contains("14 days") && n.text.contains("60 days"));
        assert!(n.text.contains("45 days"));
        assert!(n.text.contains("open to allowed email domains"));
        assert!(
            n.text.contains("urgent event happened"),
            "§5.4 trade-off stated"
        );
        assert_eq!(n.registration_mode, "open");
        assert!(n.text.contains("Reach outs") && n.text.contains("Check-ins"));
        assert!(
            n.text.contains("Pairing suggestions")
                && n.text.contains("Devices (computers and phones)")
        );
    }
}
