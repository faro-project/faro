//! Windows: the service's side of an administrator's approval of enrolling
//! from the agent (`faro_platform_windows::ui::approval` has the whole
//! contract; this is the "Service" column).
//!
//! 1. The agent asks UAC to run `faro-service approve-enroll --request
//!    <hex>` elevated. That helper connects to the **admin pipe**
//!    (`enroll.S-1-5-32-544` next to the agent pipes, whose DACL admits only
//!    an elevated Administrators token) or, for a development service, the
//!    ordinary enroll pipe, and sends `ApproveEnroll { request }`.
//! 2. [`approve`] reads the helper's **own token** from the connection
//!    (`ImpersonateNamedPipeClient`, never a pid lookup) and requires an
//!    elevated administrator at High or System integrity
//!    ([`check_approver_token`]); the token's session must be the
//!    connection's; and, in the real (SYSTEM) service, that session must
//!    have an agent ([`crate::win::agent_in_session`]), so an approval in
//!    one session cannot serve another. It records `(request, session,
//!    approver SID, time)` for [`APPROVAL_TTL`] in an [`ApprovalTable`],
//!    holding at most [`MAX_RECORDS`].
//! 3. On `Enroll` the agent sends the same bytes as `authorization`.
//!    [`answer`] compares them in constant time with the live records,
//!    removes a matching record whatever happens next (one use), requires
//!    that it was recorded for the session of the connection that sends
//!    `Enroll`, and logs the approver's SID. No record: `Failed {
//!    NotApproved }`. Only then does the shared enrollment code run
//!    ([`EnrollService::handle_with`], which still checks the instance's
//!    identity against what the person confirmed).
//!
//! Who may send what: `Status`, `Preview` and `Enroll` only from the pipe's
//! own account (the SID read from the connection) and, when
//! `ipc.agent_requirement` is set, a validly signed agent image;
//! `ApproveEnroll` from any account that passes the token check, with the
//! same image check on the helper (it is the signed service binary).
//! A `dev` build's missing requirement changes none of this: the approval
//! still needs the elevated token.

use crate::enroll_server::{ApprovalError, Approver, EnrollService};
use crate::source::ipc::{check_policy, PeerPolicy};
use faro_ipc::{
    AccountId, Connection, EnrollRequest, EnrollResponse, EnrollServerConnection, FailureKind,
    PeerInfo, ServerStream, Sid, AUTHORIZATION_LEN,
};
use faro_platform_windows::ui::approval::{check_approver_token, APPROVAL_TTL};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

/// The "account" of the pipe an administrator's helper connects to.
pub const ADMIN_PIPE_ACCOUNT: AccountId = Sid::BUILTIN_ADMINISTRATORS;
/// Approvals kept at once; the oldest is dropped for a new one.
pub const MAX_RECORDS: usize = 8;

struct Record {
    request: [u8; AUTHORIZATION_LEN],
    session: u32,
    approver: String,
    at: Instant,
}

/// The approvals recorded and not yet used or expired.
#[derive(Default)]
pub struct ApprovalTable(Mutex<VecDeque<Record>>);

impl ApprovalTable {
    pub fn record(
        &self,
        request: [u8; AUTHORIZATION_LEN],
        session: u32,
        approver: String,
        now: Instant,
    ) {
        let mut t = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        t.retain(|r| now.saturating_duration_since(r.at) < APPROVAL_TTL);
        while t.len() >= MAX_RECORDS {
            t.pop_front();
        }
        t.push_back(Record {
            request,
            session,
            approver,
            at: now,
        });
    }

    /// Use the approval for `request`, if one is live: removed whatever
    /// the session, valid (returning the approver's SID) only for the
    /// session it was recorded for.
    pub fn consume(
        &self,
        request: &[u8; AUTHORIZATION_LEN],
        session: u32,
        now: Instant,
    ) -> Option<String> {
        let mut t = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        t.retain(|r| now.saturating_duration_since(r.at) < APPROVAL_TTL);
        // Compare against every record, without stopping at the first hit.
        let mut found = None;
        for (i, r) in t.iter().enumerate() {
            if ct_eq(&r.request, request) {
                found = Some(i);
            }
        }
        let r = t.remove(found?)?;
        (r.session == session).then_some(r.approver)
    }
}

fn ct_eq(a: &[u8; AUTHORIZATION_LEN], b: &[u8; AUTHORIZATION_LEN]) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// How the pipe a request arrived on treats it.
pub struct PipeRules {
    /// The account the pipe is for.
    pub account: AccountId,
    /// The administrators' approval pipe: takes only `ApproveEnroll`.
    pub admin_pipe: bool,
    pub policy: Result<PeerPolicy, String>,
}

fn refused(why: impl Into<String>) -> EnrollResponse {
    EnrollResponse::failed(FailureKind::NotApproved, why)
}

/// Record an approval from the helper on the other end of `pipe`.
fn approve(
    table: &ApprovalTable,
    peer: &PeerInfo,
    pipe: &ServerStream,
    request: [u8; AUTHORIZATION_LEN],
) -> EnrollResponse {
    let Some(session) = peer.windows_session_id else {
        return refused("the client's session is unknown");
    };
    let token = match crate::win::pipe_client_token(pipe) {
        Ok(t) => t,
        Err(e) => return refused(format!("cannot read the client's token: {e}")),
    };
    // SAFETY: `token` is a valid token handle with TOKEN_QUERY and
    // TOKEN_DUPLICATE, alive for the call.
    let approver = match unsafe { check_approver_token(token.handle()) } {
        Ok(a) => a,
        Err(e) => {
            tracing::warn!(error = %e, "refused an enrollment approval");
            return refused(e.to_string());
        }
    };
    if approver.session_id != session {
        tracing::warn!(
            token_session = approver.session_id,
            pipe_session = session,
            "refused an enrollment approval from another session"
        );
        return refused("the approval is from another session");
    }
    // A development service has no launcher, so it cannot know.
    if crate::win::is_system() && !crate::win::agent_in_session(session) {
        tracing::warn!(
            session,
            "refused an enrollment approval: no agent in the session"
        );
        return refused("no Faro agent is running in the approver's session");
    }
    tracing::info!(session, approver = %approver.user_sid, "recorded an enrollment approval");
    table.record(request, session, approver.user_sid, Instant::now());
    EnrollResponse::Approved
}

/// An approver that says yes: used only after [`ApprovalTable::consume`]
/// found the administrator's recorded approval.
struct AlreadyApproved;

impl Approver for AlreadyApproved {
    fn approve(&self, _: &[u8; AUTHORIZATION_LEN], _: &str) -> Result<(), ApprovalError> {
        Ok(())
    }
}

/// Answer one request on a Windows enroll pipe. Returns the connection so
/// the caller can send the answer (an approval takes the stream apart to
/// read the client's token).
pub async fn answer(
    table: &ApprovalTable,
    rules: PipeRules,
    conn: EnrollServerConnection<ServerStream>,
    req: EnrollRequest,
    service: &EnrollService,
    have_slot: bool,
) -> (EnrollServerConnection<ServerStream>, EnrollResponse) {
    let Some(peer) = conn.peer().copied() else {
        return (conn, EnrollResponse::failed(FailureKind::Failed, "no peer"));
    };
    // The signature check reads files and calls WinVerifyTrust.
    let checked = {
        let policy = rules.policy.clone();
        tokio::task::spawn_blocking(move || check_policy(&peer, &policy))
            .await
            .map_err(|e| e.to_string())
            .and_then(|r| r.map_err(|e| e.to_string()))
    };
    if let Err(why) = checked {
        tracing::warn!(%why, "refused an enroll client");
        return (
            conn,
            EnrollResponse::failed(FailureKind::Unavailable, "not allowed"),
        );
    }
    if let EnrollRequest::ApproveEnroll { request } = req {
        let stream = conn.into_inner();
        let resp = approve(table, &peer, &stream, request);
        return (Connection::with_peer(stream, Some(peer)), resp);
    }
    let resp = if rules.admin_pipe || peer.windows_sid != Some(rules.account) {
        EnrollResponse::failed(
            FailureKind::Unavailable,
            "this pipe is not for this account",
        )
    } else if !have_slot {
        EnrollResponse::failed(FailureKind::Busy, "too many requests at once")
    } else if let EnrollRequest::Enroll { authorization, .. } = &req {
        let session = peer.windows_session_id.unwrap_or(u32::MAX);
        match table.consume(authorization, session, Instant::now()) {
            Some(approver) => {
                tracing::info!(%approver, session, "enrolling with an administrator's approval");
                service.handle_with(req, Arc::new(AlreadyApproved)).await
            }
            None => refused("no administrator has approved this enrollment"),
        }
    } else {
        service.handle(req).await
    };
    (conn, resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_approval_is_used_once_by_its_own_session() {
        let t = ApprovalTable::default();
        let now = Instant::now();
        t.record([1; 32], 3, "S-1-5-21-1".into(), now);
        t.record([2; 32], 4, "S-1-5-21-2".into(), now);
        assert_eq!(t.consume(&[9; 32], 3, now), None);
        // Another session's attempt uses the approval up.
        assert_eq!(t.consume(&[1; 32], 4, now), None);
        assert_eq!(t.consume(&[1; 32], 3, now), None);
        assert_eq!(t.consume(&[2; 32], 4, now).as_deref(), Some("S-1-5-21-2"));
        assert_eq!(t.consume(&[2; 32], 4, now), None);
    }

    #[test]
    fn approvals_expire_and_the_table_is_bounded() {
        let t = ApprovalTable::default();
        let now = Instant::now();
        t.record([1; 32], 3, "a".into(), now);
        assert_eq!(t.consume(&[1; 32], 3, now + APPROVAL_TTL), None);
        for i in 0..(MAX_RECORDS as u8 + 3) {
            t.record([i; 32], 3, "a".into(), now);
        }
        assert_eq!(t.consume(&[0; 32], 3, now), None, "the oldest was dropped");
        assert!(t.consume(&[MAX_RECORDS as u8 + 2; 32], 3, now).is_some());
    }
}
