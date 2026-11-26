# Faro: Groups

**Status:** Proposal, draft v0.2 (2026-11-26). Nothing here is built yet. Working name: "Circles".
**Changes in v0.2:** decisions on every open question (§22), and every limit explained in Appendix A. The feature is now **groups**, led by **facilitators**. Groups can be **listed** in a directory on the instance and joined by request (§8.8). Groups have **no size limit**, and §10.5 covers what that changes.
**Replaces:** "Optional groups (Phase 2)" in [ARCHITECTURE.md §4.3](ARCHITECTURE.md#43-roles-within-an-instance).
**Depends on:** ally links, recipient manifests and safety codes ([ARCHITECTURE.md §5.2](ARCHITECTURE.md#52-key-lifecycle), [PROTOCOL.md §5.1](PROTOCOL.md)), the notifier (§5.4), and account deletion (§12).

---

## 1. Summary

A **group** is a space inside a Faro instance for a real-life accountability group: a men's group that meets on Tuesdays, a recovery cohort at a college, three friends who check in on each other. It gives that group a shared place in Faro, where people can:

- see who else is in the group,
- **ask** someone in the group to be their ally, **offer** to be someone's ally, or **partner up** (each becomes the other's ally), without typing anyone's email address,
- know when the group meets and get a reminder,
- **reach out** when they are struggling,
- **find and ask to join** the groups their instance lists, for example the several recovery groups a ministry runs on its instance,
- and, later, share short check-ins with the group, encrypted end to end.

A group is a social layer **on top of** the existing ally model. It never grants access to anyone's reports. Every alliance formed in a group is still an ordinary one-to-one ally link, still approved and signed by the member, and is ended the same way.

---

## 2. Why

Faro's model today is one person and the allies they invite by email. Real accountability rarely works like that. People meet in groups, pair up within them, rotate partners, and lean on the whole group when one partner isn't available. Today, a church small group that wants to use Faro has to:

1. collect everyone's email addresses outside Faro,
2. have each person send each of their allies an email invite, one at a time,
3. keep track of who is allied with whom on paper.

Nothing in Faro reflects that the group exists, so there is nowhere to put the group's shared rhythm (meetings, check-ins, "I need to talk tonight"). An institution that runs many groups also has no way inside Faro to show people which groups exist and let them ask to join.

Groups fix that without weakening any of Faro's guarantees.

---

## 3. Goals and non-goals

### Goals

1. **Mirror the real group.** A group has a name, the people in it, one or more facilitators and, optionally, a meeting time.
2. **Make alliance easy inside a group.** Asking, offering and partnering take one action each, with no email addresses needed.
3. **Let institutions offer groups.** A facilitator can list a group so that people on the instance can find it and ask to join.
4. **No pressure.** Saying no, or saying nothing, is always easy and private.
5. **Keep every existing guarantee.** Reports stay end to end encrypted to member-signed allies. The operator, and now facilitators too, can't see content. Nobody can make an alliance on someone else's behalf.
6. **Cheap to run, at any group size.** Nothing about groups needs ML, background crypto on the server, or extra infrastructure, and nothing breaks when a group has hundreds of people.

### Non-goals

- **Sharing reports, flags or thumbnails with the whole group.** Only allies see reports. A group is not a shared ally.
- **Facilitator or institutional dashboards** of participants' monitoring. Facilitators get no visibility that ordinary participants don't have.
- **Leaderboards, streak rankings or any scoring** that compares people.
- **Groups across instances.** Same rule as allies (ARCHITECTURE.md §14).
- **Public directories.** Listed groups (§8.8) are visible only to people signed in to the instance, never to visitors or search engines, and never with their rosters.
- **Minors.** Same as the rest of Faro (ARCHITECTURE.md §12).

---

## 4. Principles (invariants)

Every change that implements groups must keep these. They extend the six invariants in [DEVELOPMENT.md](DEVELOPMENT.md#invariants-every-change-must-keep), and would be added to that list when Phase A ships.

1. **Group membership grants no content access.** Being in a group, or facilitating one, never makes a report, alert, thumbnail or device-health detail visible. Only an active, member-signed ally link does that, exactly as today.
2. **The only way a link becomes active is the member's approval.** Groups add new ways to *start* a link (§7). The member's client still compares safety codes and signs a new recipient manifest through the existing `POST /v1/me/allies/{ally_id}/approve`. No group route creates or activates an `ally_links` row on its own.
3. **Nobody acts for anyone else.** A facilitator or admin can't send a proposal on someone's behalf, accept one for them, or pair people up. They can only *suggest* (§8.5).
4. **Alliances outlive groups.** Leaving a group, being removed from it, or the group being archived never ends an alliance. Ending an alliance is still the member's or the ally's own action, and it still raises the tamper-class `ally_removed` alert.
5. **Declining is private.** The proposer is never told whether a proposal was declined or just expired, and facilitators never see proposals between other people. The same holds for join requests (§8.8).
6. **Sharing is opt-in, per group, and reversible.** Anything a participant shows the group about themselves (status, who their allies are) is off until they turn it on, for that group only.
7. **Emails never name the group.** Group names are often sensitive ("Tuesday recovery group"), and email passes through third parties. Emails say "a group on *instance*". The name appears only inside Faro, after sign-in.
8. **Group content is end to end encrypted.** Anything participants write for each other (notes, reach-out messages, check-ins) is encrypted to its recipients and signed by its author. The server stores ciphertext only (§10).
9. **Every join is someone's choice twice.** A person joins only by accepting an invite or by asking to join, and only once a facilitator has invited or accepted them. There is no open joining.

---

## 5. Terms

| Term | Meaning |
|---|---|
| **Group** | A named set of people on one instance, matching a real-life accountability group. |
| **Participant** | Anyone in a group. Deliberately not "member", which in Faro means the person whose computer is monitored. A participant may be a Faro member, an ally, both, or neither yet. |
| **Facilitator** | A participant who can manage the group (§6). A group has between 1 and 32 facilitators. |
| **Listed group** | A group its facilitators have put in the instance's directory (§8.8). Groups are unlisted by default. |
| **Join request** | A request from someone on the instance to join a listed group, answered by a facilitator (§8.8). |
| **Proposal** | An offer to form an ally link between two participants: a **request**, an **offer** or a **partnership** (§7). |
| **Origin group** | The group an ally link was proposed in. Shown as a label only, never used to authorize anything. |
| **Reach out** | A signal that a participant wants to talk soon, with an optional encrypted message (§8.3). |
| **Check-in** | A short, encrypted, self-written update shared with chosen people in the group (§8.6, Phase C). |

---

## 6. Roles and permissions

| Role | Can | Cannot |
|---|---|---|
| **Facilitator** | Rename the group and edit its description. Set the meeting schedule. Invite people (by email, or by picking existing users on the instance). List or unlist the group, and accept or decline join requests (§8.8). Set an optional participant limit. Remove a participant (they are told). Make another participant a facilitator, or step down. Archive the group. Post pairing suggestions (§8.5). Everything a participant can. | See anyone's reports, alerts, device health or status unless that person shares it with the whole group. See proposals between other people. Create, accept or decline a proposal for anyone else. Add someone without their acceptance. Read check-ins not addressed to them. |
| **Participant** | See the group's name, description, meeting and roster. Send and answer proposals. Reach out. Choose what to share with the group (§8.2). Leave at any time. Invite people too, if the facilitators allow it. | Everything a facilitator can't do, plus the facilitator actions. See join requests. |
| **Instance admin** | See groups as **metadata**: name, size, facilitators, whether listed, created and archived dates (§11). Unlist or archive a group, for example over an abusive name (participants are told and it goes into the admin log). Create a group and invite people as a normal user, then hand the facilitator role on. Set instance-wide group settings (§13). | Join a group without an invite or an accepted request. See rosters beyond counts and facilitators, or anything inside a group. Everything in the facilitator's "Cannot" column. |

Admins are users (ARCHITECTURE.md §4.3). An admin who is also a participant has a participant's view of that group, and the admin role adds nothing inside it.

**Every group has at least one facilitator, and at most 32.** The upper limit keeps "send to the facilitators" within one item's recipient limit (§10.5). It doesn't limit the group's size. The last facilitator can't leave without first making someone else a facilitator, unless they are the last participant, in which case leaving archives the group. For what happens when the last facilitator's account is deleted, see §9.

---

## 7. Alliance inside a group

These are the core of the feature. Each proposal is between two people who are both active participants in the same group.

### 7.1 Three kinds of proposal

| Kind | Sent by | Meaning | Sender needs | Recipient needs |
|---|---|---|---|---|
| **Request** ("Ask *Jo* to be my ally") | A | B becomes A's ally | A member key | An ally key (B creates one on accepting if needed) |
| **Offer** ("Offer to be *Jo*'s ally") | B | B becomes A's ally | An ally key (B creates one on sending if needed) | A member key |
| **Partnership** ("Partner up with *Jo*") | A | Each becomes the other's ally | Member and ally keys | Member and ally keys (created on accepting if needed) |

When a person can't take part in a kind (for example, they have no member key, so nobody can be their ally yet), the roster simply doesn't show that action for them. It never says why.

A proposal can carry an optional **note** of up to 500 characters ("Would you be my Thursday call?"). The note is encrypted to the recipient and signed by the sender (§10.2).

### 7.2 Request: A asks B to be their ally

```
A: "Ask B to be my ally"  ──▶  proposal(request, open)
                                   │  B is notified (normal)
                                   ▼
B: Accept ── creates or unlocks B's ally key ──▶ ally_link(A←B, pending)   [same as an email invite accepted]
B: Decline ─────────────────────────────────────▶ proposal(not_accepted)    [A sees "Not accepted"]
                                   │  A is notified: "B accepted"
                                   ▼
A: compares safety codes with B, then approves ──▶ ally_link(active)       [existing approve route; manifest re-signed]
                                                    A's other allies get `ally_added` as today
```

Accepting a request is the same server operation as accepting an email invite today (`invites::accept` with an `AllyKeyUpload`), except that the proposal is bound to B's user id, not an email address. The token-in-a-link and email-matching checks are replaced by "B is signed in and is the proposal's recipient".

### 7.3 Offer: B offers to be A's ally

```
B: "Offer to be A's ally" ── B's ally key must exist ──▶ proposal(offer, open, ally_key_id)
                                   │  A is notified (normal)
                                   ▼
A: Accept ──▶ ally_link(A←B, pending) using B's *current* ally key
          ──▶ A's client goes straight to "Compare safety codes" and approve
A: Decline ─▶ proposal(not_accepted)
```

An offer is the mirror image of a request: B has done their half up front, so A's acceptance and approval can happen in one sitting. A can also accept now and compare codes later; the link waits in `pending` as any other does. If B's ally key has changed since the offer, the link uses B's current key, and the safety code reflects it.

### 7.4 Partnership: A and B become each other's allies

A partnership is a request and an offer combined. When B accepts:

1. B's ally link to A and A's ally link to B are both created as `pending`.
2. B's client offers to compare **both** safety codes on one screen, then B approves A as their ally (B signs B's manifest).
3. A is notified and does the same for B.

Each side approves only their own manifest. Neither direction becomes active because of the other. If one side approves and the other never does, the result is one active link and one pending link, the same as if they had sent two separate proposals.

### 7.5 Comparing safety codes at the meeting

Groups meet in person, which is the best place to compare safety codes (ARCHITECTURE.md §5.2 step 4). When a group has links waiting to be compared, the group page lists them under **"Compare at your next meeting"**. The list is visible only to the two people in each pair. Opening one shows the code, large, ready to read aloud. Nothing about comparison changes; this only reminds people at the right moment.

### 7.6 Rules

- **One open proposal per direction.** If A has an open request to B and B tries to offer to A, B is shown A's request to accept instead. A partnership counts as both directions.
- **No duplicates.** Actions are hidden when a live link already exists in that direction.
- **Expiry.** Proposals expire after 14 days, and the sender sees "Not accepted", the same as a decline.
- **Cool-down.** After a proposal is declined or expires, the sender can't send the same kind to the same person for 30 days. The sender's UI shows "You can ask again on *date*" and nothing else.
- **Withdraw.** The sender can withdraw an open proposal at any time. The recipient's notification then shows "withdrawn".
- **Don't propose to me.** Any participant can privately stop one person from sending them proposals, in any group. The blocked person's actions for them are silently hidden. Unblocking is in Settings.
- **Limits.** Pending proposals count toward `MAX_LIVE_INVITES` (20) for the sender, and accepted ones toward `MAX_ALLIES` (32) for the member. If accepting would go over a limit, the person accepting is told plainly and nothing is created. The other person isn't told why. These are per-person limits, so a group's size doesn't change them.
- **Rate limit.** At most 10 new proposals per sender per day across all groups.
- **Accounts in deletion hold, or disabled,** can't send or receive proposals, and their open proposals become void (§9).
- **Leaving or archiving.** When either person leaves the group or the group is archived, their open proposals in it become void. Links already created, pending or active, are untouched (principle 4).

### 7.7 States

```
                 ┌───────────── withdraw ─────────────▶ withdrawn
open ────────────┼───────────── accept ───────────────▶ accepted  (link(s) now pending)
                 ├───────────── decline / expire ─────▶ not_accepted
                 └─ leave / remove / archive / disable / deletion hold ─▶ void
```

The sender's UI maps `not_accepted` and `void` to the same "Not accepted". The recipient's UI shows their own decisions as they made them.

---

## 8. Other group features

### 8.1 Roster and presence

The group page lists every participant: their display name, a **Facilitator** badge, and your relationship to them ("Your ally", "You're their ally", "Partners", "Waiting for safety codes"). People you have a relationship with are listed first. The roster has search and loads in pages, so it works for a group of 5 or 500.

Joins, leaves and removals appear in a **group history** that every participant can see ("Sam joined on 3 Nov"), so nobody can be added unseen. That matters most for E2EE content (§10.3). In busy groups the history collapses runs of changes ("14 people joined this week"), and each can be expanded.

### 8.2 Opt-in sharing with the group

Off by default, chosen per group under **"What this group can see about me"**:

| Setting | What the group sees | Where it comes from |
|---|---|---|
| **Show my status** | One dot per participant: *Monitoring on*, *Paused*, *Not checked in*, or *No computer yet*. Never ratings, flags or tamper details. | Liveness metadata the server already has (§3.7). Nothing new is collected. |
| **Show my allies in this group** | Who in this group is your ally, and whom you are an ally for. | `ally_links` the server already has. Only links where both people are in this group are shown. |

Each setting shows how many people would see it ("28 people in this group"), so nobody shares with a large group by accident.

Turning a setting off hides it immediately and **tells nobody** (decision 5). The dot then reads *Not shared*, exactly as if it had never been on. These settings change only what other *participants* see. They change nothing for allies, who keep seeing everything they see today.

### 8.3 Reach out

A participant who is struggling taps **Reach out** and chooses:

- **Recipients:** "my allies" (the default), the facilitators, up to 32 specific people in the group, or (Phase C) the whole group if it has 32 participants or fewer. In larger groups, "the whole group" isn't offered: urgent alerts to hundreds of people would be noise, and an easy way to harass a group.
- **An optional message** ("Rough night, can someone call me?"), encrypted to the recipients and signed by the sender (§10.2).

Recipients get an **urgent**, content-free notification: *"Sam is reaching out. Open Faro to see."* Inside Faro, each recipient can tap **"I'll call"** or **"I'm here"**. The sender sees who answered, and the other recipients see that someone has, so five people don't all call at once.

**Quiet hours (decision 4).** A reach out respects each recipient's quiet hours, like any alert, unless the recipient has chosen **"Let *Sam*'s reach outs through quiet hours"** for that person. The setting is offered on the first reach out from someone, and in notification settings.

Reach out is not tamper-class: recipients can move it to the digest or switch it off for a given person, like any normal alert. It is rate-limited to 3 per sender per hour. It is also available outside any group, to a member's own allies.

### 8.4 Meetings

Facilitators can set a meeting schedule: a weekly or fortnightly weekday, a time with a fixed UTC offset (the server has no time-zone database, as with quiet hours), and an optional free-text place ("Room 104" or "Zoom, see group chat"). Participants get a reminder before each meeting (default: 2 hours before, switchable per person). The reminder email doesn't name the group (principle 7): *"Your group on faro.example.org meets at 7:00 pm today."* In groups of more than 32 participants, reminders default to in-app and Web Push only, and each person can turn email on (§10.5).

The meeting is what §7.5's "Compare at your next meeting" list and §8.6's check-in prompt are timed around. The place is plaintext and visible to the operator, and the form says so.

### 8.5 Pairing suggestions

Many groups rotate partners or assign accountability pairs. A facilitator can post **suggested pairings** ("This month: Sam and Jo, Alex and Riley"), one at a time or as a pasted list for large groups. Each person sees only their own suggestion, as a card with a ready-made proposal ("Partner up with Jo?") that they can send, change to a one-way request or offer, or dismiss. A suggestion is not a proposal. Nothing is sent until the participant acts (principle 3), and the facilitator can't see who acted on it.

### 8.6 Check-ins (Phase C)

A check-in is a short, structured update a participant writes for the group, usually before a meeting:

- **"How's it going?"** on a 1–5 scale,
- optional **"What went well"** and **"What was hard"** free text,
- optional **"What I'd like from the group"**,
- **audience:** my allies in this group (the default), the facilitators, up to 32 specific people, or the whole group.

Check-ins are encrypted to their audience and signed by the author (§10). A check-in to the whole group uses the group's current epoch key (§10.5), so it costs the same in a group of any size. Check-ins never send notifications; they appear in the group's feed. Faro prompts for one a day before each meeting, if the participant turns that on. Recipients can reply privately with a short encrypted message.

Check-ins are self-written. Faro never fills them in from reports, so a check-in never reveals monitoring data the author didn't choose to share.

### 8.7 Bulk invites and onboarding

A facilitator can invite several people at once, by pasting email addresses or picking existing users on the instance. This replaces the admin-only "bulk invites" in the old groups plan.

- **Existing users** get an in-app notification and an email: *"Sam invited you to join a group on faro.example.org."*
- **New people** get the same email with a 7-day link. Under `invite-only` registration, a group invite lets that address create an account, like an ally invite does today, unless the admin turns that off (§13).
- Accepting shows the group's name, description, facilitators, meeting, a plain explanation that joining shares nothing about their computer, and the "What this group can see about me" settings, all off.

For a new person who wants to be monitored, the group page links them to the normal member onboarding (MEMBER-GUIDE.md). Joining a group doesn't require being a member or an ally.

### 8.8 Listed groups and join requests

Institutions often run several groups and want people to find one, the way a church lists its small groups on a sign-up board. Facilitators can **list** a group in the instance's directory, and anyone signed in to the instance can **ask to join**.

**Listing.** Off by default. A facilitator turns on **"List this group on *instance*"** (if the admin allows it, §13) and chooses what the listing shows:

| In the listing | Default |
|---|---|
| Name and description | Always |
| Facilitators' display names | Always: people should know whom they are asking |
| Meeting day and time | Shown |
| Meeting place | Hidden (shown once someone has joined) |
| "Full" | Only if the facilitators set a participant limit and the group has reached it |

A listing **never shows who is in the group, or how many people are**. The form recommends a name that says who the group is for without naming the struggle ("Men, Tuesday evenings" rather than "Porn recovery, Tuesday").

**The directory.** Groups → **Find a group** lists every listed group on the instance, with search and paging. It is served only to signed-in users of that instance: never to signed-out visitors, never by an unauthenticated route, and never in emails (decision 8). Someone who wants to browse it has to be invited to the instance first. That keeps it out of search engines and away from scraping.

**Asking to join.**

```
P: "Ask to join"  ──▶  join_request(open)          [visible to P and the group's facilitators only]
                            │  facilitators are notified (normal)
                            ▼
Facilitator: Accept ──▶ P joins (sharing settings all off), P is notified, group history: "P joined"
Facilitator: Decline / 14 days pass ──▶ P sees "Not accepted"
P: Withdraw ──▶ request removed
```

- A request can carry an optional note to the facilitators ("I'm new to the church and was told to ask about this group"), encrypted to the facilitators' keys and signed (§10.2, Phase B). In Phase A, requests carry no note.
- **Private like proposals.** Other participants never see requests. The requester can't tell a decline from an expiry. After either, they can't ask the same group again for 30 days. A person may have at most 5 open join requests.
- **Facilitators can't see anything about a requester** beyond their display name and note: not whether they are monitored, nor who their allies are.
- **No open joining.** Every join needs a facilitator's yes (principle 9). Real groups vet newcomers, and in Phase C each join must be signed into the roster by a facilitator (§10.3).
- **Unlisting** removes the group from the directory at once. Open requests become "Not accepted". An admin can unlist any group, which is written to the admin log and tells the facilitators.

Facilitators can still invite people directly. A listed group's name is visible to everyone on the instance, so it stays in plaintext whatever is decided later about encrypting names (decision 1).

---

## 9. Lifecycle and edge cases

| Event | What happens |
|---|---|
| **Create** | Any user can create a group, unless the admin restricts it (§13). The creator is its first facilitator. |
| **Invite accepted** | The person joins and appears in the group history. Facilitators are told (normal, switchable; a daily summary in groups of more than 32). |
| **Invite declined or expired** | The inviter sees "Not accepted", as with proposals. |
| **Join request accepted** | Same as an accepted invite, and the requester is told. |
| **Join request declined or expired** | The requester sees "Not accepted" (§8.8). |
| **Leave** | Always possible, in one step. Facilitators are told. Open proposals become void. Alliances stay, and the confirmation says so: *"You'll stay allies with Jo and Alex. To end an alliance, go to Allies."* |
| **Removed by a facilitator** | The person is told (normal). Same effects as leaving. |
| **Archived by a facilitator or admin** | Everyone is told. The group is unlisted. The roster and history become read-only for 30 days, then the group is deleted. Open proposals and join requests become void. Alliances stay. An admin archive is written to the admin log. |
| **Last facilitator's account deleted** (§12 purge) | The participant who joined first is offered the facilitator role. If nobody accepts within 14 days, the group continues without facilitators: proposals, reach out and check-ins keep working, but nobody can invite, accept join requests, remove or edit, and the group is unlisted. Admins see the group flagged "No facilitator". In Phase C, roster changes wait for a facilitator too (§10.5). |
| **Account deletion requested** (hold) | The person stays in their groups during the 7-day hold but can't send or receive proposals or join requests. Their participant rows, proposals, join requests, notes, reach-outs and check-ins are deleted in the purge. |
| **Account disabled** | The person stays listed but is shown as unavailable. Their open proposals and join requests become void. |
| **A participant hits `MAX_ALLIES`** | Offers to them stay open, and accepting one fails with an explanation for them only. |
| **Participant limit reached** | Only if the facilitators set one. Invites and join requests are refused with "This group is full", and a listing shows "Full". Groups have no limit otherwise (decision 7). |

---

## 10. Cryptography and trust

### 10.1 Phases A and B need no new cryptography

Alliances formed in groups go through the existing invite-accept and approve paths, so they inherit member-signed manifests and safety codes unchanged. A compromised or curious operator who forges a group, a roster entry, a listing or a proposal can at most get someone to a `pending` link. Making it active still needs the member's signature over a key they compared in person. That is the same position as an operator who forges an email invite today.

### 10.2 Signed, encrypted messages

Proposal notes, join-request notes and reach-out messages are written by one person for specific people:

- **Encryption:** a random content key with XChaCha20-Poly1305, wrapped with `crypto_box_seal` for each recipient's encryption key and for the sender's own key, so they can see what they sent. This is the same construction as reports (ARCHITECTURE.md §5.1). At most 32 recipients per item, plus the sender (Appendix A).
- **Authenticity:** the author signs `{instance_id, group_id, item_id, kind, recipients, ciphertext hash}` with their member signing key. Without the signature, an operator who knows everyone's public keys could forge a message "from" anyone.
- **Phases A and B:** only senders with a member signing key can attach a note or message. Ally-only participants can still send proposals, join requests and content-free reach-outs, which the UI marks *"Sent through the server. Can't be verified."*
- **Recipients' keys:** in Phase B, messages go only to the sender's own allies (keys the sender already signed in their manifest), people the sender has a link with, or the facilitators (keys shown with a "not yet verified" note until Phase C). Sealing to arbitrary participants needs the roster rules in §10.3.

### 10.3 Phase C: participant keys and a signed roster log

Sending check-ins to "the whole group" means sealing to keys the server hands out, and the server could slip in a key of its own. Phase C closes that, in the same spirit as the recipient manifest:

1. **Keys.** Everyone in the group needs an X25519 encryption key to receive group content. Members use their member key and allies their ally key. Anyone with neither creates one when they join. Signing keys (Ed25519): members reuse their member signing key. An ally-only person creates one, wrapped with their existing passphrase, **when they become a facilitator** (at group creation or when given the role, with a one-screen explanation; decision 6) or the first time they write group content.
2. **Roster log.** Every change (join, leave, removal, role change, key rotation, epoch rotation) is an entry `{group_id, seq, prev_hash, at, change}`, signed by a facilitator. It is domain-separated as `faro/group-roster/v1` and encoded like PROTOCOL.md §5.1. An entry is valid only if its signer was a facilitator in the roster as of the previous entry. The first entry is signed by the creator. Because it is a hash-chained log of changes, not a re-signed full list, its cost per change doesn't grow with the group (§10.5).
3. **Checkpoints.** Every 256 entries, and whenever a facilitator's client chooses, a facilitator signs a snapshot of the full roster at that `seq`. A new joiner fetches the latest snapshot and the entries after it, not the whole history.
4. **Client rules.** Each client keeps its accepted `(seq, hash)` and applies only entries that extend it. A fork, a rollback or a bad signature is refused, and the client keeps its last accepted roster and shows a warning. These are the same rules as devices apply to recipient manifests (PROTOCOL.md §5.1).
5. **Pinning and the group safety code.** A joiner pins the signing key of the facilitator who invited or accepted them. The **group safety code** is a fingerprint of the current roster head. In a large group, comparing it with any one facilitator is enough, since every entry is facilitator-signed.
6. **Content** is sealed only to keys in the accepted roster and signed by the author's signing key.

Under this model, the server can't add a reader. A facilitator can, but every addition is visible in the group history and needs the new person's own keys. That is the honest limit of a group whose facilitators choose its members.

### 10.4 What doesn't change

- Reports, alerts and thumbnails are still sealed only to the member and their manifest's allies. Nothing a group does adds a recipient to a device's manifest.
- Devices never learn about groups. No client or wire-protocol change is needed until Phase C, and Phase C only touches the web app and server.

### 10.5 Groups have no size limit

Groups are uncapped (decision 7). A facilitator may set a participant limit for their own group, but nothing in Faro requires one. These are the parts of the design that would break or degrade at hundreds of participants, and how the spec handles each.

| Concern | What happens at scale | How it's handled |
|---|---|---|
| **Encrypting to "the whole group"** | Wrapping each item's key to every participant costs one envelope per person, and ingest accepts at most 64 envelopes per item. | **Epoch keys** (Phase C). A facilitator's client creates a random group key for each *epoch*, seals it to each participant's encryption key, and records the new epoch in the signed roster log. Whole-group content wraps its content key once, with the current epoch key. Each item costs one envelope, whatever the group's size. |
| **Removed people keep reading** | Someone who leaves still holds the current epoch key. | **The epoch rotates on every join, leave and removal**, as part of the facilitator-signed roster entry. Rotation is one sealed box per participant: about 80 bytes and well under a millisecond each, so a 1,000-person group re-keys in about a second in the browser. Joiners get only the new epoch, so they can't read what came before. As with allies, the instance also serves a group item only to people who were participants when it arrived. |
| **Nobody online to rotate** | A leave is recorded at once, but the signed entry and rotation wait for a facilitator's client. | Any facilitator's client does pending roster work automatically when they open Faro. Until then, the server stops serving new group items to the departed person, and clients pause whole-group posting with "Waiting for a facilitator to update the group", offering to send to named people instead. Faro doesn't escalate this to admins. Keeping the group up to date is the facilitators' job, and a group whose facilitators are absent sorts it out itself (decision 9). |
| **Small audiences** | Per-recipient wrapping is still right for "my allies", "the facilitators" and named people. | Those audiences are capped at 32 recipients, which is why a group has at most 32 facilitators (§6). Appendix A explains where 32 comes from. |
| **Roster size** | A re-signed full list would grow without bound and cost every client a large fetch. | Signed log with periodic snapshots (§10.3). Clients cap a snapshot fetch at 8 MiB (roughly 40,000 participants) and fetch log entries in pages. |
| **Urgent notifications** | A whole-group reach out to 500 people. | Whole-group reach outs are offered only in groups of 32 or fewer (§8.3). Check-ins never notify. |
| **Email volume** | A weekly reminder to 500 people is 500 emails, and hosted email providers cap daily sends. | Reminders in groups of more than 32 default to in-app and Web Push, with email per person by choice (§8.4). Join and leave notices to facilitators become a daily summary above 32. SELF-HOSTING.md notes that large groups add email volume. |
| **Roster and history UI** | Long lists. | Search, paging and collapsed history (§8.1). The API pages roster and history 100 at a time. |
| **Accidental oversharing** | "Show my status" in a group of 400. | The sharing settings show the audience size (§8.2). |
| **Server load** | More rows, not new kinds of work. | Indexes on `(group_id, state)` and `(user_id, state)`. Per-person storage and notification work is unchanged, so the resource guide (ARCHITECTURE.md §4.2) still holds. |

**Large groups and accountability.** Accountability usually works best in small groups. Faro doesn't enforce a size, but the create form says that most accountability groups are 3 to 12 people, and the directory makes it easy for an institution to run many small groups rather than one large one.

---

## 11. Privacy: who sees what

| | Operator / admins | Facilitators | Other participants | Others on the instance | Allies (outside the group) |
|---|---|---|---|---|---|
| Name, description (unlisted group) | Yes (plaintext) | Yes | Yes | No | No |
| Listing: name, description, facilitators, meeting time | Yes (plaintext) | Yes | Yes | **Yes, if listed** | Only if on the instance |
| Meeting place | Yes (plaintext) | Yes | Yes | No | No |
| Roster and roles | Server: yes. Admin console: counts and facilitators only | Yes | Yes | No | No |
| Group history (joins, leaves) | Server: yes | Yes | Yes | No | No |
| Join requests | Server: yes (metadata) | Yes | No | Only the requester | No |
| Join-request notes | Ciphertext only | Yes | No | Only the requester | No |
| Who proposed to whom, and the outcome | Server: yes (metadata) | No | Only the two people | No | No |
| Proposal notes | Ciphertext only | No | Only the recipient | No | No |
| Status dot | Server already knows liveness | Only if shared | Only if shared | No | Allies already see device health |
| Who is allied with whom | Server already knows (§5.3) | Only if shared | Only if shared | No | As today |
| Reach out: that it happened, sender, recipients, time | Yes (metadata) | Only if a recipient | Only if a recipient | No | Yes, if a recipient |
| Reach-out message | Ciphertext only | Only if a recipient | Only if a recipient | No | Only if a recipient |
| Check-ins (Phase C): content | Ciphertext only | Only if in the audience | Only if in the audience | No | No |
| Reports, flags, thumbnails | Never | Never (unless also an ally) | Never (unless also an ally) | Never | As today |

**New operator-visible metadata,** to add to the operator privacy notice ([operators/PRIVACY-NOTICE.md](operators/PRIVACY-NOTICE.md)): group names, descriptions, listings, meeting details, rosters, join requests, who proposed alliances to whom, and when people reached out and to whom. **Group names and descriptions are plaintext** (decision 1). The group form recommends a neutral name, and the operator privacy notice says names are visible to the operator. Encrypting the names of unlisted groups will be looked at again in Phase C, once every participant has keys.

---

## 12. Abuse resistance

Groups bring institutional settings (churches, colleges) closer to individual accountability, which raises the risk of pressure. The design answers that with structure:

| Risk | Mitigation |
|---|---|
| A facilitator or institution pressures people into being monitored, or into accepting particular allies | Facilitators can't create, accept or see proposals (principles 3, 5). Joining a group doesn't require being monitored. Nothing in Faro shows a facilitator who is or isn't monitored, unless each person chooses to share it. |
| A "compliance dashboard" by the back door | No facilitator view aggregates anyone's status beyond what each person shares with the whole group. There are no counts across people who haven't opted in, since in a group of eight, "7 of 8" names the eighth. |
| Social pressure to accept a proposal | Declines look like expiry. Cool-downs, private blocks and a daily rate limit. No public list of pending proposals. |
| Being outed by group membership | Unlisted by default. Listings never show who is in a group or how many. The directory is for signed-in users only. Join requests are seen only by facilitators. Emails never name the group. Leaving is one step and tells only the facilitators. |
| Browsing the directory to work out who is struggling | The directory shows groups, never people. Facilitators are the only names in a listing, and they chose to list it. |
| Someone using a listed group to get close to vulnerable people | Every join needs a facilitator's yes (principle 9). Facilitators are named in the listing. Joining shares nothing about anyone's computer, and the sharing settings start off. Admins can unlist or archive any group, and participants can block proposals from a person. |
| An unwanted person joining unseen | Joins need an accepted invite or an accepted request, appear in the group history, and (Phase C) need a facilitator's signature that every client checks. |
| Groups used to get around consent for monitoring | Impossible by construction. Monitoring still needs the member to install Faro and enroll their own computer, and an ally still needs the member's signature (ARCHITECTURE.md §12). |
| Harassment by reach out, notes or join requests | Rate limits, private blocks, a 5-request limit on open join requests with a 30-day cool-down, no whole-group reach out above 32 participants, and recipients can switch off reach outs from a person. Facilitators can remove a participant. |

---

## 13. Instance settings

Under Admin → Settings → Groups:

| Setting | Default | Notes |
|---|---|---|
| Groups enabled | On | Off hides the feature; existing groups become read-only and unlisted. Alliances are never affected. |
| Who can create groups | Anyone | Or: admins only. |
| Who can list groups | Facilitators | Or: admins only (a facilitator asks, an admin lists), or nobody (no directory). |
| Who can invite into a group | Facilitators | Or: any participant. A facilitator can choose per group, within this setting. |
| Group invites can create accounts | On | Under `invite-only` registration, whether a group invite lets a new address sign up (as an ally invite does). Join requests never create accounts: only signed-in users can see the directory. |
| Maximum groups per user | 10 | |

There is deliberately no instance-wide group size limit (decision 7).

---

## 14. Notifications

All new kinds use the existing alert and notifier pipeline (ARCHITECTURE.md §5.4). Notification text stays content-free and never names the group (principle 7). **None of the new kinds is tamper-class.** The existing tamper-class kinds (`ally_removed` and the others) fire unchanged for alliances formed in groups.

| Kind | To | Urgency | Notification text |
|---|---|---|---|
| `group_invited` | Invitee | normal | "*Sam* invited you to join a group on *instance*." |
| `group_join_requested` | Facilitators | normal | "Someone asked to join your group." |
| `group_join_accepted` | Requester | normal | "You've been added to a group you asked to join." |
| `group_joined`, `group_left` | Facilitators | normal (daily summary above 32 participants) | "Someone joined/left your group." |
| `group_removed` | The removed person | normal | "You were removed from a group." |
| `group_unlisted` | Facilitators (admin unlist only) | normal | "An admin removed your group from the directory." |
| `group_archived` | Everyone in it | normal | "A group you're in was closed." |
| `alliance_requested` | Recipient | normal | "*Sam* asked you to be their ally." |
| `alliance_offered` | Recipient | normal | "*Sam* offered to be your ally." |
| `alliance_partnership` | Recipient | normal | "*Sam* asked to partner up." |
| `alliance_accepted` | Sender | normal | "*Jo* accepted. Compare safety codes to finish." |
| `meeting_reminder` | Each participant | normal (email off by default above 32) | "Your group meets at *7:00 pm* today." |
| `reach_out` | Chosen recipients | urgent (respects quiet hours unless let through) | "*Sam* is reaching out. Open Faro to see." |
| `reach_out_answered` | Sender | normal | "*Jo* answered." |
| `check_in` (Phase C) | Audience | none (feed only) | |

Declines, expiries and withdrawals, of proposals and of join requests, send no notification.

---

## 15. Data model (sketch)

Same portability rules as the existing migrations: `BIGINT` and `TEXT` only, Unix-ms timestamps, and partial indexes that work on SQLite and Postgres. The main table is `accountability_groups`, not `groups`: `GROUPS` is a keyword in both SQLite's and Postgres's window-function syntax.

```sql
accountability_groups(id, name, description, created_by, created_at,
        meeting_json,            -- {cadence, weekday, minute_of_day, tz_offset_min, place}
        settings_json,           -- {who_can_invite}
        listed, listing_json,    -- 0/1; {show_meeting_time, show_place}
        max_participants NULL,   -- optional, set by facilitators
        archived_at, archived_by, delete_after)
  INDEX (listed) WHERE archived_at IS NULL

group_participants(group_id, user_id, role[facilitator|participant],
        state[active|left|removed], invited_by, joined_via[invite|request|created],
        joined_at, ended_at, share_status, share_allies)   -- 0/1, default 0
  UNIQUE (group_id, user_id) WHERE state = 'active'
  INDEX (group_id, state), INDEX (user_id, state)

group_history(id, group_id, at, kind[joined|left|removed|facilitator_added|facilitator_removed|renamed|listed|unlisted|archived],
        subject_id, actor_id)

group_invites(token_hash, group_id, inviter_id, email, user_id,  -- one of email/user_id
        created_at, expires_at, used_at, used_by, outcome)

group_join_requests(id, group_id, user_id, note_blob_ref NULL,
        state[open|accepted|not_accepted|withdrawn|void],
        created_at, expires_at, decided_at, decided_by, cooldown_until)
  UNIQUE (group_id, user_id) WHERE state = 'open'

alliance_proposals(id, group_id, from_id, to_id, kind[request|offer|partnership],
        offer_ally_key_id,                   -- offers and partnerships
        note_blob_ref,                       -- encrypted, signed (§10.2), nullable
        state[open|accepted|not_accepted|withdrawn|void],
        created_at, expires_at, decided_at, cooldown_until)
  UNIQUE (from_id, to_id, kind) WHERE state = 'open'

proposal_blocks(user_id, blocked_id, created_at)

pairing_suggestions(id, group_id, facilitator_id, user_a, user_b, created_at, dismissed_a, dismissed_b)

reach_outs(id, sender_id, group_id NULL, created_at, sig, blob_ref NULL)
reach_out_recipients(reach_out_id, recipient_id, answered_at, answer[call|here])
-- notes and reach-out content keys use the existing envelopes table

notification_prefs + quiet_hours_bypass(user_id, sender_id)   -- "let Sam's reach outs through"

ALTER TABLE ally_links ADD COLUMN origin_group_id TEXT NULL;  -- label only, never for authorization

-- Phase C
group_keys(group_id, user_id, sign_pubkey NULL, enc_pubkey, created_at)
group_roster_log(group_id, seq, prev_hash, hash, signer_id, entry_json, sig, created_at)
group_roster_snapshots(group_id, seq, hash, signer_id, snapshot_blob_ref, sig, created_at)
group_epoch_keys(group_id, epoch, user_id, sealed_key, created_at)
group_posts(id, group_id, author_id, kind[check_in|reply], parent_id, epoch NULL,
        created_at, sig, blob_ref)
```

`ally_links.origin_group_id` uses `ON DELETE SET NULL`, so deleting a group leaves its alliances intact (principle 4).

Every column above that references `users` must be added to `db::repo::deletion::USER_COLUMNS` (DEVELOPMENT.md invariant 6), or `every_reference_to_users_is_purged` fails.

---

## 16. API (sketch)

```
POST   /v1/groups                                  create {name, description?}
GET    /v1/groups                                  groups I'm in
GET    /v1/groups/{id}                             group, my sharing, meeting (participants only)
GET    /v1/groups/{id}/participants?q=&cursor=     roster, 100 per page (participants only)
GET    /v1/groups/{id}/history?cursor=             history, 100 per page (participants only)
PATCH  /v1/groups/{id}                             facilitators: name, description, meeting,
                                                   who_can_invite, listed, listing, max_participants
DELETE /v1/groups/{id}                             facilitators: archive
POST   /v1/groups/{id}/invites                     {emails[]?, user_ids[]?}
GET    /v1/group-invites/{token}                   who invited, group name (after sign-in only)
POST   /v1/group-invites/{token}/accept|decline
DELETE /v1/groups/{id}/me                          leave
DELETE /v1/groups/{id}/participants/{user_id}      facilitators: remove
PUT    /v1/groups/{id}/participants/{user_id}/role facilitators: {facilitator: bool}
PUT    /v1/groups/{id}/me/sharing                  {share_status, share_allies}
POST   /v1/groups/{id}/suggestions                 facilitators: [{a, b}]

GET    /v1/group-directory?q=&cursor=              signed-in users: listed groups, listing fields only
POST   /v1/groups/{id}/join-requests               {note?}        (listed groups only)
DELETE /v1/groups/{id}/join-requests/me            withdraw
GET    /v1/groups/{id}/join-requests               facilitators
POST   /v1/join-requests/{id}/accept|decline       facilitators

POST   /v1/groups/{id}/proposals                   {to, kind, note?}
GET    /v1/me/proposals                            incoming and outgoing
POST   /v1/proposals/{id}/accept                   request/partnership: AllyKeyUpload or existing key;
                                                   offer: creates the pending link.
                                                   Then the client calls the existing
                                                   POST /v1/me/allies/{ally_id}/approve
POST   /v1/proposals/{id}/decline
DELETE /v1/proposals/{id}                          withdraw
PUT|DELETE /v1/me/proposal-blocks/{user_id}

POST   /v1/me/reach-outs                           {recipients[] | audience, group_id?, sig, ciphertext?, envelopes?}
POST   /v1/reach-outs/{id}/answer                  {answer}
PUT|DELETE /v1/me/quiet-hours-bypass/{user_id}

-- Phase C
GET    /v1/groups/{id}/roster?after_seq=           latest snapshot if needed, then log entries, paged
POST   /v1/groups/{id}/roster                      facilitators: signed entry (+ sealed epoch keys on rotation)
GET    /v1/groups/{id}/epoch-key                   my sealed key for the current epoch
POST   /v1/groups/{id}/posts                       check-ins and replies

GET    /admin/api/groups                           metadata only: name, size, facilitators, listed, dates, flags
PUT    /admin/api/groups/{id}/listed               {listed: false}   (admin log + notice to facilitators)
DELETE /admin/api/groups/{id}                      archive (admin log + notices)
```

Authorization is checked on every route against `group_participants` (state `active`) and role. Someone who isn't in a group gets `404`, not `403`, so group ids can't be probed. The only exceptions are a listed group's directory entry and its join-request route, which any signed-in user can reach while the group is listed.

---

## 17. Web app

- **Groups** in the main navigation: a list of your groups, each showing the next meeting and anything waiting for you, and **Find a group** (when the instance has listed groups).
- **Find a group:** search and a list of listings. Each listing has **Ask to join**, or shows "Requested" or "Full".
- **Group page:** the meeting card; "Waiting for you" (proposals, suggestions, safety codes to compare); the roster with search and each person's action menu (*Ask to be my ally*, *Offer to be their ally*, *Partner up*, *Don't let them send me proposals*); the group history; **"What this group can see about me"**; and for facilitators, a **Manage** tab (details, meeting, listing, join requests, invites, facilitators, participant limit).
- **Allies page:** proposals appear next to email invites, with the origin group as a label ("From Tuesday group").
- **Reach out:** a button on the home page and on every group page.
- **Language:** plain and warm, never "compliance", "violations" or "reporting on". The ally and member guides get a "Groups" section each.

---

## 18. Retention and deletion

- **Proposals and join requests:** pruned 90 days after they are decided. Encrypted notes go with them.
- **Reach-outs:** follow the instance's alert retention (default 90 days).
- **Check-ins (Phase C):** follow blob retention (default 30 days). Members can choose shorter, as with reports. An epoch key is pruned once no stored item uses it.
- **Group history and the roster log:** kept while the group exists. Log entries before the latest snapshot may be pruned after 90 days, since a snapshot replaces them for new joiners.
- **Archived groups:** deleted 30 days after archiving, with their rows, invites, join requests, suggestions, roster log and posts. The admin log keeps the archive entry.
- **Account purge** (ARCHITECTURE.md §12): removes the person's participant rows, invites, join requests, proposals, blocks, quiet-hours bypasses, suggestions, reach-outs, posts and sealed epoch keys, through the same retention code path. Their entries in group history are kept, with the user id removed ("Someone left"). Signed roster-log entries keep their opaque user id and public keys, as other members' signed headers already do (ARCHITECTURE.md §12, "What remains").

---

## 19. Testing

- **Authorization matrix:** for every route, facilitator, participant, ex-participant, requester, non-participant, signed-out visitor and admin, with the expected outcome. In particular, no admin or facilitator can create, accept or see another person's proposal, and no participant can see join requests.
- **Invariant test:** no code path other than `approve` moves an `ally_links` row to `active`. Every group route is exercised and the link states are checked afterwards.
- **Directory tests:** nothing is served signed out. Listings never contain participant ids, names or counts. An unlisted group returns `404` from the directory and join-request routes.
- **Email content test:** no outgoing email body or subject contains a group's name or description.
- **Lifecycle tests:** leave, remove, unlist, archive and purge each leave alliances untouched and void open proposals and requests.
- **Decline privacy tests:** the sender's API responses are byte-identical for declined, expired and void proposals, and the same for join requests.
- **Playwright:** a request, an offer, a partnership and a join request end to end, including the safety-code comparison, on SQLite and Postgres.
- **Phase C:** roster-log fork, rollback, a forged signature, a signer who wasn't a facilitator, and a withheld entry, using the same cases as the recipient-manifest tests; epoch rotation on join and leave; a removed participant can't fetch items posted after their removal.
- **Scale:** a seeded group of 1,000 participants: roster paging, snapshot fetch within the 8 MiB cap, epoch rotation time in a headless browser, and notifier throughput for a meeting reminder.

---

## 20. Rollout

| Phase | Scope | New crypto |
|---|---|---|
| **A: Groups core** | Groups, invites, roster and history (paged), roles, request/offer/partnership, decline privacy, "Compare at your next meeting", meeting schedule and reminders, bulk invites, **listed groups, the directory and join requests (without notes)**, optional participant limits, admin settings and metadata view, notifications, deletion handling. | None |
| **B: Support** | Reach out (to allies, facilitators and named people) with quiet-hours bypass, signed and encrypted notes on proposals and join requests, opt-in status and ally sharing, pairing suggestions, proposal blocks. | Signatures and sealing with existing keys |
| **C: Shared** | Participant keys (and signing keys for ally-only facilitators), the signed roster log with snapshots, epoch keys, the group safety code, check-ins and replies, whole-group reach out in groups of 32 or fewer. | Roster log (`faro/group-roster/v1`), epoch keys |

Phase A fits the ARCHITECTURE.md Phase 2 slot that "groups" held. B and C can follow independently.

**Docs to update when Phase A ships:** ARCHITECTURE.md §4.3 (replace "Optional groups"), §4.4, §4.5, §5.4 (new alert kinds), §13 (roadmap); PROTOCOL.md (Phase C only); the operator privacy notice; ALLY-GUIDE.md and MEMBER-GUIDE.md; SELF-HOSTING.md (settings, and email volume from large groups).

---

## 21. Considered and left out

- **Sharing flags or reports with the whole group.** That would turn a group into a shared ally, mean dozens of recipients for every report, and make declining to share visible. People who want a group-wide view can each make the others their allies.
- **Streaks and "days clean" counters.** Faro can't compute them without reading reports. Counters invite comparison and shame, which works against honest conversation. Check-ins let people share progress in their own words.
- **Facilitators assigning allies.** This conflicts with principle 3. Suggestions (§8.5) cover the real need.
- **Anonymous participation.** Accountability depends on knowing who you are talking to, and safety codes need real identities.
- **Open joining for listed groups.** Every join needs a facilitator's yes (principle 9, §8.8).
- **Showing rosters or sizes in the directory.** Either could identify who is in a group.
- **A fixed size limit.** Replaced by epoch keys, a signed roster log and scale-aware defaults (§10.5, decision 7).

---

## 22. Decisions and open questions

### Decisions (2026-11-26)

1. **Group names and descriptions are plaintext.** They are shown with a warning on the form and in the operator privacy notice. Encrypting unlisted groups' names will be looked at again in Phase C. Listed groups stay plaintext regardless (§8.8, §11).
2. **Groups can be discoverable.** Facilitators can list a group in a directory for signed-in users of the instance, and people ask to join (§8.8). Groups are unlisted by default, and the admin controls who may list them (§13).
3. **Naming: "group" and "facilitator".** "Participant" stays, to avoid confusion with "member".
4. **Reach outs respect quiet hours,** with a per-person "let *Sam*'s reach outs through quiet hours" setting (§8.3).
5. **Turning status sharing off tells nobody.** The dot reads *Not shared*, the same as never having shared (§8.2).
6. **Ally-only facilitators create a signing key when they become a facilitator,** in Phase C (§10.3).
7. **Groups have no size limit.** Facilitators may set an optional limit. The consequences are dealt with in §10.5: epoch keys for whole-group content, a signed roster log with snapshots, 32-recipient limits on named audiences and facilitators, and scale-aware defaults for notifications.

8. **The directory is never visible signed out.** There is no public page, no unauthenticated route, and nothing in emails (§8.8).
9. **Absent facilitators are the group's problem, not the instance's.** Roster changes and epoch rotations wait for a facilitator's client (§10.5), and Faro doesn't alert admins when facilitators don't sign in. Facilitators are expected to be responsible for their group. The only admin-facing flag is the existing one for a group with *no* facilitator at all, after the last one's account is purged (§9).

10. **One threshold of 32 participants for all three large-group behaviours:** no whole-group reach out, email reminders off by default, and daily summaries of joins and leaves. Facilitators can't change it for their group (Appendix A, section B).
11. **The limits against pressure and spam in Appendix A, section C are adopted as written.**

### Open

None at present.

---

## Appendix A: Every limit, and why it exists

Groups themselves are uncapped (decision 7). Everything below is either a technical limit on one encrypted item or download, a default that changes how a large group behaves (the group keeps working), or a limit against pressure and spam. Nothing else is limited: not group size, the number of groups on an instance, or the number of listed groups.

### A. Technical limits

These come from how per-recipient encryption works and from limits already in the code. They can't be raised without changing the protocol.

| Limit | Value | Why |
|---|---|---|
| Recipients of one item sealed to each person ("my allies", "the facilitators", named people) | **32**, plus the sender's own copy | Each recipient costs one sealed box to make and one envelope to store. Faro already caps a member's recipient list at 32 (`MAX_MANIFEST_ALLIES` in `faro-proto/src/keys.rs`), so that a hostile server can't make a client do unbounded work. The server accepts at most 64 envelopes per item (`MAX_ENVELOPES` in `server/src/api/events.rs`). Using the same 32 keeps group items consistent with reports and well inside the server's limit. Whole-group content doesn't use this path: it uses one epoch-key envelope, whatever the group's size (§10.5). |
| Facilitators per group | **32** | "Send to the facilitators" (reach outs, join-request notes) is a per-person audience, so it has to fit the limit above. With 33 facilitators, a note to "the facilitators" couldn't be sent as one item. |
| Allies per member | **32** (existing, `MAX_ALLIES`) | Unchanged by groups: it's the recipient-list limit above. A proposal that would take a member past it fails for them only (§7.6). |
| Roster snapshot download (Phase C) | **8 MiB**, about 40,000 participants | A client must cap what it downloads before it can check the signature, as it already caps recipient lists at 64 KiB (PROTOCOL.md §5.1). One roster entry is roughly 200 bytes (an id and two public keys). It isn't meant to limit group size in practice. If a group ever got near it, the cap would be raised in a release. |
| Page size for rosters, history and the directory | **100** per page | Keeps each response small whatever the group's size. Not a limit on how many there are. |
| Roster snapshot interval (Phase C) | Every **256** entries | Bounds how many log entries a new joiner downloads and checks after the latest snapshot. |

### B. Large-group defaults (at more than 32 participants)

These aren't limits on size. A group of 500 works fully. They change behaviour that becomes noisy or costly as a group grows. 32 is reused so there is one number to remember: a group that fits in one item's recipient list counts as "small". It is a judgment call, not a technical need, and the same threshold applies to all three (decision 10).

| Above 32 participants | Why |
|---|---|
| No whole-group **reach out** | A reach out is an urgent alert. Sent to hundreds of people, it would mostly be noise, and it is the easiest way to harass a whole group. Reach outs to allies, facilitators or up to 32 named people still work. Encryption isn't the reason: an epoch key could carry it. |
| **Meeting reminders** default to in-app and Web Push, with email off by default (each person can turn it on) | A weekly reminder to 500 people is 500 emails a week from the instance's SMTP account. Hosted providers (church Google Workspace, Microsoft 365) cap daily sends, and a large group could use up the allowance that tamper alerts also need. |
| **Join and leave notices** to facilitators come as one daily summary | In a busy large group, a notice for every change would bury facilitators. |

### C. Limits against pressure and spam

These protect people from being pressured or flooded. They are adopted as written (decision 11).

| Limit | Value | Why |
|---|---|---|
| New proposals | **10** per sender per day, across all groups | Stops anyone working through a whole roster asking everyone to be their ally. |
| Proposal expiry | **14 days** | An unanswered proposal ends on its own, so nobody has to decline outright. The sender sees the same "Not accepted" as a decline. |
| Proposal cool-down | **30 days**, same kind, same person | After a "no" or no answer, the person isn't asked again straight away. |
| Pending proposals | Count toward the existing **20** live invites (`MAX_LIVE_INVITES`) | One person can't have unlimited open asks. Proposals and email invites share the limit. |
| Open join requests | **5** per person | Stops one account from requesting every listed group on the instance. |
| Join-request expiry and cool-down | **14 days** and **30 days** per group | Same reasons as proposals. Facilitators never have to decline outright, and a requester can't keep asking. |
| Reach outs | **3** per sender per hour | Allows a real crisis, where someone retries when nobody answered, but stops a reach out being used to spam people. |
| Notes (proposals, join requests) | **500** characters | They are an introduction, not a conversation. It also keeps the encrypted blobs small. |
| Groups per person | **10** (admin setting) | Real people are in a handful of groups. It limits invite and join-request spam, and the admin can raise it. |
| Group invite links | **7 days**, one use, for the invited address | The same as ally invites today. |

### D. Timers

| Timer | Value | Why |
|---|---|---|
| Last facilitator's account purged | **14 days** for the earliest participant to accept the role, then the group runs without facilitators | Gives the group time to pick someone. Without one, invites, join requests and edits stop, but alliances, proposals, reach outs and check-ins carry on. |
| Archived group | **30 days** read-only, then deleted | Lets people see who was in it and finish forming alliances before it goes. |
| Retention | Proposals and join requests 90 days after decided; reach-outs follow alert retention; check-ins follow blob retention | Follows ARCHITECTURE.md §8, so groups keep nothing longer than the rest of Faro. |
