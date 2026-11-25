# Security policy

Faro handles some of the most sensitive data a person has. If you find a way to break its promises, please tell us privately first.

## Reporting a vulnerability

**Please don't report vulnerabilities in public issues, pull requests or discussions.**

- **Once this repository is public:** use GitHub private vulnerability reporting. Open the repository's **Security** tab and click **Report a vulnerability**. The report is visible only to you and the maintainers.
- **Until then:** contact the maintainer through GitHub. Open an issue that says only that you have a security report and would like a private channel, with no details of the problem, and the maintainer will reply with a private way to send it.

A useful report includes:

- the component and version (a release tag, or a commit on `main`);
- what an attacker can do, and what they need first (for example network access, an ally account, admin rights on the member's computer, or control of the instance);
- steps to reproduce, or a proof of concept;
- any suggested fix.

Test only against instances and computers you own or have permission to test. Don't access other people's data, and don't degrade an instance someone else depends on.

## Scope

In scope: everything in this repository.

- **The desktop client:** the Rust crates in `crates/` (service, agent, detection, IPC, platform layers, cryptography, wire format).
- **The server:** `faro-server` in `server/`, including the update mirror.
- **The web app:** `web/`, served by every instance to members, allies and admins.
- **The installers and uninstallers:** `installers/`.
- **Update signing:** the release metadata and its verification in `faro-update` ([PROTOCOL.md §8](docs/PROTOCOL.md#8-updates)).

The threat model is in [ARCHITECTURE.md §9](docs/ARCHITECTURE.md#9-security-considerations), with the instance operator's position in [§5.3](docs/ARCHITECTURE.md#53-trusting-the-instance-operator). Examples of what we treat as vulnerabilities:

- **Defeating local monitoring silently.** Faro is tamper-evident, not tamper-proof: someone with admin rights on their own computer can stop it, but allies must find out. Any way to stop, blind, pause or downgrade monitoring, or to remove, reorder or hold back events, *without* an alert reaching allies is a vulnerability, even if it needs admin rights on that computer.
- Silencing or delaying tamper alerts beyond what the notification design allows (urgent tamper alerts can only be moved to the digest, never turned off).
- Anything that lets the instance operator, a server compromise or a network attacker read report contents, add a key that devices encrypt to, forge or downgrade an event's urgency, or push code to clients.
- Any path by which an unblurred screen image is written to disk, sent over IPC beyond the classifier, or leaves the device.
- Getting an ally key, member key, passphrase or recovery code out of the web app, other than by the operator changing the code it serves (below).
- Bypassing update signature checks or rollback protection. An instance may delay updates or choose the channel, but must never make a client install something the project didn't sign, or an older release.
- Monitoring someone without their knowledge: enrolling a device for another person, making oneself an ally without the member's approval, or hiding Faro's tray icon and notices.
- The usual server and web issues: authentication bypass, privilege escalation, injection, CSP bypass, request forgery.

Known limits that are **not** vulnerabilities on their own (they are documented and accepted):

- The operator can see the metadata listed in §5.3: who is linked to whom, device names, timing, event kinds and urgency levels.
- An ally or member using the web app trusts the operator not to change the JavaScript the instance serves. Signed web bundles and a desktop ally app are planned (§5.3). A way for *someone other than the operator* to change that code is in scope.
- Someone with admin rights on their own computer can stop monitoring, as long as allies are told.
- An operator can delete data or shut the instance down.
- Vulnerabilities in third-party dependencies with no Faro-specific impact: please report those upstream.

## What to expect

There is one maintainer, so these timelines are modest:

- **Acknowledgement** within 7 days.
- **An initial assessment** (whether we can reproduce it and how severe it is) within 14 days.
- **A fix** for high-severity issues as soon as practical, aiming for 90 days. We'll keep you updated if it takes longer.

We follow **coordinated disclosure**. We'll agree a disclosure date with you, normally when a fixed release is out or 90 days after your report, whichever comes first, and publish an advisory then. We'll credit you in the advisory unless you'd rather not be named.

## Supported versions

Faro is pre-1.0. Only the **latest release** gets security fixes. Until there is a first release, fixes go to `main`.
