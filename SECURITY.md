# Security policy

Faro handles some of the most sensitive data a person has. If you find a way to break its promises, please tell us privately first.

## Reporting a vulnerability

**Please don't report vulnerabilities in public issues, pull requests or discussions.**

- **By email:** send your report to **[TO FILL IN: monitored security address]**. Anyone can use this, including pilot operators, members and allies who have no access to this repository.
- **Once this repository is public,** you can also use GitHub private vulnerability reporting: open the repository's **Security** tab and click **Report a vulnerability**. The report is visible only to you and the maintainers.

Please don't put details of a vulnerability in an issue, even a private repository's.

A useful report includes:

- the component and version (a release tag, or a commit on `main`);
- what an attacker can do, and what they need first (for example network access, an ally account, admin rights on the member's computer, or control of the instance);
- steps to reproduce, or a proof of concept;
- any suggested fix.

Test only against instances and devices you own or have permission to test. Don't access other people's data, and don't degrade an instance someone else depends on.

**Good faith.** If you make a good-faith effort to follow this policy (you stay within your own instances and devices, stop when you reach someone else's data, don't disclose before we've agreed a date, and give us reasonable time to fix the problem), we will treat your research as authorised, won't pursue or support legal action over it, and will work with you to understand and fix the issue. This is the maintainer's statement of intent. It can't bind anyone else, such as an instance operator or a third party, and it isn't legal advice.

## Scope

In scope: everything in this repository.

- **The desktop client:** the Rust crates in `crates/` (service, agent, detection, IPC, platform layers, cryptography, wire format).
- **The mobile clients:** the iPhone and Android apps in `apps/`, the shared Rust code in `crates/faro-mobile`, `crates/faro-android`, and the DNS filter, `crates/faro-dnsfilter`.
- **The server:** `faro-server` in `server/`, including the update mirror.
- **The web app:** `web/`, served by every instance to members, allies and admins.
- **The installers and uninstallers:** `installers/`.
- **Update signing and the release pipeline:** the release metadata and its verification in `faro-update` ([PROTOCOL.md §8](docs/PROTOCOL.md#8-updates)), `release/`, and the release workflows in `.github/workflows/` (how artifacts are built, signed and published).

The threat model is in [ARCHITECTURE.md §9](docs/ARCHITECTURE.md#9-security-considerations), with the instance operator's position in [§5.3](docs/ARCHITECTURE.md#53-trusting-the-instance-operator). Those sections describe the design, and some protections they describe aren't built yet. Check what exists before relying on one, and see the accepted gaps under "Known limits" below. Examples of what we treat as vulnerabilities:

- **Defeating local monitoring silently.** Faro is tamper-evident, not tamper-proof: someone with admin rights on their own computer can stop it, but allies must find out. Any way to stop, blind, pause or downgrade monitoring, or to remove, reorder or hold back events, *without* an alert reaching allies is a vulnerability, even if it needs admin rights on that computer. Copying a device's key by someone with root or administrator rights is a known limit (below), not an example of this.
- Silencing or delaying tamper alerts beyond what the notification design allows (tamper-class alerts can only be moved to the digest, never turned off; [ARCHITECTURE.md §5.4](docs/ARCHITECTURE.md#54-urgency-flags) lists them).
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
- **Device keys are plain files** on the device. Someone with root or administrator rights can copy a device's key and send reports as that device. We want to protect them with the operating system's secure storage; until then, this isn't a vulnerability on its own.
- **The menu-bar icon** can be turned off on macOS 26 and later, and hidden in the Windows notification overflow, without allies being told. We treat hiding the icon by some *other* means, or silencing alerts, as in scope; these two OS features are accepted gaps.
- **Private browser windows** can't be told apart from ordinary ones, so the website a private window shows is treated like any other.
- **The project's update root keys don't exist yet.** Until they do, there is no real project key for clients to verify updates against, so that protection is not yet in force in practice. A flaw in how the signing and verification code would behave once keys exist is still in scope.
- An operator can delete data or shut the instance down.
- Vulnerabilities in third-party dependencies with no Faro-specific impact: please report those upstream.

## What to expect

There is one maintainer, so these timelines are modest:

- **Acknowledgement** within 7 days.
- **An initial assessment** (whether we can reproduce it and how severe it is) within 14 days.
- **A fix** for high-severity issues as soon as practical. We'll keep you updated, and tell you if it will take longer than we hoped.

We follow **coordinated disclosure**. We'll agree a disclosure date with you, normally when a fixed release is out. If there is no fix after 90 days, we'll talk to you about it. If a fix is in progress, we'll ask to extend by a stated period, because many Faro users can't update at once. We won't publish details of an unfixed vulnerability without telling you first, and we'll publish earlier than planned if it is being exploited or the details are already public. Once a fixed release is out, we'll publish an advisory. We'll credit you in the advisory unless you'd rather not be named.

## Supported versions

Faro is pre-1.0. Only the **latest release** gets security fixes. Until there is a first release, fixes go to `main`.
