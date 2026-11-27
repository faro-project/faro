# The Faro closed beta

**Who this is for:** the people taking part in Faro's closed beta. That means the operators of the two or three pilot instances (one person running Faro for themselves, a church and a college) and the members and allies they enroll.

This guide covers what is different about the beta, and what to expect from it. For the step-by-step instructions it links to the other guides:

- [Self-hosting Faro](SELF-HOSTING.md), for operators: setting up, email, backups, upgrading.
- [Adding your Mac, Windows PC or iPhone to Faro](MEMBER-GUIDE.md), for members: enrolling a computer or phone, checking that Faro works, problem reports.
- [A guide for allies](ALLY-GUIDE.md), for allies: accepting an invitation, reading alerts, having the conversation.
- [Developing Faro](DEVELOPMENT.md), for anyone who wants the technical detail behind this guide.

Notes in the form **[Maintainer: …]** mark things the Faro project still has to fill in or confirm. Until a note is resolved, don't rely on that part.

## Contents

1. [What the beta is](#1-what-the-beta-is)
2. [For operators](#2-for-operators)
3. [For members](#3-for-members)
4. [Known limitations and false alarms](#4-known-limitations-and-false-alarms)
5. [Reporting problems](#5-reporting-problems)
6. [Leaving the beta](#6-leaving-the-beta)

---

## 1. What the beta is

- **One version: `0.1.0-beta.1`.** The Mac app, the Windows client and the server have the same version number.
- **Macs and Windows PCs.** The Mac package runs on Apple Silicon and Intel Macs with macOS 13 or later. [Maintainer: confirm the minimum macOS for the beta. ONNX Runtime, which runs the image model, is built for macOS 13.3, and nobody has tried Faro on 13.0 to 13.2.]
- **Windows 10 and 11, x64 only.** The Windows package is an MSI. It runs on Windows 10 22H2 (build 19045) and Windows 11, on 64-bit (x64) PCs. Windows on ARM comes later.
- **iPhones, through TestFlight.** The iPhone app blocks rather than watches, and has its own setup and limits ([3.9](#39-on-an-iphone), [4.6](#46-on-an-iphone)).
- **The `beta` update channel.** Members' computers get updates through their instance, and the instance offers one channel. A `0.1.0-beta.1` release goes to `beta` only. `stable` gets nothing until `0.1.0`, so every pilot instance must choose **Beta** ([2.2](#22-choose-the-beta-update-channel)).
- **Small on purpose.** A few instances and the people they invite, so problems are found while they are easy to fix. Expect some false alarms ([section 4](#4-known-limitations-and-false-alarms)), and please report what goes wrong ([section 5](#5-reporting-problems)).

### What works

- **The instance** (`faro-server`), with its web app: setup, sign-in by emailed link, the admin console, and the member and ally pages. SQLite only: Postgres is experimental and not supported in the beta ([SELF-HOSTING.md](SELF-HOSTING.md)).
- **The Mac app**, one package with two parts: the Faro service, which checks the screen, and **Faro Agent**, the Faro icon in the menu bar. Members enroll from the web app's **Open in Faro** button or the menu's **Enroll this computer…**, with an administrator of the Mac approving in macOS's own password dialog.
- **The Windows client**, one MSI with two parts: the **Faro Service** (`FaroService`), which checks the screen, and **Faro Agent**, the tray icon in the notification area. Members enroll from the link in the web app, or **Enroll this computer…** in the tray menu. An administrator approves through the Windows UAC prompt. The service starts by itself.
- **Image checks**, with Yahoo's OpenNSFW model, which the Mac package and the Windows installer both include.
- **Website categories (adult and gambling sites).** The package includes the list, so this works from the moment Faro is installed, even before the Mac has reached the update channel. The update channel can replace the list with a newer one without a new version of the app. The list's sources and their credits are in `/Library/Faro/notices/domains.txt`. On a Mac, Faro can only tell which website is open with the Accessibility permission, in Safari, Chrome, Edge, Brave or Arc ([3.5](#35-screen-recording-and-accessibility)). On Windows it reads the address bar in Edge, Chrome, Brave, Firefox, LibreWolf, Waterfox, Zen and Floorp, and needs no permission.
- **Tamper alerts**, including "Screen Recording is off", a window hidden from Faro, and Faro not seeing the screen ([section 4](#4-known-limitations-and-false-alarms)). On Windows: a stopped service, a killed agent, a changed clock, or Faro's files made writable by a non-administrator ([4.5](#45-on-windows)).
- **The status menu** in the Faro icon (the tray icon on Windows): what Faro is doing and what to do about it, **Report a problem…** and **About Faro…** ([the member guide's table](MEMBER-GUIDE.md#checking-that-faro-is-working)).
- **`sudo /Library/Faro/bin/faro-service status`** (and `--json`), which shows whether monitoring is working, and **`faro-service diagnose`**, which makes a problem report ([section 5](#5-reporting-problems)).
- **On Windows,** run `& "C:\Program Files\Faro\faro-service.exe" status` in a terminal opened as administrator (in Command Prompt, leave out the leading `& `). A problem report is made the same way, with `diagnose` ([section 5](#5-reporting-problems)).
- **Logs** in `/Library/Logs/Faro/faro-service.log` (any administrator of the Mac can read it) and `~/Library/Logs/Faro/faro-agent.log` for each account ([Faro's logs](MEMBER-GUIDE.md#faros-logs)).
- **Logs on Windows:** `C:\ProgramData\Faro\logs\faro-service.log` (Administrators can read it) and `%LOCALAPPDATA%\Faro\Logs\faro-agent.log` for each account. Logs rotate at 5 MiB, and 3 old files are kept.
- **Signed updates** for the Mac app, the image model and the website list, through the instance ([2.3](#23-updates-for-members-computers)). On Windows, the service checks the project-signed update metadata first, as on a Mac, and then installs the signed MSI after checking its Authenticode signature and that its version is the expected, newer one.
- **Licences.** The notices for the software Faro is built from are in `/Library/Faro/notices/` on the Mac (**About Faro…** has a button that opens the folder), and on the **Licences** page (`/licenses`) of every instance's web app.
- **Admin changes are never silent.** Disabling or re-enabling an account is in the admin log and is emailed to the other admins, and the person and their allies are always told.

### What isn't built yet

- **Linux.** There is no package for it.
- **Windows on ARM.** Only x64 is supported for now.
- **Signed Windows packages.** No Windows release is published until a signing provider is chosen. Until then there are only unsigned development builds, which are not safe to use on anyone.
- **Passkeys.** Everyone signs in with an emailed link.
- **Web Push and phone notifications.** Alerts come by email only.
- **S3 storage.** Encrypted attachments are kept on the instance's own disk.
- **The browser extension.** Faro reads the website from the browser instead: through Accessibility on a Mac, and UI Automation on Windows. Neither can tell a private window from an ordinary one.
- **Pausing.** There is no way for a member to pause monitoring yet: neither the web app nor the menu has one.
- **An allowlist for apps that hide their windows.** Every third-party app that does it is reported by name ([4.3](#43-a-window-was-hidden-from-faro)).
- **A desktop app for allies.** Allies read their alerts in the instance's web app.
- **Sending a problem report from the menu.** **Report a problem…** explains how to make one in Terminal and copies the command; it doesn't make or send the report itself.
- **Allies' names on an iPhone.** An iPhone shows its allies by count and safety code until issue #169 adds their names.

---

## 2. For operators

### 2.1 Set up or upgrade the instance

Follow [SELF-HOSTING.md](SELF-HOSTING.md): what you need, the three ways to host it, the first admin account, email, `doctor`, backups and upgrading. Everything there applies to the beta.

**Get the `0.1.0-beta.1` server.** [Maintainer: how pilot operators get the `0.1.0-beta.1` server. A release tags the container image `ghcr.io/faro-project/faro-server:0.1.0-beta.1`, and the GitHub Release has the `faro-server` binaries, but the repository is private, so only its collaborators can download from it.] Until then, the development image `:main` from SELF-HOSTING.md is the latest code, which can be broken.

**Before every upgrade, make a backup** and copy it off the server ([section 9](SELF-HOSTING.md#9-backups-and-restore) and [section 10](SELF-HOSTING.md#10-upgrading) of SELF-HOSTING.md). Database changes only go forward: the only way back to an older version is restoring the backup you made before upgrading. Keep a copy of `faro.env` too, which isn't in the backup.

### 2.2 Choose the beta update channel

On the admin console's **Settings** page, under **Software updates**, choose **Beta** and save. (If that section says the server isn't passing on updates yet, set up the mirror first: [2.3](#23-updates-for-members-computers).) You can also set `FARO_UPDATES_CHANNEL=beta` in `faro.env`, or `channel = "beta"` in the `[updates]` section of `faro.toml`. A choice saved on the Settings page wins over the file.

On **Stable**, the default, members' computers on `0.1.0-beta.1` get no updates at all until `0.1.0` exists. **One release behind** has nothing to offer either.

### 2.3 Updates for members' computers

Members' computers get updates only through your instance, and only if its update mirror is on. It needs two settings ([Updates for members' computers](SELF-HOSTING.md#updates-for-members-computers)):

```sh
FARO_UPDATES_ROOT=/usr/share/faro/update-root.json   # the project's root of trust
FARO_UPDATES_UPSTREAM=https://updates.faro-project.org/   # updates.upstream in faro.toml
```

- The official image includes `update-root.json` once the project has made it (the key ceremony). An instance without the image downloads the file and points `FARO_UPDATES_ROOT` at it.
- Check your copy with `shasum -a 256 update-root.json` and compare it with **[Maintainer: the SHA-256 of `update-root.json` for `0.1.0-beta.1`]**.
- [Maintainer: confirm when `https://updates.faro-project.org/` serves `0.1.0-beta.1`. Until the first real release, nothing is published there, and the mirror has nothing to fetch.]

Your instance can't change an update: every computer checks the project's signature itself. A Mac checks your instance for updates about every 6 hours, and a Windows PC checks on the same schedule. On Windows, the project-signed update metadata is checked first, as on a Mac, and then the MSI's Authenticode signature and version.

### 2.4 What to watch in `faro-server doctor`

Run `faro-server doctor` after setting up, after every upgrade and whenever something seems wrong ([section 8](SELF-HOSTING.md#8-checking-your-instance-faro-server-doctor) of SELF-HOSTING.md). It only reads, never changes anything, and its output contains no secrets. For the beta, look at these lines:

| Line | What you want | If it says something else |
|---|---|---|
| `updates` | `[OK  ]` `release metadata version …` | `off: clients get no updates through this instance`: set the two settings in [2.3](#23-updates-for-members-computers). `no release mirrored yet`: the mirror hasn't fetched a release; check the upstream address and the log. `… has expired`: the latest refreshes failed, so Macs take no update until the next good one. |
| `smtp` | `[OK  ]` | Fix email first ([section 7](SELF-HOSTING.md#7-email-smtp) of SELF-HOSTING.md). Without email, nobody can sign in, allies get no alerts, and account deletions wait. |
| `deletions` | `no account deletions pending` | A `WARN` means a deletion has waited more than a week past its 7-day hold, almost always because email isn't getting through. |
| `database` | `sqlite reachable, schema up to date` | A `postgres` `WARN` line means you're on Postgres, which the beta doesn't support. |
| `disk` | plenty free | Make room before the next backup. |
| `backups` | (always the same) | `doctor` can't see your backups. Make sure the nightly backup runs and the copies leave the server. |

`doctor` doesn't show the update channel: check it on the **Settings** page. `faro-server updates status` shows when the instance last checked for a release and which files it holds.

### 2.5 Before you invite members

- **Read what you can and can't see** ([section 11](SELF-HOSTING.md#11-what-you-as-the-operator-can-and-cannot-see) of SELF-HOSTING.md), publish your own privacy notice ([template](operators/PRIVACY-NOTICE.md)), and read [what to do about apparently illegal material](operators/ILLEGAL-MATERIAL.md). Give that guide to your allies before anything happens.
- **Only people who choose Faro for themselves.** Don't enroll minors. Faro monitors **every account** on a Mac, including ones added later and the guest account. On Windows, it monitors every signed-in session of every account, including Remote Desktop. Everyone who logs in is told. So only install it on a member's own computer, never on a shared computer such as a lab or office Mac or PC that other people use without having chosen Faro.
- **Send your members and allies this guide,** especially [section 4](#4-known-limitations-and-false-alarms), so allies aren't alarmed by the alerts that setting up causes.
- **Make a second admin** ([More than one admin](SELF-HOSTING.md#more-than-one-admin)), so the instance doesn't depend on one person's email.

---

## 3. For members

The order that works best:

1. Accept the invitation to your instance and set up your keys ([3.3](#33-your-account-your-keys-and-your-allies)).
2. Invite your allies and approve them. Then they see everything from the start, including the alerts setting up causes, and they know what to expect ([section 4](#4-known-limitations-and-false-alarms)).
3. Download and install Faro ([3.1](#31-download-only-the-signed-package), [3.2](#32-install-it)).
4. Enroll the computer ([3.4](#34-enroll-the-computer)) and grant the permissions straight away ([3.5](#35-screen-recording-and-accessibility)).
5. Check that Faro is working ([3.6](#36-check-that-it-works)).

### 3.1 Download: only the signed package

Download Faro from **[Maintainer: download link for 0.1.0-beta.1]**.

**Only install a signed, notarized package from that link.** The Faro project also makes unsigned test packages for its own testing (their names end in `-dev.pkg`). They are not safe to use on anyone: an unsigned package's service accepts any program running in a logged-in account as its agent. If someone sends you a Faro package any other way, don't install it.

To check the package before you open it, run in Terminal (with the real file name):

```sh
pkgutil --check-signature ~/Downloads/Faro-0.1.0-beta.1.pkg
```

It must say the package is signed with a **Developer ID Installer** certificate and is **notarized** by Apple, and name **[Maintainer: the Developer ID name and Team ID pilots should see]**. If it says `no signature`, delete the file. The package's name has no `-dev` in it.

**On Windows,** the installer is `Faro-0.1.0-beta.1-x64.msi`. No Windows package is published yet, because the signing provider isn't chosen, so there is no Windows link for the beta. Don't install an unsigned build. To check the signature, right-click the MSI, choose **Properties**, then **Digital Signatures**. TODO(windows): the publisher name to expect, which depends on the signing provider.

### 3.2 Install it

Double-click the package and follow the installer. Faro installs for the whole Mac, so macOS asks for an administrator name and password. The installer's first page says what Faro does: read it, especially the part about every account being monitored. If the guest account is on, turn it off first (System Settings → Users & Groups).

After installing, the Faro icon is in the menu bar and its menu says **Status: Not enrolled**. Faro monitors nothing until you enroll the computer.

On Windows, the MSI installs Faro to `C:\Program Files\Faro` for the whole computer, so Windows asks for an administrator. The Faro Service starts by itself. The tray icon is in the notification area, and its menu also says **Status: Not enrolled**.

### 3.3 Your account, your keys and your allies

1. **Accept the invitation.** Your operator invites you by email. Open the link and sign in: Faro emails you a sign-in link (there is no password).
2. **Set up your keys** on the **Keys** page: choose a passphrase, click **Create my keys**, and save the recovery code the page shows once. Then sign your recipient list there (**Sign my recipient list**). Your computers can't start until you have.
3. **Invite your allies** on the **Allies** page: type their email address and click **Send invitation**. Each invitation works for 7 days. Send them the [ally guide](ALLY-GUIDE.md).
4. **Approve each ally** once they have accepted: compare the safety code with them in person or on a call, then approve them on the **Allies** page ([Comparing the safety code](ALLY-GUIDE.md#4-comparing-the-safety-code)). Allies only see what happened after you approved them.

### 3.4 Enroll the computer

Follow [Adding your Mac or Windows PC to Faro](MEMBER-GUIDE.md): create an enrollment code on the **Computers** page, open the link with **Open in Faro** (or **Enroll this computer…** in the Faro icon's menu), check the instance and the list of accounts, let an administrator approve in macOS's password dialog, then compare the code and approve the computer in the web app. Monitoring starts once you approve it.

On Windows, the link opens the running Faro Agent, and an administrator approves through the Windows UAC prompt. Cancelling the UAC prompt cancels enrolling. The enrollment preview and confirmation show the same content and button names as on a Mac, as ordinary Windows dialog windows: the accounts list, the guest-account warning, and the confirm button.

### 3.5 Screen Recording and Accessibility

**Screen Recording is required.** Without it Faro can't see the screen, and your allies are told. After you approve the computer, macOS asks every account on the Mac, once, to let **Faro Agent** record the screen. Allow it straight away: if captures keep failing for a few minutes (5 in a row), your allies get **"Screen Recording is off"**.

If you missed the question, or the menu says **Status: Screen Recording is off**: choose **Open Screen Recording Settings…** in the menu, or open System Settings → Privacy & Security → **Screen & System Audio Recording** (called **Screen Recording** on macOS 13 and 14), and switch on **Faro Agent**. If it is on already, select it, remove it with **−** and add it again (`/Library/Faro/Faro Agent.app`). [Maintainer: confirm whether Faro Agent needs a log out and in after Screen Recording is first switched on.]

**Accessibility is optional, but without it Faro can't tell which website a browser shows,** so the website categories don't work, and Faro doesn't see window titles. macOS never asks for it: switch it on yourself in System Settings → Privacy & Security → **Accessibility** (add **Faro Agent** if it isn't listed). While it is off, the menu shows **Monitoring** with a note about it and an **Open Accessibility Settings…** item. Turning it off after it was on sends your allies an urgent alert. Never turning it on sends nothing.

[Maintainer: whether recent versions of macOS ask again from time to time if Faro Agent may keep recording the screen, and what members should answer.]

**On Windows,** there is no Screen Recording or Accessibility permission, and Windows asks for nothing. Websites are read with no permission. The lock screen, UAC prompts and the Ctrl+Alt+Del screen can't be captured, so they are recorded as unavailable, not as tamper. Video with copy protection shows black in Faro's captures.

### 3.6 Check that it works

Click the Faro icon (the tray icon on Windows). **Status: Monitoring** means Faro is working. The [member guide's table](MEMBER-GUIDE.md#checking-that-faro-is-working) says what every other status means and what to do. For more detail, someone with an administrator password can run:

```sh
sudo /Library/Faro/bin/faro-service status
```

If it ever shows **`Thresholds: LOWERED FOR TESTING`**, the Mac has an unsigned test package, which flags ordinary screens on purpose. Uninstall it and install the signed package ([3.1](#31-download-only-the-signed-package)). A signed package ignores those test settings.

### 3.7 Pausing

You can't pause monitoring in the beta. The menu can say **Paused until …**, but nothing in the beta starts a pause yet. If you need Faro off for a while, the honest way is to tell your allies first: anything that stops Faro reaches them as an alert.

### 3.8 Uninstalling

In Terminal, with an administrator password:

```sh
sudo /Library/Faro/bin/faro-uninstall
```

It tells your allies first, with an urgent **"Faro stopped on a computer"** ("Faro was uninstalled from this computer"), then removes Faro, its settings and its logs. If your instance can't be reached, it removes nothing, so that allies aren't left in the dark: try again when the Mac is online. `--force` removes Faro anyway, and allies then see a missed check-in instead.

On Windows, uninstall in **Settings → Apps**, or run `msiexec /x` with the MSI. Faro tells the allies first. If the instance can't be reached, it still uninstalls, but then it can't tell them.

To stop a computer reporting without uninstalling, remove it on the **Computers** page (**Remove…**). Your allies get an urgent alert that a computer was removed. Uninstall Faro on it afterwards, too.

### 3.9 On an iPhone

The iPhone app blocks adult websites and apps on the phone. It doesn't watch the screen. The steps are in [Adding your iPhone](MEMBER-GUIDE.md#adding-your-iphone). Before you start:

- **Get the app through TestFlight.** In the beta the iPhone app comes through Apple's TestFlight, not the App Store. [Maintainer: confirm how pilot members are invited to TestFlight, and by whom.]
- **The phone needs iOS 17 or later.**
- **Setup asks for Screen Time and the VPN,** and can't be finished without them. Turning either one off later is reported to your allies.
- **The version is 0.1.0.** The iPhone app doesn't carry the `-beta.1` suffix of the Mac and Windows builds. [Maintainer: confirm the version and build number that TestFlight shows.]
- **To remove Faro,** use **Leave Faro** in its Settings ([Leaving Faro](MEMBER-GUIDE.md#9-leaving-faro)). You can't delete the app while Faro protects itself.

---

## 4. Known limitations and false alarms

**For allies, members and operators.** Faro is new, and in the beta some alerts will have innocent causes, especially while someone is setting up. This section says which ones to expect. It doesn't make any alert meaningless: when one arrives, ask ([Having the conversation](ALLY-GUIDE.md#9-having-the-conversation)). The [ally guide's alert table](ALLY-GUIDE.md#tamper-alerts) says what every alert means.

### 4.1 Alerts you may see while a member is setting up

| What happens on the Mac | What allies may see | Is it expected? |
|---|---|---|
| The computer is approved, but Screen Recording isn't allowed yet in the account being used | After about 5 failed captures (a few minutes): **Possible tampering**, which unlocks to **"Screen Recording is off on *computer*"**, saying Faro doesn't have the permission on this computer | Yes, if the member was slow to allow it. It should stop once they do ([3.5](#35-screen-recording-and-accessibility)). |
| Faro is reinstalled, or a new test package installed | **"Screen Recording is off"**, because the reinstall dropped the permission even though System Settings may still show Faro Agent switched on | Yes for unsigned test packages: **every** reinstall of one drops the permission. The fix is to remove Faro Agent with **−** in System Settings and add it again. [Maintainer: confirm whether an update from one signed package to the next keeps the permission.] |
| Faro is reinstalled or updated | **Computer shut down** and **Computer started** (not urgent): installing stops Faro and starts it again | Yes. |
| A second account on the Mac logs in for the first time | **"Screen Recording is off"** for that account, until that account allows it too. Every account is asked once. | Yes, on a Mac with several accounts. |
| Someone uses an account in which Faro Agent isn't running, for more than about 90 seconds | **Possible tampering**: "Someone used the account *name* while Faro wasn't running in it." | Rarely innocent. If Faro Agent didn't start after an install, logging out and in again starts it. |
| Faro Agent stops and starts again in the same account | **Faro kept restarting** (normal; allies can switch it off) | Once in a while, yes. **Three times within 10 minutes** becomes **Possible tampering**: "Faro was stopped 3 times in 10 minutes." |
| Faro Agent is running, but Faro takes no screenshot for about 5 minutes while the Mac is in use | **Possible tampering**: "Faro couldn't see the screen 5 times in a row." | It shouldn't happen. A locked screen, sleep, idle time and logging out don't count. But that has only been tested with simulated events, not on a real Mac (see [4.4](#44-not-yet-tested-on-real-macs)), so a false alarm here is possible: please report it. |
| Screenshots keep failing (5 in a row) for any other reason | The same **"Faro couldn't see the screen … times in a row"** | Worth a problem report ([section 5](#5-reporting-problems)). |
| Accessibility is switched off after being on | **Possible tampering**: "A permission Faro needs was turned off (accessibility)." | Sometimes innocent (a macOS update can switch permissions off), but ask. |
| The Mac restarts, sleeps or is switched off | Nothing urgent. If it stays offline longer than the instance allows (3 hours unless the admin changed it): **"*Computer* stopped checking in"**, then **"*Computer* is back online"** | Yes: a closed laptop is the usual reason ([Missed check-ins](ALLY-GUIDE.md#missed-check-ins)). |
| The instance itself is down | Nothing is blamed on the member. Faro keeps what it records and sends it later. | Yes. |
| A file in Faro's installed folder is removed or changed (the image model or the website list) | **Possible tampering**: "A part of Faro was changed or damaged (domain list (missing))", or `image model (missing)` and similar | Not from setting up. Reinstalling the signed package puts the files back. |
| A VPN is on, including iCloud Private Relay, Tailscale and work VPNs | Not an alert: the daily report's **Health** may say "A VPN was on." | Yes: many ordinary tools look like a VPN to Faro. |

### 4.2 What Faro doesn't flag

- **Ordinary swimwear and other suggestive images aren't flagged.** The image model (OpenNSFW) has no "suggestive" output, only explicit or not. It rates an ordinary swimwear photo about 0.06 to 0.15, and Faro only counts a screen as low at 0.40 and flags it at 0.60. That is deliberate, but it means Faro is mostly blind to suggestive content.
- **It makes mistakes the other way too.** Faro decides on the Mac, by itself, and a flag is a reason to ask, not a verdict. How the screenshot is prepared for the model is still being decided by the project, so the image checks may change during the beta, through an update.
- **Websites only with Accessibility, and only in Safari, Chrome, Edge, Brave and Arc.** In Firefox or any other browser, or without Accessibility ([3.5](#35-screen-recording-and-accessibility)), Faro doesn't know which website is open and judges by the screen alone. Private windows can't be told apart from ordinary ones. On Windows, the browsers are listed in [4.5](#45-on-windows).
- **Adult sites are flagged; gambling sites are counted.** A site on the adult list is flagged as medium (high if the screen also looks explicit). A gambling site is rated low, which only shows in the daily report's counts.
- **Faro looks at screenshots now and then, not all the time.** What it doesn't happen to catch isn't reported.

### 4.3 "A window was hidden from Faro"

Any app can keep a window out of screenshots and screen recordings. Faro then can't see what it shows, so when a large window of an app does this, allies get **Possible tampering**, which unlocks to **"A window was hidden from Faro on *computer*"**, naming the app (never the window's title).

**In the beta, legitimate apps will set this off.** There is no list of trusted third-party apps yet, so every app that hides a window is reported by name. Expect it from:

- **password managers;**
- **Zoom or Teams while sharing the screen;**
- **video players with copy protection.**

Only macOS's own windows (password and Touch ID prompts, the screenshot toolbar, the lock screen) are left out, and thin strips such as toolbars and call controls don't count. Each app is reported once, and again only after it has had no hidden window for a while.

So when an alert names a password manager or a video-call app, the member was probably using it. A browser, an image viewer or an app you don't recognize deserves a question. A member who doesn't need the window can close it, or turn off the app's setting that hides its windows from screen sharing, if it has one.

On Windows, the same applies to windows excluded from capture: Faro reports the app by name, with the same kind of alert. Windows' own programs in `System32` and `SystemApps` are allowed, except script hosts ([4.5](#45-on-windows)).

### 4.4 Not yet tested on real Macs

The Faro project tests a lot automatically, but some things can only be checked by a person on a real Mac, and these haven't been yet. If any of them goes wrong for you, please send a problem report ([section 5](#5-reporting-problems)).

- **Enrolling:** macOS's administrator dialog itself (its wording, the app name it shows), whether clicking **Open in Faro** reaches the running Faro Agent, and the enrollment windows' layout. If clicking the link does nothing, use **Enroll this computer…** in the menu. If Faro says "This computer can't be enrolled from here", an administrator can enroll it in Terminal ([the member guide](MEMBER-GUIDE.md#if-something-goes-wrong)).
- **The status menu:** none of it has run on a real Mac yet. Times are shown in 24-hour format whatever the Mac's setting. **Can't reach *your instance*** shows from the first failed check-in, so a short network blip can show it briefly.
- **The "Screen Recording is off" notice** on the Mac, and its **Open System Settings** button (on macOS 13 and 14 the setting is called Screen Recording).
- **The "couldn't see the screen" check** with a real locked screen, display sleep, fast user switching and Power Nap, which may cause a false alarm ([4.1](#41-alerts-you-may-see-while-a-member-is-setting-up)).
- **Hidden windows:** which of macOS's own windows read as hidden (a false alarm naming a part of macOS is possible), and which common apps hide windows large enough to be reported ([4.3](#43-a-window-was-hidden-from-faro)).
- **Website list:** that the installed Faro loads the list the package includes, and the alert when it is missing.
- **`faro-service status`** on an installed Mac. Right after the Mac wakes, it can look out of date for up to 30 seconds.
- **`faro-service diagnose`** with `sudo` on an installed Mac, including writing to the Desktop ([section 5](#5-reporting-problems)).
- **The log files** written by the installed Faro, rotation, and the logs showing in the Console app. If Faro Agent's log is missing, its output went nowhere: say so in your report.
- **The uninstaller** on a real Mac.
- **Older Macs and Intel:** macOS 13.0 to 13.2 hasn't been tried, and Intel Macs have only been checked by the project's automated tests.

### 4.5 On Windows

The same kinds of alert apply to a Windows PC, with these differences.

- **Tamper alerts.** The service stopped (its check-ins stop, so allies get a missed check-in alert), an agent is killed, the clock is changed, or Faro's program files are made writable by someone who isn't an administrator. A VPN is not an alert, as on a Mac: the daily report's **Health** may mention it ([4.1](#41-alerts-you-may-see-while-a-member-is-setting-up)). A virtual machine is treated the same as on a Mac.
- **Hidden windows.** A window excluded from capture is reported by app name, as on a Mac ([4.3](#43-a-window-was-hidden-from-faro)). Windows' own programs in `System32` and `SystemApps` are allowed, except script hosts.
- **The lock screen.** The lock screen, UAC prompts and the Ctrl+Alt+Del screen can't be captured. They are recorded as unavailable, not as tamper. Video with copy protection shows black.
- **Some sessions.** Some Remote Desktop sessions and VMs use the GDI fallback for capture.
- **Websites.** Faro reads the address bar of Edge, Chrome, Brave, Firefox, LibreWolf, Waterfox, Zen and Floorp. Only `scheme://host/` leaves the computer. Private windows can't be told apart, and Chrome hides `http://`, so a plain-http site shows as https (the host is right). Browsers are recognized by their program's file name, so a renamed copy of a browser is judged by the screen alone, as an unknown app.
- **The notice.** The monitoring notice at sign-in is a window, not a notification, because Focus Assist and full-screen apps silently drop notifications.
- **Not yet tested on a real Windows PC:** several monitors; Remote Desktop sessions; fast user switching; the lock screen and UAC screen being recorded as unavailable; Brave, Waterfox, Zen and Floorp; a real VPN or virtual machine; signed builds and updates; the image model. As on a Mac ([4.4](#44-not-yet-tested-on-real-macs)), please report anything that goes wrong.

### 4.6 On an iPhone

The alerts an iPhone can send, and what to say about each, are in the [ally guide's section 10](ALLY-GUIDE.md#10-if-the-member-uses-an-iphone). These are the limits to expect in the beta:

- **It blocks; it doesn't watch.** There are no screen checks, no pictures and no image model. Allies see blocked lookups by category and host, and how often a blocked app was opened, never which app.
- **Some sites get around the DNS filter.** Sites reached through some private DNS services or apps aren't blocked. Sites reached by IP address, or on brand-new domains, aren't covered by the DNS filter either. Apple's filter still covers adult sites in Safari and other web views.
- **For a moment after a network change, lookups aren't filtered.** Faro needs to read the network's DNS servers, which takes well under a second each time the network changes. Lookups in that moment go unfiltered.
- **One VPN at a time.** Another VPN takes over, and Faro reports it as **Another VPN took over**.
- **Bursts may be noise.** A burst of blocked lookups is flagged from its count and timing. Adverts and link previews can cause one, and the thresholds are set from beta data.
- **Silence looks like a missed check-in.** A phone that is asleep, switched off or out of signal is reported as **stopped checking in** until it reconnects. The grace period for phones is the same as for computers, for now. [Maintainer: confirm after the beta shows how long phones sleep (IOS.md §19).]
- **Offline removal is invisible at once.** If a member turns off Screen Time access and deletes the app without a connection, the alert never leaves the phone. Allies get a missed check-in instead.
- **Expected alerts while you test.** Turning off the VPN, Connect On Demand or Screen Time to test them sends the alerts in the ally guide. Tell your allies first, so these don't come as a surprise.
- **Problem reports from an iPhone.** The report in [section 5](#5-reporting-problems) is made on a Mac or PC. [Maintainer: say how an iPhone member sends a problem report.]
- **Before the pilot.** [Maintainer: confirm that the spikes S1 to S8 in [IOS.md §17](IOS.md#17-spikes-what-to-confirm-on-a-device-first) have been answered on real phones.]

---

## 5. Reporting problems

When something doesn't work, make a **problem report** on the Mac. Someone with an administrator password runs this in Terminal, from the member's own account:

```sh
sudo /Library/Faro/bin/faro-service diagnose
```

It lists what it will put in the report and writes nothing until you agree: **s** shows everything, **y** writes it, anything else stops. The report is a zip on the Desktop, `faro-report-`*date*`-`*time*`Z.zip`, that only your account can open. Web addresses, email addresses, other computers' and websites' names, window titles and app names are taken out. It never contains keys, passwords, screenshots, or what Faro reported. **Report a problem…** in the Faro icon's menu shows the same steps and copies the command. The details are in [Reporting a problem](MEMBER-GUIDE.md#reporting-a-problem) and, for the technically minded, [Problem reports](DEVELOPMENT.md#problem-reports).

- If macOS asks whether Terminal may access the Desktop, allow it, or save the report elsewhere: `sudo /Library/Faro/bin/faro-service diagnose --output ~/Documents`.
- Read it before you send it, if you like: it is a folder of plain-text files.

On Windows, run `& "C:\Program Files\Faro\faro-service.exe" diagnose` in a terminal opened as administrator, and approve the administrator prompt. Faro lists what is in the report before it writes anything: **s** reads all of it, **y** writes it, **n** stops. The file is saved on your Desktop as `faro-report-….zip`; `--output <folder>` saves it elsewhere. The tray menu's **Report a problem…** explains this and copies the command. The report holds the same kind of content as on a Mac, with private details removed: status, versions, the service state, sessions and agents, and recent service and agent logs.

Send the zip to **[Maintainer: where to send problem reports]**, with a few words on what went wrong and when.

**Operators:** for a problem with the instance itself, send the output of `faro-server doctor` and the relevant log lines ([Troubleshooting](SELF-HOSTING.md#13-troubleshooting)). Never send `faro.env`, `identity.key`, backup files, setup tokens or sign-in links.

**Allies:** if an alert puzzles you, ask the member first. If something in the web app doesn't work, tell your operator.

---

## 6. Leaving the beta

### A member leaving

1. **Tell your allies** first, so the alerts don't come as a surprise.
2. **Uninstall Faro on each computer** ([3.8](#38-uninstalling)). Allies get "Faro was uninstalled". Problem reports you saved on the Desktop are your own files: Faro doesn't remove them.
3. **Delete your account** in the web app: **Settings**, then **Delete your account** at the bottom. Your allies are emailed straight away. For 7 days nothing else changes and you can cancel. After that, once everyone has been told, the instance removes everything about you.

If you delete your account without uninstalling, your computers keep being monitored until the 7 days are up; after that the instance refuses them, and they report nothing more. Uninstall Faro on them anyway.

On an iPhone, there is no uninstall step for Faro itself. Use **Leave Faro** in Faro's Settings instead. It tells your allies first, then turns Faro off, and then you delete the app ([Leaving Faro](MEMBER-GUIDE.md#9-leaving-faro)). Step 3 still applies.

### An ally leaving

Use **Stop being *name*'s ally…** on the member's page, or delete your own account in **Settings** ([If you want to stop being an ally](ALLY-GUIDE.md#7-if-you-want-to-stop-being-an-ally)). The member and their other allies are told.

### What the operator keeps

Once a deleted account is removed, the instance keeps:

- **its backups,** which still hold the account until they are rotated out. Keep backups no longer than your retention period, and tell the person when the last one is gone ([Deleting someone's account](SELF-HOSTING.md#deleting-someones-account)). Restoring an older backup brings the account back;
- **the admin log,** whose entries Faro never removes, with the person's name taken out;
- **a hash of each of their computers' tokens,** so that a computer still running Faro is told the account is gone instead of being accepted.

The operator never had the person's reports, screenshots or keys: those were encrypted on the Mac for the member and their allies only.
