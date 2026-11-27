# Adding your Mac or Windows PC to Faro

**Who this is for:** a **member**: someone who chose to use Faro on their own computer. You need your Faro web app, the computer, and someone who knows an administrator name and password for it. That can be you.

If you use an iPhone, read the last section, [Adding your iPhone](#adding-your-iphone). It works differently from the computer steps. There is no Android app in the beta.

Two words you'll see: your **instance** is the Faro server your account lives on, run by a church, a college, a small group or one person, and its name is at the top of each page. Your **member key** is the key that Faro makes for you in the web app: it approves your allies and your computers, and nobody else can use it.

If someone made you install Faro, read [If this wasn't your choice](#if-this-wasnt-your-choice) first.

## What your allies see

Once an ally is approved, they can read what your computer reports, in their web browser, after they type their own passphrase. They see:

- **Flagged moments.** When Faro rates what is on your screen as worth a look, your allies see how it was rated and why, the app you were in, the window's title, the website (only the site's name, such as `https://example.com/`, never the page or anything you typed), and the name of the computer account you were using. You can add a note to a flag.
- **A blurred picture** for each flagged moment. It is blurred heavily on your computer before anything is saved or sent, and the clear picture is thrown away. Nobody can un-blur it.
- **A daily report.** A bar for the day showing when the computer was in use, idle, locked, asleep, paused or off, with the account used, and any time it wasn't monitored. It also counts the screen checks that were clean, low, medium or high, and says if anything went wrong. **Most used apps** and **Most visited sites** are in it only if you chose to share them. They are off unless you switched them on.
- **Alerts** when Faro is switched off, interfered with, stops checking in, is uninstalled, a computer is removed, your settings change, or you delete your account.

They don't see everyday screen checks that found nothing, one by one, only the counts. They see nothing from before you approved them. You see exactly what they see, on your own **Activity** page. The people who run your instance see only that something happened and when, not what it was ([the ally guide](ALLY-GUIDE.md#8-what-the-people-running-the-server-can-and-cant-see) says more).

## What other people who use this computer see

Faro monitors **every account** on the computer, including ones added later and the guest account. There is no way to leave one out. Everyone who uses the computer sees:

- **The Faro icon**: in the menu bar on a Mac, in the notification area on Windows. Its menu says what Faro is doing. Nothing on its menu switches Faro off or hides it.
- **A notice when they sign in**, saying that the computer is monitored by Faro for a member of your instance (it names the instance, not you), that screenshots are blurred and shared only with the member and their allies, and how many allies there are. It doesn't name you or your allies, and says that switching to another account doesn't turn monitoring off.

If other people use the computer, tell them before you install Faro. Only install it on a computer that is yours, not on a shared one such as a lab or office computer.

## The web app and your passphrase

The web page you use to unlock your keys comes from your instance. If the person running it changed that page on purpose, they could in principle capture your passphrase. For you that matters more than for an ally, because your member key approves your allies and your computers, so someone with it could add themselves as an ally or approve a computer you didn't enroll. So use an instance run by someone you trust. **What this instance can see**, at the bottom of every Faro page, says what its operator can and can't see. A separate app for members and allies, which wouldn't depend on the server for this, is planned.

## If this wasn't your choice

Faro is for people who choose it for themselves. If someone pressured you to install it, you are using it because you were made to, or you no longer want it and are afraid to say so, this is for you.

- **What Faro is.** It looks at your screen on this computer, checks what it finds there, and sends the allies you chose a report with blurred pictures. It tells them if it is switched off or tampered with. The people who run your instance can't see your reports.
- **Everyone who uses the computer is told.** See [what other people who use this computer see](#what-other-people-who-use-this-computer-see).
- **There is no quiet way out.** Every exit tells your allies first. Faro can't hide that, and that is by design. If leaving openly isn't safe for you, your safety comes first: talk to someone you trust, or, in an emergency, the emergency services.
- **Two ways out need no administrator password:**
  - **Computers → Remove…** in the web app. The computer stops reporting at once. Your allies get an urgent alert that a computer was removed. Faro stays installed on that computer until an administrator uninstalls it, but it sends nothing more.
  - **Settings → Delete your account** in the web app. You need to have signed in within the last 10 minutes and you type your email address to confirm. Your allies are emailed straight away. For 7 days nothing else changes: the computer is still monitored and you can cancel. After that, everything about you is removed from the instance and it stops accepting your computers.
- **Uninstalling Faro needs an administrator's name and password** on the computer, on a Mac and on Windows. If someone else keeps that password, you can't uninstall it yourself. The two exits above still work. Don't hand anyone the password to hold if that would leave you unable to leave: [the ally guide](ALLY-GUIDE.md#an-ally-holding-the-administrator-password) tells allies the same.
- **Your allies are told in every case**: uninstalling, removing a computer, and deleting your account.

If you can't use the web app, the person who runs your instance can start the account deletion for you, with the same 7 days and the same notices.

## Before you start

- **In the closed beta,** read [BETA.md](BETA.md) first: where to download Faro, the permissions to grant, and the alerts your allies may see while you set up.
- **Faro is installed** on the computer, from the official installer. After installing, the Faro icon is in the menu bar on a Mac (a lighthouse) or in the notification area on Windows (the tray icon). Faro monitors nothing until you finish the steps below.
- **Your member key is set up** in the web app: on Home, choose **Set up keys**. Read [If you lose your passphrase and recovery code](#if-you-lose-your-passphrase-and-recovery-code) first, because Faro can't create your member key a second time.

## 1. Get an enrollment link

1. In your Faro web app, open **Computers** and click **Add a computer**.
2. Unlock your key if the page asks.
3. Click **Create an enrollment code**. The page shows a code, and an enrollment link that starts with `faro://enroll`. They work once, for 10 minutes.

## 2. Open the link on your computer

- **If the web app is open on the Mac:** click **Open in Faro**.
- **On Windows:** click the link in the web app. It opens the running Faro Agent.
- **If it is open on another device** (a phone, say): click **Copy link** and send the link to the Mac, for example by email to yourself. On the Mac, click the Faro icon in the menu bar, choose **Enroll this computer…**, paste the link into the first field and click **Continue**. You can also type your Faro address in the first field and the code in the second. On Windows, the tray icon's menu has the same **Enroll this computer…** item.

## 3. Check and confirm

Faro shows a window titled **"Enroll this computer with *name*?"**. Check:

- The **name** and **address** are your Faro instance. If you don't recognize them, click **Cancel**.
- The list of **accounts**. Faro monitors every account on this Mac, including ones added later. If the guest account is on, Faro says so: anyone could use the Mac without a password, so consider turning it off in System Settings > Users & Groups.

On Windows, the preview and confirmation windows show the same content and button names as on a Mac, as ordinary Windows dialog windows: the name and address, the list of accounts, the guest-account warning, and the **Enroll** button.

Click **Enroll**.

## 4. An administrator approves

macOS asks for an **administrator's name and password**. This is macOS's own window, and it names your Faro instance. Faro only enrolls the Mac if an administrator approves here. If you are not an administrator of this Mac, ask someone who is to type theirs.

On Windows, the administrator approves through the Windows UAC prompt instead, and cancelling that prompt cancels enrolling.

## 5. Compare the code and approve in the web app

Faro shows **"This computer is enrolled"** with a code of 16 letters and numbers.

1. In the web app, the new computer appears on the **Computers** page as waiting.
2. Check that the web app shows **the same code** for it. Approve it only if it does.
3. If Faro also shows a **member key** to check, compare it with the member key on your **Settings** page. If they differ, don't approve, and remove the computer.

Monitoring starts once you approve. The first time, macOS asks every account on the Mac to let **Faro Agent** record the screen. Windows asks for no such permission ([BETA.md](BETA.md#35-screen-recording-and-accessibility)).

## If something goes wrong

| Faro says | What to do |
|---|---|
| The code didn't work | Each code works once and expires after 10 minutes. Create a new one and start again. |
| Faro can't reach your instance | Check that the Mac is online and the address is right. |
| Not approved | Nothing changed. Try again when an administrator can type their password. |
| Enrollment stopped to keep you safe | The instance answered with a key that doesn't match your link. Don't continue. Remove the new computer in the web app if it appears there, and tell whoever runs your instance. |
| This computer can't be enrolled from here | An administrator can enroll it in Terminal instead: `sudo /Library/Faro/bin/faro-service enroll --link '…'` with your link. On Windows, an administrator can run `& "C:\Program Files\Faro\faro-service.exe" enroll --link '…'` in a terminal opened as administrator, with your link. |
| Faro can't see one of your windows | An app (it names it) keeps a window out of screenshots and screen recordings, so Faro can't check it, and your allies are told which app. Close the window if you don't need it, or turn off the app's setting that hides its windows from screen sharing, if it has one. |
| Nothing happens when you click the link | Restart the computer, or log out and in again, and try again. If it still doesn't open, use **Enroll this computer…** from the Faro icon (in the menu bar on a Mac, the tray icon on Windows) and paste the link. |

### Faro's logs

If something doesn't work and you want to see why, or someone helping you asks for the logs, Faro keeps them on the computer:

- **The service:** `/Library/Logs/Faro/faro-service.log`. Any administrator of the Mac can read it.
- **The menu-bar agent, for each account:** `~/Library/Logs/Faro/faro-agent.log`, readable only by that account.
- **On Windows, the service:** `C:\ProgramData\Faro\logs\faro-service.log`. Administrators can read it.
- **On Windows, the agent, for each account:** `%LOCALAPPDATA%\Faro\Logs\faro-agent.log`.

Open them in the Console app (under **Log Reports**), or follow them in Terminal with `tail -F /Library/Logs/Faro/faro-service.log`. Older entries are in the same folder, in files ending `.1`, `.2` and `.3`. On Windows, a log file is replaced by a new one when it reaches about 5 megabytes, and 3 old files are kept. At their usual level, the logs never contain the web addresses or window titles Faro sees, or anything from your screen.

## Checking that Faro is working

Click the Faro icon in the menu bar (the tray icon in the notification area on Windows). The line under **This computer is monitored by Faro** says what Faro is doing. Click it to see what it means and what to do; when something can fix it, an item just below opens it.

| The menu says | What to do |
|---|---|
| **Status: Monitoring** | Nothing: Faro is working. |
| **Status: Paused until** *time* | Nothing. Your allies were told about the pause, and monitoring starts again by itself. |
| **Status: Not enrolled** | Faro monitors nothing yet. Follow the steps at the top of this guide. |
| **Status: Waiting for approval in the web app** | Choose **Open the Computers Page…**, check the code, and approve the computer ([step 5](#5-compare-the-code-and-approve-in-the-web-app)). |
| **Status: Connecting to the Faro service…** | Wait a minute. If it stays, log out and in again, or restart the Mac. |
| **Status: Screen Recording is off** (Mac only) | Choose **Open Screen Recording Settings…** and switch on **Faro Agent**. If it is on already (after reinstalling Faro, for example), select it, remove it with **−** and add it again. Your allies are told while it is off. |
| **Status: Can't reach** *your instance* | Check that the Mac is online. Faro keeps what it records and sends it once your instance answers. |
| **Status: Faro can't take screenshots** | Restart the Mac. If it still says so, tell whoever runs your instance. |
| **Status: Faro stopped sending to** *your instance* | Your instance no longer has the identity this Mac was enrolled with. Tell whoever runs your instance. |
| **Status: The Faro service isn't running** | Restart the Mac. If it still says so, tell whoever runs your instance. |

The menu also has **Open Faro** (your Faro web app), **Report a problem…** ([Reporting a problem](#reporting-a-problem)) and **About Faro…** (the versions, your instance, and the licences of the software Faro includes). Nothing on the menu turns Faro off, pauses it or hides anything. On Windows there is no Exit item either.

For more detail, someone who knows an administrator password can check in Terminal:

```sh
sudo /Library/Faro/bin/faro-service status
```

It shows what Faro is doing, never what was on the screen. The lines to look at:

| It says | What it means |
|---|---|
| **Service:** not running | Faro's service has stopped. Restart the Mac. If it still says so, tell whoever runs your instance; the **Log** line names the file that says why ([Faro's logs](#faros-logs)). |
| **Capture:** active | Faro is working. `paused` because the screen is locked, the Mac is asleep or nobody is using it is normal too. |
| **Capture:** none: the agent of *account* is not connected | Faro Agent isn't running in that account. Log out of it and in again. Your allies are told if this lasts. |
| **Permissions:** Screen Recording denied, or **Failures:** permission denied: screen_recording | Open System Settings > Privacy & Security > Screen Recording (Screen & System Audio Recording on newer macOS) in that account and turn on **Faro Agent**. |
| **Image model:** none | Faro can't check images on this Mac and rates the screen from the apps and websites in use only. Reinstall Faro, and tell whoever runs your instance if it stays. |
| **Updates:** last check … failed | Faro couldn't check for updates. It tries again later; if it keeps failing, tell whoever runs your instance. |

On Windows, run `& "C:\Program Files\Faro\faro-service.exe" status` in a terminal opened as administrator. It shows the same details.

## If you lose your passphrase and recovery code

Your passphrase and your recovery code are the only two things that unlock your member key. Faro can't reset either, and neither can the people who run your instance.

- **Lost only one?** You're fine. Unlock with the other, then open **Settings**, under **Your keys**. **Change my passphrase…** sets a new passphrase, and **Get a new recovery code…** replaces the recovery code (the old one stops working, and the new one is shown once, so save it). On an unlock screen, **Forgot it? Use the recovery code** unlocks with the recovery code.
- **Lost both?** Faro can't get your key back, and it can't create your member keys again: the web app refuses, saying your keys are already set up. The only way forward is to delete your account and start again:
  1. Tell your allies, so it isn't a surprise.
  2. Open **Settings**, choose **Delete your account** at the bottom, and follow the steps. It waits 7 days. Your allies are emailed straight away.
  3. After 7 days your account is deleted, including your reports, keys and allies. From then on the instance refuses your computers, so uninstall Faro on each ([a new, replaced, wiped or lost computer](#a-new-replaced-wiped-or-lost-computer)).
  4. Sign up again with the same address, if your instance allows it, set up new keys, and invite your allies again. They see only what happens after they approve you again. What was sent before can't be read by anyone any more.
- **In those 7 days** your computers keep reporting to the allies you had approved, and your allies keep seeing alerts. You can't approve new allies or computers, and you can't add a computer, without your key.

## A new, replaced, wiped or lost computer

Every computer has its own enrollment. Your allies are told about each change.

- **A new computer.** Install Faro on it and enroll it ([step 1](#1-get-an-enrollment-link)). You need your key unlocked to make the enrollment code. Approve it in the web app after comparing the code.
- **A replaced computer you still have.** Uninstall Faro on the old one first ([BETA.md](BETA.md#38-uninstalling) has the command). Your allies are told **"Faro stopped on a computer"**, which is expected. Then enroll the new one. If the old one can't be reached, remove it in the web app instead (below).
- **A wiped or reinstalled computer.** Faro is gone from it, and it can't tell your allies. They will see **"*Computer* stopped checking in"** after a few hours. Remove the old entry on the **Computers** page (**Remove…**; your allies get **"*Computer* was removed"**), then install Faro and enroll again with a new code. A computer where Faro is still installed says it is already enrolled, and won't enroll again until Faro is uninstalled.
- **A lost or stolen computer.** Open **Computers** and choose **Remove…** for it. Its key stops working on the instance, so it can't report. Tell your allies why, so the alerts don't alarm them.

## Groups

A **group** is a place for people doing this together, such as a recovery group or a small group at church. Groups are in the web app under **Groups**. Being in one shares nothing about your Mac or your reports, and nobody in a group sees them.

- **Joining and leaving.** Accept an invitation from its email, or from **Look at it** under **Invitations** on the **Groups** page, then choose **Join this group**. To leave, open the group, choose **Leave group…**, then **Leave group**. Your alliances stay as they are.
- **Asking someone to be your ally.** In a group's **People** list, choose **Ally…** next to a person. Then choose **Ask to be my ally**, **Offer to be their ally** or **Partner up**. A proposal is only a question. Nothing becomes active until you both compare safety codes and the link is approved on your **Allies** page, as in [the ally guide](ALLY-GUIDE.md#4-comparing-the-safety-code).
- **Stopping proposals from someone.** Under **Ally…**, choose **Don't let them send me proposals**. They aren't told.
- **Answering proposals.** Proposals to you, and safety codes to compare, are under **Waiting for you** on the group's page. If you say no, the other person is never told that you did.
- **Meetings.** A facilitator can set a meeting day, time and place. Under **Meeting**, tick **Remind me before each meeting**, and **Also email me** if you want the reminder by email. In a large group, email reminders start switched off. A reminder email says only that your group meets. It never names the group.
- **Finding a group.** Choose **Find a group** on the **Groups** page and search by name. You can ask to join a listed group, and its facilitators decide. A group doesn't say why it said no.
- **Facilitating.** A group has at least one facilitator. Facilitators can edit the group, invite people, remove people and close it, on the **Manage** tab. They can't see anyone's reports or alerts.

## Reporting a problem

If Faro isn't working and you'd like help, make a **problem report**: one file with what Faro is doing on your Mac and its recent logs, with private details taken out. Someone who knows an administrator password runs, in Terminal, from your account:

```sh
sudo /Library/Faro/bin/faro-service diagnose
```

**Report a problem…** in the Faro icon's menu shows these steps too, and its **Copy Command** button puts that line on the clipboard, ready to paste into Terminal.

1. Faro gathers the report and lists the files in it, with what each one is. Nothing is written yet.
2. Type **s** to read everything in it first, **y** to write it, or **n** to stop.
3. It writes **`faro-report-`*date*`-`*time*`Z.zip`** to your **Desktop** (for example `faro-report-20261125-101500Z.zip`; the time is in UTC). The file is yours, and only your account can open it.
4. Send that file to **[TO FILL IN: where to send problem reports]**. Say what went wrong and when.

The zip holds one folder of plain-text files, so you can open any of them before you send it:

| File | What it says |
|---|---|
| `README.txt` | what the report is and when it was made |
| `status.txt`, `status.json` | what `faro-service status` shows ([Checking that Faro is working](#checking-that-faro-is-working)) |
| `permissions.txt` | whether Faro Agent may record the screen |
| `system.txt` | the versions of Faro and macOS, the Mac's model, and free disk space |
| `launchd.txt` | whether Faro's service and agent are running, and how often they restarted |
| `package.txt` | which Faro package is installed, and its signatures |
| `files.txt` | the names, sizes and permissions of Faro's files, never what is in them |
| `config.txt` | Faro's settings on this Mac |
| `logs/faro-service.log`, `logs/faro-agent.log` | the last 2000 lines of the service's log and of **your** account's agent log ([Faro's logs](#faros-logs)) |
| `logs/update-install.log` | if Faro has updated itself, what the installer said |

**Taken out of every file:** web addresses, email addresses, and the names and addresses of other computers and websites (your Faro instance's address stays), window titles and app names. **Never in it:** keys, passwords, what Faro recorded or reported (events, reports, screenshots or thumbnails), and other accounts' logs.

- To save it somewhere else than the Desktop: `sudo /Library/Faro/bin/faro-service diagnose --output ~/Documents`.
- To read it all in Terminal without saving anything: `sudo /Library/Faro/bin/faro-service diagnose --print`.
- Fewer or more log lines: `--lines 500`.
- On Windows: run `& "C:\Program Files\Faro\faro-service.exe" diagnose` in a terminal opened as administrator, and approve the administrator prompt. Faro lists the report's contents before it writes anything, as on a Mac. The file is saved on your Desktop as `faro-report-….zip`, or use `--output <folder>` to save it elsewhere. The tray menu's **Report a problem…** explains this and copies the command.

---

## Adding your iPhone

**Who this is for:** a **member** who wants Faro on their own iPhone. You need your Faro web app and your iPhone. You don't need a computer, and no administrator password.

Faro on an iPhone **blocks**. It doesn't watch your screen and never takes screenshots. It blocks adult websites in Safari, in other browsers and in apps. If protection is ever turned off, loosened or removed, the allies you chose are told.

### Before you start

- **In the closed beta,** read [BETA.md](BETA.md#39-on-an-iphone) first: how to get the app through TestFlight, and the limits.
- **The app needs iOS 17 or later.**
- **Your member key is set up** in the web app (the **Keys** page).

### What setup asks, and what it costs

Setup begins with a page called **Faro on your iPhone**. Read it, then tap **I understand, continue**. It says:

- **Apps can't be deleted.** While Faro is protecting itself, no app on the phone can be deleted, Faro included. To remove Faro, turn off its Screen Time access in Settings, or use **Leave Faro** in Faro's settings.
- **No other VPN at the same time.** Faro uses a VPN setting to check website names. An iPhone runs only one VPN at a time, so a work or privacy VPN won't work while Faro is on.
- **iCloud Private Relay is turned off.** Private Relay hides website names from Faro's filter, so the two can't run together.
- **Date and time stay automatic.** Faro locks this setting so the clock can't be used to get around it. Explicit music, podcasts, books and TV are also blocked in Apple's apps. You can change that later.

The same page says what your allies see. They see when each protection was on, how often something was blocked, **the names of blocked adult and gambling sites**, and how many times a blocked app was opened. They don't see which app. Faro never sees your pages, messages or anything else you do, because the VPN carries only website name lookups. Some private DNS services and apps can get around the filter, so Faro can't block everything. Your allies are told that too.

Setup can't be finished without the Screen Time step and the VPN step. There is no skip. Faro's optional blocks, such as gambling sites, are not part of setup. You choose them later ([section 8](#8-choose-what-is-blocked)).

### 1. Get an enrollment link

In the Faro web app, open **Computers**, click **Add an iPhone**, unlock your key if the page asks, and click **Create an enrollment code**. The page shows the enrollment link as a **QR code** and as text. The link starts with `faro://enroll`. It works once, for 10 minutes.

The page makes the QR code in your browser. The link is never sent to another service to draw it.

### 2. Open the link on the iPhone

- **Scan the QR code.** In the Faro app, on the **Add this phone** screen, tap **Scan the QR code** and point the phone's camera at the code on your screen.
- **If the web app is open on the iPhone,** tap **Open in Faro** instead.
- **Otherwise,** copy the link and send it to the phone, for example by email to yourself. Then, in the Faro app, paste it into the box on the **Add this phone** screen and tap **Use this link**.

If Faro says **That isn't a Faro enrollment link**, check that the link starts with `faro://enroll`, and copy it again.

### 3. Check the instance and name the phone

Faro shows **Is this your instance?**, with the **Name**, **Address** and **Instance key** of your Faro instance. If you don't recognize them, tap **Use a different link**. Otherwise tap **Yes, this is it**. Faro remembers the key. If the instance ever shows a different one, Faro stops talking to it.

If the link doesn't name your member key, Faro says so. Then compare the safety code with the one in the web app, as in step 4.

Next, **Name this phone**. The name appears in the web app and in your allies' reports. Tap **Add this phone**.

### 4. Wait for approval

The phone shows **Waiting for you to approve**. The phone is added, but it doesn't count yet. Open the Faro web app on a computer, check that it shows the same codes as the phone (**This phone's code** and **Safety code**), and approve the phone only if they match. The phone checks every few seconds. Tap **Check now** to check at once.

### 5. Turn on Screen Time

Tap **Turn on Screen Time**. You confirm with Face ID or your passcode. Faro then:

- turns on Apple's adult website filter, which is the same one as **Limit Adult Websites** in Content Restrictions;
- stops apps from being deleted while Faro is protecting itself;
- blocks explicit music, podcasts, books and TV in Apple's apps;
- keeps the date and time automatic.

To undo the Screen Time step, turn off Faro's access under **Settings**, then **Screen Time**. Your allies are told if you do.

### 6. Allow the VPN

Tap **Allow the VPN**. iPhone asks you to allow the VPN setting. After that:

- The VPN starts by itself after a restart or a network change. Turning it off, or turning off **Connect On Demand** in Settings, is reported to your allies.
- Once a month, Faro sends a notification that shows who it reports to.

### 7. The status screen

After setup, the **Faro** screen shows what is on and what isn't. Your allies are told when any of the protection below is turned off.

| The screen says | What to do |
|---|---|
| **Screen Time: On** | Nothing. |
| **Screen Time: Off.** Faro can be deleted and settings aren't applied | Tap **Turn Screen Time back on**. |
| **Website filter: On** | Nothing. |
| **Website filter: Starting** or **Stopping** | Wait a moment. |
| **Website filter: Off** or **Not set up** | Tap **Turn the filter back on**. |
| **Starts by itself: Connect On Demand is off** | Tap **Turn the filter back on**. |
| **Waiting to send** | Nothing. Faro keeps what it records and sends it once your instance answers. |

Under **Never out of sight**, **Who Faro reports to** lists your allies. It shows each ally by the name you signed and a safety code, and says how many there are. Your web app shows the same code next to each ally's name. **Next monthly notice** shows when the next reminder is due. If notifications for Faro are off, the reminder can't appear. You can still open the same list from this screen.

### 8. Choose what is blocked

Tap **Choose what is blocked** on the status screen. Adult sites are always blocked. You can add:

- **Gambling sites**, under **Websites**. They are blocked in Safari and in every app.
- **Sites you choose**, under **Sites you choose**. Type a name such as `example.com`. It blocks that site and everything under it.
- **Apps and categories**, under **Apps**. Tap **Choose apps and categories**. Blocked apps show Faro's block screen. Faro never learns which apps you picked, only how many.
- **Other limits**: block explicit music, podcasts and books, and choose an **App Store age limit** (None, 4+, 9+, 12+ or 17+).

Tap **Save** under **Your changes** to apply them. Faro shows what each change does before you save.

- **Blocking more takes effect at once.**
- **Blocking less waits.** **Wait before loosening** sets how long, from 0 to 72 hours. It starts at 24 hours. Your allies are told when you ask, and again when the change takes effect. Until then, the old blocking stays. Under **Waiting to take effect**, tap **Cancel this change** to stop it. Once the time has passed, the change has taken effect, and it can't be cancelled.
- **Making the wait shorter also waits.** The current wait still has to pass first.

### 9. Leaving Faro

Tap **Settings**, then **Leave Faro**. Faro asks you to confirm with **Tell my allies and leave**. Then, in order:

1. Faro tells your instance that you are leaving. Your allies are told that Faro was removed from this phone.
2. Only when your instance has that message does Faro turn its protection off. Apps can be deleted again, Faro's Screen Time settings are cleared, and its VPN is removed.
3. Delete the Faro app: touch and hold its icon, then choose **Remove App**.

If the phone is offline, nothing changes. Faro says **Your allies haven't been told yet**. Tap **Try again** when the phone can reach your instance. If the message has been written but your instance hasn't confirmed it yet, Faro is still on. It has stopped sending anything else, and it leaves as soon as your instance has the message.

Turning off Faro's Screen Time access in Settings also works. Your allies are told about it.

#### If your instance is gone for good

Faro can't say goodbye through an instance that no longer exists, so **Leave Faro** can't finish. Do this instead:

1. Under **Settings**, go to **Screen Time** and turn off Faro's access.
2. Delete the Faro app.
3. If Settings still lists a Faro VPN, remove it under **General**, then **VPN & Device Management**.

Faro can't tell your allies this way, because the instance that would tell them is gone. Tell them yourself.
