# Adding your Mac to Faro

**Who this is for:** a **member**: someone who chose to use Faro on their own computer. You need your Faro web app, the Mac, and someone who knows an administrator name and password for that Mac. That can be you.

## Before you start

- **Faro is installed** on the Mac, from the official installer. After installing, an eye icon is in the menu bar. Faro monitors nothing until you finish the steps below.
- **Your member key is set up** in the web app (the **Keys** page).

## 1. Get an enrollment link

1. In your Faro web app, open **Computers** and click **Add a computer**.
2. Unlock your key if the page asks.
3. Click **Create an enrollment code**. The page shows a code, and an enrollment link that starts with `faro://enroll`. They work once, for 10 minutes.

## 2. Open the link on the Mac

- **If the web app is open on the Mac:** click **Open in Faro**.
- **If it is open on another device** (a phone, say): click **Copy link** and send the link to the Mac, for example by email to yourself. On the Mac, click the eye icon in the menu bar, choose **Enroll this computer…**, paste the link into the first field and click **Continue**. You can also type your Faro address in the first field and the code in the second.

## 3. Check and confirm

Faro shows a window titled **"Enroll this computer with *name*?"**. Check:

- The **name** and **address** are your Faro instance. If you don't recognize them, click **Cancel**.
- The list of **accounts**. Faro monitors every account on this Mac, including ones added later. If the guest account is on, Faro says so: anyone could use the Mac without a password, so consider turning it off in System Settings > Users & Groups.

Click **Enroll**.

## 4. An administrator approves

macOS asks for an **administrator's name and password**. This is macOS's own window, and it names your Faro instance. Faro only enrolls the Mac if an administrator approves here. If you are not an administrator of this Mac, ask someone who is to type theirs.

## 5. Compare the code and approve in the web app

Faro shows **"This computer is enrolled"** with a code of 16 letters and numbers.

1. In the web app, the new computer appears on the **Computers** page as waiting.
2. Check that the web app shows **the same code** for it. Approve it only if it does.
3. If Faro also shows a **member key** to check, compare it with the member key on your **Settings** page. If they differ, don't approve, and remove the computer.

Monitoring starts once you approve. The first time, macOS asks every account on the Mac to let **Faro Agent** record the screen.

## If something goes wrong

| Faro says | What to do |
|---|---|
| The code didn't work | Each code works once and expires after 10 minutes. Create a new one and start again. |
| Faro can't reach your instance | Check that the Mac is online and the address is right. |
| Not approved | Nothing changed. Try again when an administrator can type their password. |
| Enrollment stopped to keep you safe | The instance answered with a key that doesn't match your link. Don't continue. Remove the new computer in the web app if it appears there, and tell whoever runs your instance. |
| This computer can't be enrolled from here | An administrator can enroll it in Terminal instead: `sudo /Library/Faro/bin/faro-service enroll --link '…'` with your link. |
| Faro can't see one of your windows | An app (it names it) keeps a window out of screenshots and screen recordings, so Faro can't check it, and your allies are told which app. Close the window if you don't need it, or turn off the app's setting that hides its windows from screen sharing, if it has one. |
| Nothing happens when you click the link | Restart the Mac, or log out and in again, and try again. If it still doesn't open, use **Enroll this computer…** from the eye icon and paste the link. |

### Faro's logs

If something doesn't work and you want to see why, or someone helping you asks for the logs, Faro keeps them on the Mac:

- **The service:** `/Library/Logs/Faro/faro-service.log`. Any administrator of the Mac can read it.
- **The menu-bar agent, for each account:** `~/Library/Logs/Faro/faro-agent.log`, readable only by that account.

Open them in the Console app (under **Log Reports**), or follow them in Terminal with `tail -F /Library/Logs/Faro/faro-service.log`. Older entries are in the same folder, in files ending `.1`, `.2` and `.3`. At their usual level, the logs never contain the web addresses or window titles Faro sees, or anything from your screen.

## Checking that Faro is working

Click the eye icon in the menu bar. The line under **This computer is monitored by Faro** says what Faro is doing. Click it to see what it means and what to do; when something can fix it, an item just below opens it.

| The menu says | What to do |
|---|---|
| **Status: Monitoring** | Nothing: Faro is working. |
| **Status: Paused until** *time* | Nothing. Your allies were told about the pause, and monitoring starts again by itself. |
| **Status: Not enrolled** | Faro monitors nothing yet. Follow the steps at the top of this guide. |
| **Status: Waiting for approval in the web app** | Choose **Open the Computers Page…**, check the code, and approve the computer ([step 5](#5-compare-the-code-and-approve-in-the-web-app)). |
| **Status: Connecting to the Faro service…** | Wait a minute. If it stays, log out and in again, or restart the Mac. |
| **Status: Screen Recording is off** | Choose **Open Screen Recording Settings…** and switch on **Faro Agent**. If it is on already (after reinstalling Faro, for example), select it, remove it with **−** and add it again. Your allies are told while it is off. |
| **Status: Can't reach** *your instance* | Check that the Mac is online. Faro keeps what it records and sends it once your instance answers. |
| **Status: Faro can't take screenshots** | Restart the Mac. If it still says so, tell whoever runs your instance. |
| **Status: Faro stopped sending to** *your instance* | Your instance no longer has the identity this Mac was enrolled with. Tell whoever runs your instance. |
| **Status: The Faro service isn't running** | Restart the Mac. If it still says so, tell whoever runs your instance. |

The menu also has **Open Faro** (your Faro web app), **Report a problem…** ([Reporting a problem](#reporting-a-problem)) and **About Faro…** (the versions, your instance, and the licences of the software Faro includes). Nothing on the menu turns Faro off, pauses it or hides anything.

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

## Reporting a problem

If Faro isn't working and you'd like help, make a **problem report**: one file with what Faro is doing on your Mac and its recent logs, with private details taken out. Someone who knows an administrator password runs, in Terminal, from your account:

```sh
sudo /Library/Faro/bin/faro-service diagnose
```

**Report a problem…** in the eye icon's menu shows these steps too, and its **Copy Command** button puts that line on the clipboard, ready to paste into Terminal.

1. Faro gathers the report and lists the files in it, with what each one is. Nothing is written yet.
2. Type **s** to read everything in it first, **y** to write it, or **n** to stop.
3. It writes **`faro-report-`*date*`-`*time*`Z.zip`** to your **Desktop** (for example `faro-report-20261125-101500Z.zip`; the time is in UTC). The file is yours, and only your account can open it.
4. Send that file to **[where to send problem reports: to be added]**. Say what went wrong and when.

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
