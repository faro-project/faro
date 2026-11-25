# The update key ceremony

**Audience:** the Faro maintainer. This runbook creates the keys that sign Faro's updates, and later rotates them. You do it once, carefully, on a computer that never touches a network. You don't need to be a cryptographer. You do need to type commands exactly as written.

Every Faro client and every instance checks updates against a **root of trust** that ships inside the software. This runbook makes that root. If it goes wrong, the fix is a manual reinstall on every member's computer, so take your time.

Background: PROTOCOL.md §8, ARCHITECTURE.md §3.8, and the crate docs in `crates/faro-update/src/lib.rs` (roles, thresholds, expiry, rotation). The tool is `faro-release` (`crates/faro-update/examples/faro-release.rs`).

## Contents

1. [The keys at a glance](#1-the-keys-at-a-glance)
2. [Before the ceremony](#2-before-the-ceremony)
3. [The ceremony](#3-the-ceremony)
4. [Storage](#4-storage)
5. [Shipping root 1](#5-shipping-root-1)
6. [Rotation and compromise](#6-rotation-and-compromise)
7. [Printable checklist](#7-printable-checklist)
8. [Ceremony log template](#8-ceremony-log-template)

---

## 1. The keys at a glance

There are three roles. Each key is an Ed25519 key in a small JSON file made by `faro-release keygen`. Its **key id** (16 hex characters) is its fingerprint.

| Role | Keys | Threshold | Signs | Lives | What it signs expires after |
|---|---|---|---|---|---|
| `root` | 3 (A, B, C) | 2 | the list of every role's keys, including its own | offline, on encrypted USB drives in three places | 1 year |
| `targets` | 1 | 1 | `targets.json`: the list of release files, with their length and BLAKE3 | online, read by the release workflow (#58) | a few weeks |
| `timestamp` | 1 | 1 | `timestamp.json`: which `targets.json` is current | online, read by the re-signing job (#58, every 8 hours) | about 1 day |

What each threshold means:

- **Root 2-of-3.** Any two root keys can sign a new root. One lost key is not a disaster, and one stolen key is not enough for an attacker.
- **Targets and timestamp 1-of-1.** These sign often and automatically, so one key each.

The code doesn't force these numbers. `faro-release` only refuses a threshold of 0 or one higher than the number of keys. The 2-of-3, the 1 year and the 1 day come from the design in `lib.rs`, and this runbook writes them into root 1.

What clients do with them:

- A client trusts the root it shipped with, never the instance.
- On every check it first fetches `roots/<n+1>.json` until there is none. Each new root must be signed by 2 keys of the old root **and** 2 keys of the new root.
- It then checks `timestamp.json` and `targets.json` against the newest root. If the newest root has expired, it stops there and installs nothing.
- Versions never go down, so nobody can roll a client back.

---

## 2. Before the ceremony

Allow a week to get things ready and about three hours for the ceremony itself.

### 2.1 What to get

- **A spare Mac** for the ceremony. It becomes the **air-gapped Mac**: after you set it up, it never connects to a network again. An Apple Silicon Mac is easiest (see [2.4](#24-build-faro-release-on-your-connected-mac)). Keep it afterwards for the yearly root renewal.
- **Seven USB drives**, 8 GB or larger, from a known brand, new and still sealed. Label them with a marker or label tape:

  | Label | Holds |
  |---|---|
  | `ROOT-A`, `ROOT-A2` | root key A, and its backup |
  | `ROOT-B`, `ROOT-B2` | root key B, and its backup |
  | `ROOT-C`, `ROOT-C2` | root key C, and its backup |
  | `TRANSFER` | the `faro-release` program going in; public files and the online keys coming out |

- **Three places** to keep the root drives, far enough apart that one fire or burglary hits only one. For example: a safe at home, a bank safe deposit box, and a trusted person's home. Each place gets one key and its backup, never two different keys. Two different keys in one place would put the threshold in one place.
- **Seven tamper-evident bags** (optional but cheap), one per drive.
- **A printout** of this runbook, the [checklist](#7-printable-checklist) and the [log](#8-ceremony-log-template), and a pen.
- **Passphrases.** One passphrase per key (`ROOT-A` and `ROOT-A2` share one), plus one for `TRANSFER`. Generate them in your password manager beforehand, at least five random words each. Store them there, and also on paper in a different place from the drive they open. Whoever keeps drive C doesn't need its passphrase.

### 2.2 Rehearse first (recommended)

Do the whole of [section 3](#3-the-ceremony) once on your everyday Mac with throwaway keys, using folders instead of drives. Then delete the folders. This takes 20 minutes and catches typos before they matter.

### 2.3 Prepare the air-gapped Mac

1. Erase it: **System Settings → General → Transfer or Reset → Erase All Content and Settings**. Reinstall macOS if asked. The setup needs the internet once for activation.
2. In Setup Assistant: don't sign in with an Apple Account, turn off Location Services and analytics, create a local administrator account, and turn on FileVault.
3. Turn off Wi-Fi and Bluetooth in System Settings. Don't plug in a network cable. **From now on, never connect this Mac to any network.**
4. In System Settings, turn off Time Machine and automatic updates.
5. Check that it is offline. In Terminal:

   ```sh
   ping -c 1 -t 3 1.1.1.1
   ```

   It must fail (`No route to host` or `100.0% packet loss`).

### 2.4 Build `faro-release` on your connected Mac

Build it from a clean clone, check that its tests pass, and take its checksum. Write down the commit you built from.

```sh
gh repo clone faro-project/faro ~/faro-ceremony-build
cd ~/faro-ceremony-build
git checkout main
git log -1 --format='%H %s'
git status --short
cargo test --locked -p faro-update
cargo build --release --locked -p faro-update --example faro-release
file target/release/examples/faro-release
```

- `git status --short` must print nothing.
- Write the commit hash from `git log` in the log.
- `file` must say `Mach-O 64-bit executable arm64`.

If the air-gapped Mac is an Intel Mac, build for it instead (once: `rustup target add x86_64-apple-darwin`). The program is then at `target/x86_64-apple-darwin/release/examples/faro-release`, and `file` must say `x86_64`. Use that path below.

```sh
cargo build --release --locked -p faro-update --example faro-release --target x86_64-apple-darwin
```

### 2.5 Prepare the `TRANSFER` drive and copy the program

Plug in the `TRANSFER` drive and find its disk number:

```sh
diskutil list external physical
```

Find the line for your USB drive (check the size). Its identifier is `/dev/diskN`, for example `/dev/disk4`. In the next two commands, **replace `diskN` with that identifier**. `eraseDisk` wipes the whole disk you name, so check it twice.

```sh
diskutil eraseDisk APFS TRANSFER GPT diskN
diskutil apfs encryptVolume /Volumes/TRANSFER -user disk
```

`encryptVolume` asks for the `TRANSFER` passphrase. Then copy the program and its checksum:

```sh
cp ~/faro-ceremony-build/target/release/examples/faro-release /Volumes/TRANSFER/
cd /Volumes/TRANSFER
shasum -a 256 faro-release > faro-release.sha256
cat faro-release.sha256
diskutil eject /Volumes/TRANSFER
```

Write the checksum's first 8 and last 8 characters in the log. A checksum stored on the same drive only catches a damaged copy. The one written on paper also catches a swapped one.

---

## 3. The ceremony

Work through this in order and tick the [checklist](#7-printable-checklist) as you go. Read each command before you press Return. Never plug a root drive into a computer other than the air-gapped Mac.

### 3.1 Set up

1. Check the air-gapped Mac's clock against your phone. Every expiry date is computed from it.

   ```sh
   date -u
   ```

   If it is more than a minute off, fix it in **System Settings → General → Date & Time** (turn off "Set time and date automatically" and set it by hand).

2. Plug in `TRANSFER` and type its passphrase when macOS asks. Copy the program to a working folder and check it:

   ```sh
   mkdir -p ~/ceremony/pub
   cp /Volumes/TRANSFER/faro-release /Volumes/TRANSFER/faro-release.sha256 ~/ceremony/
   cd ~/ceremony
   shasum -a 256 -c faro-release.sha256
   cat faro-release.sha256
   ./faro-release --help
   ```

   `shasum` must print `faro-release: OK`, and the checksum must match the one in the log.

`~/ceremony` only ever holds public files. The secret key files go straight onto the USB drives.

### 3.2 Encrypt the six root drives

Do this for each of `ROOT-A`, `ROOT-A2`, `ROOT-B`, `ROOT-B2`, `ROOT-C`, `ROOT-C2`, one at a time. Plug in the drive and find its identifier:

```sh
diskutil list external physical
```

Then, with **`diskN` replaced** by that drive's identifier and the name matching the drive's label (here `ROOT-A`):

```sh
diskutil eraseDisk APFS ROOT-A GPT diskN
diskutil apfs encryptVolume /Volumes/ROOT-A -user disk
```

Type key A's passphrase when asked. `ROOT-A2` gets the same passphrase as `ROOT-A`, and so on. Leave the drive plugged in only if you have enough ports. Otherwise eject it (`diskutil eject /Volumes/ROOT-A`) and plug it back in when you need it. macOS asks for the passphrase each time.

### 3.3 Generate the three root keys

For key A, plug in `ROOT-A` and `ROOT-A2`, then:

```sh
cd ~/ceremony
./faro-release keygen --out /Volumes/ROOT-A/root-a.key.json | tee pub/root-a.pub
cp -p /Volumes/ROOT-A/root-a.key.json /Volumes/ROOT-A2/root-a.key.json
cmp /Volumes/ROOT-A/root-a.key.json /Volumes/ROOT-A2/root-a.key.json && echo "backup OK"
```

`keygen` prints the key id and the public key, and `tee` saves them in `pub/root-a.pub`. It writes the key file with permissions `0600` and refuses to overwrite an existing file. You must see `backup OK`. Then eject both:

```sh
diskutil eject /Volumes/ROOT-A
diskutil eject /Volumes/ROOT-A2
```

Key B, with `ROOT-B` and `ROOT-B2`:

```sh
cd ~/ceremony
./faro-release keygen --out /Volumes/ROOT-B/root-b.key.json | tee pub/root-b.pub
cp -p /Volumes/ROOT-B/root-b.key.json /Volumes/ROOT-B2/root-b.key.json
cmp /Volumes/ROOT-B/root-b.key.json /Volumes/ROOT-B2/root-b.key.json && echo "backup OK"
diskutil eject /Volumes/ROOT-B
diskutil eject /Volumes/ROOT-B2
```

Key C, with `ROOT-C` and `ROOT-C2`:

```sh
cd ~/ceremony
./faro-release keygen --out /Volumes/ROOT-C/root-c.key.json | tee pub/root-c.pub
cp -p /Volumes/ROOT-C/root-c.key.json /Volumes/ROOT-C2/root-c.key.json
cmp /Volumes/ROOT-C/root-c.key.json /Volumes/ROOT-C2/root-c.key.json && echo "backup OK"
diskutil eject /Volumes/ROOT-C
diskutil eject /Volumes/ROOT-C2
```

### 3.4 Generate the targets and timestamp keys

These go onto `TRANSFER`, because they leave the air-gapped Mac (see [4.2](#42-the-online-keys-targets-and-timestamp)). With `TRANSFER` plugged in:

```sh
cd ~/ceremony
mkdir /Volumes/TRANSFER/online
./faro-release keygen --out /Volumes/TRANSFER/online/targets.key.json | tee pub/targets.pub
./faro-release keygen --out /Volumes/TRANSFER/online/timestamp.key.json | tee pub/timestamp.pub
```

### 3.5 Write root 1

Root 1 lists all five public keys and says which role each belongs to. This block reads them from `pub/` and writes the unsigned root. The first eight lines are its settings. Later rotations reuse this block with different settings ([6.1](#61-signing-a-new-root)).

```sh
cd ~/ceremony
ROOT_VERSION=1
ROOT_EXPIRES_MS=$(( $(date -v+1y +%s) * 1000 ))
ROOT_A=pub/root-a.pub
ROOT_B=pub/root-b.pub
ROOT_C=pub/root-c.pub
TARGETS=pub/targets.pub
TIMESTAMP=pub/timestamp.pub
read A_ID A_PUB < $ROOT_A
read B_ID B_PUB < $ROOT_B
read C_ID C_PUB < $ROOT_C
read T_ID T_PUB < $TARGETS
read S_ID S_PUB < $TIMESTAMP
cat > root-$ROOT_VERSION.unsigned.json <<EOF
{
  "version": $ROOT_VERSION,
  "expires_ms": $ROOT_EXPIRES_MS,
  "keys": {
    "$A_ID": "$A_PUB",
    "$B_ID": "$B_PUB",
    "$C_ID": "$C_PUB",
    "$T_ID": "$T_PUB",
    "$S_ID": "$S_PUB"
  },
  "roles": {
    "root": { "keyids": ["$A_ID", "$B_ID", "$C_ID"], "threshold": 2 },
    "targets": { "keyids": ["$T_ID"], "threshold": 1 },
    "timestamp": { "keyids": ["$S_ID"], "threshold": 1 }
  }
}
EOF
cat root-$ROOT_VERSION.unsigned.json
date -u -r $(( ROOT_EXPIRES_MS / 1000 ))
```

Check the output: five different key ids, none empty, and an expiry date one year from today.

### 3.6 Sign root 1 with all three root keys

Two signatures are enough, but signing with all three proves that every root key works. Plug in each drive when its line needs it, and eject it after.

```sh
cd ~/ceremony
./faro-release sign-root --metadata root-1.unsigned.json --key /Volumes/ROOT-A/root-a.key.json --out 1.root.json
./faro-release add-signature --envelope 1.root.json --key /Volumes/ROOT-B/root-b.key.json --out 1.root.json
./faro-release add-signature --envelope 1.root.json --key /Volumes/ROOT-C/root-c.key.json --out 1.root.json
```

Each prints `wrote 1.root.json`. `sign-root` refuses a root that clients would reject (for example a threshold higher than the number of keys).

### 3.7 Verify root 1

`faro-release verify` checks a full set the way a client does, so it needs a targets and a timestamp document too. Make throwaway ones that expire tomorrow, with `TRANSFER` plugged in:

```sh
cd ~/ceremony
TEST_EXPIRES_MS=$(( $(date -v+1d +%s) * 1000 ))
cat > test-targets.unsigned.json <<EOF
{ "version": 1, "expires_ms": $TEST_EXPIRES_MS, "targets": {} }
EOF
./faro-release sign-targets --metadata test-targets.unsigned.json --key /Volumes/TRANSFER/online/targets.key.json --out test-targets.json
./faro-release sign-timestamp --targets test-targets.json --version 1 --expires-ms $TEST_EXPIRES_MS --key /Volumes/TRANSFER/online/timestamp.key.json --out test-timestamp.json
./faro-release verify --root 1.root.json --timestamp test-timestamp.json --targets test-targets.json
```

The last line must print `OK: root v1, timestamp v1 (expires …), targets v1`. That proves root 1 is well formed, carries enough root signatures, and names the targets and timestamp keys you just made.

Now check that one root key alone is **not** enough. With `ROOT-A` plugged in:

```sh
cd ~/ceremony
./faro-release sign-root --metadata root-1.unsigned.json --key /Volumes/ROOT-A/root-a.key.json --out check-one-signature.json
./faro-release verify --root check-one-signature.json --timestamp test-timestamp.json --targets test-targets.json
```

The verify must **fail** with `Error: initial root` and `root signature threshold not met: 1 valid of 2 required`. Then delete the throwaway files. Never publish them.

```sh
cd ~/ceremony
rm check-one-signature.json test-targets.unsigned.json test-targets.json test-timestamp.json
```

### 3.8 Record the fingerprints

```sh
cd ~/ceremony
cat pub/root-a.pub pub/root-b.pub pub/root-c.pub pub/targets.pub pub/timestamp.pub
shasum -a 256 1.root.json
```

Copy each key id into the log, and the `1.root.json` checksum. The checksum is what instance admins compare against later. The public keys are optional in the log because they are inside `1.root.json` anyway.

### 3.9 Copy the public files out

Copy the public records to `TRANSFER` (to take to the connected Mac) and to every root drive (so a future rotation has them even if the air-gapped Mac dies). With `TRANSFER` plugged in:

```sh
cd ~/ceremony
mkdir /Volumes/TRANSFER/public
cp -R pub 1.root.json root-1.unsigned.json /Volumes/TRANSFER/public/
ls -R /Volumes/TRANSFER/public
diskutil eject /Volumes/TRANSFER
```

Then for each root drive, one at a time (here `ROOT-A`; repeat with the other five names):

```sh
cd ~/ceremony
mkdir /Volumes/ROOT-A/public
cp -R pub 1.root.json root-1.unsigned.json /Volumes/ROOT-A/public/
ls /Volumes/ROOT-A
diskutil eject /Volumes/ROOT-A
```

`ls` must show `public` and the drive's one key file, nothing else. Put each drive in its bag, seal it, and write the bag's number in the log.

Leave `~/ceremony` on the air-gapped Mac. It holds `faro-release` and public files only. Shut the Mac down.

---

## 4. Storage

### 4.1 The root keys

| Place | Drives | Passphrase kept |
|---|---|---|
| Place 1 (for example a safe at home) | `ROOT-A`, `ROOT-A2` | password manager, and on paper away from place 1 |
| Place 2 (for example a bank box) | `ROOT-B`, `ROOT-B2` | password manager, and on paper away from place 2 |
| Place 3 (for example a trusted person) | `ROOT-C`, `ROOT-C2` | password manager, and on paper away from place 3 |

- Each place holds one key and its backup drive. Losing a whole place loses one key, and the other two still meet the threshold.
- A root drive only ever goes into the air-gapped Mac.
- Once a year, at the [root renewal](#62-renew-the-root-every-year), you plug in two keys. That doubles as a check that their drives still work. Use the backup drive if a primary fails, and replace the failed drive with a new copy.
- Flash drives can lose data after years unpowered. Copy each key to a fresh drive every 3 years.

### 4.2 The online keys (targets and timestamp)

The timestamp must be re-signed about every day, by a machine, with no one present. The release workflow (#58) also signs `targets.json` on every release. So both keys must be somewhere a machine can use them. Where exactly is your decision. Here are the options.

First, what a leak costs:

- **Timestamp key alone:** an attacker can keep clients on the current release (for example hold back a security fix) until `targets.json` expires, and can push clients' timestamp version so high that your real timestamps are refused until you rotate. They can't add or change a release file.
- **Targets and timestamp keys together:** an attacker who also controls what some clients download (their own instance, or your publishing location) can approve any file as a release. Treat the targets key as the most valuable key after the root keys.
  - **On macOS a second layer stops most of this.** Before installing, the updater checks the package itself (PROTOCOL.md §8.2, steps 5 and 6). It must carry Faro's Developer ID Installer signature (the Team ID compiled into the installed client) and be notarized. And the version written inside it must be the one the metadata names, and above the installed one. So the attacker also needs the Developer ID Installer key and the notary credentials, which live in the Mac runner's keychain, not in Actions. A package that fails is not installed, and allies get a tamper alert.
  - **Listing an old release under a higher version doesn't work.** The package's own version gives it away, so the attacker can't move clients back to an older release.
  - **What it doesn't stop:** a package you did sign and notarize, offered as the version it really is, when that is above what a client runs. The attacker could make clients install a build you signed but never published (a release candidate, say), or hold them on an older release that is still newer than theirs. Keep the signing keychain locked when no release is building (DEVELOPMENT.md, "Releasing").
  - **Other platforms** have no second layer yet. There, these two keys are enough.

#### Option A: GitHub Actions secrets

The keys are stored as encrypted Actions secrets and given to the workflow jobs that sign.

- **How #58 reads it:** the job maps the secret to an environment variable, writes it to a file only it can read, signs, and deletes the file. For example, in a step: `umask 077; printf '%s' "$FARO_TARGETS_KEY" > "$RUNNER_TEMP/targets.key.json"`, then `faro-release sign-targets … --key "$RUNNER_TEMP/targets.key.json"`. The timestamp job (`update-timestamp.yml`) does the same with `FARO_TIMESTAMP_KEY` and `sign-timestamp`.
- **Risks:**
  - On the current GitHub Free plan, a private repository has only repository secrets. **Every workflow on every branch can read them.** So anyone, or any tool, that can push a branch can change a workflow to print them. That includes coding agents that push with your token.
  - Environment secrets fix this: they can be limited to `v*` tags and `main`, and the targets one can require your approval. They need the repository to be public or a paid plan. Check GitHub's plans page for which protection rules your plan allows on a private repository.
  - The self-hosted runners aren't sandboxed and keep files between jobs (DEVELOPMENT.md, "CI runners"). A key used there could be left on disk or read by a later job.
  - GitHub itself holds the keys.
- **Cost:** none. No new code and no new machine.

#### Option B: a small signing server

A small server you run (a VPS, not one of the CI runners) holds both keys. A cron job re-signs the timestamp and uploads it. The release workflow sends the unsigned `targets.json` to the server and gets it back signed.

- **How #58 reads it:** the workflow never sees the keys. It holds an SSH key (an Actions secret) that may only run one command on the server: "sign this targets file". The server signs the targets and a new timestamp and publishes them, or hands them back for `faro-release verify` and the publish step.
- **Risks:**
  - Another internet-facing machine to patch, monitor and back up.
  - The SSH key in Actions can still ask the server to sign *any* targets file. Unless the server asks you to approve each one, the protection is barely better than option A.
  - If the server is down, the timestamp expires and every client stops updating (they keep running).
- **Cost:** a few dollars a month, plus your time.

#### Option C: a hardware key

The targets key lives on a hardware security key (for example a YubiKey with Ed25519 support) that can't export it. You touch it to sign each release.

- **How #58 would read it:** the workflow stops after building, and uploads the unsigned `targets.json` as an artifact. You download it, sign it on your Mac with the hardware key, and send the signed file back (for example as input to a second workflow run). The workflow then signs the timestamp, verifies and publishes.
- **Risks:**
  - **`faro-release` can't do this today.** It only reads key files. Someone has to add hardware-key signing first.
  - Every release needs you, with the key.
  - The timestamp can't live on a hardware key unless the key stays plugged into an always-on machine (which is option B). So the timestamp key still needs option A or B.
  - Losing the hardware key means a root rotation to replace it (no worse than any other lost online key).
- **Cost:** about 50 to 100 dollars per key, plus the new code.

#### Recommendation: option A now, with these limits

Use **GitHub Actions secrets** for both keys now. It is what #58 is building, it needs no new code or machine, and a leak of either key can be recovered from by a root rotation ([6.6](#66-when-something-goes-wrong)). Option B costs more and protects little more. Option C is the right long-term home for the targets key but needs code first.

Keep the risk small:

1. Store them as two separate secrets, `FARO_TARGETS_KEY` and `FARO_TIMESTAMP_KEY`, for Actions only (`--app actions`). The daily timestamp job reads only the timestamp key. (Use whatever names #58's workflow reads, if they differ.)
2. Run every job that reads a key on a **GitHub-hosted runner**, never on the self-hosted ones.
3. Keep write access to the repository to yourself, and be aware that anything pushing branches with your token could read the secrets.
4. When the repository becomes public (or the plan allows it), move both secrets into environments: `release` (only `v*` tags, your approval required) for the targets key and `timestamp` (only `main`) for the timestamp key.
5. Keep no other copy of the online keys. If one is lost, rotate it ([6.3](#63-rotate-the-targets-or-timestamp-key)).
6. Later, open an issue for hardware-key signing and move the targets key to option C.

The timestamp re-signing schedule belongs to #58, but note one thing: instances fetch at most every 6 hours (`updates.refresh_secs`) and clients check about every 6 hours. A timestamp that expires 1 day after signing should therefore be re-signed at least every 12 hours. Otherwise clients see an expired one for part of each day. `update-timestamp.yml` re-signs it every 8 hours, and renews `targets.json` (42 days) when it has under 21 days left (DEVELOPMENT.md, "Releasing").

### 4.3 Upload the online keys (option A)

On your connected Mac, plug in `TRANSFER`. Then:

```sh
gh secret set FARO_TARGETS_KEY --app actions --repo faro-project/faro < /Volumes/TRANSFER/online/targets.key.json
gh secret set FARO_TIMESTAMP_KEY --app actions --repo faro-project/faro < /Volumes/TRANSFER/online/timestamp.key.json
gh secret list --app actions --repo faro-project/faro
```

The list must show both names. Next, copy the public files off `TRANSFER`, into your checkout (see [5](#5-shipping-root-1)):

```sh
mkdir -p ~/faro-ceremony-public
cp -R /Volumes/TRANSFER/public/ ~/faro-ceremony-public/
ls -R ~/faro-ceremony-public
```

Then erase `TRANSFER`. Erasing an encrypted drive throws away its encryption key, so the online keys on it can't be recovered. Find its identifier with `diskutil list external physical` and **replace `diskN`**:

```sh
diskutil eraseDisk APFS TRANSFER GPT diskN
```

`TRANSFER` is now an empty, unencrypted drive. Keep it for the next rotation.

---

## 5. Shipping root 1

`1.root.json` is public: it contains only public keys and signatures. It goes in three places.

1. **The repository.** Commit it as `release/update-root.json`. That path always holds the root that new packages and images ship. Later roots also go in `release/roots/<n>.json` ([6.1](#61-signing-a-new-root)).

   ```sh
   cd ~/Github/faro-project/faro
   git switch -c release-root-1 origin/main
   mkdir -p release
   mkdir -p release/roots
   cp ~/faro-ceremony-public/1.root.json release/update-root.json
   cp ~/faro-ceremony-public/1.root.json release/roots/1.json
   shasum -a 256 release/update-root.json
   git add release/update-root.json release/roots/1.json
   git commit -m "Release: update root 1"
   ```

   The checksum must match the one in the log. Push and open a pull request as usual. `release/roots/1.json` is never published. It lets the release workflow walk the whole chain from root 1, as an old client does, which it needs to carry the published `targets.json` forward after an online key is replaced.

2. **The macOS package.** `build-pkg.sh` installs the file named by `FARO_UPDATE_ROOT` as `/Library/Faro/update-root.json`. A release package can't be built without it, and `check-pkg.sh` fails a release package that lacks it. The release workflow (#58) sets it:

   ```sh
   FARO_UPDATE_ROOT=release/update-root.json installers/macos/build-pkg.sh
   ```

   (plus the signing variables from DEVELOPMENT.md, "The macOS installer").

3. **Instances** (`updates.root`, or `FARO_UPDATES_ROOT` in `faro.env`). SELF-HOSTING.md tells admins to set:

   ```sh
   FARO_UPDATES_ROOT=/usr/share/faro/update-root.json
   FARO_UPDATES_UPSTREAM=https://…
   ```

   - The container image copies `release/update-root.json` to that path (`deploy/Dockerfile`), once the file exists.
   - `updates.upstream` is the publishing location #58 sets up (it recommends `https://updates.faro-project.org/`).
   - An instance without the image (the binary and systemd) downloads `update-root.json` and points `FARO_UPDATES_ROOT` at it.
   - Admins can check their copy with `shasum -a 256 update-root.json`. Publish the checksum from the log in SELF-HOSTING.md and the release notes so they have something to compare with.

Root 1 is never published under `roots/`. Every client and instance already has it.

---

## 6. Rotation and compromise

### 6.1 Signing a new root

Every change to the keys, and the yearly renewal, is a new root with the next version number. The rules (from `Updater::update_root`):

- Version must be exactly the current version plus one.
- It must be signed by 2 keys of the **current** root **and** 2 keys of the **new** root. If you keep keys A and B, signing with A and B satisfies both.
- If a targets or timestamp key is removed, clients forget the versions they saw for that role. That is how a compromised online key is undone. Adding a key or changing a threshold doesn't reset anything.
- Clients accept an older root that has expired while walking forward, so a late renewal still works. Only the newest root must be unexpired.

The steps below make root 2. For a later root, use its number in place of `2` everywhere. On the air-gapped Mac:

1. Check the clock (`date -u`). If `~/ceremony/pub` is missing (for example on a new air-gapped Mac), plug in any root drive and copy the public files back:

   ```sh
   mkdir -p ~/ceremony
   cp -R /Volumes/ROOT-A/public/pub ~/ceremony/
   ```

   You also need a checked `faro-release` in `~/ceremony` ([2.4](#24-build-faro-release-on-your-connected-mac), [3.1](#31-set-up)).
2. If a key is being replaced, generate the new one first (as in [3.3](#33-generate-the-three-root-keys) or [3.4](#34-generate-the-targets-and-timestamp-keys)), with a new file name: `root-d`, `targets-2`, `timestamp-2` and so on.
3. Run the block from [3.5](#35-write-root-1), changing only its settings: `ROOT_VERSION` to the new version, and each `ROOT_A`…`TIMESTAMP` line to the public key file for that slot. `ROOT_EXPIRES_MS` stays one year from today.
4. Sign with two root keys that are in both the current and the new root (here A and B, for version 2):

   ```sh
   cd ~/ceremony
   ./faro-release sign-root --metadata root-2.unsigned.json --key /Volumes/ROOT-A/root-a.key.json --out 2.root.json
   ./faro-release add-signature --envelope 2.root.json --key /Volumes/ROOT-B/root-b.key.json --out 2.root.json
   ```

   If you added a new root key D, sign with it too, to prove it works:

   ```sh
   ./faro-release add-signature --envelope 2.root.json --key /Volumes/ROOT-D/root-d.key.json --out 2.root.json
   ```

5. Copy the public files to `TRANSFER`, and to every root drive that you have plugged in (here `ROOT-A`):

   ```sh
   cd ~/ceremony
   mkdir -p /Volumes/TRANSFER/public /Volumes/ROOT-A/public
   cp -R pub 2.root.json root-2.unsigned.json /Volumes/TRANSFER/public/
   cp -R pub 2.root.json root-2.unsigned.json /Volumes/ROOT-A/public/
   ```

   Update the other root drives' `public` folders the next time each one is plugged in.

6. On the connected Mac, copy the files off `TRANSFER` (as in [4.3](#43-upload-the-online-keys-option-a)) and check the new root against what is published now. `release/update-root.json` in your checkout is the newest root before this one. Fetch the timestamp first, then the targets file (replace the address with the publishing location from #58):

   ```sh
   cp -R /Volumes/TRANSFER/public/ ~/faro-ceremony-public/
   cd ~/faro-ceremony-public
   curl -fsSO https://updates.faro-project.org/timestamp.json
   curl -fsSO https://updates.faro-project.org/targets.json
   ~/faro-ceremony-build/target/release/examples/faro-release verify --root ~/Github/faro-project/faro/release/update-root.json --root-update 2.root.json --timestamp timestamp.json --targets targets.json
   ```

   It must print `OK: root v2, …`. If a release was published between the two downloads, the check fails with a timestamp mismatch: download both again. If you changed the targets or timestamp key, this check **fails** (`signature threshold not met: 0 valid of 1 required`) until the files are re-signed with the new key. Run it again after step 7.

7. Commit the new root in your checkout (here `~/Github/faro-project/faro`). `release/roots/2.json` is published as `roots/2.json` in the layout. `release/update-root.json` now holds the newest root, so new packages and images start from it.

   ```sh
   cd ~/Github/faro-project/faro
   git switch -c release-root-2 origin/main
   mkdir -p release/roots
   cp ~/faro-ceremony-public/2.root.json release/roots/2.json
   cp ~/faro-ceremony-public/2.root.json release/update-root.json
   git add release/roots/2.json release/update-root.json
   git commit -m "Release: update root 2"
   ```

   Publish `roots/2.json` with the next run of `update-timestamp.yml` (every 8 hours, or `gh workflow run update-timestamp.yml`) or the next release. When an online key changed, update its secret first, so that the same run re-signs `targets.json` and `timestamp.json` with the new key: when `release/update-root.json` names a targets key that didn't sign the published `targets.json`, the job renews it. Clients that see the new root before the new timestamp fail that one check and retry later. Never remove an old root from the layout: clients still on an old package walk through every one.
8. Write a log entry ([8](#8-ceremony-log-template)).

### 6.2 Renew the root every year

Root 1 expires one year after the ceremony. After that, clients and instances accept no new timestamp until a newer root is published. Put a reminder in your calendar **two months before** the expiry date in the log.

Renewal is [6.1](#61-signing-a-new-root) with no key changes: same five public key files, `ROOT_VERSION` plus one, a new expiry. Sign with any two root keys.

If you miss it: updates stop, but nothing breaks for good. Publish the renewed root as soon as you can, and clients pick it up on their next check.

### 6.3 Rotate the targets or timestamp key

Do this when a key may have leaked, when a secret is lost, or when it moves (for example to a hardware key).

1. On the air-gapped Mac, generate the new key onto `TRANSFER`, for example:

   ```sh
   cd ~/ceremony
   mkdir -p /Volumes/TRANSFER/online
   ./faro-release keygen --out /Volumes/TRANSFER/online/targets-2.key.json | tee pub/targets-2.pub
   ```

   For the timestamp key, use `timestamp-2` in place of `targets-2`.

2. Sign the next root with `TARGETS=pub/targets-2.pub` (or `TIMESTAMP=pub/timestamp-2.pub`) in its settings ([6.1](#61-signing-a-new-root)).
3. On the connected Mac, replace the secret, then erase `TRANSFER` as in [4.3](#43-upload-the-online-keys-option-a):

   ```sh
   gh secret set FARO_TARGETS_KEY --app actions --repo faro-project/faro < /Volumes/TRANSFER/online/targets-2.key.json
   ```

   For the timestamp key:

   ```sh
   gh secret set FARO_TIMESTAMP_KEY --app actions --repo faro-project/faro < /Volumes/TRANSFER/online/timestamp-2.key.json
   ```

4. Publish the new root together with a freshly signed `targets.json` and `timestamp.json` (step 7 of [6.1](#61-signing-a-new-root)). Keep counting versions up as usual.

What clients do: they fetch the new root, drop the old key, forget the versions the old key signed, and accept files from the new key.

### 6.4 Replace a root key

Do this when a root drive and its backup are both lost or dead, when a key may have leaked, or when a place stops being safe.

1. Prepare two new drives labelled `ROOT-D` and `ROOT-D2` as in [3.2](#32-encrypt-the-six-root-drives), with a new passphrase. Then generate key D:

   ```sh
   cd ~/ceremony
   ./faro-release keygen --out /Volumes/ROOT-D/root-d.key.json | tee pub/root-d.pub
   cp -p /Volumes/ROOT-D/root-d.key.json /Volumes/ROOT-D2/root-d.key.json
   cmp /Volumes/ROOT-D/root-d.key.json /Volumes/ROOT-D2/root-d.key.json && echo "backup OK"
   ```

2. Sign the next root with key D in the old key's slot (here C is replaced: `ROOT_C=pub/root-d.pub` in the settings), using the two remaining old keys, plus D ([6.1](#61-signing-a-new-root)).
3. Erase the old key's drives if you still have them (`diskutil eraseDisk` as in [4.3](#43-upload-the-online-keys-option-a), with the drive's own name), and give the new drives the old key's place. The next replacement key is E.

What clients do: they accept the new root, and from then on the old key counts for nothing.

### 6.5 Moving the root keys onto hardware keys

`lib.rs` describes the root keys as hardware keys. `faro-release` can't use hardware keys yet. When it can, replace A, B and C one at a time with [6.4](#64-replace-a-root-key), or all three in one root signed by two old keys and two new ones.

### 6.6 When something goes wrong

| What happened | What you do | What clients do |
|---|---|---|
| **The timestamp key leaked** | Rotate it at once ([6.3](#63-rotate-the-targets-or-timestamp-key)). | Until the new root: the attacker can hold them on the current release, but not change it. After it: they forget the attacker's timestamps and continue. |
| **The targets key leaked** (with option A, assume the timestamp key leaked too) | Rotate **both** at once in one root. Tell instance admins. Check every published file against what you built. Find how the key leaked before trusting the new place. | Clients that installed nothing bad are fine after the new root. macOS clients refuse a package that Faro's Developer ID didn't sign and notarize, and tell allies (a tamper alert). A client that installed a package you didn't build is compromised and must be reinstalled by hand. |
| **An online key was lost** (secret deleted) | Rotate it ([6.3](#63-rotate-the-targets-or-timestamp-key)). | Nothing until the timestamp expires, then no updates until you publish. They keep running. |
| **One root drive died** | Use its backup. Copy the key to a new drive. | Nothing. |
| **One root key is lost** (both drives) | Replace it soon ([6.4](#64-replace-a-root-key)) with the other two. | Nothing. |
| **One root key may have leaked** | Replace it at once ([6.4](#64-replace-a-root-key)). One key can't sign a root alone. | Nothing. They follow the new root. |
| **Two root keys are lost** | You can no longer sign a root. See below. | Updates keep working until the root expires, then stop. |
| **Two root keys leaked** | Sign a new root without them **immediately**, with the keys you still have, and publish it. Then see below. | A client that took your new root first is safe. A client that took a root signed by the attacker first now trusts the attacker and must be reset by hand. |

**Starting a new root of trust.** When the threshold is lost or leaked, no update can fix clients, because every update is checked against the old keys. You need a new ceremony and a manual reinstall:

1. Hold a new ceremony ([section 3](#3-the-ceremony)) with all new keys. Set `ROOT_VERSION` higher than any root you or the attacker could have published (when in doubt, a large round number such as `1000`).
2. Build new packages and images with the new `release/update-root.json`.
3. Announce it. Members install the new package by hand over the old one. The updater uses the shipped root when it is newer than the one it stored (`load_trust` in `crates/faro-service/src/update/mod.rs`), so the new trust takes over and no data is lost. Instance admins replace their `update-root.json`, and the mirror does the same (`server/src/updates/mod.rs`).
4. If an attacker pushed a client to an even higher root version, the shipped root isn't newer and is ignored. On that computer, delete `/Library/Application Support/Faro/update-trust.json` and restart the service (`sudo launchctl kickstart -k system/org.faro.service`).

---

## 7. Printable checklist

**Before**

- [ ] Spare Mac erased, set up with a local account, FileVault on, Wi-Fi and Bluetooth off, offline check fails ([2.3](#23-prepare-the-air-gapped-mac))
- [ ] Seven new USB drives, labelled `ROOT-A`, `ROOT-A2`, `ROOT-B`, `ROOT-B2`, `ROOT-C`, `ROOT-C2`, `TRANSFER`
- [ ] Three places chosen, one key per place
- [ ] Four passphrases generated and saved (A, B, C, TRANSFER)
- [ ] Rehearsal done with throwaway keys and deleted ([2.2](#22-rehearse-first-recommended))
- [ ] `faro-release` built from a clean clone, tests pass, commit written in the log ([2.4](#24-build-faro-release-on-your-connected-mac))
- [ ] `TRANSFER` encrypted, program and checksum copied, checksum written in the log ([2.5](#25-prepare-the-transfer-drive-and-copy-the-program))
- [ ] Printouts and pen ready

**Ceremony**

- [ ] Clock checked against a phone ([3.1](#31-set-up))
- [ ] `faro-release: OK`, checksum matches the log
- [ ] Six root drives encrypted ([3.2](#32-encrypt-the-six-root-drives))
- [ ] Key A generated, `backup OK` ([3.3](#33-generate-the-three-root-keys))
- [ ] Key B generated, `backup OK`
- [ ] Key C generated, `backup OK`
- [ ] Targets and timestamp keys generated on `TRANSFER` ([3.4](#34-generate-the-targets-and-timestamp-keys))
- [ ] Root 1 written: five different key ids, expiry one year out ([3.5](#35-write-root-1))
- [ ] Root 1 signed with A, B and C ([3.6](#36-sign-root-1-with-all-three-root-keys))
- [ ] `verify` prints `OK: root v1, timestamp v1 …, targets v1` ([3.7](#37-verify-root-1))
- [ ] One-signature check fails as expected, throwaway files deleted
- [ ] Key ids and the `1.root.json` checksum written in the log ([3.8](#38-record-the-fingerprints))
- [ ] Public files on `TRANSFER` and on all six root drives ([3.9](#39-copy-the-public-files-out))
- [ ] Each drive bagged, sealed, bag numbers in the log
- [ ] Air-gapped Mac shut down

**After**

- [ ] Online keys uploaded, `gh secret list` shows both ([4.3](#43-upload-the-online-keys-option-a))
- [ ] Public files copied off, `TRANSFER` erased
- [ ] Root drives taken to their three places ([4.1](#41-the-root-keys))
- [ ] `release/update-root.json` committed, checksum matches the log ([5](#5-shipping-root-1))
- [ ] Calendar reminder set two months before the root expires ([6.2](#62-renew-the-root-every-year))
- [ ] Log signed, photographed, and kept with the place 1 drives

---

## 8. Ceremony log template

Print one per ceremony or rotation. Keep the original with the place 1 drives and a photo in your password manager. It holds no secrets.

```text
FARO UPDATE KEY CEREMONY LOG

Kind:           [ ] first ceremony   [ ] root renewal   [ ] rotation   [ ] compromise
Date (UTC):     ____________________   Start: ________   End: ________
Location:       ______________________________________________
Present:        ______________________________________________
                ______________________________________________

faro-release built from commit:  ________________________________________
faro-release SHA-256 (first 8 / last 8):  ________ … ________
Air-gapped Mac (model, serial):  ________________________________________
Clock checked against:  ____________   Difference: ________

New root version:  ______   Expires (UTC):  ____________________
Signed by root keys:  [ ] A   [ ] B   [ ] C   [ ] ________

KEY IDS (16 hex characters)
  root A:      ________________     drives: ROOT-A, ROOT-A2    place: __________
  root B:      ________________     drives: ROOT-B, ROOT-B2    place: __________
  root C:      ________________     drives: ROOT-C, ROOT-C2    place: __________
  targets:     ________________     stored: __________________________
  timestamp:   ________________     stored: __________________________

<n>.root.json SHA-256:
  ________________________________________________________________

verify output:  ____________________________________________________

Tamper-evident bag numbers:
  ROOT-A ______  ROOT-A2 ______  ROOT-B ______  ROOT-B2 ______
  ROOT-C ______  ROOT-C2 ______

Keys removed in this rotation, and why:
  ________________________________________________________________

Notes / anything unexpected:
  ________________________________________________________________
  ________________________________________________________________

Signed: ______________________   Witness: ______________________
```
