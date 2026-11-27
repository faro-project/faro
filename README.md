<p align="center">
  <img src="assets/brand/faro-wordmark.svg" alt="Faro" width="360">
</p>

<p align="center"><strong>Free, open-source, self-hosted screen accountability.</strong></p>

Faro is an accountability tool, not a surveillance tool. A person chooses to install it on their own computer and invites people they trust (their **allies**). Faro detects explicit content **on the device** and sends allies an **end-to-end-encrypted** report: a summary, a timeline and heavily blurred thumbnails. Allies are also told when monitoring stops or is tampered with.

There is no central Faro service. A church, a college, a small group or one person runs their own **Faro instance**, and the instance operator can't see anyone's reports.

> **Status: pre-alpha.** The protocol, cryptography and core crates are under active construction. Nothing here is ready to install yet.

## How it's private by construction

- **No unblurred image is ever stored, by anyone,** including the member's own device. Frames exist only in memory long enough to classify and blur, and are then zeroized.
- **The instance is an encrypted mailbox.** It stores ciphertext plus the minimal metadata it needs for routing, liveness and notification timing. It never runs ML or decrypts anything.
- **Members control the keys.** Devices only encrypt to ally keys signed by the member, so neither the operator nor an attacker who breaks into the server can add an eavesdropper.
- **Tamper-evident, not tamper-proof.** Every event is signed and hash-chained. Allies find out when monitoring stops, gets tampered with, or has events removed.
- **Updates are signed by the project,** not the instance, so a compromised instance can't push code to clients.

## Documentation

- [Architecture](docs/ARCHITECTURE.md): the full design, threat model and roadmap.
- [Status](docs/STATUS.md): what is built, partly built and only planned, dated. Read it alongside the architecture.
- [Wire protocol](docs/PROTOCOL.md): byte-level signing, hashing and encryption formats.
- [Development](docs/DEVELOPMENT.md): building, testing, crate map and the invariants every change must keep.
- [iOS client](docs/IOS.md): the design of the iPhone client, which blocks rather than watches, and what it can and can't do.
- [Closed beta](docs/BETA.md): for the pilot instances and the people they enroll: what the beta is (the Mac, Windows and iPhone clients), setting up, the alerts to expect, reporting problems and leaving.
- [Self-hosting](docs/SELF-HOSTING.md): running a Faro instance, for operators.
- [Ally guide](docs/ALLY-GUIDE.md): a plain-language guide for allies, from accepting an invitation to having the conversation.
- [Adding your Mac, Windows PC or iPhone](docs/MEMBER-GUIDE.md): a plain-language guide for members, from the enrollment link to approving the computer or phone.
- [Key ceremony](docs/KEY-CEREMONY.md): the maintainer's runbook for creating and rotating the update signing keys.
- [Security policy](SECURITY.md): how to report a vulnerability, and what's in scope.

## Repository layout

```
crates/   Rust client crates (proto, crypto, core, client, detect, dnsfilter, mobile, ipc, platform, update, service, agent)
server/   faro-server, the self-hosted instance
apps/     the iOS app and its extensions (apps/ios)
docs/     architecture, protocol and development docs
assets/   brand assets (logo, colours)
```

## License

Copyright © 2026 Isaiah Zimmerman.

Faro is free software under the [GNU Affero General Public License, version 3 or later](LICENSE) (AGPL-3.0-or-later). You may use, study, modify and share it. If you distribute a modified version, or run one that people use over a network (a modified `faro-server`, for example), you must offer those people its source under the same licence. Running an unmodified Faro instance asks nothing extra of you.

Contributions are accepted under the [Contributor License Agreement](CLA.md). Contributors keep their copyright and grant the maintainer a licence that also allows distributing Faro under other terms (for example an app-store build or a commercial edition). In return, the CLA promises that every contribution stays publicly available under the AGPL or another open-source licence. See [CONTRIBUTING.md](CONTRIBUTING.md).

The "Faro" name and logo are not covered by the licence and are reserved for official, project-signed builds (see ARCHITECTURE.md §11 and [assets/brand](assets/brand/README.md)). Forks are welcome under their own name.

Faro is built on open-source software by others. The licences and copyright notices of everything it ships with are generated at build time and travel with it ([how](docs/DEVELOPMENT.md#third-party-notices)):

- **On a Mac:** `/Library/Faro/notices/`, `third-party.txt` for the Rust crates, next to the image model's, the domain list's (`domains.txt`) and ONNX Runtime's notices.
- **On Windows:** the MSI installs them in `C:\Program Files\Faro\notices`.
- **The server image:** `/usr/share/faro/notices/`, `third-party.txt` for the Rust crates in `faro-server` and `third-party-web.txt` for the web app's npm packages.
- **The server binaries:** `faro-server-<version>-linux-<arch>-third-party.txt`, next to each binary in the release.
- **The web app:** the **Licences** page (`/licenses`, linked from every page's footer) of any instance.
