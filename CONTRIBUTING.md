# Contributing to Faro

Thank you for helping. Faro is a monitoring tool that people trust with their privacy, so every change is reviewed against a short list of guarantees it must never weaken.

## Before you start

- **Read the design first.** [ARCHITECTURE.md](docs/ARCHITECTURE.md) explains what Faro does and why. [DEVELOPMENT.md](docs/DEVELOPMENT.md) covers building, testing and the crate map.
- **Know the invariants.** [DEVELOPMENT.md, "Invariants every change must keep"](docs/DEVELOPMENT.md#invariants-every-change-must-keep) lists the six rules reviewers check on every pull request: for example, no unblurred image ever leaves memory, and tamper alerts can't be silenced.
- **For anything large, open an issue first,** so we can agree on the approach before you spend time on it.
- **Security problems:** don't open a public issue. Contact the maintainer privately through GitHub.

## Making a change

1. Work on a branch and keep each pull request to one change.
2. Run the checks CI runs:

   ```sh
   cargo fmt --all
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test --workspace
   cargo deny check
   ```

   For changes in `web/`, also run `npm run lint`, `npm run check` and `npm test` there.
3. Explain in the pull request what changed and why, and how you tested it.

## Licence and the CLA

Faro is under the [GNU AGPL, version 3 or later](LICENSE). Before your first pull request can be merged, you sign the [Contributor License Agreement](CLA.md) by posting a comment on the pull request; a bot asks you to and records it. In short:

- **You keep the copyright** in your contribution.
- **You grant the maintainer a licence** to use it, including under terms other than the AGPL, for example an app-store build (app-store terms conflict with the GPL family) or a commercial edition.
- **The maintainer promises** that every contribution stays publicly available under the AGPL or another open-source licence.
- **You confirm** that you have the right to contribute it: it is your own work, or you have permission, and you have reviewed any part an AI tool wrote.

Third-party code, models and data you add must be under a permissive licence (Apache-2.0, MIT, BSD and similar; see ARCHITECTURE.md §11). `cargo deny check` enforces this for Rust dependencies.

The "Faro" name and logo aren't covered by the licence; see [assets/brand](assets/brand/README.md).
