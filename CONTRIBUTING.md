# Contributing

Use focused changes within the architecture ownership map. Keep production command entries thin, native calls behind their platform/transaction boundaries and the desktop limited to intent and presentation. Do not rename compatibility identities during cleanup.

Run `python3 scripts/project.py check` and `python3 scripts/project.py package` before proposing a distribution change. Preserve original library notices. Catalog updates require an official origin, independently recorded digest, signer requirement and tested failure/retry paths. Never add a third-party installer, driver, runtime, signing key, token, raw device log or private device identifier to Git.

Preserve protected journal ownership and independent readback. A retained log or successful cross-build is not hardware proof. Report Windows/Mac/iPad validation separately and leave untested cases pending.

This source repository intentionally has a new public history. The original development history, package archives, untracked local documents and device evidence stay in their local source workspace.

Develop directly in this checkout; do not maintain a second publication copy.
Run `python3 scripts/project.py setup` once per clone to enable the Git checks.
Private material belongs in the ignored `.local/` directory. See
[workspace and synchronization](docs/WORKSPACE.md).
