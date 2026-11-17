# Releasing

This checklist covers the one-time repository setup and each release. It is
deliberately conservative: never publish a firmware image or a commit that
contains deployment credentials.

## One-time setup

1. Create the GitHub repository (suggested name: `wimon`) and push `main`.
2. Replace the `OWNER` placeholder in:
   - `README.md` (CI badge)
   - `pyproject.toml` (`[project.urls]`)
   - `.github/ISSUE_TEMPLATE/config.yml`
3. Enable:
   - Issues and Discussions
   - Private vulnerability reporting (Security → Advisories)
   - Branch protection on `main`: require CI, the firmware matrix and the secret
     scan before merging
   - Dependabot alerts and security updates
4. Confirm that `git remote -v` points at the new repository and that no
   `refs/t3/*` or other local tool refs are present:

   ```sh
   git for-each-ref
   ```

5. Run a secret scan over the full history before the first push:

   ```sh
   gitleaks detect --redact --log-opts="--all"
   ```

## Every release

1. Update `wimon/_version.py`, `pyproject.toml` and `CHANGELOG.md`.
2. Run the full local checks:

   ```powershell
   py wimon/tests/run_all.py
   ruff check .
   idf.py set-target esp32c5
   idf.py build
   ```

3. Build firmware **only** with placeholder credentials. The simplest way is to
   remove the local `sdkconfig`, build from `sdkconfig.defaults`, and confirm the
   image contains no real SSID, passphrase or OTA token:

   ```powershell
   Remove-Item sdkconfig -ErrorAction SilentlyContinue
   idf.py set-target esp32c5
   idf.py build
   ```

   Do not attach `build/esp32_wifi_monitor_cluster.bin` if it was produced with
   a real `sdkconfig`. Prefer source-only releases; if you publish binaries,
   document exactly how they were built and include SHA-256 checksums.

4. Tag and push:

   ```sh
   git tag -s v0.1.0 -m "wimon 0.1.0"
   git push origin main --tags
   ```

5. Create a GitHub Release from the tag. Include:
   - a short summary and the changelog section;
   - upgrade notes for firmware or capture-format changes;
   - checksums for any attached artifact;
   - a link to `SECURITY.md`.

## What must never be committed

- `sdkconfig`, `sdkconfig.old`, `.wimon/`
- `captures/`, `telemetry.jsonl`, `*.pcap`, `*.sqlite`
- `build/`, `build-*/`, `managed_components/`
- `eim_config.toml` (machine-specific ESP-IDF installation paths)
- real SSIDs, passphrases, OTA tokens, MAC addresses, hostnames or public IPs

The repository history was rewritten once to remove deployment data. If you
import old commits from a backup, scan them again before pushing.
