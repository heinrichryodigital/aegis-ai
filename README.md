# Aegis AI

**An open-source device security and performance workbench, created by Heinrich.**

Aegis combines a React + TypeScript dashboard with an Electron desktop app for Windows and macOS. Inspect a folder, review security and resource findings, quarantine eligible detections, and ask an offline advisor or a supported local AI CLI to explain the results.

This is an early preview, not a certified antivirus or a replacement for Microsoft Defender, macOS built-in protection, or professional incident response. No scanner can guarantee detection of every virus, miner, surveillance tool, or vulnerability. Keep your operating system protection enabled.

[Website preview](https://aegis-ai-heinrich.netlify.app) · [Source](https://github.com/heinrichryodigital/aegis-ai) · [Releases](https://github.com/heinrichryodigital/aegis-ai/releases) · [Security policy](SECURITY.md) · [Contributing](CONTRIBUTING.md) · [MIT license](LICENSE)

## What works

| Feature | Current implementation | Boundary |
| --- | --- | --- |
| Web dashboard | Interactive React preview with labeled example data | A website cannot inspect this device, quarantine files, or change OS settings. Native actions require the desktop app. |
| Manual file scan | User-selected folder; separate local ClamAV integration; built-in harmless EICAR test check | ClamAV and current signatures must be installed separately. Without them, the built-in check detects only the EICAR test file. |
| Quarantine | Reversible isolation for eligible current detections; optional automatic quarantine | Single-link regular files on the same filesystem as quarantine storage. Heuristic and potentially unwanted application findings are excluded. |
| Device diagnostics | CPU, memory, disk use, process resource use, battery charge, available temperature and SMART readings | Snapshots and heuristic findings; missing readings remain unavailable. RAM usage is not a physical-memory test. |
| Network review | This host's interfaces, connections, selected listening services, and OS firewall state | No subnet discovery, remote port scanning, exploit testing, packet interception, or router assessment. |
| Download watch | Watches additions/changes in Downloads and queues bounded folder scans | App must remain open. It does not block downloads or intercept files before execution. |
| Network watch | Notices a change in the default gateway address | App must remain open; a changed address can be normal, and an unchanged address does not establish network safety. |
| Cleanup | Preview eligible `.tmp`, `.temp`, and `.log` files at least seven days old, then send reviewed candidates to OS Trash | Specific personal folder only; protected locations, links, and changed files are excluded. Age and extension do not prove a file is disposable. |
| Power profiles | Select existing Windows balanced/performance/battery schemes when permitted; read Mac energy mode | macOS generally requires changing energy mode in System Settings. There is no universal High Power Mode or guaranteed speed increase. |
| Per-app tuning | Request low/normal/high scheduling priority for a verified same-user process on macOS or Windows | OS permissions can prevent changes. Windows uses BelowNormal/Normal/AboveNormal, never High or Realtime; its mutation path still needs native runtime validation. No CPU/RAM reservation or GPU overclocking. |
| AI explanations | Always-available offline rules; optional Codex or Claude Code CLI analysis | External analysis is user-initiated. Responses are displayed as advice and never executed as commands or remediation plans. |

Automatic remediation is limited to the quarantine setting. Cleanup, restoration, power changes, and process-priority changes require explicit user actions. Aegis does not silently install patches, delete suspicious applications, terminate processes, or alter firewall rules.

## Getting started

### Desktop download

Check [GitHub Releases](https://github.com/heinrichryodigital/aegis-ai/releases) for completed builds. The release workflow targets:

- Windows x64: NSIS `.exe` installer.
- macOS Apple Silicon (`arm64`): `.dmg` and `.zip`.
- macOS Intel (`x64`): `.dmg` and `.zip`.

Early builds are unsigned and macOS builds are not notarized. OS security warnings may appear. Review the source and release provenance; do not disable system-wide protections to install Aegis. Release checksums, when present, help verify downloaded file integrity but are not a publisher signature. If a release is not available, build from source below. A successful package build does not demonstrate compatibility with every OS version or device.

### Run from source

Use Node.js 22 and npm, matching CI. Clone the repository, then install dependencies:

```sh
git clone https://github.com/heinrichryodigital/aegis-ai.git
cd aegis-ai
npm ci
npm test
npm run desktop
```

`npm run desktop` builds the React interface and opens the local Electron application. Run it as your regular user. Aegis does not request administrator credentials or install a background service.

For the browser preview:

```sh
npm run dev
```

Open the localhost address printed by Vite. The browser uses example readings and simulated actions; it does not scan your computer. To preview a production web build, use `npm run build` followed by `npm run preview`.

### Install a malware engine

ClamAV is **not bundled**. Install it separately, configure its signature database updater, and verify that **Settings → Engines & integrations** recognizes it. Aegis invokes `clamscan` locally; it does not invoke Microsoft Defender, download signature updates, or manage ClamAV services.

On macOS, an existing Homebrew installation can install ClamAV:

```sh
brew install clamav
```

Follow the official [package instructions](https://docs.clamav.net/manual/Installing/Packages.html) to create `freshclam.conf` from the supplied sample if needed and remove/comment its `Example` line. Configuration paths depend on the package prefix; use `brew --prefix` to identify your installation. Aegis recognizes the usual Homebrew executable paths `/opt/homebrew/bin/clamscan` and `/usr/local/bin/clamscan`, plus the official macOS package location `/usr/local/clamav/bin/clamscan`. The official package requires its own configuration/database setup; consult [ClamAV installation](https://docs.clamav.net/manual/Installing.html#macos).

On Windows, use the official installer described in [ClamAV installation](https://docs.clamav.net/manual/Installing.html#windows). Aegis looks for `ClamAV\clamscan.exe` under `Program Files`; a portable copy in another folder is not automatically discovered. Follow [ClamAV configuration](https://docs.clamav.net/manual/Usage/Configuration.html) to create and configure `freshclam.conf` and the database location.

After configuration, update signatures using `freshclam` (`freshclam.exe` on Windows), then check `clamscan --version`. Keep updates current according to the official [signature update guide](https://docs.clamav.net/manual/Usage/SignatureManagement.html). The app reports the database date when the CLI provides it, and warns when it appears older than seven days or freshness is unknown. That warning is not an automatic update or a guarantee of coverage.

### First use

1. Open the desktop app and refresh readings. Review any unavailable checks.
2. Confirm the ClamAV engine and signature status in Settings.
3. Choose a specific folder in Security scan. Read the findings, skipped counts, and coverage warnings.
4. Quarantine an eligible finding if appropriate. Enable automatic quarantine only if you want future eligible detections in scanned/watched folders moved automatically.
5. Use AI assistant for an explanation. Offline guidance does not contact a provider; an external provider requires a separate send confirmation.

## Scan and quarantine boundaries

The scanner handles regular files under the selected folder. It skips symbolic links, redirected paths, private scanner storage, inaccessible entries, and files over 64 MiB. Each scan is bounded to 20,000 files, 100,000 enumerated entries, 4 GiB of file data, 32 directory levels, and approximately 20 minutes; engine work also has its own limits. Read warnings even when a scan's status is `complete`: completion of the bounded run is not complete device coverage.

ClamAV archive inspection is subject to engine limits and does not make encrypted content readable. Aegis does not inspect process memory, boot sectors, firmware, or kernel activity. Resource pressure and mining-related process names are leads for review, not proof of unauthorized mining or surveillance.

Quarantine records the original path, file identity, and SHA-256, checks the file again before moving it, and uses an atomic same-filesystem rename. Hard-linked files and changed files are refused. Cross-volume isolation is not supported, so a file on an external drive may need the operating system antivirus instead. Heuristic/PUA alerts do not qualify for automatic isolation; the harmless EICAR test file does, to exercise the workflow.

Restoration checks the stored payload and refuses to overwrite an existing destination. On platforms with Unix permission bits, restored files do not regain executable bits. If a record says recovery is required, preserve the quarantine directory and investigate before manually moving files. Quarantine is user-owned storage, not an encrypted vault or protection against malware already running as the same user.

## Cleanup and performance

Choose a specific personal folder and review the cleanup list before confirming. Cleanup excludes broad roots, the whole home folder, hidden directories, app bundles, application data, system locations, symbolic/hard links, and other protected paths. Only qualifying regular `.tmp`, `.temp`, and `.log` files are candidates; logs may still be valuable. The UI currently moves the reviewed candidate set together, so cancel if any candidate should be retained.

A preview is bounded to 200 candidates, 64 MiB per file, 256 MiB hashed data, 5,000 entries, 500 directories, eight levels, and approximately 20 seconds. Previews expire after 15 minutes. Before trashing, Aegis rechecks identity, age, paths, and contents. OS Trash is path-based; these checks reduce races but do not create a kernel-enforced deletion boundary. Recover files through Trash or Recycle Bin. Aegis does not empty it.

There is no registry sweeping, memory flushing, or automatic deletion of applications. High memory use alone is not defective RAM. SMART and temperature availability varies with hardware, permissions, bridges, and sensor support; use manufacturer/OS diagnostics for hardware testing. Power profiles and priority adjustments affect scheduling and energy policy, not hardware capabilities or guaranteed performance. Windows process tuning verifies ownership and process identity and refuses elevated/ambiguous requests; native Windows mutation behavior remains to be validated, so check the reported result instead of assuming a change succeeded.

## AI providers and privacy

The offline advisor uses deterministic local rules. It is not an on-device language model and works without an account or API key.

For cloud explanations, Aegis can reuse a **supported native CLI's own existing login**. It never extracts browser sessions, reads token stores directly, or copies credentials from another application. Being signed into an arbitrary browser chat or desktop app does not necessarily make a CLI available.

- **Codex / ChatGPT:** install the official Codex CLI or use a discoverable bundled native CLI, sign in with `codex login`, and check `codex login status`. The adapter verifies required CLI capabilities. Analysis uses an empty temporary working directory, read-only sandbox, ephemeral execution, and disabled shell, browser/computer, hooks, plugins, apps, and other execution-related features. It ignores user configuration and rules for that invocation. Codex remains a trusted local program: this is not an OS privacy sandbox or a verified deny-all-tools boundary. See [Codex authentication](https://learn.chatgpt.com/docs/auth) and [non-interactive mode](https://learn.chatgpt.com/docs/non-interactive-mode).
- **Claude Code:** install a supported native CLI and sign in using `claude auth login`. Required flags include bare/restricted execution, no built-in tools, denied tools, an empty strict MCP configuration, and no session persistence. Older CLIs without verified controls are unavailable. See the official [Claude Code CLI reference](https://code.claude.com/docs/en/cli-reference).
- **Antigravity:** unavailable in this version because no supported tool-free headless interface has been verified. Aegis does not work around this by extracting a login session.

No background AI analysis occurs. After you select a cloud provider and confirm **Send summary & analyze**, its CLI receives fixed-schema counts, severity/category values, derived signal labels, numeric resource metrics, and your redacted question. Raw report paths, filenames, process names, IP addresses, hostnames, raw evidence, and file contents are omitted from that report summary. Question redaction is best effort; do not put secrets or confidential file contents into the question. Provider account limits, availability, and data policies still apply. Aegis does not promise free or unlimited inference.

Provider responses are displayed as text. They do not authorize shell execution, quarantine, deletion, or OS changes. Aegis has no API-key entry form and does not forward inherited OpenAI/Anthropic API-key environment variables to these adapters.

The app does not implement its own telemetry or a report-upload service. External CLIs, your web host, and dependency/update tools have their own behavior and policies. A manual **Export current report** saves the full report, which can include device names, paths, process information, and network addresses. Review exports before sharing; they are not the same as the reduced AI summary.

Local preferences are stored in Electron's application user-data directory. Quarantine uses its `security/quarantine` subdirectory, with metadata and a local `security/quarantine-audit.jsonl` trail. Those records contain original paths and hashes. Keep this data private and do not commit it.

## Build, release, and web hosting

```sh
npm test
npm run build
```

Build desktop packages on the corresponding OS:

```sh
# macOS: Apple Silicon and Intel DMG/ZIP targets
npm run dist:mac

# Windows: x64 installer
npm run dist:win
```

Packages are written to `release/`. Code signing is intentionally unconfigured for this preview. Do not represent these artifacts as signed, notarized, independently audited, or certified.

The [GitHub Actions workflow](.github/workflows/build.yml) validates tests, TypeScript/web builds, and production dependency auditing; it then builds on Windows and macOS runners. A successfully completed `v*` tag workflow publishes installers and `SHA256SUMS.txt` to GitHub Releases. Check the workflow result and actual assets before announcing a release. Maintainers should smoke-test the packaged app on each target OS and architecture.

Netlify serves only the web preview. The included [netlify.toml](netlify.toml) sets Node 22, runs `npm run build`, and publishes `dist/` with security headers and SPA routing. The public preview is deployed at [aegis-ai-heinrich.netlify.app](https://aegis-ai-heinrich.netlify.app). Deployment was published through the Netlify CLI; automatic GitHub-to-Netlify deployment is not configured. Desktop binaries belong in GitHub Releases, not the browser's native bridge.

## Project layout

```text
src/                    React + TypeScript UI and labeled demo data
desktop/main.cjs        Electron window, IPC validation, confirmations, watchers
desktop/preload.cjs     Narrow renderer bridge
desktop/scanner.mjs     Bounded file scanning and reversible quarantine
desktop/diagnostics.mjs Host inventory, exposure review, power and priority controls
desktop/cleanup.mjs     Reviewed temporary-file cleanup through OS Trash
desktop/providers.mjs   Reduced AI summaries and native CLI adapters
desktop/*.test.mjs      Node tests for native behavior and boundaries
.github/workflows/      Validation and unsigned release packaging
```

Created and maintained by **Heinrich**. Aegis code is available under the [MIT license](LICENSE); dependencies and external antivirus/AI tools retain their own licenses and terms.
