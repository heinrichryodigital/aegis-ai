# Security policy

Aegis AI is an early, user-space security workbench. It is not a certified endpoint protection product, tamper-resistant agent, or assurance that a device is free of malware. Keep operating system security protections enabled.

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/heinrichryodigital/aegis-ai/security/advisories/new) if it is enabled. If private reporting is unavailable, open a minimal issue requesting a private contact method; do not include exploit details, malware samples, credentials, or personal reports in that public request.

Include the affected version or commit, OS/architecture, reproduction steps using harmless fixtures, expected/actual behavior, and the security impact. Redact usernames, paths, IPs, tokens, and other personal data. Do not upload live malware. There is no guaranteed response time or bug bounty. Security fixes are developed against the latest source; older preview builds are not promised backported fixes.

## Trust boundaries

- The browser preview is demonstration software. It has no native device bridge.
- The desktop renderer has context isolation, sandboxing, and no Node integration. The preload bridge exposes a fixed action list, and main-process IPC checks the sender frame and loaded application URL.
- The native main process runs with the current user's privileges. It can read selected files and system metadata and can perform the explicitly exposed mutations. Aegis does not request privilege escalation or install a service/driver.
- The installed ClamAV and AI CLI executables are trusted dependencies. Discovery/version checks are not cryptographic verification of those executables. Keep them current and use trusted installation sources.
- Filenames, engine output, process names, findings, and AI responses are untrusted input. AI responses must remain display-only; never feed them into a shell or a generic action executor.

The security model does not protect against a compromised OS, a malicious process with equivalent user access, an administrator, or a modified Aegis binary. Filesystem checks reduce path-redirection and replacement risks; user-space checks cannot eliminate every concurrent filesystem race.

## Scan and remediation boundaries

Scanning is bounded and limited to selected folders or the Downloads watcher. It does not inspect memory, boot sectors, firmware, kernel activity, or arbitrary remote hosts. Without separately installed ClamAV and a usable signature database, the built-in check only recognizes the harmless EICAR test file. Missing detections and a completed bounded scan are not proof of safety.

Quarantine is restricted to current eligible detections whose identity and hash still match. Single-link files are moved into private application storage with same-filesystem rename. Cross-volume operations, changed files, and heuristic/PUA findings are refused for automatic isolation. The EICAR test file is eligible so that users can test the workflow. Restoring does not overwrite an existing file and does not restore Unix executable bits. Preserve payloads and metadata when recovery is required. Quarantine is neither encrypted nor isolated from other programs running as the same user.

Cleanup previews only aged `.tmp`, `.temp`, and `.log` candidates in specific personal folders. It excludes protected locations and links and revalidates metadata/hash before calling OS Trash. It does not prove that a candidate is unneeded or currently unused. OS Trash remains path-based; do not use cleanup as an adversarial filesystem sandbox. Back up important data and review the entire candidate list.

Network review reads this host's interfaces, connections, selected listeners, and firewall state. It does not verify remote exploitability, inspect Wi-Fi traffic, or block an attacker. Gateway-change monitoring can produce benign notices and cannot detect every hijack. Watchers stop when the app exits and do not block files before execution.

## AI and data handling

The offline advisor has no model-provider dependency. External analysis requires a user action and confirmation, then reuses a supported native CLI's own login. Aegis does not directly read/copy credential stores or browser sessions.

The report sent to a provider is a fixed-schema summary: counts, bounded numeric telemetry, severity/categories, and derived fixed signal labels. Raw file bytes, paths, filenames, process names, IPs, hostnames, and evidence strings are excluded. The user's question is sent after best-effort redaction; do not enter secrets. Exported JSON reports are different: they can contain personal device metadata and require review before sharing.

Claude Code runs with tools denied, empty strict MCP configuration, bare/restricted behavior, and session persistence disabled. Codex runs in an empty temporary working directory with read-only sandboxing, ephemeral execution, ignored user configuration/rules, and verified execution-feature disables. Codex has no verified universal deny-all-tools boundary in this integration; its CLI remains a trusted local application with account access. Provider administrative policies, runtime behavior, and service-side data handling are outside Aegis's control. Do not claim that the read-only sandbox guarantees all local data is inaccessible.

AI output never drives remediation. Authentication and capability probes do not send a scan report for analysis. No AI analysis is scheduled by the protection watchers.

## Local data and releases

Electron user-data storage holds preferences and quarantine metadata/payloads. The quarantine audit log includes original paths and hashes. Unix file modes are restricted where supported, but Aegis does not implement encrypted storage or additional Windows ACL management. Never commit this data, account configuration, exported reports, or signing credentials.

Initial Windows/macOS packages are unsigned; macOS packages are not notarized. Release checksums detect changed downloads relative to the published manifest but do not replace code signing or establish an independent trust anchor. CI builds and tests provide useful checks, not antivirus certification or an independent security audit.
