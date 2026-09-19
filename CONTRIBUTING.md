# Contributing to Aegis AI

Thank you for helping improve Aegis. The project is created by Heinrich and licensed under MIT. Keep contributions focused, reviewable, and honest about what the app can verify.

## Development

Use Node.js 22 and npm:

```sh
npm ci
npm test
npm run build
```

Use `npm run dev` for the browser preview and `npm run desktop` for the Electron app. Browser fixtures must remain visibly labeled as examples. Native functions belong behind the explicit preload/IPC interface; do not add Node access to the renderer or load a remote website into the privileged desktop window.

Before submitting a pull request, describe the concrete problem, resulting behavior, tests run, and any platform limitations. Add screenshots for visible UI changes. Use the actual native outcome when reporting success; a message or demo animation must never imply that a scan, repair, or OS change occurred.

## Testing

`npm test` runs the native Node test suite. Add focused regression tests for new filesystem mutations, input validation, redaction, engine parsing, and provider invocation boundaries. Use temporary directories, generated harmless fixtures, and injected command/provider mocks. The harmless EICAR test signature may trigger a locally installed antivirus; do not disable that antivirus to make tests pass. Never add live malware, account tokens, private device reports, or private file paths to fixtures.

Cloud-provider tests must not spend account usage or transmit real reports. CLI authentication checks should be read-only and must not scrape credential stores. Separate optional live/manual integration checks from the default test suite and explain their data/account effects before running them.

For platform-specific behavior, test on the relevant OS or clearly record what remains unverified. Packaging success is not proof that diagnostics, permissions, sensors, quarantine, or power controls work on every machine. Use the matching native runner for Windows and macOS builds.

## Design and security expectations

- Preserve the default of explicit, bounded device access and reversible actions where possible.
- Keep symlink, hard-link, identity/hash, and root-boundary checks around filesystem mutations. Do not replace same-volume quarantine with a copy-and-delete fallback without a reviewed recovery design.
- Treat paths, scanner output, findings, and model responses as untrusted data. Use subprocess argument arrays with no shell; never construct commands from an AI response.
- Keep cloud analysis opt-in and report summaries allowlisted. Do not add raw file contents, process command lines, addresses, or credentials to provider prompts.
- Report unknowns as unknowns. Heuristic names/resource use do not prove malware; missing sensor data does not mean healthy hardware.
- Do not add broad automatic deletion, arbitrary remediation executors, silent OS protection changes, hidden background persistence, or claims of universal virus/vulnerability detection.
- Keep capability tables, platform restrictions, setup links, and release notes synchronized with the implementation.

Read [SECURITY.md](SECURITY.md) before changing security boundaries. Report exploitable issues privately where possible rather than publishing exploit details in a pull request.

## Builds and releases

The workflow validates tests, builds the web UI, audits production dependencies, and builds Windows/macOS packages. `npm run dist:win` and `npm run dist:mac` write to `release/`. Early artifacts are unsigned and macOS builds are not notarized; preserve that disclosure unless signing is actually configured and verified.

Maintainers publish through a `v*` tag after reviewing checks and smoke-testing packaged applications. The release workflow publishes installers and a SHA-256 manifest only after its build jobs succeed. Check the actual release assets before updating download claims. Netlify hosts only `dist/`, the browser preview; it must not be presented as a native security service.

Do not commit `node_modules/`, `dist/`, `release/`, `.netlify/`, environment secrets, account state, signing materials, scan exports, or quarantine storage. Dependency updates should include the lockfile, relevant checks, and review of runtime permissions. Contributions are accepted under the project's [MIT license](LICENSE).
