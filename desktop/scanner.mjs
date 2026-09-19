import fs from "node:fs/promises";
import { constants } from "node:fs";
import path from "node:path";
import { createHash, randomUUID } from "node:crypto";
import { spawn } from "node:child_process";

// This module deliberately has no network access, privilege escalation, shell execution,
// or heuristic cleanup. EICAR is a harmless scanner test, not a malware engine.
const EICAR = Buffer.from(
  "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
);
const LIMITS = Object.freeze({
  files: 20_000,
  entries: 100_000,
  bytes: 4 * 1024 ** 3,
  fileBytes: 64 * 1024 ** 2,
  depth: 32,
  duration: 20 * 60_000,
});
const UUID = /^[a-f0-9-]{36}$/i;
const inside = (root, candidate) => {
  const relative = path.relative(root, candidate);
  return (
    relative === "" ||
    (!relative.startsWith(`..${path.sep}`) &&
      relative !== ".." &&
      !path.isAbsolute(relative))
  );
};
const identity = (stat) => ({
  dev: stat.dev,
  ino: stat.ino,
  size: stat.size,
  mtimeMs: stat.mtimeMs,
  ctimeMs: stat.ctimeMs,
  mode: stat.mode,
  nlink: stat.nlink,
});
const sameFile = (a, b, includeChangeTime = true) =>
  a.dev === b.dev &&
  a.ino === b.ino &&
  a.size === b.size &&
  a.mtimeMs === b.mtimeMs &&
  (!includeChangeTime || a.ctimeMs === b.ctimeMs);
const message = (error) =>
  error instanceof Error ? error.message : String(error);

/** Local, bounded scanner. Scans only a user-selected directory and never follows symlinks. */
export function createScanner({ dataDir, onProgress = () => {} } = {}) {
  if (!dataDir || !path.isAbsolute(dataDir))
    throw new Error("An absolute private data directory is required.");
  const directory = path.resolve(dataDir);
  const quarantineRoot = path.join(directory, "quarantine");
  const detections = new Map();
  const children = new Set();
  let scanState = null;
  let closed = false;
  let initialization;
  let operation = Promise.resolve();
  let engineCache;

  function progress(data) {
    try {
      onProgress(data);
    } catch {
      /* UI callbacks cannot break scanner safety. */
    }
  }
  function exclusive(task) {
    const next = operation.then(task);
    operation = next.catch(() => {});
    return next;
  }
  async function ensurePrivateDirectory(target) {
    await fs.mkdir(target, { recursive: true, mode: 0o700 });
    const stat = await fs.lstat(target);
    if (!stat.isDirectory() || stat.isSymbolicLink())
      throw new Error("Private storage must be a real directory.");
    // macOS has system-managed /var -> /private/var links; canonicalize only storage.
    if (process.platform !== "win32") {
      if (typeof process.getuid === "function" && stat.uid !== process.getuid())
        throw new Error("Private storage has a different owner.");
      await fs.chmod(target, 0o700);
    }
  }
  async function initialize() {
    if (!initialization)
      initialization = (async () => {
        await ensurePrivateDirectory(directory);
        await ensurePrivateDirectory(quarantineRoot);
      })();
    return initialization;
  }
  async function audit(action, record, detail) {
    const file = await fs.open(
      path.join(directory, "quarantine-audit.jsonl"),
      constants.O_APPEND |
        constants.O_CREAT |
        constants.O_WRONLY |
        (constants.O_NOFOLLOW || 0),
      0o600,
    );
    try {
      await file.writeFile(
        `${JSON.stringify({ at: new Date().toISOString(), action, id: record.id, originalPath: record.originalPath, sha256: record.sha256, ...(detail ? { detail } : {}) })}\n`,
      );
      await file.sync();
    } finally {
      await file.close();
    }
  }
  async function writeRecord(record) {
    const targetDirectory = path.join(quarantineRoot, record.id);
    const temp = path.join(targetDirectory, `${randomUUID()}.tmp`);
    const file = await fs.open(temp, "wx", 0o600);
    try {
      await file.writeFile(JSON.stringify(record, null, 2));
      await file.sync();
    } finally {
      await file.close();
    }
    await fs.rename(temp, path.join(targetDirectory, "metadata.json"));
    // Directory fsync makes the metadata rename durable where the OS supports it.
    if (process.platform !== "win32") {
      const dir = await fs.open(targetDirectory, "r");
      try {
        await dir.sync();
      } finally {
        await dir.close();
      }
    }
  }
  async function run(command, args, timeout = 120_000) {
    return new Promise((resolve) => {
      let output = "",
        errorOutput = "",
        timedOut = false,
        outputLimit = false;
      let child;
      try {
        child = spawn(command, args, {
          shell: false,
          windowsHide: true,
          stdio: ["ignore", "pipe", "pipe"],
        });
      } catch (error) {
        resolve({ code: -1, output, errorOutput: message(error) });
        return;
      }
      children.add(child);
      const timer = setTimeout(() => {
        timedOut = true;
        child.kill("SIGKILL");
      }, timeout);
      const collect = (kind, chunk) => {
        if (output.length + errorOutput.length > 1024 * 1024) {
          outputLimit = true;
          child.kill("SIGKILL");
          return;
        }
        if (kind === "out") output += chunk.toString();
        else errorOutput += chunk.toString();
      };
      child.stdout.on("data", (chunk) => collect("out", chunk));
      child.stderr.on("data", (chunk) => collect("err", chunk));
      child.on("error", (error) => {
        errorOutput += message(error);
      });
      child.on("close", (code) => {
        clearTimeout(timer);
        children.delete(child);
        resolve({
          code: code ?? -1,
          output,
          errorOutput,
          timedOut,
          outputLimit,
        });
      });
    });
  }
  async function engines() {
    if (engineCache && Date.now() - engineCache.at < 60_000)
      return engineCache.value.map(({ command, ...item }) => ({ ...item }));
    // Explicit, absolute locations avoid executing a lookalike from the scan directory.
    const candidates =
      process.platform === "win32"
        ? [
            path.join(
              process.env.ProgramFiles || "C:\\Program Files",
              "ClamAV",
              "clamscan.exe",
            ),
          ]
        : [
            "/opt/homebrew/bin/clamscan",
            "/usr/local/clamav/bin/clamscan",
            "/usr/local/bin/clamscan",
            "/usr/bin/clamscan",
          ];
    let clam = {
      id: "clamav",
      name: "ClamAV",
      available: false,
      detail:
        "ClamAV is not installed in a supported system location. Install ClamAV and update its database with freshclam.",
    };
    for (const command of candidates) {
      try {
        await fs.access(command, constants.X_OK);
      } catch {
        continue;
      }
      const version = await run(command, ["--version"], 10_000);
      if (version.code !== 0) continue;
      const text = version.output.trim().split("\n")[0];
      const match = text.match(/\/\d+\/(.+)$/);
      const databaseDate = match ? Date.parse(match[1]) : NaN;
      const age = Number.isFinite(databaseDate)
        ? Math.max(0, Math.floor((Date.now() - databaseDate) / 86_400_000))
        : null;
      clam = {
        id: "clamav",
        name: "ClamAV",
        available: true,
        command,
        detail: `${text}. ${age === null ? "Database freshness is unknown; run freshclam." : `Reported signature database age: ${age} day(s). ${age > 7 ? "STALE: update with freshclam before relying on results." : "Keep updating with freshclam."}`} A successful version check does not establish complete malware coverage.`,
      };
      break;
    }
    engineCache = {
      at: Date.now(),
      value: [
        clam,
        {
          id: "eicar",
          name: "EICAR test check",
          available: true,
          detail:
            "Limited built-in check for the harmless EICAR test file only. It does not detect real malware, archives, miners, or spyware.",
        },
        {
          id: "defender",
          name: "Microsoft Defender",
          available: false,
          detail:
            process.platform === "win32"
              ? "Managed separately by Windows Security. This adapter does not invoke Defender or change its protection settings."
              : "Windows-only protection; not available on this platform.",
        },
      ],
    };
    return engineCache.value.map(({ command, ...item }) => ({ ...item }));
  }
  async function safePath(root, filePath) {
    if (!inside(root, filePath))
      throw new Error("File is outside the selected scan root.");
    const stat = await fs.lstat(filePath);
    if (!stat.isFile() || stat.isSymbolicLink())
      throw new Error("Only regular files can be inspected or quarantined.");
    // realpath also rejects symlinks introduced in any ancestor after enumeration.
    if ((await fs.realpath(filePath)) !== filePath)
      throw new Error("Symlinks and redirected paths are not allowed.");
    return stat;
  }
  async function inspect(root, filePath, state, expected) {
    const initial = await safePath(root, filePath);
    if (initial.size > LIMITS.fileBytes)
      throw new Error("File exceeds the 64 MiB scan limit.");
    if (expected && !sameFile(initial, expected))
      throw new Error(
        "File changed since detection; scan again before taking action.",
      );
    const handle = await fs.open(
      filePath,
      constants.O_RDONLY |
        (constants.O_NOFOLLOW || 0) |
        (constants.O_NONBLOCK || 0),
    );
    try {
      const before = await handle.stat();
      if (!before.isFile() || !sameFile(before, initial))
        throw new Error("File identity changed while opening it.");
      const hash = createHash("sha256");
      const buffer = Buffer.allocUnsafe(128 * 1024);
      const sample = Buffer.alloc(Math.min(129, before.size));
      let total = 0;
      while (true) {
        if (state?.cancelled) throw new Error("Scan cancelled.");
        const { bytesRead } = await handle.read(
          buffer,
          0,
          buffer.length,
          total,
        );
        if (!bytesRead) break;
        if (total < sample.length)
          buffer.copy(
            sample,
            total,
            0,
            Math.min(bytesRead, sample.length - total),
          );
        total += bytesRead;
        if (total > LIMITS.fileBytes)
          throw new Error("File grew beyond the scan limit.");
        hash.update(buffer.subarray(0, bytesRead));
      }
      const after = await handle.stat();
      const current = await safePath(root, filePath);
      if (
        total !== before.size ||
        !sameFile(before, after) ||
        !sameFile(before, current)
      )
        throw new Error("File changed during inspection.");
      const sha256 = hash.digest("hex");
      if (expected && expected.sha256 !== sha256)
        throw new Error("File contents changed since detection; scan again.");
      const eicar =
        total >= EICAR.length &&
        total <= 128 &&
        sample.subarray(0, EICAR.length).equals(EICAR) &&
        /^[\t\n\r\x20\x1a]*$/.test(
          sample.subarray(EICAR.length, total).toString("latin1"),
        );
      return { path: filePath, ...identity(after), sha256, eicar };
    } finally {
      await handle.close();
    }
  }
  function makeFinding(snapshot, root, signature, engine) {
    const test = snapshot.eicar || /eicar/i.test(signature);
    const heuristic = /^(Heuristics\.|PUA\.)/i.test(signature);
    const finding = {
      id: randomUUID(),
      title: test
        ? "EICAR antivirus test file"
        : `ClamAV detection: ${signature}`,
      severity: test ? "medium" : heuristic ? "medium" : "high",
      category: test ? "test-file" : heuristic ? "suspicious-file" : "malware",
      path: snapshot.path,
      evidence: `${engine}: ${signature}. SHA-256: ${snapshot.sha256}${snapshot.nlink !== 1 ? ". File has multiple hard links; quarantine is disabled." : ""}`,
      recommendation: test
        ? "This is a harmless test signature. Remove the test file or use quarantine to verify the workflow."
        : heuristic
          ? "Review this heuristic alert with your operating system antivirus. It is not eligible for automatic quarantine."
          : "Quarantine the detected file, verify the detection with an updated antivirus, and investigate its origin.",
      quarantinable: !heuristic && snapshot.nlink === 1,
      quarantined: false,
    };
    detections.set(finding.id, { finding, snapshot, root });
    return finding;
  }
  async function scan({ root, autoQuarantine = false } = {}) {
    if (closed) throw new Error("Scanner is closed.");
    if (scanState) throw new Error("A scan is already running.");
    if (typeof root !== "string" || !path.isAbsolute(root))
      throw new Error("Select an absolute scan directory.");
    const state = { cancelled: false };
    scanState = state;
    const result = {
      id: randomUUID(),
      startedAt: new Date().toISOString(),
      finishedAt: null,
      root: path.resolve(root),
      scanned: 0,
      skipped: 0,
      status: "complete",
      engine: "EICAR test check only",
      findings: [],
      warnings: [],
    };
    const warned = new Set();
    const warn = (value) => {
      if (!warned.has(value) && warned.size < 100) {
        warned.add(value);
        result.warnings.push(value);
      }
    };
    let bytes = 0,
      entries = 0,
      clamCompleted = 0,
      batch = [],
      batchChars = 0;
    const began = Date.now();
    try {
      await initialize();
      const rootStat = await fs.lstat(result.root);
      if (
        !rootStat.isDirectory() ||
        rootStat.isSymbolicLink() ||
        (await fs.realpath(result.root)) !== result.root
      )
        throw new Error(
          "The scan root must be a real directory without symlink ancestors.",
        );
      const privateRoot = await fs.realpath(directory);
      if (inside(privateRoot, result.root))
        throw new Error(
          "Private scanner data cannot be selected as a scan root.",
        );
      await engines();
      const clam = engineCache.value.find((engine) => engine.id === "clamav");
      if (clam.available) {
        result.engine = "ClamAV + EICAR test check";
        warn(clam.detail);
      } else
        warn(
          "LIMITED COVERAGE: ClamAV is unavailable. Only the harmless EICAR test signature is checked; a scan with no findings does not mean this device is malware-free.",
        );
      warn(
        "Scope: selected directory only; no memory, boot sector, kernel, network, or encrypted-content inspection. Limits: 20,000 files, 4 GiB total, 64 MiB per file, 32 directory levels, 20 minutes. Symlinks and scanner private data are skipped.",
      );
      const addFinding = async (snapshot, signature, engine) => {
        const finding = makeFinding(snapshot, result.root, signature, engine);
        result.findings.push(finding);
        if (autoQuarantine && finding.quarantinable && !state.cancelled) {
          try {
            await quarantine(finding.id);
          } catch (error) {
            warn(`Quarantine refused for ${snapshot.path}: ${message(error)}`);
          }
        }
      };
      const flush = async () => {
        if (!batch.length || state.cancelled) {
          batch = [];
          batchChars = 0;
          return;
        }
        const current = batch;
        batch = [];
        batchChars = 0;
        // Scans fixed regular-file paths only; no recursive or engine remediation flags.
        const response = await run(clam.command, [
          "--no-summary",
          "--stdout",
          "--infected",
          "--follow-file-symlinks=0",
          "--follow-dir-symlinks=0",
          "--max-filesize=64M",
          "--max-scansize=128M",
          "--max-recursion=10",
          "--max-files=10000",
          "--max-scantime=30000",
          "--alert-exceeds-max=yes",
          "--",
          ...current.map((item) => item.path),
        ]);
        if (state.cancelled) return;
        if (response.code !== 0 && response.code !== 1)
          warn(
            `ClamAV batch incomplete: ${response.timedOut ? "time limit reached" : response.outputLimit ? "output limit reached" : (response.errorOutput || response.output || `exit ${response.code}`).trim().slice(0, 600)}. These files have only the built-in test check.`,
          );
        else clamCompleted += current.length;
        const lines = response.output.split(/\r?\n/);
        for (const snapshot of current) {
          const prefix = `${snapshot.path}: `;
          const line = lines.find(
            (value) => value.startsWith(prefix) && value.endsWith(" FOUND"),
          );
          if (!line) continue;
          const signature = line.slice(prefix.length, -6);
          if (/^Heuristics\.Limits\./i.test(signature)) {
            warn(
              `ClamAV could not completely inspect ${snapshot.path}: ${signature}.`,
            );
            continue;
          }
          try {
            await inspect(result.root, snapshot.path, state, snapshot);
            await addFinding(snapshot, signature, "ClamAV");
          } catch (error) {
            warn(
              `Detection requires a rescan of ${snapshot.path}: ${message(error)}`,
            );
          }
        }
      };
      const limited = () =>
        result.scanned >= LIMITS.files ||
        entries >= LIMITS.entries ||
        bytes >= LIMITS.bytes ||
        Date.now() - began > LIMITS.duration;
      const walk = async (folder, depth) => {
        if (state.cancelled || limited()) return;
        if (depth > LIMITS.depth) {
          result.skipped++;
          warn(
            "Directory depth limit reached; some content was not inspected.",
          );
          return;
        }
        let dir;
        try {
          if ((await fs.realpath(folder)) !== folder)
            throw new Error("Directory is a symlink or was redirected.");
          dir = await fs.opendir(folder);
          for await (const entry of dir) {
            if (state.cancelled || limited()) break;
            entries++;
            const filePath = path.join(folder, entry.name);
            if (inside(privateRoot, filePath) || /[\r\n\x00]/.test(filePath)) {
              result.skipped++;
              continue;
            }
            try {
              const stat = await fs.lstat(filePath);
              if (stat.isSymbolicLink()) {
                result.skipped++;
                continue;
              }
              if (stat.isDirectory()) {
                await walk(filePath, depth + 1);
                continue;
              }
              if (
                !stat.isFile() ||
                stat.size > LIMITS.fileBytes ||
                bytes + stat.size > LIMITS.bytes
              ) {
                result.skipped++;
                continue;
              }
              const snapshot = await inspect(result.root, filePath, state);
              result.scanned++;
              bytes += snapshot.size;
              progress({
                scanned: result.scanned,
                current: filePath,
                status: "scanning",
              });
              if (snapshot.eicar)
                await addFinding(
                  snapshot,
                  "EICAR-STANDARD-ANTIVIRUS-TEST-FILE",
                  "Built-in test check",
                );
              else if (clam.available) {
                if (batch.length >= 96 || batchChars + filePath.length > 16_000)
                  await flush();
                batch.push(snapshot);
                batchChars += filePath.length + 1;
              }
            } catch (error) {
              result.skipped++;
              if (!state.cancelled)
                warn(`Skipped ${filePath}: ${message(error)}`);
            }
          }
        } catch (error) {
          result.skipped++;
          warn(`Cannot inspect directory ${folder}: ${message(error)}`);
        }
      };
      await walk(result.root, 0);
      await flush();
      if (limited())
        warn(
          "Scan resource limit reached. Select a smaller directory to inspect remaining content.",
        );
      if (result.skipped)
        warn(
          `${result.skipped} file(s) or directory entries were skipped; this scan is not complete device coverage.`,
        );
      if (clam.available && clamCompleted === 0)
        warn(
          "No ordinary files completed a ClamAV scan. Results provide only the EICAR test check.",
        );
      if (state.cancelled) result.status = "cancelled";
    } catch (error) {
      result.status = state.cancelled ? "cancelled" : "error";
      warn(message(error));
    } finally {
      result.finishedAt = new Date().toISOString();
      scanState = null;
      progress({ scanned: result.scanned, current: "", status: result.status });
    }
    return result;
  }
  function cancel() {
    if (scanState) scanState.cancelled = true;
    for (const child of children) child.kill("SIGKILL");
  }
  async function validateRecord(id) {
    if (!UUID.test(id)) throw new Error("Invalid quarantine record ID.");
    const itemDirectory = path.join(quarantineRoot, id);
    const stat = await fs.lstat(itemDirectory);
    if (!stat.isDirectory() || stat.isSymbolicLink())
      throw new Error("Unsafe quarantine record directory.");
    const metadata = path.join(itemDirectory, "metadata.json");
    if (
      !(await fs.lstat(metadata)).isFile() ||
      (await fs.lstat(metadata)).isSymbolicLink()
    )
      throw new Error("Unsafe quarantine metadata.");
    const record = JSON.parse(await fs.readFile(metadata, "utf8"));
    if (
      record.id !== id ||
      !path.isAbsolute(record.originalPath) ||
      !path.isAbsolute(record.root) ||
      !inside(record.root, record.originalPath) ||
      !/^[a-f0-9]{64}$/.test(record.sha256)
    )
      throw new Error("Invalid quarantine metadata.");
    return record;
  }
  async function quarantine(findingId) {
    return exclusive(async () => {
      if (closed) throw new Error("Scanner is closed.");
      await initialize();
      const detection = detections.get(findingId);
      if (!detection?.finding.quarantinable || detection.finding.quarantined)
        throw new Error(
          "Only a current, confirmed, single-link detection can be quarantined.",
        );
      const { finding, snapshot, root } = detection;
      const current = await inspect(root, snapshot.path, undefined, snapshot);
      if (current.nlink !== 1)
        throw new Error("Hard-linked files cannot be safely isolated.");
      const id = randomUUID();
      const itemDirectory = path.join(quarantineRoot, id);
      await fs.mkdir(itemDirectory, { mode: 0o700 });
      const payload = path.join(itemDirectory, "payload");
      const record = {
        id,
        findingId,
        originalPath: snapshot.path,
        root,
        title: finding.title,
        sha256: snapshot.sha256,
        identity: snapshot,
        originalMode: current.mode & 0o777,
        quarantinedAt: new Date().toISOString(),
        status: "pending",
      };
      await writeRecord(record);
      await audit("quarantine-pending", record);
      let moved = false;
      try {
        const last = await safePath(root, snapshot.path);
        if (!sameFile(last, current))
          throw new Error("File identity changed before quarantine.");
        // Atomic same-filesystem rename; do not fall back to copy/unlink across volumes.
        // A fresh private UUID directory makes the destination exclusive.
        await fs.rename(snapshot.path, payload);
        moved = true;
        const capturedStat = await fs.lstat(payload);
        if (
          !capturedStat.isFile() ||
          capturedStat.isSymbolicLink() ||
          capturedStat.nlink !== 1 ||
          !sameFile(capturedStat, snapshot, false)
        )
          throw new Error("File identity changed during quarantine.");
        const captured = await inspect(
          await fs.realpath(itemDirectory),
          await fs.realpath(payload),
        );
        if (captured.sha256 !== snapshot.sha256)
          throw new Error("File contents changed during quarantine.");
        await fs.chmod(payload, 0o600);
        record.status = "quarantined";
        await writeRecord(record);
        await audit("quarantined", record);
        finding.quarantined = true;
        return { ...record, path: record.originalPath };
      } catch (error) {
        if (moved) {
          // Exclusive hard-link rollback cannot overwrite a newly created source file.
          try {
            if (
              (await fs.realpath(path.dirname(snapshot.path))) !==
              path.dirname(snapshot.path)
            )
              throw new Error("Original parent directory was redirected.");
            await fs.link(payload, snapshot.path);
            await fs.unlink(payload);
            record.status = "rolled-back";
          } catch (rollbackError) {
            record.status = "recovery-required";
            record.recovery = `Original was moved but cannot be restored automatically: ${message(rollbackError)}`;
          }
        } else record.status = "failed";
        record.error =
          error?.code === "EXDEV"
            ? "Cross-volume quarantine is not supported. Move the app data and scan target onto the same volume or use the operating system antivirus."
            : message(error);
        await writeRecord(record);
        await audit(record.status, record, record.error);
        throw new Error(
          `${record.error}${record.status === "recovery-required" ? ` Recovery record: ${id}.` : ""}`,
        );
      }
    });
  }
  async function listQuarantine() {
    await initialize();
    const result = [];
    for (const entry of await fs.readdir(quarantineRoot, {
      withFileTypes: true,
    })) {
      if (!entry.isDirectory() || !UUID.test(entry.name)) continue;
      try {
        const record = await validateRecord(entry.name);
        if (
          ["quarantined", "pending", "recovery-required"].includes(
            record.status,
          )
        )
          result.push({ ...record, path: record.originalPath });
      } catch {
        /* Invalid records are not eligible for actions. */
      }
    }
    return result.sort((a, b) =>
      b.quarantinedAt.localeCompare(a.quarantinedAt),
    );
  }
  async function restore(id) {
    return exclusive(async () => {
      if (closed) throw new Error("Scanner is closed.");
      await initialize();
      const record = await validateRecord(id);
      if (record.status !== "quarantined")
        throw new Error(
          "This record requires manual recovery or has already been restored.",
        );
      const payload = path.join(quarantineRoot, id, "payload");
      const canonicalPayload = await fs.realpath(payload);
      if (
        canonicalPayload !==
        path.join(await fs.realpath(quarantineRoot), id, "payload")
      )
        throw new Error("Quarantine payload was redirected.");
      const snapshot = await inspect(
        path.dirname(canonicalPayload),
        canonicalPayload,
      );
      if (
        snapshot.sha256 !== record.sha256 ||
        !sameFile(snapshot, record.identity, false) ||
        snapshot.nlink !== 1
      )
        throw new Error("Quarantined file changed; restoration refused.");
      const parent = path.dirname(record.originalPath);
      if (
        (await fs.realpath(parent)) !== parent ||
        !inside(record.root, parent)
      )
        throw new Error("Original parent directory is missing or redirected.");
      await audit("restore-pending", record);
      // link() is exclusive: it fails with EEXIST, preserving any newly created file.
      await fs.link(payload, record.originalPath);
      try {
        const restored = await safePath(record.root, record.originalPath);
        if (!sameFile(restored, snapshot, false))
          throw new Error("Restored path identity changed.");
        // Remove executable bits. Restoring malware is never permission to execute it.
        const restoredHandle = await fs.open(
          record.originalPath,
          constants.O_RDONLY | (constants.O_NOFOLLOW || 0),
        );
        try {
          if (!sameFile(await restoredHandle.stat(), snapshot, false))
            throw new Error("Restored file was replaced.");
          await restoredHandle.chmod(record.originalMode & 0o666);
        } finally {
          await restoredHandle.close();
        }
        await fs.unlink(payload);
      } catch (error) {
        record.status = "recovery-required";
        record.recovery = `Restoration partially completed: ${message(error)}`;
        await writeRecord(record);
        await audit("recovery-required", record, record.recovery);
        throw error;
      }
      record.status = "restored";
      record.restoredAt = new Date().toISOString();
      await writeRecord(record);
      await audit("restored", record);
      const detection = detections.get(record.findingId);
      if (detection) {
        detection.finding.quarantined = false;
        detection.finding.quarantinable = false;
      }
      return { ...record, path: record.originalPath };
    });
  }
  async function close() {
    closed = true;
    cancel();
    await operation;
  }
  return { scan, cancel, listQuarantine, quarantine, restore, engines, close };
}
