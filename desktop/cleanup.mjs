import fs from "node:fs/promises";
import { constants } from "node:fs";
import path from "node:path";
import os from "node:os";
import { fileURLToPath } from "node:url";
import { createHash, randomUUID } from "node:crypto";

export const CLEANUP_LIMITS = Object.freeze({
  minAgeMs: 7 * 24 * 60 * 60 * 1000,
  maxFileBytes: 64 * 1024 * 1024,
  maxPreviewBytes: 256 * 1024 * 1024,
  maxEntries: 5000,
  maxDirectories: 500,
  maxDepth: 8,
  maxCandidates: 200,
  maxDurationMs: 20_000,
  previewLifetimeMs: 15 * 60 * 1000,
});

const APP_ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const BLOCKED_COMPONENTS = new Set([
  "appdata",
  "application support",
  "keychains",
  "credentials",
  "secrets",
  "passwords",
  "wallets",
  "node_modules",
  "library",
  "windows",
  "program files",
  "program files (x86)",
  "programdata",
  "system volume information",
  "$recycle.bin",
]);
const ELIGIBLE_EXTENSION = /\.(?:tmp|temp|log)$/i;
const folded = (value) =>
  ["win32", "darwin"].includes(process.platform) ? value.toLowerCase() : value;
const samePath = (a, b) => folded(path.resolve(a)) === folded(path.resolve(b));
const isWithin = (parent, child) => {
  const relative = path.relative(
    folded(path.resolve(parent)),
    folded(path.resolve(child)),
  );
  return (
    relative === "" ||
    (!relative.startsWith(`..${path.sep}`) &&
      relative !== ".." &&
      !path.isAbsolute(relative))
  );
};
const owned = (stat) =>
  typeof process.getuid !== "function" || stat.uid === process.getuid();
const identity = (stat) => ({
  dev: stat.dev,
  ino: stat.ino,
  size: stat.size,
  mtimeMs: stat.mtimeMs,
  ctimeMs: stat.ctimeMs,
  nlink: stat.nlink,
  uid: stat.uid,
});
const sameIdentity = (a, b) =>
  a.dev === b.dev &&
  a.ino === b.ino &&
  a.size === b.size &&
  a.mtimeMs === b.mtimeMs &&
  a.ctimeMs === b.ctimeMs &&
  a.nlink === b.nlink &&
  a.uid === b.uid;
const sameDirectory = (a, b) =>
  a.dev === b.dev && a.ino === b.ino && a.uid === b.uid;

function hasProtectedComponent(filePath) {
  const resolved = path.resolve(filePath);
  // The personal Windows Temp folder is a deliberate exception to AppData exclusion.
  // Check every component beneath Temp normally; no other AppData is eligible.
  const personalTemp = path.join(os.homedir(), "AppData", "Local", "Temp");
  const checked =
    process.platform === "win32" && isWithin(personalTemp, resolved)
      ? path.relative(personalTemp, resolved)
      : resolved;
  return checked
    .split(path.sep)
    .some(
      (component) =>
        component.startsWith(".") ||
        /\.app$/i.test(component) ||
        BLOCKED_COMPONENTS.has(component.toLowerCase()),
    );
}

function deniedLocation(filePath) {
  if (hasProtectedComponent(filePath) || isWithin(APP_ROOT, filePath))
    return true;
  if (process.platform === "win32") {
    if (filePath.startsWith("\\\\")) return true; // Network shares are outside this local cleanup tool.
    const drive = path.parse(filePath).root;
    return [
      "Windows",
      "Program Files",
      "Program Files (x86)",
      "ProgramData",
    ].some((name) => isWithin(path.join(drive, name), filePath));
  }
  return [
    "/System",
    "/Library",
    "/Applications",
    "/usr",
    "/bin",
    "/sbin",
    "/etc",
    "/opt",
    "/boot",
    "/dev",
    "/proc",
    "/sys",
    "/run",
    "/var/lib",
    "/var/log",
    "/var/db",
    "/var/root",
    "/private/etc",
    "/private/var/db",
    "/private/var/log",
    "/private/var/root",
  ].some((root) => isWithin(root, filePath));
}

function eligibleFile(filePath, stat, now) {
  return (
    !deniedLocation(filePath) &&
    ELIGIBLE_EXTENSION.test(path.basename(filePath)) &&
    stat.isFile() &&
    !stat.isSymbolicLink() &&
    stat.nlink === 1 &&
    owned(stat) &&
    stat.size > 0 &&
    stat.size <= CLEANUP_LIMITS.maxFileBytes &&
    Number.isFinite(stat.mtimeMs) &&
    stat.mtimeMs <= now - CLEANUP_LIMITS.minAgeMs
  );
}

async function ensureNoLinks(filePath) {
  const full = path.resolve(filePath);
  const root = path.parse(full).root;
  let current = root;
  for (const component of full
    .slice(root.length)
    .split(path.sep)
    .filter(Boolean)) {
    current = path.join(current, component);
    const stat = await fs.lstat(current);
    if (stat.isSymbolicLink())
      throw new Error(
        "Symbolic links and linked parent folders are not eligible for cleanup.",
      );
  }
}

async function validateRoot(input) {
  if (
    typeof input !== "string" ||
    !path.isAbsolute(input) ||
    input.includes("\0") ||
    input.split(/[\\/]/).includes("..")
  )
    throw new Error(
      "Choose an absolute local folder without parent traversal.",
    );
  const resolved = path.resolve(input);
  const canonical = await fs.realpath(resolved);
  if (!samePath(resolved, canonical))
    throw new Error(
      "Choose the original folder, not a symbolic link or linked parent folder.",
    );
  await ensureNoLinks(canonical);
  const stat = await fs.lstat(canonical);
  if (!stat.isDirectory() || !owned(stat))
    throw new Error("Choose a folder owned by your current user.");
  const home = await fs.realpath(os.homedir()).catch(() => os.homedir());
  const forbiddenExact = [
    path.parse(canonical).root,
    home,
    "/Users",
    "/home",
    "/private",
    "/private/var",
    "/var",
    path.join(path.parse(canonical).root, "Users"),
  ];
  if (
    forbiddenExact.some((item) => samePath(canonical, item)) ||
    deniedLocation(canonical)
  )
    throw new Error(
      "Choose a specific personal folder. System folders, your whole home folder, app data, hidden folders, and this app’s code are excluded.",
    );
  return { path: canonical, identity: identity(stat) };
}

async function verifyRoot(root) {
  const canonical = await fs.realpath(root.path);
  if (!samePath(canonical, root.path))
    throw new Error("The selected folder changed.");
  await ensureNoLinks(root.path);
  const stat = await fs.lstat(root.path);
  if (!stat.isDirectory() || !sameDirectory(identity(stat), root.identity))
    throw new Error("The selected folder changed.");
}

async function fileDigest(filePath, expected) {
  // O_NOFOLLOW and inode verification prevent accepting a swapped symlink at open time.
  const file = await fs.open(
    filePath,
    constants.O_RDONLY | (constants.O_NOFOLLOW || 0),
  );
  try {
    const start = await file.stat();
    if (!start.isFile() || !sameIdentity(identity(start), expected))
      throw new Error("The file changed.");
    const hash = createHash("sha256");
    const chunk = Buffer.allocUnsafe(64 * 1024);
    let position = 0;
    while (position < expected.size) {
      const { bytesRead } = await file.read(
        chunk,
        0,
        Math.min(chunk.length, expected.size - position),
        position,
      );
      if (bytesRead === 0)
        throw new Error("The file changed while it was read.");
      hash.update(chunk.subarray(0, bytesRead));
      position += bytesRead;
    }
    if (!sameIdentity(identity(await file.stat()), expected))
      throw new Error("The file changed while it was read.");
    return hash.digest("hex");
  } finally {
    await file.close();
  }
}

/**
 * Only Electron shell.trashItem (or a test double) may perform a cleanup mutation.
 * Previews are reviewable candidates, not a statement that these files are worthless.
 * OS Trash is path-based: checks reduce races but cannot make OS trashing atomic.
 */
export function createCleanup({ trashItem } = {}) {
  if (typeof trashItem !== "function")
    throw new TypeError("An operating system Trash function is required.");
  let candidates = new Map();
  let busy = false;

  async function preview({ root } = {}) {
    if (busy) throw new Error("Another cleanup operation is in progress.");
    busy = true;
    candidates = new Map();
    try {
      const selected = await validateRoot(root);
      const now = Date.now();
      const deadline = now + CLEANUP_LIMITS.maxDurationMs;
      const stack = [{ path: selected.path, depth: 0 }];
      const result = [];
      let entries = 0;
      let directories = 0;
      let hashedBytes = 0;
      while (
        stack.length &&
        directories < CLEANUP_LIMITS.maxDirectories &&
        entries < CLEANUP_LIMITS.maxEntries &&
        result.length < CLEANUP_LIMITS.maxCandidates &&
        Date.now() < deadline
      ) {
        const current = stack.pop();
        directories++;
        if (deniedLocation(current.path)) continue;
        let directory;
        try {
          await ensureNoLinks(current.path);
          if (!isWithin(selected.path, await fs.realpath(current.path)))
            continue;
          directory = await fs.opendir(current.path);
        } catch {
          continue;
        }
        try {
          for await (const entry of directory) {
            if (
              ++entries > CLEANUP_LIMITS.maxEntries ||
              result.length >= CLEANUP_LIMITS.maxCandidates ||
              Date.now() >= deadline
            )
              break;
            const filePath = path.join(current.path, entry.name);
            if (entry.isSymbolicLink() || deniedLocation(filePath)) continue;
            try {
              const stat = await fs.lstat(filePath);
              if (stat.isSymbolicLink()) continue;
              if (stat.isDirectory()) {
                if (
                  current.depth < CLEANUP_LIMITS.maxDepth &&
                  stack.length + directories < CLEANUP_LIMITS.maxDirectories &&
                  owned(stat)
                )
                  stack.push({ path: filePath, depth: current.depth + 1 });
                continue;
              }
              if (
                !eligibleFile(filePath, stat, now) ||
                hashedBytes + stat.size > CLEANUP_LIMITS.maxPreviewBytes
              )
                continue;
              await ensureNoLinks(filePath);
              if (!samePath(await fs.realpath(filePath), filePath)) continue;
              const expected = identity(stat);
              hashedBytes += stat.size;
              const digest = await fileDigest(filePath, expected);
              const id = randomUUID();
              candidates.set(id, {
                root: selected,
                path: filePath,
                identity: expected,
                digest,
                created: now,
              });
              result.push({
                id,
                path: filePath,
                size: stat.size,
                modified: new Date(stat.mtimeMs).toISOString(),
              });
            } catch {
              /* Inaccessible or concurrently modified entries are skipped. */
            }
          }
        } catch {
          /* A directory can disappear or lose permission while being scanned. */
        }
      }
      await verifyRoot(selected);
      return result.sort((a, b) => b.size - a.size);
    } catch (error) {
      candidates.clear();
      throw error;
    } finally {
      busy = false;
    }
  }

  async function trash({ ids } = {}) {
    if (busy) throw new Error("Another cleanup operation is in progress.");
    if (
      !Array.isArray(ids) ||
      ids.length === 0 ||
      ids.length > CLEANUP_LIMITS.maxCandidates ||
      ids.some((id) => typeof id !== "string" || id.length > 100)
    )
      throw new TypeError(
        "Select one or more files from the current cleanup preview.",
      );
    busy = true;
    let moved = 0;
    let skipped = 0;
    const deadline = Date.now() + CLEANUP_LIMITS.maxDurationMs;
    try {
      for (const id of ids) {
        const item = candidates.get(id);
        candidates.delete(id); // An ID authorizes at most one attempt.
        if (
          !item ||
          Date.now() - item.created > CLEANUP_LIMITS.previewLifetimeMs ||
          Date.now() >= deadline
        ) {
          skipped++;
          continue;
        }
        try {
          await verifyRoot(item.root);
          if (!isWithin(item.root.path, item.path))
            throw new Error("File moved outside the selected folder.");
          await ensureNoLinks(item.path);
          if (!samePath(await fs.realpath(item.path), item.path))
            throw new Error("File is now a link.");
          const stat = await fs.lstat(item.path);
          if (
            !eligibleFile(item.path, stat, Date.now()) ||
            !sameIdentity(identity(stat), item.identity)
          )
            throw new Error("File is no longer eligible.");
          if ((await fileDigest(item.path, item.identity)) !== item.digest)
            throw new Error("File contents changed since the preview.");
          // Check parents and metadata again immediately before the path-based OS call.
          await verifyRoot(item.root);
          await ensureNoLinks(item.path);
          if (!sameIdentity(identity(await fs.lstat(item.path)), item.identity))
            throw new Error("File changed before cleanup.");
          await trashItem(item.path);
          moved++;
        } catch {
          skipped++;
        }
      }
      return {
        message: `Sent ${moved} file${moved === 1 ? "" : "s"} to the operating system Trash. ${skipped} skipped. Restore files using the system Trash or Recycle Bin if needed.`,
        moved,
        skipped,
      };
    } finally {
      busy = false;
    }
  }

  return { preview, trash };
}
