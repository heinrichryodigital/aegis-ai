import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import vm from "node:vm";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

// The main process runs in a VM with Electron, providers, and scanner mocked.
// app.whenReady() never resolves, so no real imports, device scans, UI, or login
// checks run. Only the settings tests touch files, inside a temporary directory.
const source = await fs.readFile(
  new URL("./main.cjs", import.meta.url),
  "utf8",
);
const realRequire = createRequire(import.meta.url);
const desktopDirectory = path.dirname(fileURLToPath(import.meta.url));
const tick = () => new Promise((resolve) => setImmediate(resolve));
function deferred() {
  let resolve, reject;
  const promise = new Promise((ok, fail) => {
    resolve = ok;
    reject = fail;
  });
  return { promise, resolve, reject };
}
function harness({
  dataDir = "/unused/aegis-test",
  provider,
  uuid,
  fileSystem = fs,
} = {}) {
  const events = new Map();
  const confirmations = [];
  const calls = { provider: 0, scannerClose: 0, watcherClose: 0, quit: 0 };
  const electron = {
    app: {
      whenReady: () => new Promise(() => {}),
      on: (name, callback) => events.set(name, callback),
      getPath: () => dataDir,
      quit: () => {
        calls.quit++;
        events.get("before-quit")?.({ preventDefault() {} });
      },
    },
    ipcMain: {},
    session: {},
    shell: {},
    dialog: {
      showMessageBox: () => {
        const response = deferred();
        confirmations.push(response);
        return response.promise;
      },
    },
  };
  const context = vm.createContext({
    require: (id) =>
      id === "electron"
        ? electron
        : id === "node:fs/promises"
          ? fileSystem
          : id === "node:crypto" && uuid
            ? { randomUUID: uuid }
            : realRequire(id),
    __dirname: desktopDirectory,
    URL,
    Promise,
    setTimeout,
    clearTimeout,
    setInterval,
    clearInterval,
  });
  vm.runInContext(
    source +
      `
    globalThis.testControls = {
      handle, handleIPC, persistSettings, trustedURL,
      setServices(value) { if ('window' in value) window=value.window; if ('scanner' in value) scanner=value.scanner; if ('providers' in value) providers=value.providers; if ('watcher' in value) watcher=value.watcher; },
      setSettings(value) { settings=value; },
      getSettings() { return settings; }
    };
  `,
    context,
    { filename: "desktop/main.cjs" },
  );
  const controls = context.testControls;
  const frame = { url: controls.trustedURL };
  const webContents = { mainFrame: frame };
  const window = { webContents };
  controls.setServices({
    window,
    providers: {
      analyzeReport: async (request) => {
        calls.provider++;
        return provider ? provider(request) : { text: "Mock advice." };
      },
    },
  });
  return {
    controls,
    events,
    calls,
    confirmations,
    frame,
    webContents,
    event: { sender: webContents, senderFrame: frame },
  };
}
const request = {
  provider: "codex",
  question: "Review the summary.",
  report: {},
};

test("IPC rejects foreign webContents, subframes, remote navigation and missing frame", async () => {
  const { controls, event, frame, webContents } = harness();
  const settings = await controls.handleIPC(event, "settings.get");
  assert.equal(settings.autoQuarantine, false);
  await assert.rejects(
    controls.handleIPC({ ...event, sender: {} }, "settings.get"),
    /Untrusted/,
  );
  await assert.rejects(
    controls.handleIPC(
      { sender: webContents, senderFrame: { url: controls.trustedURL } },
      "settings.get",
    ),
    /Untrusted/,
  );
  await assert.rejects(
    controls.handleIPC({ sender: webContents }, "settings.get"),
    /Untrusted/,
  );
  frame.url = "https://attacker.invalid/";
  await assert.rejects(controls.handleIPC(event, "settings.get"), /Untrusted/);
  frame.url = `${controls.trustedURL}#overview`;
  assert.equal(
    (await controls.handleIPC(event, "settings.get")).watchDownloads,
    false,
  );
  controls.setServices({ window: null });
  await assert.rejects(controls.handleIPC(event, "settings.get"), /Untrusted/);
});

test("analysis lock covers confirmation and execution; duplicate requests never prompt", async () => {
  const providerResult = deferred();
  const { controls, confirmations, calls } = harness({
    provider: () => providerResult.promise,
  });
  const first = controls.handle("analyze", request);
  assert.equal(confirmations.length, 1);
  await assert.rejects(controls.handle("analyze", request), /already running/);
  assert.equal(confirmations.length, 1);
  assert.equal(calls.provider, 0);
  confirmations[0].resolve({ response: 1 });
  await tick();
  assert.equal(calls.provider, 1);
  await assert.rejects(controls.handle("analyze", request), /already running/);
  providerResult.resolve({ text: "Finished" });
  assert.equal((await first).text, "Finished");
  const next = controls.handle("analyze", request);
  assert.equal(confirmations.length, 2);
  confirmations[1].resolve({ response: 0 });
  await assert.rejects(next, /cancelled/);
});

test("cancelling confirmation releases the lock without contacting a provider", async () => {
  const { controls, confirmations, calls } = harness();
  const first = controls.handle("analyze", request);
  confirmations[0].resolve({ response: 0 });
  await assert.rejects(first, /cancelled/);
  assert.equal(calls.provider, 0);
  const next = controls.handle("analyze", request);
  confirmations[1].resolve({ response: 1 });
  await next;
  assert.equal(calls.provider, 1);
});

test("failed provider execution releases the analysis lock", async () => {
  const { controls, confirmations, calls } = harness({
    provider: () => {
      throw new Error("Mock provider failure");
    },
  });
  const first = controls.handle("analyze", request);
  confirmations[0].resolve({ response: 1 });
  await assert.rejects(first, /Mock provider failure/);
  const next = controls.handle("analyze", request);
  confirmations[1].resolve({ response: 0 });
  await assert.rejects(next, /cancelled/);
  assert.equal(calls.provider, 1);
});

test("invalid analysis payload is rejected before confirmation", async () => {
  const { controls, confirmations } = harness();
  for (const invalid of [
    { ...request, report: undefined },
    { ...request, report: [] },
    { ...request, question: "x".repeat(2001) },
    { ...request, provider: "shell" },
  ])
    await assert.rejects(
      controls.handle("analyze", invalid),
      /Invalid analysis request/,
    );
  assert.equal(confirmations.length, 0);
});

test("shutdown waits for scanner and watcher to close exactly once before quitting", async () => {
  const scannerDone = deferred(),
    watcherDone = deferred();
  const { controls, events, calls } = harness();
  controls.setServices({
    scanner: {
      close: () => {
        calls.scannerClose++;
        return scannerDone.promise;
      },
    },
    watcher: {
      close: () => {
        calls.watcherClose++;
        return watcherDone.promise;
      },
    },
  });
  controls.setSettings({
    autoQuarantine: true,
    watchDownloads: true,
    watchNetwork: true,
  });
  let prevented = 0;
  const event = {
    preventDefault() {
      prevented++;
    },
  };
  events.get("before-quit")(event);
  events.get("before-quit")(event);
  assert.equal(prevented, 2);
  assert.equal(calls.scannerClose, 1);
  assert.equal(calls.watcherClose, 1);
  assert.equal(calls.quit, 0);
  assert.equal(controls.getSettings().watchDownloads, false);
  assert.equal(controls.getSettings().watchNetwork, false);
  watcherDone.resolve();
  await tick();
  assert.equal(calls.quit, 0);
  scannerDone.resolve();
  await tick();
  assert.equal(calls.quit, 1);
  assert.equal(calls.scannerClose, 1);
});

test("settings temp creation is exclusive and cannot overwrite pre-existing data", async (t) => {
  const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), "aegis-main-test-"));
  t.after(() => fs.rm(dataDir, { recursive: true, force: true }));
  const temporary = path.join(dataDir, ".settings-test-id.tmp");
  await fs.writeFile(temporary, "Existing user content");
  const { controls } = harness({ dataDir, uuid: () => "test-id" });
  await assert.rejects(controls.persistSettings(), { code: "EEXIST" });
  assert.equal(await fs.readFile(temporary, "utf8"), "Existing user content");
  await fs.unlink(temporary);
  await controls.persistSettings();
  const settings = JSON.parse(
    await fs.readFile(path.join(dataDir, "settings.json"), "utf8"),
  );
  assert.equal(settings.autoQuarantine, false);
  await assert.rejects(fs.access(temporary), { code: "ENOENT" });
  if (process.platform !== "win32")
    assert.equal(
      (await fs.stat(path.join(dataDir, "settings.json"))).mode & 0o777,
      0o600,
    );
});

test("settings writes reject symlink temp paths without modifying their targets", async (t) => {
  const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), "aegis-main-test-"));
  t.after(() => fs.rm(dataDir, { recursive: true, force: true }));
  const target = path.join(dataDir, "precious.txt");
  await fs.writeFile(target, "Precious data");
  const temporary = path.join(dataDir, ".settings-test-id.tmp");
  try {
    await fs.symlink(target, temporary);
  } catch (error) {
    if (error.code === "EPERM") {
      t.skip("Windows symlink permission unavailable.");
      return;
    }
    throw error;
  }
  const { controls } = harness({ dataDir, uuid: () => "test-id" });
  await assert.rejects(controls.persistSettings(), { code: "EEXIST" });
  assert.equal(await fs.readFile(target, "utf8"), "Precious data");
  assert.equal((await fs.lstat(temporary)).isSymbolicLink(), true);
});
