import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { createScanner } from './scanner.mjs';

// Harmless, industry-standard antivirus test content, created only in a temporary directory.
const TEST_SIGNATURE = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
async function fixture(t, onProgress) {
  const temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-scanner-test-'));
  // /var is a macOS system symlink, so tests use the canonical selected directory.
  const base = await fs.realpath(temporary);
  const root = path.join(base, 'selected');
  const dataDir = path.join(base, 'private');
  await fs.mkdir(root);
  const scanner = createScanner({ dataDir, onProgress });
  t.after(async () => { await scanner.close(); await fs.rm(base, { recursive: true, force: true }); });
  return { base, root, dataDir, scanner };
}

test('ordinary files are not findings; EICAR is explicitly a harmless test', async (t) => {
  const progress = [];
  const { root, scanner } = await fixture(t, (event) => progress.push(event));
  await fs.writeFile(path.join(root, 'ordinary.txt'), 'A regular user document.');
  await fs.writeFile(path.join(root, 'scanner-source.txt'), `const example = ${JSON.stringify(TEST_SIGNATURE)}`);
  await fs.writeFile(path.join(root, 'eicar.test'), TEST_SIGNATURE);
  const result = await scanner.scan({ root });
  assert.equal(result.status, 'complete');
  assert.equal(result.scanned, 3);
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].category, 'test-file');
  assert.match(result.findings[0].title, /test file/i);
  assert.equal(result.findings[0].quarantinable, true);
  assert.equal(result.findings[0].quarantined, false);
  assert.match(result.warnings.join(' '), /selected directory only/i);
  assert.equal(progress.at(-1).status, 'complete');
});

test('quarantine and restart-safe restore preserve content and write durable audit', async (t) => {
  const { root, dataDir, scanner } = await fixture(t);
  const original = path.join(root, 'test.com');
  await fs.writeFile(original, TEST_SIGNATURE, { mode: 0o755 });
  const result = await scanner.scan({ root, autoQuarantine: true });
  assert.equal(result.findings[0].quarantined, true);
  await assert.rejects(fs.access(original), { code: 'ENOENT' });
  const records = await scanner.listQuarantine();
  assert.equal(records.length, 1);
  const record = records[0];
  assert.equal(record.status, 'quarantined');
  if (process.platform !== 'win32') assert.equal((await fs.stat(path.join(dataDir, 'quarantine', record.id, 'payload'))).mode & 0o777, 0o600);
  const restarted = createScanner({ dataDir });
  try {
    await restarted.restore(record.id);
    assert.equal(await fs.readFile(original, 'utf8'), TEST_SIGNATURE);
    assert.equal((await restarted.listQuarantine()).length, 0);
    if (process.platform !== 'win32') assert.equal((await fs.stat(original)).mode & 0o111, 0);
  } finally { await restarted.close(); }
  const audit = (await fs.readFile(path.join(dataDir, 'quarantine-audit.jsonl'), 'utf8')).trim().split('\n').map(JSON.parse);
  assert.deepEqual(audit.map((event) => event.action), ['quarantine-pending', 'quarantined', 'restore-pending', 'restored']);
});

test('restore never overwrites a new file at the original path', async (t) => {
  const { root, scanner } = await fixture(t);
  const original = path.join(root, 'test.com');
  await fs.writeFile(original, TEST_SIGNATURE);
  await scanner.scan({ root, autoQuarantine: true });
  const [record] = await scanner.listQuarantine();
  await fs.writeFile(original, 'New user content');
  await assert.rejects(scanner.restore(record.id), { code: 'EEXIST' });
  assert.equal(await fs.readFile(original, 'utf8'), 'New user content');
  assert.equal((await scanner.listQuarantine())[0].status, 'quarantined');
});

test('mutated detections are refused without moving the changed file', async (t) => {
  const { root, scanner } = await fixture(t);
  const original = path.join(root, 'test.com');
  await fs.writeFile(original, TEST_SIGNATURE);
  const result = await scanner.scan({ root });
  await fs.writeFile(original, 'This file changed after its scan.');
  await assert.rejects(scanner.quarantine(result.findings[0].id), /changed/i);
  assert.equal(await fs.readFile(original, 'utf8'), 'This file changed after its scan.');
  assert.equal((await scanner.listQuarantine()).length, 0);
});

test('replacement inode with identical bytes is refused', async (t) => {
  const { root, scanner } = await fixture(t);
  const original = path.join(root, 'test.com');
  await fs.writeFile(original, TEST_SIGNATURE);
  const result = await scanner.scan({ root });
  await fs.rename(original, path.join(root, 'old.test'));
  await fs.writeFile(original, TEST_SIGNATURE);
  await assert.rejects(scanner.quarantine(result.findings[0].id), /changed/i);
  assert.equal(await fs.readFile(original, 'utf8'), TEST_SIGNATURE);
});

test('file and directory symlinks are not followed and symlink roots are rejected', async (t) => {
  const { base, root, scanner } = await fixture(t);
  const outside = path.join(base, 'outside');
  await fs.mkdir(outside);
  await fs.writeFile(path.join(outside, 'test.com'), TEST_SIGNATURE);
  try {
    await fs.symlink(path.join(outside, 'test.com'), path.join(root, 'linked.test'), 'file');
    await fs.symlink(outside, path.join(root, 'linked-directory'), process.platform === 'win32' ? 'junction' : 'dir');
  } catch (error) { if (error.code === 'EPERM') { t.skip('Windows symlink permission not available.'); return; } throw error; }
  const result = await scanner.scan({ root, autoQuarantine: true });
  assert.equal(result.findings.length, 0);
  assert.equal(result.scanned, 0);
  assert.equal(result.skipped, 2);
  assert.equal(await fs.readFile(path.join(outside, 'test.com'), 'utf8'), TEST_SIGNATURE);
  const linkedRootResult = await scanner.scan({ root: path.join(root, 'linked-directory') });
  assert.equal(linkedRootResult.status, 'error');
});

test('replacing a detected file with a symlink cannot quarantine outside content', async (t) => {
  const { base, root, scanner } = await fixture(t);
  const original = path.join(root, 'test.com');
  const outside = path.join(base, 'outside.txt');
  await fs.writeFile(original, TEST_SIGNATURE);
  await fs.writeFile(outside, 'Precious outside content');
  const result = await scanner.scan({ root });
  await fs.unlink(original);
  try { await fs.symlink(outside, original); }
  catch (error) { if (error.code === 'EPERM') { t.skip('Windows symlink permission not available.'); return; } throw error; }
  await assert.rejects(scanner.quarantine(result.findings[0].id), /regular files/i);
  assert.equal(await fs.readFile(outside, 'utf8'), 'Precious outside content');
});

test('hard-linked files are detected but not eligible for quarantine', async (t) => {
  const { root, scanner } = await fixture(t);
  const original = path.join(root, 'test.com');
  await fs.writeFile(original, TEST_SIGNATURE);
  await fs.link(original, path.join(root, 'second.test'));
  const result = await scanner.scan({ root, autoQuarantine: true });
  assert.equal(result.findings.length, 2);
  assert.ok(result.findings.every((finding) => !finding.quarantinable && !finding.quarantined));
  await assert.rejects(scanner.quarantine(result.findings[0].id), /single-link/i);
});

test('tampered quarantine payload cannot be restored', async (t) => {
  const { root, dataDir, scanner } = await fixture(t);
  await fs.writeFile(path.join(root, 'test.com'), TEST_SIGNATURE);
  await scanner.scan({ root, autoQuarantine: true });
  const [record] = await scanner.listQuarantine();
  await fs.writeFile(path.join(dataDir, 'quarantine', record.id, 'payload'), 'Tampered storage');
  await assert.rejects(scanner.restore(record.id), /changed/i);
  await assert.rejects(fs.access(record.originalPath), { code: 'ENOENT' });
});

test('private quarantine storage is excluded from later scans', async (t) => {
  const { base, root, scanner } = await fixture(t);
  await fs.writeFile(path.join(root, 'test.com'), TEST_SIGNATURE);
  await scanner.scan({ root, autoQuarantine: true });
  const result = await scanner.scan({ root: base });
  assert.equal(result.status, 'complete');
  assert.equal(result.findings.length, 0);
  assert.ok(result.skipped > 0);
});

test('cancellation stops a running scan and concurrent scans are refused', async (t) => {
  let scanner;
  const setup = await fixture(t, (event) => { if (event.scanned === 1 && event.status === 'scanning') scanner.cancel(); });
  scanner = setup.scanner;
  await fs.writeFile(path.join(setup.root, 'one.txt'), 'one');
  await fs.writeFile(path.join(setup.root, 'two.txt'), 'two');
  const first = scanner.scan({ root: setup.root });
  await assert.rejects(scanner.scan({ root: setup.root }), /already running/i);
  const result = await first;
  assert.equal(result.status, 'cancelled');
  assert.equal(result.scanned, 1);
});
