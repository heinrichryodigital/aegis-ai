import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { CLEANUP_LIMITS, createCleanup } from './cleanup.mjs';

async function fixture(t) {
  const temporary = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'aegis-cleanup-test-')));
  t.after(() => fs.rm(temporary, { recursive: true, force: true }));
  return temporary;
}

async function oldFile(root, name, content = 'Old expendable fixture log') {
  const file = path.join(root, name);
  await fs.mkdir(path.dirname(file), { recursive: true });
  await fs.writeFile(file, content);
  const old = new Date(Date.now() - CLEANUP_LIMITS.minAgeMs - 60_000);
  await fs.utimes(file, old, old);
  return file;
}

test('preview includes only old, regular, singly linked eligible files', async t => {
  const root = await fixture(t);
  const expected = await oldFile(root, 'eligible.log');
  await oldFile(root, 'notes.txt');
  await oldFile(root, 'empty.tmp', '');
  await fs.writeFile(path.join(root, 'recent.temp'), 'Still in use');
  await oldFile(root, '.hidden.log');
  await oldFile(root, '.ssh/session.log');
  await oldFile(root, 'secrets/token.log');
  await oldFile(root, 'node_modules/dependency/build.log');
  const linked = await oldFile(root, 'hardlink.log');
  await fs.link(linked, path.join(root, 'second-link.log'));
  await fs.symlink(expected, path.join(root, 'symlink.log')).catch(error => {
    if (process.platform !== 'win32' || error.code !== 'EPERM') throw error;
    // Non-administrator Windows may not permit file symlinks; junction coverage is below.
  });
  const cleanup = createCleanup({ trashItem: async () => assert.fail('Preview must never mutate') });
  const results = await cleanup.preview({ root });
  assert.equal(results.length, 1);
  assert.equal(results[0].path, expected);
  assert.equal(results[0].size, Buffer.byteLength('Old expendable fixture log'));
  assert.ok(Date.parse(results[0].modified) < Date.now() - CLEANUP_LIMITS.minAgeMs);
  assert.match(results[0].id, /^[a-f0-9-]{36}$/);
});

test('only preview IDs invoke the injected Trash function, once', async t => {
  const root = await fixture(t);
  const file = await oldFile(root, 'old.tmp');
  const calls = [];
  const cleanup = createCleanup({ trashItem: async value => { calls.push(value); } });
  const [entry] = await cleanup.preview({ root });
  const result = await cleanup.trash({ ids: [entry.id, entry.id, file, 'unknown-id'] });
  assert.deepEqual(calls, [file]);
  assert.equal(result.moved, 1);
  assert.equal(result.skipped, 3);
  assert.equal(await fs.readFile(file, 'utf8'), 'Old expendable fixture log', 'No deletion fallback is permitted');
});

test('modified files and a replaced inode are skipped after a preview', async t => {
  const root = await fixture(t);
  const edited = await oldFile(root, 'edited.log');
  const replaced = await oldFile(root, 'replaced.temp');
  const cleanup = createCleanup({ trashItem: async () => assert.fail('Changed files must never be trashed') });
  const entries = await cleanup.preview({ root });
  await fs.writeFile(edited, 'Changed fixture contents');
  await fs.rename(replaced, path.join(root, 'moved-original.txt'));
  await oldFile(root, 'replaced.temp');
  const result = await cleanup.trash({ ids: entries.map(entry => entry.id) });
  assert.equal(result.moved, 0);
  assert.equal(result.skipped, 2);
});

test('hardlinks introduced after preview prevent trashing', async t => {
  const root = await fixture(t);
  const file = await oldFile(root, 'single.log');
  const cleanup = createCleanup({ trashItem: async () => assert.fail('Hardlinked files are ineligible') });
  const [entry] = await cleanup.preview({ root });
  await fs.link(file, path.join(root, 'new-link.log'));
  const result = await cleanup.trash({ ids: [entry.id] });
  assert.equal(result.moved, 0);
  assert.equal(result.skipped, 1);
});

test('symlink parent replacement cannot escape the reviewed root', async t => {
  const root = await fixture(t);
  const outside = await fixture(t);
  await oldFile(root, 'sub/old.log');
  await oldFile(outside, 'old.log', 'Must remain untouched');
  const cleanup = createCleanup({ trashItem: async () => assert.fail('Parent links must never be followed') });
  const [entry] = await cleanup.preview({ root });
  await fs.rename(path.join(root, 'sub'), path.join(root, 'original-sub'));
  await fs.symlink(outside, path.join(root, 'sub'), process.platform === 'win32' ? 'junction' : 'dir');
  const result = await cleanup.trash({ ids: [entry.id] });
  assert.equal(result.moved, 0);
  assert.equal(result.skipped, 1);
  assert.equal(await fs.readFile(path.join(outside, 'old.log'), 'utf8'), 'Must remain untouched');
});

test('new previews expire old IDs and Trash errors never cause permanent deletion', async t => {
  const root = await fixture(t);
  const file = await oldFile(root, 'old.log');
  const cleanup = createCleanup({ trashItem: async () => { throw new Error('Trash denied'); } });
  const [oldEntry] = await cleanup.preview({ root });
  const [newEntry] = await cleanup.preview({ root });
  const result = await cleanup.trash({ ids: [oldEntry.id, newEntry.id] });
  assert.equal(result.moved, 0);
  assert.equal(result.skipped, 2);
  assert.equal(await fs.readFile(file, 'utf8'), 'Old expendable fixture log');
});

test('rejects root, whole home, app code, linked roots and traversal', async t => {
  const root = await fixture(t);
  const link = path.join(root, 'linked-root');
  const target = path.join(root, 'target');
  await fs.mkdir(target);
  await fs.symlink(target, link, process.platform === 'win32' ? 'junction' : 'dir');
  const cleanup = createCleanup({ trashItem: async () => assert.fail('Root validation must not mutate') });
  const appRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
  for (const denied of [path.parse(root).root, os.homedir(), appRoot, link, `${root}/../${path.basename(root)}`, '.']) await assert.rejects(cleanup.preview({ root: denied }));
});

test('depth and file-size bounds prevent previewing unbounded candidates', async t => {
  const root = await fixture(t);
  const deep = Array.from({ length: CLEANUP_LIMITS.maxDepth + 2 }, (_, i) => `level-${i}`).join(path.sep);
  await oldFile(root, path.join(deep, 'too-deep.log'));
  const large = await oldFile(root, 'large.log');
  await fs.truncate(large, CLEANUP_LIMITS.maxFileBytes + 1);
  const old = new Date(Date.now() - CLEANUP_LIMITS.minAgeMs - 60_000);
  await fs.utimes(large, old, old);
  const cleanup = createCleanup({ trashItem: async () => assert.fail('Preview must not mutate') });
  assert.deepEqual(await cleanup.preview({ root }), []);
});

test('rejects malformed cleanup requests before calling Trash', async () => {
  assert.throws(() => createCleanup(), TypeError);
  const cleanup = createCleanup({ trashItem: async () => assert.fail('Invalid input cannot trigger Trash') });
  for (const ids of [undefined, [], 'file', [123], ['x'.repeat(101)], Array(CLEANUP_LIMITS.maxCandidates + 1).fill('id')]) await assert.rejects(cleanup.trash({ ids }), TypeError);
});
