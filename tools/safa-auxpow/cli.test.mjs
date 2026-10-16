import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { binToHex } from '@bitauth/libauth';
import { readJson } from './cli.mjs';
import { deriveWork, encodeUnlock } from './lib.mjs';
import { createSafaProof, createSafaSpend, temporaryInput } from './test_utils.mjs';

const cli = fileURLToPath(new URL('cli.mjs', import.meta.url));

test('the work CLI produces the same non-palindromic category work as the VM adapter', context => {
  const spend = createSafaSpend();
  const path = temporaryInput(context, JSON.stringify({
    category: binToHex(spend.category), previous_baton: binToHex(spend.previous),
    recipient: binToHex(spend.transaction.outputs[1].lockingBytecode),
    age: spend.age, timestamp: 1792100001, nonce: 2,
  }));
  const result = spawnSync(process.execPath, [cli, 'work', path], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  const output = JSON.parse(result.stdout);
  assert.deepEqual(output.work, deriveWork(spend.category, spend.previous, spend.next));
  assert.equal(output.next_baton, binToHex(spend.next));
  assert.equal(output.target, '7fffff' + '00'.repeat(29));
});

test('the unlock CLI consumes the Rust AuxPowProof representation', context => {
  const spend = createSafaSpend();
  const proof = createSafaProof(spend);
  const path = temporaryInput(context, JSON.stringify(proof));
  const result = spawnSync(process.execPath, [cli, 'unlock', path, String(spend.age)], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout.trim(), binToHex(encodeUnlock(spend.age, proof)));
});

test('malformed hex and invalid age fail the CLI', context => {
  const path = temporaryInput(context, '{"previous_baton":"gg"}');
  const result = spawnSync(process.execPath, [cli, 'work', path], { encoding: 'utf8' });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /hexadecimal/);
  const spend = createSafaSpend();
  const proofPath = temporaryInput(context, JSON.stringify(createSafaProof(spend)));
  const invalidAge = spawnSync(process.execPath, [cli, 'unlock', proofPath, 'invalid'], { encoding: 'utf8' });
  assert.notEqual(invalidAge.status, 0);
  assert.match(invalidAge.stderr, /block age/);
});

test('the CLI JSON reader accepts exactly 1 MiB and rejects the next byte', context => {
  const exact = temporaryInput(context, '{}' + ' '.repeat(1024 * 1024 - 2));
  assert.deepEqual(readJson(exact), {});
  const excessive = temporaryInput(context, '{}' + ' '.repeat(1024 * 1024 - 1));
  assert.throws(() => readJson(excessive), /exceeds 1 MiB/);
});
