import { closeSync, fstatSync, openSync, readSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { binToHex } from '@bitauth/libauth';
import {
  decodeTarget, deriveWork, encodeUnlock, fromHex, lockingBytecode, nextBaton, redeemScript,
} from './lib.mjs';

export function readJson(path) {
  const handle = openSync(path, 'r');
  try {
    if (!fstatSync(handle).isFile()) throw new Error('input must be a regular file');
    const buffer = Buffer.alloc(1024 * 1024 + 1);
    let length = 0;
    let received;
    do {
      received = readSync(handle, buffer, length, buffer.length - length, null);
      length += received;
    } while (received !== 0 && length < buffer.length);
    if (length > 1024 * 1024) throw new Error('input JSON exceeds 1 MiB');
    return JSON.parse(buffer.subarray(0, length).toString('utf8'));
  } finally {
    closeSync(handle);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const [command, file, age, extra] = process.argv.slice(2);
    if (!file || extra !== undefined) throw new Error('usage: node cli.mjs work state.json | unlock proof.json age');
    const input = readJson(file);
    if (command === 'work' && age === undefined) {
      const previous = fromHex(input.previous_baton, 80);
      const next = nextBaton(previous, fromHex(input.recipient), input.age, input.timestamp, input.nonce);
      const bits = new DataView(next.buffer, next.byteOffset, next.byteLength).getUint32(72, true);
      console.log(JSON.stringify({
        work: deriveWork(fromHex(input.category, 32), previous, next),
        next_baton: binToHex(next), target: decodeTarget(bits).toString(16).padStart(64, '0'),
        locking_bytecode: binToHex(lockingBytecode), redeem_script: binToHex(redeemScript),
      }, null, 2));
    } else if (command === 'unlock' && age !== undefined) {
      console.log(binToHex(encodeUnlock(Number(age), input)));
    } else {
      throw new Error('usage: node cli.mjs work state.json | unlock proof.json age');
    }
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
