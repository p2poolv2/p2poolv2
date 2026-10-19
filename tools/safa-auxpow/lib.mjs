import { readFileSync } from 'node:fs';
import {
  bigIntToVmNumber,
  binToHex,
  createCompilerBch,
  createVirtualMachineBch2026,
  encodeDataPush,
  encodeTransactionBch,
  flattenBinArray,
  hash256,
  hexToBin,
  numberToBinUint32LE,
} from '@bitauth/libauth';

export const MAX_TARGET = (1n << 256n) - 1n;
export const WORK_DOMAIN = new TextEncoder().encode('BCH-SAFA-AUXPOW-V1\0');
const compiler = createCompilerBch({
  scripts: { lock: readFileSync(new URL('safa.cash', import.meta.url), 'utf8') },
  vm: createVirtualMachineBch2026(false),
});
const compiled = compiler.generateBytecode({ scriptId: 'lock', data: {} });
if (!compiled.success) throw new Error(JSON.stringify(compiled.errors));
export const redeemScript = compiled.bytecode;
export const lockingBytecode = flattenBinArray([
  Uint8Array.of(0xaa, 32), hash256(redeemScript), Uint8Array.of(0x87),
]);

function bytes(value, length, name) {
  if (!(value instanceof Uint8Array) || value.length !== length) {
    throw new Error(`${name} must contain ${length} bytes`);
  }
  return value;
}

function uint32(value) {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    throw new Error('value must be an unsigned 32-bit integer');
  }
  return numberToBinUint32LE(value);
}

export function fromHex(value, length) {
  if (typeof value !== 'string' || !/^(?:[0-9a-fA-F]{2})*$/.test(value)) {
    throw new Error('invalid hexadecimal bytes');
  }
  const decoded = hexToBin(value);
  return length === undefined ? decoded : bytes(decoded, length, 'hexadecimal field');
}

function readUint32(value, offset = 0) {
  return new DataView(value.buffer, value.byteOffset, value.byteLength).getUint32(offset, true);
}

export function encodeTarget(target) {
  if (typeof target !== 'bigint' || target <= 0n || target > MAX_TARGET) {
    throw new Error('target must be a positive 256-bit integer');
  }
  let size = Math.ceil(target.toString(16).length / 2);
  let mantissa = Number(size <= 3
    ? target << BigInt(8 * (3 - size))
    : target >> BigInt(8 * (size - 3)));
  if ((mantissa & 0x800000) !== 0) {
    mantissa >>>= 8;
    size += 1;
  }
  return size * 0x1000000 + mantissa;
}

export function decodeTarget(compact) {
  uint32(compact);
  const exponent = compact >>> 24;
  const mantissa = compact & 0xffffff;
  if (mantissa === 0 || mantissa > 0x7fffff || exponent < 1 || exponent > 33) {
    throw new Error('invalid compact target');
  }
  const shift = BigInt(8 * (exponent - 3));
  const target = shift >= 0n ? BigInt(mantissa) << shift : BigInt(mantissa) >> -shift;
  if (target <= 0n || target > MAX_TARGET || encodeTarget(target) !== compact) {
    throw new Error('noncanonical or overflowing compact target');
  }
  return target;
}

export function nextBaton(previous, recipient, age, timestamp, nonce) {
  bytes(previous, 80, 'previous baton');
  if (!(recipient instanceof Uint8Array) || recipient.length === 0) {
    throw new Error('recipient locking bytecode is required');
  }
  if (!Number.isInteger(age) || age < 0 || age >= 65535) throw new Error('invalid block age');
  uint32(timestamp);
  if (timestamp <= 500000000 || timestamp < readUint32(previous, 68)) {
    throw new Error('timestamp must be a nondecreasing Unix timestamp');
  }
  const adjusted = decodeTarget(readUint32(previous, 72))
    * (BigInt(age) * 5000n / 71n + 5000n) / 10000n;
  const clamped = adjusted < 1n ? 1n : adjusted > MAX_TARGET ? MAX_TARGET : adjusted;
  return flattenBinArray([
    previous.slice(0, 4), hash256(previous), hash256(recipient),
    uint32(timestamp), uint32(encodeTarget(clamped)), uint32(nonce),
  ]);
}

export function deriveWork(category, previous, next, covenant = lockingBytecode) {
  bytes(category, 32, 'category');
  bytes(previous, 80, 'previous baton');
  bytes(next, 80, 'next baton');
  if (!(covenant instanceof Uint8Array) || covenant.length === 0) {
    throw new Error('covenant locking bytecode is required');
  }
  const hash = hash256(flattenBinArray([
    WORK_DOMAIN, Uint8Array.from(category).reverse(), hash256(covenant),
    hash256(previous), hash256(next),
  ]));
  return { chain_id: readUint32(hash), hash: binToHex(Uint8Array.from(hash).reverse()) };
}

export function encodeCoinbase(coinbase) {
  uint32(coinbase.version);
  uint32(coinbase.lock_time);
  return encodeTransactionBch({
    version: coinbase.version,
    locktime: coinbase.lock_time,
    inputs: coinbase.input.map(input => {
      const [hash, index, extra] = input.previous_output.split(':');
      if (extra !== undefined || index === undefined || input.witness.length !== 0) {
        throw new Error('invalid coinbase input');
      }
      const outpointIndex = Number(index);
      uint32(outpointIndex);
      uint32(input.sequence);
      return {
        outpointTransactionHash: fromHex(hash, 32), outpointIndex,
        sequenceNumber: input.sequence, unlockingBytecode: fromHex(input.script_sig),
      };
    }),
    outputs: coinbase.output.map(output => {
      if (!Number.isSafeInteger(output.value) || output.value < 0) throw new Error('invalid output value');
      return { valueSatoshis: BigInt(output.value), lockingBytecode: fromHex(output.script_pubkey) };
    }),
  });
}

export function encodeHeader(header) {
  if (!Number.isInteger(header.version) || header.version < -0x80000000 || header.version > 0x7fffffff) {
    throw new Error('invalid header version');
  }
  return flattenBinArray([
    uint32(header.version >>> 0), fromHex(header.prev_blockhash, 32).reverse(),
    fromHex(header.merkle_root, 32).reverse(), uint32(header.time),
    uint32(header.bits), uint32(header.nonce),
  ]);
}

export function encodeUnlock(age, proof) {
  if (!Number.isInteger(age) || age < 0 || age >= 65535) throw new Error('invalid block age');
  if (proof.coinbase_branch.length > 25 || proof.auxiliary.branch.length > 30) {
    throw new Error('proof exceeds the Merkle branch limits');
  }
  const unlockingBytecode = flattenBinArray([
    encodeDataPush(bigIntToVmNumber(BigInt(age))),
    encodeDataPush(encodeHeader(proof.parent_header)),
    encodeDataPush(encodeCoinbase(proof.coinbase)),
    encodeDataPush(flattenBinArray(proof.coinbase_branch.map(hash => fromHex(hash, 32).reverse()))),
    encodeDataPush(flattenBinArray(proof.auxiliary.branch.map(hash => fromHex(hash, 32).reverse()))),
    encodeDataPush(redeemScript),
  ]);
  if (unlockingBytecode.length > 10000) throw new Error('complete SAFA unlocking bytecode exceeds 10000 bytes');
  return unlockingBytecode;
}
