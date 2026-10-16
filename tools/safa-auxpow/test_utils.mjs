import {
  binToHex, createVirtualMachineBch2026, encodeDataPush, flattenBinArray,
  hash256, hexToBin, numberToBinUint32LE,
} from '@bitauth/libauth';
import {
  decodeTarget, deriveWork, encodeCoinbase, encodeHeader, encodeUnlock,
  lockingBytecode, nextBaton, redeemScript,
} from './lib.mjs';

export function temporaryInput(test, contents) {
  const directory = mkdtempSync(join(tmpdir(), 'safa-auxpow-'));
  const path = join(directory, 'input.json');
  writeFileSync(path, contents);
  test.after(() => { unlinkSync(path); rmdirSync(directory); });
  return path;
}

export function createSafaSpend({ age = 71, bits = 0x207fffff } = {}) {
  const category = hash256(new TextEncoder().encode('SAFA category in display order'));
  const recipient = hexToBin(`76a914${'22'.repeat(20)}88ac`);
  const previous = flattenBinArray([
    numberToBinUint32LE(70), hash256(new TextEncoder().encode('initial SAFA thread')),
    hash256(recipient), numberToBinUint32LE(1792100000),
    numberToBinUint32LE(bits), numberToBinUint32LE(1),
  ]);
  const next = nextBaton(previous, recipient, age, 1792100001, 2);
  const token = { category, amount: 420000000n, nft: { capability: 'mutable', commitment: previous } };
  const sourceOutputs = [{ lockingBytecode, valueSatoshis: 100000n, token }];
  const transaction = {
    version: 2, locktime: 1792100001,
    inputs: [{
      outpointTransactionHash: new Uint8Array(32).fill(0x11), outpointIndex: 0,
      sequenceNumber: age, unlockingBytecode: new Uint8Array(),
    }],
    outputs: [
      { lockingBytecode, valueSatoshis: 98500n, token: {
        ...token, amount: 419999000n, nft: { capability: 'mutable', commitment: next },
      } },
      { lockingBytecode: recipient, valueSatoshis: 800n, token: { category, amount: 1000n } },
    ],
  };
  return { age, category, previous, next, transaction, sourceOutputs };
}

export function createSafaProof(spend, { auxiliaryDepth = 1, coinbaseDepth = 1 } = {}) {
  const work = deriveWork(spend.category, spend.previous, spend.next);
  const rawHash = hexToBin(work.hash).reverse();
  let root = rawHash;
  const treeSize = 2 ** auxiliaryDepth;
  let slot = Number(((12345n + BigInt(work.chain_id)) * 1103515245n + 12345n) % BigInt(treeSize));
  const branch = [];
  for (let level = 0; level < auxiliaryDepth; level += 1) {
    const sibling = hash256(Uint8Array.of(level, 0xaa));
    branch.push(binToHex(Uint8Array.from(sibling).reverse()));
    root = hash256(flattenBinArray(slot % 2 === 0 ? [root, sibling] : [sibling, root]));
    slot = Math.floor(slot / 2);
  }
  const auxScript = flattenBinArray([
    hexToBin('6a2cfabe6d6d'), Uint8Array.from(root).reverse(),
    numberToBinUint32LE(treeSize), numberToBinUint32LE(0),
  ]);
  const coinbase = {
    version: 2, lock_time: 208,
    input: [{ previous_output: `${'00'.repeat(32)}:4294967295`, script_sig: '02d100', sequence: 0xfffffffe, witness: [] }],
    output: [
      { value: 2462500000, script_pubkey: `76a914${'11'.repeat(20)}88ac` },
      { value: 37500000, script_pubkey: `76a914${'33'.repeat(20)}88ac` },
      { value: 0, script_pubkey: binToHex(auxScript) },
    ],
  };
  const proof = { coinbase, auxiliary: { work, branch }, coinbase_branch: [] };
  return remineSafaProof(proof, spend.next, coinbaseDepth);
}

export function remineSafaProof(proof, next, coinbaseDepth = proof.coinbase_branch.length) {
  let root = hash256(encodeCoinbase(proof.coinbase));
  proof.coinbase_branch = [];
  for (let level = 0; level < coinbaseDepth; level += 1) {
    const sibling = hash256(Uint8Array.of(level, 0xbb));
    proof.coinbase_branch.push(binToHex(Uint8Array.from(sibling).reverse()));
    root = hash256(flattenBinArray([root, sibling]));
  }
  const bits = new DataView(next.buffer, next.byteOffset, next.byteLength).getUint32(72, true);
  const target = decodeTarget(bits);
  proof.parent_header = {
    version: 0x20000000, prev_blockhash: '44'.repeat(32), merkle_root: binToHex(root.reverse()),
    time: 1792100001, bits: proof.parent_header?.bits ?? 0x207fffff, nonce: 0,
  };
  while (BigInt(`0x${binToHex(hash256(encodeHeader(proof.parent_header)).reverse())}`) > target) {
    proof.parent_header.nonce += 1;
    if (proof.parent_header.nonce > 100000) throw new Error('test mining exceeded its work budget');
  }
  return proof;
}

export function verifySafaSpend(spend, proof) {
  return verifySafaUnlock(spend, encodeUnlock(spend.age, proof));
}

export function verifySafaUnlock(spend, unlockingBytecode) {
  spend.transaction.inputs[0].unlockingBytecode = unlockingBytecode;
  return createVirtualMachineBch2026(true).verify({
    transaction: spend.transaction, sourceOutputs: spend.sourceOutputs,
  });
}

export function verifySafaMarket(spend) {
  return verifySafaUnlock(spend, encodeDataPush(redeemScript));
}

export function createSafaBatch() {
  const first = createSafaSpend();
  const second = createSafaSpend();
  second.previous.set(numberToBinUint32LE(2), 76);
  second.next = nextBaton(second.previous, second.transaction.outputs[1].lockingBytecode, second.age, 1792100001, 3);
  second.sourceOutputs[0].valueSatoshis = 60000n;
  second.sourceOutputs[0].token.amount = 252000000n;
  second.transaction.outputs[0].valueSatoshis = 58500n;
  second.transaction.outputs[0].token.nft.commitment = second.next;
  second.transaction.outputs[0].token.amount = 251999400n;
  second.transaction.outputs[1].token.amount = 600n;
  second.transaction.inputs[0].outpointTransactionHash = new Uint8Array(32).fill(0x12);
  first.transaction.inputs[0].unlockingBytecode = encodeUnlock(first.age, createSafaProof(first));
  second.transaction.inputs[0].unlockingBytecode = encodeUnlock(second.age, createSafaProof(second));
  return {
    sourceOutputs: [first.sourceOutputs[0], second.sourceOutputs[0]],
    transaction: {
      version: 2, locktime: first.transaction.locktime,
      inputs: [first.transaction.inputs[0], second.transaction.inputs[0]],
      outputs: [
        first.transaction.outputs[0], second.transaction.outputs[0],
        first.transaction.outputs[1], second.transaction.outputs[1],
      ],
    },
  };
}
import { mkdtempSync, rmdirSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
