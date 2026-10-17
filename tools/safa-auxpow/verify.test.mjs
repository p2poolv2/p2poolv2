import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import {
  binToHex, createVirtualMachineBch2026, decodeAuthenticationInstructions,
  decodeTransactionBch, encodeDataPush, encodeTransactionBch, flattenBinArray,
  hash256, hexToBin, numberToBinUint32LE,
} from '@bitauth/libauth';
import {
  MAX_TARGET, decodeTarget, deriveWork, encodeHeader, encodeTarget, encodeUnlock, fromHex,
  nextBaton, redeemScript,
} from './lib.mjs';
import {
  createSafaBatch, createSafaProof, createSafaSpend, remineSafaProof, verifySafaMarket,
  verifySafaSpend, verifySafaUnlock,
} from './test_utils.mjs';

const fixture = JSON.parse(readFileSync(new URL('test_data/regtest-withdrawal.json', import.meta.url), 'utf8'));

test('the BCHN-accepted regtest withdrawal verifies against its actual genesis outputs', () => {
  assert.equal(binToHex(hash256(redeemScript)), '41487c18c5644504dd4c13015739131d21cac3b0961ffd05a5d1d7f02bc7e3da');
  assert.equal(binToHex(hash256(fromHex(fixture.genesis_hex)).reverse()), fixture.genesis_txid);
  assert.equal(binToHex(hash256(fromHex(fixture.withdrawal_hex)).reverse()), fixture.withdrawal_txid);
  const genesis = decodeTransactionBch(fromHex(fixture.genesis_hex));
  const transaction = decodeTransactionBch(fromHex(fixture.withdrawal_hex));
  assert.notEqual(typeof genesis, 'string');
  assert.notEqual(typeof transaction, 'string');
  assert.equal(binToHex(transaction.inputs[0].outpointTransactionHash), fixture.genesis_txid);
  assert.equal(transaction.inputs[0].outpointIndex, 0);
  assert.equal(transaction.inputs[0].sequenceNumber, fixture.relative_age);
  assert.equal(binToHex(transaction.inputs[1].outpointTransactionHash), fixture.genesis_txid);
  assert.equal(transaction.inputs[1].outpointIndex, 1);
  assert.equal(createVirtualMachineBch2026(true).verify({ transaction, sourceOutputs: genesis.outputs }), true);
});

test('the same real withdrawal also verifies the two-work Full-Template proof', () => {
  const genesis = decodeTransactionBch(fromHex(fixture.genesis_hex));
  const transaction = decodeTransactionBch(fromHex(fixture.withdrawal_hex));
  transaction.inputs[0].unlockingBytecode = encodeUnlock(transaction.inputs[0].sequenceNumber, fixture.full_proof);
  assert.equal(createVirtualMachineBch2026(true).verify({ transaction, sourceOutputs: genesis.outputs }), true);
});

test('a SAFA withdrawal verifies its complete AuxPoW inside the standard BCH 2026 VM', () => {
  const spend = createSafaSpend();
  const proof = createSafaProof(spend);
  assert.equal(verifySafaSpend(spend, proof), true);
});

test('an unchanged baton keeps the SAFA market path available without a mining proof', () => {
  const spend = createSafaSpend();
  spend.transaction.outputs = [structuredClone(spend.sourceOutputs[0])];
  assert.equal(verifySafaMarket(spend), true);
});

test('a proof-free unchanged market self-cycle replaces the outpoint but preserves the claimed mining age', () => {
  const spend = createSafaSpend();
  const proof = createSafaProof(spend);
  const vault = structuredClone(spend.sourceOutputs[0]);
  const spentOutpoint = Uint8Array.from(spend.transaction.inputs[0].outpointTransactionHash);
  spend.transaction.inputs[0].sequenceNumber = 0xffffffff;
  spend.sourceOutputs.push({ valueSatoshis: 2000n, lockingBytecode: Uint8Array.of(0x51) });
  spend.transaction.inputs.push({
    outpointTransactionHash: new Uint8Array(32).fill(0x55), outpointIndex: 1,
    sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(),
  });
  spend.transaction.outputs = [vault, {
    valueSatoshis: 1000n, lockingBytecode: Uint8Array.of(0x51),
  }];
  assert.equal(verifySafaMarket(spend), true);
  assert.deepEqual(spend.transaction.inputs[0].unlockingBytecode, encodeDataPush(redeemScript));
  assert.deepEqual(spend.transaction.outputs[0], spend.sourceOutputs[0]);
  assert.equal(
    spend.sourceOutputs[0].valueSatoshis + spend.sourceOutputs[1].valueSatoshis
      - spend.transaction.outputs[0].valueSatoshis - spend.transaction.outputs[1].valueSatoshis,
    1000n,
  );
  const replacementOutpoint = hash256(encodeTransactionBch(spend.transaction)).reverse();
  assert.notDeepEqual(replacementOutpoint, spentOutpoint);

  const continued = createSafaSpend();
  continued.sourceOutputs[0] = structuredClone(vault);
  continued.transaction.inputs[0].outpointTransactionHash = replacementOutpoint;
  assert.equal(continued.transaction.inputs[0].outpointIndex, 0);
  assert.equal(continued.transaction.inputs[0].sequenceNumber, 71);
  assert.equal(verifySafaSpend(continued, proof), true);
  // The VM checks CSV against the sequence; BCHN must check the new output's actual age.
  continued.transaction.inputs[0].sequenceNumber = 0;
  assert.notEqual(verifySafaSpend(continued, proof), true);
});

test('a real market exchange preserves the virtual constant product', () => {
  const spend = createSafaSpend();
  spend.sourceOutputs[0].valueSatoshis = 100000n;
  const vault = structuredClone(spend.sourceOutputs[0]);
  vault.valueSatoshis += 50000n;
  vault.token.amount -= 20000n;
  spend.sourceOutputs.push({ lockingBytecode: Uint8Array.of(0x51), valueSatoshis: 51000n });
  spend.transaction.inputs.push({
    outpointTransactionHash: new Uint8Array(32).fill(0x55), outpointIndex: 1,
    sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(),
  });
  spend.transaction.outputs = [vault, {
    lockingBytecode: spend.transaction.outputs[1].lockingBytecode,
    valueSatoshis: 800n, token: { category: spend.category, amount: 20000n },
  }];
  assert.equal(verifySafaMarket(spend), true);
  spend.transaction.outputs[0].token.amount -= 1000000n;
  spend.transaction.outputs[1].token.amount += 1000000n;
  assert.notEqual(verifySafaMarket(spend), true);
});

test('the maximum coinbase and auxiliary Merkle depths execute inside the VM', () => {
  const spend = createSafaSpend();
  const proof = createSafaProof(spend, { auxiliaryDepth: 30, coinbaseDepth: 25 });
  assert.equal(verifySafaSpend(spend, proof), true);
  assert.ok(encodeUnlock(spend.age, proof).length < 10000);
});

test('proof targets remain independent of the parent header nBits', () => {
  const spend = createSafaSpend();
  const proof = createSafaProof(spend);
  proof.parent_header.bits = 0;
  remineSafaProof(proof, spend.next);
  assert.equal(verifySafaSpend(spend, proof), true);
});

test('an unsigned high-bit parent hash is rejected when it exceeds the token target', () => {
  const spend = createSafaSpend();
  const proof = createSafaProof(spend);
  do { proof.parent_header.nonce += 1; }
  while (hash256(encodeHeader(proof.parent_header))[31] < 0x80);
  assert.notEqual(verifySafaSpend(spend, proof), true);
});

test('the DAA can encode and verify a target with exponent 33', () => {
  const spend = createSafaSpend({ age: 142 });
  assert.equal(spend.next[75], 33);
  assert.equal(verifySafaSpend(spend, createSafaProof(spend)), true);
});

test('compact target encoding covers one, sign padding and the 256-bit maximum', () => {
  assert.equal(encodeTarget(1n), 0x01010000);
  assert.equal(decodeTarget(0x01010000), 1n);
  assert.equal(encodeTarget(128n), 0x02008000);
  assert.equal(decodeTarget(0x02008000), 128n);
  assert.equal(encodeTarget(MAX_TARGET), 0x2100ffff);
  assert.equal(decodeTarget(0x2100ffff), 0xffffn << 240n);
  assert.throws(() => decodeTarget(0x1d80ffff));
  assert.throws(() => decodeTarget(0x21010000));
  assert.throws(() => decodeTarget(0x02000100));
  assert.throws(() => encodeTarget(MAX_TARGET + 1n));
});

test('a changed aux sibling cannot reuse the original commitment', () => {
  const spend = createSafaSpend();
  const proof = createSafaProof(spend);
  proof.auxiliary.branch[0] = '00'.repeat(32);
  assert.notEqual(verifySafaSpend(spend, proof), true);
});

test('a changed coinbase sibling cannot reuse the parent header', () => {
  const spend = createSafaSpend();
  const proof = createSafaProof(spend);
  proof.coinbase_branch[0] = '00'.repeat(32);
  assert.notEqual(verifySafaSpend(spend, proof), true);
});

test('a paid auxiliary commitment is rejected even with a newly mined parent', () => {
  const spend = createSafaSpend();
  const proof = createSafaProof(spend);
  proof.coinbase.output[2].value = 1;
  remineSafaProof(proof, spend.next);
  assert.notEqual(verifySafaSpend(spend, proof), true);
});

test('duplicate auxiliary outputs are rejected even with a newly mined parent', () => {
  const spend = createSafaSpend();
  const proof = createSafaProof(spend);
  proof.coinbase.output.push(structuredClone(proof.coinbase.output[2]));
  remineSafaProof(proof, spend.next);
  assert.notEqual(verifySafaSpend(spend, proof), true);
});

test('a non-coinbase transaction cannot serve as the parent coinbase', () => {
  const spend = createSafaSpend();
  const proof = createSafaProof(spend);
  proof.coinbase.input[0].previous_output = `${'11'.repeat(32)}:0`;
  remineSafaProof(proof, spend.next);
  assert.notEqual(verifySafaSpend(spend, proof), true);
});

test('a missing auxiliary output is rejected', () => {
  const spend = createSafaSpend();
  const proof = createSafaProof(spend);
  proof.coinbase.output.pop();
  remineSafaProof(proof, spend.next);
  assert.notEqual(verifySafaSpend(spend, proof), true);
});

test('a noncanonical CompactSize cannot hide the auxiliary output', () => {
  const spend = createSafaSpend();
  const proof = createSafaProof(spend);
  const argumentsList = decodeAuthenticationInstructions(encodeUnlock(spend.age, proof));
  const coinbase = argumentsList[2].data;
  argumentsList[2].data = flattenBinArray([coinbase.slice(0, 41), hexToBin('fd0300'), coinbase.slice(42)]);
  const rawUnlock = flattenBinArray(argumentsList.map(instruction => encodeDataPush(instruction.data)));
  assert.notEqual(verifySafaUnlock(spend, rawUnlock), true);
});

test('the complete unlocking budget accepts exactly 10000 bytes and rejects the next byte', () => {
  const spend = createSafaSpend();
  const proof = createSafaProof(spend, { auxiliaryDepth: 30, coinbaseDepth: 25 });
  proof.coinbase.output[0].script_pubkey = '51'.repeat(6000);
  remineSafaProof(proof, spend.next);
  const deficit = 10000 - encodeUnlock(spend.age, proof).length;
  proof.coinbase.output[0].script_pubkey += '51'.repeat(deficit);
  remineSafaProof(proof, spend.next);
  assert.equal(encodeUnlock(spend.age, proof).length, 10000);
  assert.equal(verifySafaSpend(spend, proof), true);
  proof.coinbase.output[0].script_pubkey += '51';
  assert.throws(() => encodeUnlock(spend.age, proof), /exceeds 10000/);
});

test('oversized branches are rejected by the adapter before constructing a spend', () => {
  const spend = createSafaSpend();
  const proof = createSafaProof(spend);
  proof.auxiliary.branch = Array(31).fill('00'.repeat(32));
  assert.throws(() => encodeUnlock(spend.age, proof), /branch limits/);
  proof.auxiliary.branch = [];
  proof.coinbase_branch = Array(26).fill('00'.repeat(32));
  assert.throws(() => encodeUnlock(spend.age, proof), /branch limits/);
});

test('reward redirection fails both with an unchanged baton and with a rewritten recipient hash', () => {
  const spend = createSafaSpend();
  const proof = createSafaProof(spend);
  spend.transaction.outputs[1].lockingBytecode = Uint8Array.of(0x51);
  assert.notEqual(verifySafaSpend(spend, proof), true);
  spend.transaction.outputs[0].token.nft.commitment = nextBaton(
    spend.previous, spend.transaction.outputs[1].lockingBytecode, spend.age, 1792100001, 2,
  );
  assert.notEqual(verifySafaSpend(spend, proof), true);
});

test('a proof cannot be replayed across token categories', () => {
  const spend = createSafaSpend();
  const proof = createSafaProof(spend);
  const foreign = new Uint8Array(32).fill(0x24);
  spend.sourceOutputs[0].token.category = foreign;
  spend.transaction.outputs[0].token.category = foreign;
  spend.transaction.outputs[1].token.category = foreign;
  assert.notEqual(verifySafaSpend(spend, proof), true);
});

test('work binds the covenant identity independently of the token category', () => {
  const spend = createSafaSpend();
  assert.notDeepEqual(
    deriveWork(spend.category, spend.previous, spend.next),
    deriveWork(spend.category, spend.previous, spend.next, Uint8Array.of(0x51)),
  );
});

test('a proof cannot be replayed after the baton advances', () => {
  const spend = createSafaSpend();
  const proof = createSafaProof(spend);
  spend.sourceOutputs[0] = structuredClone(spend.transaction.outputs[0]);
  spend.previous = spend.next;
  spend.next = nextBaton(spend.previous, spend.transaction.outputs[1].lockingBytecode, spend.age, 1792100002, 3);
  spend.transaction.outputs[0].token.nft.commitment = spend.next;
  const reward = spend.sourceOutputs[0].token.amount / 420000n;
  spend.transaction.outputs[0].token.amount = spend.sourceOutputs[0].token.amount - reward;
  spend.transaction.outputs[1].token.amount = reward;
  spend.transaction.outputs[0].valueSatoshis = spend.sourceOutputs[0].valueSatoshis - 1500n;
  spend.transaction.locktime += 1;
  assert.notEqual(verifySafaSpend(spend, proof), true);
});

test('the mutable baton cannot become a minting baton', () => {
  const spend = createSafaSpend();
  const proof = createSafaProof(spend);
  spend.sourceOutputs[0].token.nft.capability = 'minting';
  spend.transaction.outputs[0].token.nft.capability = 'minting';
  assert.notEqual(verifySafaSpend(spend, proof), true);
});

test('extra token withdrawal and excess cash subsidy are refused', () => {
  const spend = createSafaSpend();
  const proof = createSafaProof(spend);
  spend.transaction.outputs[0].token.amount -= 1n;
  spend.transaction.outputs[1].token.amount += 1n;
  assert.notEqual(verifySafaSpend(spend, proof), true);
  spend.transaction.outputs[0].token.amount += 1n;
  spend.transaction.outputs[1].token.amount -= 1n;
  spend.transaction.outputs[0].valueSatoshis -= 1n;
  assert.notEqual(verifySafaSpend(spend, proof), true);
});

test('the recipient reward must have the vault token category', () => {
  const spend = createSafaSpend();
  const proof = createSafaProof(spend);
  const foreign = new Uint8Array(32).fill(0x25);
  spend.sourceOutputs.push({
    valueSatoshis: 1000n, lockingBytecode: Uint8Array.of(0x51),
    token: { category: foreign, amount: 1000n },
  });
  spend.transaction.inputs.push({
    outpointTransactionHash: new Uint8Array(32).fill(0x66), outpointIndex: 1,
    sequenceNumber: 0xffffffff, unlockingBytecode: new Uint8Array(),
  });
  spend.transaction.outputs.push(spend.transaction.outputs[1]);
  spend.transaction.outputs[2].token = { category: foreign, amount: 1000n };
  spend.transaction.outputs[1] = { valueSatoshis: 800n, lockingBytecode: Uint8Array.of(0x51) };
  assert.notEqual(verifySafaSpend(spend, proof), true);
});

test('a future claimed age cannot bypass the input sequence lock', () => {
  const spend = createSafaSpend();
  const proof = createSafaProof(spend);
  spend.transaction.inputs[0].sequenceNumber = 70;
  assert.notEqual(verifySafaSpend(spend, proof), true);
});

test('truncated batons and noncanonical previous targets are refused', () => {
  const spend = createSafaSpend();
  const proof = createSafaProof(spend);
  spend.sourceOutputs[0].token.nft.commitment = spend.previous.slice(0, 79);
  assert.notEqual(verifySafaSpend(spend, proof), true);
  spend.sourceOutputs[0].token.nft.commitment = Uint8Array.from(spend.previous);
  spend.sourceOutputs[0].token.nft.commitment.set(numberToBinUint32LE(0x02000100), 72);
  assert.notEqual(verifySafaSpend(spend, proof), true);
});

test('a mining spend cannot roll its timestamp backward', () => {
  const spend = createSafaSpend();
  const proof = createSafaProof(spend);
  spend.transaction.outputs[0].token.nft.commitment.set(numberToBinUint32LE(1792099999), 68);
  assert.notEqual(verifySafaSpend(spend, proof), true);
});

test('two unequal SAFA inputs compose with disjoint continuing and reward outputs', () => {
  const batch = createSafaBatch();
  assert.equal(createVirtualMachineBch2026(true).verify(batch), true);
});

test('two SAFA invocations cannot count one continuing output twice', () => {
  const batch = createSafaBatch();
  batch.transaction.outputs[1].lockingBytecode = Uint8Array.of(0x51);
  batch.transaction.outputs[1].valueSatoshis = 0n;
  assert.notEqual(createVirtualMachineBch2026(true).verify(batch), true);
});

test('two SAFA invocations cannot count one reward output twice', () => {
  const batch = createSafaBatch();
  batch.transaction.outputs[2].token.amount += batch.transaction.outputs[3].token.amount;
  batch.transaction.outputs[3].token.amount = 0n;
  assert.notEqual(createVirtualMachineBch2026(true).verify(batch), true);
});

test('CSV rejects disabled sequences and the wrong relative time domain', () => {
  const spend = createSafaSpend();
  const proof = createSafaProof(spend);
  spend.transaction.inputs[0].sequenceNumber = 0x80000047;
  assert.notEqual(verifySafaSpend(spend, proof), true);
  spend.transaction.inputs[0].sequenceNumber = 0x00400047;
  assert.notEqual(verifySafaSpend(spend, proof), true);
  spend.transaction.inputs[0].sequenceNumber = 0xffffffff;
  assert.notEqual(verifySafaSpend(spend, proof), true);
});

test('CLTV enforces the baton timestamp and its time domain', () => {
  const spend = createSafaSpend();
  const proof = createSafaProof(spend);
  spend.transaction.locktime -= 1;
  assert.notEqual(verifySafaSpend(spend, proof), true);
  spend.transaction.locktime = 100;
  assert.notEqual(verifySafaSpend(spend, proof), true);
});

test('a zero rounded token reward cannot consume a mining transition', () => {
  const spend = createSafaSpend();
  const proof = createSafaProof(spend);
  spend.sourceOutputs[0].token.amount = 419999n;
  spend.transaction.outputs[0].token.amount = 419999n;
  delete spend.transaction.outputs[1].token;
  assert.notEqual(verifySafaSpend(spend, proof), true);
});
