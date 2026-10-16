import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  binToHex, cashAddressToLockingBytecode, createVirtualMachineBch2026,
  decodeTransactionBch, encodeTransactionBch, flattenBinArray, hash256,
  numberToBinUint32LE,
} from '@bitauth/libauth';
import { readJson } from './cli.mjs';
import {
  deriveWork, encodeUnlock, fromHex, lockingBytecode, nextBaton, redeemScript,
} from './lib.mjs';

const [command, directory, proofFile, extra] = process.argv.slice(2);
if (!directory || extra || !['prepare', 'spend'].includes(command)) {
  throw new Error('usage: node live-regtest.mjs prepare new-directory | spend directory proof.json');
}
const clientUrl = process.env.BCHN_JD_CLIENT_RPC;
const poolUrl = process.env.BCHN_JD_POOL_RPC;
const loopback = /^http:\/\/127\.0\.0\.1:\d+$/;
assert.ok(loopback.test(clientUrl ?? '') && loopback.test(poolUrl ?? ''));
assert.notEqual(clientUrl, poolUrl);
const auth = `Basic ${Buffer.from('p2pool-jd-test:local-regtest-only').toString('base64')}`;

async function rpc(url, method, params = [], wallet = false) {
  const response = await fetch(wallet ? `${url}/wallet/jd-regtest` : url, {
    method: 'POST', headers: { Authorization: auth, 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '1.0', id: 'safa-regtest', method, params }),
    signal: AbortSignal.timeout(30000),
  });
  const result = await response.json();
  if (result.error) throw new Error(`${method}: ${JSON.stringify(result.error)}`);
  assert.ok(response.ok);
  return result.result;
}

async function bothKnowBlock(hash) {
  const deadline = Date.now() + 15000;
  while (await rpc(poolUrl, 'getbestblockhash') !== hash) {
    if (Date.now() > deadline) throw new Error('pool node did not accept the block');
    await new Promise(resolve => setTimeout(resolve, 100));
  }
}

function addressScript(address) {
  const decoded = cashAddressToLockingBytecode(address);
  if (typeof decoded === 'string') throw new Error(decoded);
  return decoded.bytecode;
}

function save(name, value) {
  writeFileSync(join(directory, name), JSON.stringify(value, null, 2), { flag: 'wx' });
}

const clientChain = await rpc(clientUrl, 'getblockchaininfo');
assert.equal(clientChain.chain, 'regtest');
assert.equal((await rpc(poolUrl, 'getblockchaininfo')).chain, 'regtest');
assert.equal(await rpc(clientUrl, 'getconnectioncount') > 0, true);
await rpc(clientUrl, 'getwalletinfo', [], true);

if (command === 'prepare') {
  mkdirSync(directory);
  assert.equal((await rpc(clientUrl, 'getrawmempool')).length, 0);
  assert.equal((await rpc(poolUrl, 'getrawmempool')).length, 0);
  const fundingAddress = await rpc(clientUrl, 'getnewaddress', [], true);
  const changeAddress = await rpc(clientUrl, 'getnewaddress', [], true);
  const recipientAddress = await rpc(clientUrl, 'getnewaddress', [], true);
  const emptyFunding = await rpc(clientUrl, 'createrawtransaction', [[], { [fundingAddress]: 1 }]);
  const funded = await rpc(clientUrl, 'fundrawtransaction', [emptyFunding, { changePosition: 1 }], true);
  const signedFunding = await rpc(clientUrl, 'signrawtransactionwithwallet', [funded.hex], true);
  assert.equal(signedFunding.complete, true);
  const fundingTxid = await rpc(clientUrl, 'sendrawtransaction', [signedFunding.hex]);
  const category = fromHex(fundingTxid, 32);
  const recipient = addressScript(recipientAddress);
  const previous = flattenBinArray([
    numberToBinUint32LE(70), hash256(new TextEncoder().encode(`regtest thread ${fundingTxid}`)),
    hash256(recipient), numberToBinUint32LE(clientChain.mediantime - 1),
    numberToBinUint32LE(0x207fffff), numberToBinUint32LE(1),
  ]);
  const genesis = {
    version: 2, locktime: 0,
    inputs: [{ outpointTransactionHash: category, outpointIndex: 0,
      sequenceNumber: 0xfffffffe, unlockingBytecode: new Uint8Array() }],
    outputs: [
      { lockingBytecode, valueSatoshis: 2000000n,
        token: { category, amount: 420000000n, nft: { capability: 'mutable', commitment: previous } } },
      { lockingBytecode: addressScript(changeAddress), valueSatoshis: 97995000n },
    ],
  };
  const signed = await rpc(clientUrl, 'signrawtransactionwithwallet', [binToHex(encodeTransactionBch(genesis))], true);
  assert.equal(signed.complete, true);
  const genesisTxid = await rpc(clientUrl, 'sendrawtransaction', [signed.hex]);
  const blocks = await rpc(clientUrl, 'generatetoaddress', [71, fundingAddress]);
  await bothKnowBlock(blocks.at(-1));
  const next = nextBaton(previous, recipient, 71, clientChain.mediantime, 2);
  const work = deriveWork(category, previous, next);
  save('state.json', {
    category: fundingTxid, previous_baton: binToHex(previous), next_baton: binToHex(next),
    recipient: binToHex(recipient), change: binToHex(addressScript(changeAddress)), age: 71,
    timestamp: clientChain.mediantime, nonce: 2, genesis: genesisTxid,
    funding_address: fundingAddress, redeem_script: binToHex(redeemScript), work,
  });
  save('work.json', work);
  save('genesis.json', { txid: genesisTxid, hex: signed.hex, mature_height: (await rpc(clientUrl, 'getblockchaininfo')).blocks });
  console.log(JSON.stringify({ prepared: true, genesis: genesisTxid, work }));
} else {
  assert.ok(proofFile, 'supply the proof exported by the JD regtest');
  const state = readJson(join(directory, 'state.json'));
  assert.equal(binToHex(redeemScript), state.redeem_script, 'covenant changed after preparation');
  const proof = readJson(proofFile);
  assert.deepEqual(proof.auxiliary.work, state.work);
  const category = fromHex(state.category, 32);
  const previous = fromHex(state.previous_baton, 80);
  const next = fromHex(state.next_baton, 80);
  assert.deepEqual(deriveWork(category, previous, next), state.work);
  const genesis = readJson(join(directory, 'genesis.json'));
  const decodedGenesis = decodeTransactionBch(fromHex(genesis.hex));
  assert.notEqual(typeof decodedGenesis, 'string');
  const sourceOutputs = decodedGenesis.outputs;
  const transaction = {
    version: 2, locktime: state.timestamp,
    inputs: [
      { outpointTransactionHash: fromHex(state.genesis, 32), outpointIndex: 0,
        sequenceNumber: state.age, unlockingBytecode: encodeUnlock(state.age, proof) },
      { outpointTransactionHash: fromHex(state.genesis, 32), outpointIndex: 1,
        sequenceNumber: 0xfffffffe, unlockingBytecode: new Uint8Array() },
    ],
    outputs: [
      { lockingBytecode, valueSatoshis: 1998500n,
        token: { category, amount: 419999000n, nft: { capability: 'mutable', commitment: next } } },
      { lockingBytecode: fromHex(state.change), valueSatoshis: sourceOutputs[1].valueSatoshis - 4300n },
      { lockingBytecode: fromHex(state.recipient), valueSatoshis: 800n, token: { category, amount: 1000n } },
    ],
  };
  const signed = await rpc(clientUrl, 'signrawtransactionwithwallet', [binToHex(encodeTransactionBch(transaction))], true);
  const withdrawal = decodeTransactionBch(fromHex(signed.hex));
  assert.notEqual(typeof withdrawal, 'string');
  withdrawal.inputs[0].unlockingBytecode = transaction.inputs[0].unlockingBytecode;
  const vmResult = createVirtualMachineBch2026(true).verify({ transaction: withdrawal, sourceOutputs });
  assert.equal(vmResult, true);
  const raw = binToHex(encodeTransactionBch(withdrawal));
  const accepted = await rpc(clientUrl, 'testmempoolaccept', [[raw]]);
  assert.equal(accepted[0].allowed, true, JSON.stringify(accepted));
  const bad = structuredClone(withdrawal);
  const changedProof = structuredClone(proof);
  changedProof.coinbase_branch[0] = '00'.repeat(32);
  bad.inputs[0].unlockingBytecode = encodeUnlock(state.age, changedProof);
  const rejected = await rpc(clientUrl, 'testmempoolaccept', [[binToHex(encodeTransactionBch(bad))]]);
  assert.equal(rejected[0].allowed, false);
  save('withdrawal-candidate.json', { hex: raw, accepted, rejected, proof_file: proofFile });
  const txid = await rpc(clientUrl, 'sendrawtransaction', [raw]);
  const blocks = await rpc(clientUrl, 'generatetoaddress', [1, state.funding_address]);
  await bothKnowBlock(blocks[0]);
  const continued = await rpc(poolUrl, 'gettxout', [txid, 0]);
  const reward = await rpc(poolUrl, 'gettxout', [txid, 2]);
  assert.equal(continued.tokenData.nft.commitment, state.next_baton);
  assert.equal(continued.tokenData.amount, '419999000');
  assert.equal(reward.tokenData.amount, '1000');
  assert.equal(reward.tokenData.category, state.category);
  save('withdrawal.json', {
    txid, hex: raw, block: blocks[0], height: (await rpc(poolUrl, 'getblockchaininfo')).blocks,
    parent_header: proof.parent_header, unlocking_bytes: withdrawal.inputs[0].unlockingBytecode.length,
    fee_satoshis: 5000, accepted, rejected, continued, reward,
  });
  console.log(JSON.stringify({ withdrawn: true, txid, block: blocks[0], reward: reward.tokenData, rejected }));
}
