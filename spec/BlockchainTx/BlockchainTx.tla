---- MODULE BlockchainTx ----
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    Addresses,          \* Set of possible payout addresses
    MaxBlocks,          \* Maximum chain length
    Confirmations,      \* Coinbase maturity depth
    CoinbaseValue,      \* Value created by each coinbase output
    MaxOutputs          \* Max outputs per spending tx

VARIABLES
    chain,              \* Sequence of blocks; each block is a sequence of transactions
    next_txid           \* Monotonic counter for unique transaction ids

vars == <<chain, next_txid>>

(****************************************************************************)
(* Chain height derived from chain length                                   *)
(****************************************************************************)
ChainHeight == Len(chain)

(****************************************************************************)
(* Outputs from a single transaction included at a given block height.      *)
(* Each output is annotated with its txid, vout index, value, address,      *)
(* coinbase flag, and the block height where it was created.                *)
(****************************************************************************)
TxOutputs(tx, height) ==
    {[txid        |-> tx.txid,
      vout        |-> idx - 1,
      value       |-> tx.outputs[idx].value,
      addr        |-> tx.outputs[idx].addr,
      is_coinbase |-> tx.is_coinbase,
      height      |-> height]
     : idx \in 1..Len(tx.outputs)}

(****************************************************************************)
(* All outputs created in a single block                                    *)
(****************************************************************************)
BlockOutputs(block_idx) ==
    UNION {TxOutputs(chain[block_idx][tx_idx], block_idx)
           : tx_idx \in 1..Len(chain[block_idx])}

(****************************************************************************)
(* All outputs ever created across the entire chain                         *)
(****************************************************************************)
AllOutputs ==
    IF ChainHeight = 0 THEN {}
    ELSE UNION {BlockOutputs(block_idx) : block_idx \in 1..ChainHeight}

(****************************************************************************)
(* All outpoints consumed by transaction inputs in a single block           *)
(****************************************************************************)
BlockSpentOutPoints(block_idx) ==
    UNION {chain[block_idx][tx_idx].inputs
           : tx_idx \in 1..Len(chain[block_idx])}

(****************************************************************************)
(* All outpoints consumed by transaction inputs across the chain            *)
(****************************************************************************)
AllSpentOutPoints ==
    IF ChainHeight = 0 THEN {}
    ELSE UNION {BlockSpentOutPoints(block_idx) : block_idx \in 1..ChainHeight}

(****************************************************************************)
(* Unspent transaction outputs: all outputs minus those already spent       *)
(****************************************************************************)
UTXO ==
    {output \in AllOutputs :
        [txid |-> output.txid, vout |-> output.vout] \notin AllSpentOutPoints}

(****************************************************************************)
(* UTXO set considering only blocks 1..height.                              *)
(* Used to validate a block against the state before it was added.          *)
(****************************************************************************)
AllOutputsUpto(height) ==
    IF height = 0 THEN {}
    ELSE UNION {BlockOutputs(block_idx) : block_idx \in 1..height}

AllSpentOutPointsUpto(height) ==
    IF height = 0 THEN {}
    ELSE UNION {BlockSpentOutPoints(block_idx) : block_idx \in 1..height}

UTXOUpto(height) ==
    {output \in AllOutputsUpto(height) :
        [txid |-> output.txid, vout |-> output.vout] \notin AllSpentOutPointsUpto(height)}

(****************************************************************************)
(* A UTXO is spendable if it is non-coinbase, or a coinbase output with     *)
(* at least Confirmations blocks built on top of it                         *)
(****************************************************************************)
IsSpendable(output) ==
    IF output.is_coinbase
    THEN ChainHeight - output.height >= Confirmations
    ELSE TRUE

IsSpendableAt(output, height) ==
    IF output.is_coinbase
    THEN height - output.height >= Confirmations
    ELSE TRUE

(****************************************************************************)
(* The set of UTXOs that can currently be used as transaction inputs        *)
(****************************************************************************)
SpendableUTXOs == {output \in UTXO : IsSpendable(output)}

(****************************************************************************)
(* Recursive sum of .value over a set of output records                     *)
(****************************************************************************)
RECURSIVE SetSum(_)
SetSum(S) ==
    IF S = {} THEN 0
    ELSE LET elem == CHOOSE elem \in S : TRUE
         IN elem.value + SetSum(S \ {elem})

(****************************************************************************)
(* Sum output values in a transaction by walking the output sequence        *)
(****************************************************************************)
RECURSIVE IndexedSum(_, _)
IndexedSum(outputs, idx) ==
    IF idx = 0 THEN 0
    ELSE outputs[idx].value + IndexedSum(outputs, idx - 1)

TxOutputValue(tx) == IndexedSum(tx.outputs, Len(tx.outputs))

(****************************************************************************)
(* The UTXO records referenced by a set of input outpoints                  *)
(****************************************************************************)
InputUTXOs(inputs) ==
    {u \in UTXO : [txid |-> u.txid, vout |-> u.vout] \in inputs}

InputUTXOsFrom(inputs, utxo_set) ==
    {u \in utxo_set : [txid |-> u.txid, vout |-> u.vout] \in inputs}

(****************************************************************************)
(* Validate a coinbase transaction: no inputs, single output of             *)
(* CoinbaseValue, and addr in Addresses                                     *)
(****************************************************************************)
ValidateCoinbaseTx(tx) ==
    /\ tx.is_coinbase = TRUE
    /\ tx.inputs = {}
    /\ Len(tx.outputs) = 1
    /\ tx.outputs[1].value = CoinbaseValue
    /\ tx.outputs[1].addr \in Addresses

(****************************************************************************)
(* Validate a spending transaction against a given UTXO set and height:     *)
(*   - not coinbase                                                         *)
(*   - has at least one input                                               *)
(*   - all prevouts exist as unspent outputs in utxo_set                    *)
(*   - all prevouts satisfy maturity at the given height                    *)
(*   - all outputs have positive value                                      *)
(*   - total input value equals total output value (conservation)           *)
(****************************************************************************)
ValidateSpendingTxAgainst(tx, utxo_set, height) ==
    LET input_utxos == InputUTXOsFrom(tx.inputs, utxo_set)
    IN /\ tx.is_coinbase = FALSE
       /\ tx.inputs /= {}
       \* All prevouts reference existing unspent outputs
       /\ \A inp \in tx.inputs:
           \E u \in utxo_set: u.txid = inp.txid /\ u.vout = inp.vout
       \* All prevouts are spendable (coinbase maturity satisfied)
       /\ \A u \in input_utxos: IsSpendableAt(u, height)
       \* All outputs have positive value
       /\ \A idx \in 1..Len(tx.outputs): tx.outputs[idx].value > 0
       \* Value conservation: input value equals output value
       /\ SetSum(input_utxos) = TxOutputValue(tx)

ValidateSpendingTx(tx) == ValidateSpendingTxAgainst(tx, UTXO, ChainHeight)

(****************************************************************************)
(* Validate a block against a given UTXO set and height:                    *)
(*   - first transaction is a valid coinbase                                *)
(*   - remaining transactions are valid spending txs                        *)
(*   - no two spending txs in the block consume the same outpoint           *)
(****************************************************************************)
ValidateBlockAgainst(block, utxo_set, height) ==
    /\ Len(block) >= 1
    /\ ValidateCoinbaseTx(block[1])
    /\ \A tx_idx \in 2..Len(block):
        ValidateSpendingTxAgainst(block[tx_idx], utxo_set, height)
    \* No cross-tx double spend within the block
    /\ \A t1 \in 2..Len(block):
       \A t2 \in 2..Len(block):
           (t1 /= t2) => (block[t1].inputs \intersect block[t2].inputs = {})

ValidateBlock(block) == ValidateBlockAgainst(block, UTXO, ChainHeight)

(****************************************************************************)
(* All ways to split value v into exactly n positive integers.              *)
(* Each result is a sequence of length n summing to v.                      *)
(****************************************************************************)
RECURSIVE Splits(_, _)
Splits(v, n) ==
    IF n = 1 THEN {<<v>>}
    ELSE UNION {
        {<<first>> \o rest : rest \in Splits(v - first, n - 1)}
        : first \in 1..(v - n + 1)
    }

(****************************************************************************)
(* All valid output value sequences for a given total input value.          *)
(* Returns sequences of length 1 through MaxOutputs, each summing to v.    *)
(****************************************************************************)
ValueSplits(v) ==
    UNION {Splits(v, n) : n \in 1..MaxOutputs}

(****************************************************************************)
(* Construct a spending transaction from inputs, a value split, and         *)
(* output addresses                                                         *)
(****************************************************************************)
MakeSpendingTx(txid, input_set, split, output_addrs) ==
    [txid        |-> txid,
     is_coinbase |-> FALSE,
     inputs      |-> {[txid |-> u.txid, vout |-> u.vout] : u \in input_set},
     outputs     |-> [idx \in 1..Len(split) |->
                         [value |-> split[idx], addr |-> output_addrs[idx]]]]

(****************************************************************************)
(* Initial state: empty chain, txid counter at zero                         *)
(****************************************************************************)
Init ==
    /\ chain = <<>>
    /\ next_txid = 0

(****************************************************************************)
(* Add a block containing only a coinbase transaction                       *)
(****************************************************************************)
AddBlockCoinbaseOnly(addr) ==
    LET coinbase_tx == [
            txid        |-> next_txid,
            is_coinbase |-> TRUE,
            inputs      |-> {},
            outputs     |-> <<[value |-> CoinbaseValue, addr |-> addr]>>
        ]
    IN /\ chain' = Append(chain, <<coinbase_tx>>)
       /\ next_txid' = next_txid + 1

(****************************************************************************)
(* Add a block containing a coinbase and one spending transaction           *)
(****************************************************************************)
AddBlockWithSpend(addr, input_set, split, output_addrs) ==
    LET coinbase_tx == [
            txid        |-> next_txid,
            is_coinbase |-> TRUE,
            inputs      |-> {},
            outputs     |-> <<[value |-> CoinbaseValue, addr |-> addr]>>
        ]
        spending_tx == MakeSpendingTx(next_txid + 1, input_set, split, output_addrs)
    IN /\ chain' = Append(chain, <<coinbase_tx, spending_tx>>)
       /\ next_txid' = next_txid + 2

(****************************************************************************)
(* Add a new block to the chain. Each block always has a coinbase tx and    *)
(* optionally one spending tx that consumes 1-2 spendable UTXOs.            *)
(****************************************************************************)
AddBlock ==
    /\ ChainHeight < MaxBlocks
    /\ \E addr \in Addresses:
        \/ AddBlockCoinbaseOnly(addr)
        \/ /\ SpendableUTXOs /= {}
           /\ \E input_set \in (SUBSET SpendableUTXOs \ {{}}):
              /\ Cardinality(input_set) <= 2
              /\ LET total_value == SetSum(input_set)
                 IN \E split \in ValueSplits(total_value):
                    \E output_addrs \in [1..Len(split) -> Addresses]:
                        AddBlockWithSpend(addr, input_set, split, output_addrs)

(****************************************************************************)
(* Next-state relation                                                      *)
(****************************************************************************)
Next == AddBlock

(****************************************************************************)
(* Specification                                                            *)
(****************************************************************************)
Spec == Init /\ [][Next]_vars

(****************************************************************************)
(* Type invariant                                                           *)
(****************************************************************************)
TypeOK ==
    /\ chain \in Seq(Seq([txid: Nat, is_coinbase: BOOLEAN,
                          inputs: SUBSET [txid: Nat, vout: Nat],
                          outputs: Seq([value: Nat, addr: Addresses])]))
    /\ next_txid \in Nat

(****************************************************************************)
(* Total value conservation: the sum of all unspent output values equals    *)
(* the cumulative coinbase value created across all blocks.                 *)
(****************************************************************************)
TotalValueConserved ==
    IF ChainHeight = 0 THEN TRUE
    ELSE SetSum(UTXO) = ChainHeight * CoinbaseValue

(****************************************************************************)
(* No double spend: every outpoint is consumed by at most one transaction   *)
(* across the entire chain.                                                 *)
(****************************************************************************)
NoDoubleSpend ==
    \A block1 \in 1..ChainHeight:
        \A tx1 \in 1..Len(chain[block1]):
            \A spent_outpoint \in chain[block1][tx1].inputs:
                \A block2 \in 1..ChainHeight:
                    \A tx2 \in 1..Len(chain[block2]):
                        (spent_outpoint \in chain[block2][tx2].inputs) =>
                            (block1 = block2 /\ tx1 = tx2)

(****************************************************************************)
(* Every block in the chain was valid at the time it was added.             *)
(* Block at index i is validated against UTXOUpto(i-1), the UTXO set     *)
(* that existed before the block was appended.                              *)
(****************************************************************************)
AllBlocksValid ==
    \A block_idx \in 1..ChainHeight:
        ValidateBlockAgainst(chain[block_idx], UTXOUpto(block_idx - 1), block_idx - 1)

====
