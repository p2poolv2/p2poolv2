---- MODULE Pruning ----
EXTENDS BlockchainTx

CONSTANTS
    PrunedLength,       \* Number of blocks retained after pruning (deletion boundary)
    SpendWindow         \* Outputs older than this are unspendable (< PrunedLength)

VARIABLES
    prune_height        \* Blocks at or below this height are pruned

all_vars == <<chain, next_txid, prune_height>>

(****************************************************************************)
(* Maximum height that can be pruned given the current chain length         *)
(****************************************************************************)
MaxPruneHeight ==
    IF ChainHeight > PrunedLength
    THEN ChainHeight - PrunedLength
    ELSE 0

(****************************************************************************)
(* Spendable UTXOs restricted to outputs within the spend window.           *)
(* Rule 3 from pruning design: an output past SpendWindow is unspendable.   *)
(* SpendWindow < PrunedLength provides a buffer so that by the time an      *)
(* output is deleted (past PrunedLength), blocks referencing it are safely  *)
(* above the prune boundary.                                                *)
(****************************************************************************)
NotPrunedSpendableUTXOs ==
    {u \in SpendableUTXOs : ChainHeight - u.height < SpendWindow}

(****************************************************************************)
(* Add a block, only allowing spends of outputs within the prune window.    *)
(* Reuses AddBlockCoinbaseOnly and AddBlockWithSpend from the base module.  *)
(****************************************************************************)
PrunedAddBlock ==
    /\ ChainHeight < MaxBlocks
    /\ UNCHANGED prune_height
    /\ \E addr \in Addresses:
        \/ AddBlockCoinbaseOnly(addr)
        \/ /\ NotPrunedSpendableUTXOs /= {}
           /\ \E input_set \in (SUBSET NotPrunedSpendableUTXOs \ {{}}):
              /\ Cardinality(input_set) <= 2
              /\ LET total_value == SetSum(input_set)
                 IN \E split \in ValueSplits(total_value):
                    \E output_addrs \in [1..Len(split) -> Addresses]:
                        AddBlockWithSpend(addr, input_set, split, output_addrs)

(****************************************************************************)
(* Advance the prune height to the current maximum.                         *)
(****************************************************************************)
Prune ==
    /\ MaxPruneHeight > prune_height
    /\ prune_height' = MaxPruneHeight
    /\ UNCHANGED <<chain, next_txid>>

(****************************************************************************)
(* Initial state                                                            *)
(****************************************************************************)
PruningInit ==
    /\ Init
    /\ prune_height = 0

(****************************************************************************)
(* Next-state relation                                                      *)
(****************************************************************************)
PruningNext ==
    \/ PrunedAddBlock
    \/ Prune

(****************************************************************************)
(* Specification                                                            *)
(****************************************************************************)
PruningSpec == PruningInit /\ [][PruningNext]_all_vars

(****************************************************************************)
(* Prune height stays within bounds                                         *)
(****************************************************************************)
PruneHeightValid ==
    /\ prune_height >= 0
    /\ prune_height <= MaxPruneHeight

(****************************************************************************)
(* Full-chain value conservation still holds.                               *)
(* Pruning restricts spending but does not destroy the underlying chain.    *)
(****************************************************************************)
FullChainValueConserved == TotalValueConserved

(****************************************************************************)
(* No double spend across the full chain                                    *)
(****************************************************************************)
FullChainNoDoubleSpend == NoDoubleSpend

(****************************************************************************)
(* All blocks in the full chain were valid when added                       *)
(****************************************************************************)
FullChainAllBlocksValid == AllBlocksValid

(****************************************************************************)
(* All outputs created in blocks within a height range                      *)
(****************************************************************************)
AllOutputsInRange(from_height, to_height) ==
    IF from_height > to_height THEN {}
    ELSE UNION {BlockOutputs(block_idx) : block_idx \in from_height..to_height}

(****************************************************************************)
(* All outpoints spent by transactions in blocks within a height range      *)
(****************************************************************************)
AllSpentOutPointsInRange(from_height, to_height) ==
    IF from_height > to_height THEN {}
    ELSE UNION {BlockSpentOutPoints(block_idx) : block_idx \in from_height..to_height}

(****************************************************************************)
(* UTXO set considering only blocks in a height range                       *)
(****************************************************************************)
UTXOInRange(from_height, to_height) ==
    {output \in AllOutputsInRange(from_height, to_height) :
        [txid |-> output.txid, vout |-> output.vout] \notin
            AllSpentOutPointsInRange(from_height, to_height)}

(****************************************************************************)
(* The non-pruned portion of the chain can be fully validated, except for   *)
(* the first SpendWindow blocks above the prune boundary. Those blocks      *)
(* may reference outputs that were valid when built but are now pruned.     *)
(* This matches the sync protocol's relaxed validation zone (anchor block   *)
(* and nearby blocks get trusted based on PoW, not full re-validation).     *)
(*                                                                          *)
(* Proof: if block_idx > prune_height + SpendWindow, then any output O it   *)
(* references satisfies O > block_idx - 1 - SpendWindow >= prune_height,    *)
(* so O is above the prune boundary and available for validation.           *)
(****************************************************************************)
PrunedChainValid ==
    \A block_idx \in (prune_height + 1 + SpendWindow)..ChainHeight:
        ValidateBlockAgainst(
            chain[block_idx],
            UTXOInRange(prune_height + 1, block_idx - 1),
            block_idx - 1)

====
