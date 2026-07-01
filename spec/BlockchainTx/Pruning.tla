---- MODULE Pruning ----
EXTENDS BlockchainTx

CONSTANTS
    PruneDepth,         \* Number of blocks from chain tip that must be retained
    PPLNSDepth          \* Outputs older than this from tip are unspendable (< PruneDepth)

\* In production PruneDepth = 2 * PPLNSDepth (Pruning.org: "the pruned chain
\* is as long as 2x the PPLNS Depth"). The cfg uses smaller values that do not
\* satisfy this ratio in order to keep the model checker state space tractable.

VARIABLES
    prune_height        \* Blocks at or below this height are pruned

all_vars == <<chain, next_txid, prune_height>>

(****************************************************************************)
(* Maximum height that can be pruned given the current chain length         *)
(****************************************************************************)
MaxPruneHeight ==
    IF ChainHeight > PruneDepth
    THEN ChainHeight - PruneDepth
    ELSE 0

(****************************************************************************)
(* Spendable UTXOs restricted to outputs within the PPLNS Depth.            *)
(* Rule 2 from pruning design: an output past PPLNS Depth is unspendable.  *)
(* PPLNSDepth < PruneDepth provides a buffer so that by the time an        *)
(* output is deleted (past Prune Depth), blocks referencing it are safely   *)
(* above the prune boundary.                                                *)
(****************************************************************************)
NotPrunedSpendableUTXOs ==
    {u \in SpendableUTXOs : ChainHeight - u.height < PPLNSDepth}

(****************************************************************************)
(* Add a block, only allowing spends of outputs within PPLNS Depth.         *)
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
(* the first PPLNSDepth blocks above the prune boundary (the relaxed        *)
(* validation zone). Those blocks may reference outputs that were valid     *)
(* when built but are now pruned. This matches the sync protocol where      *)
(* blocks in the Prune Depth minus PPLNS Depth range are trusted via PoW.  *)
(*                                                                          *)
(* Proof: if block_idx > prune_height + PPLNSDepth, then any output O it    *)
(* references satisfies O > block_idx - 1 - PPLNSDepth >= prune_height,     *)
(* so O is above the prune boundary and available for validation.           *)
(****************************************************************************)
PrunedChainValid ==
    \A block_idx \in (prune_height + 1 + PPLNSDepth)..ChainHeight:
        ValidateBlockAgainst(
            chain[block_idx],
            UTXOInRange(prune_height + 1, block_idx - 1),
            block_idx - 1)

====
