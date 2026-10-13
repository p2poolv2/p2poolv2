---- MODULE BitcoinChainSync ----
(****************************************************************************)
(* Paying only for work on the current bitcoin chain.                       *)
(* Design: docs/architecture/mine-on-bitcoin-chain.md.                      *)
(*                                                                          *)
(* Every share names the bitcoin block it builds on, its btc_prev. A miner  *)
(* can name a hash with no block behind it (Fake), or a block on a branch   *)
(* honest bitcoinds never accept: a header-only block, or a hostile fork.   *)
(*                                                                          *)
(* Acceptance: a node accepts a share once it has accepted the share's      *)
(* parent and uncles, and knows the btc_prev header, using the bitcoin      *)
(* headers carried with the share. Fork choice and the job builder are      *)
(* unchanged.                                                               *)
(*                                                                          *)
(* Payout rule: a share's coinbase pays a window share W only if btc_prev   *)
(* of W is eligible: on the chain ending at the paying share's btc_prev, or *)
(* one block off it. Ineligible shares keep their window slots and are paid *)
(* nothing. An uncle is paid only if it is eligible. A share whose window   *)
(* holds shares but none eligible is invalid, and an honest job builder     *)
(* facing that stops mining.                                                *)
(*                                                                          *)
(* Switches: CarryHeaders FALSE removes carried headers, and nodes can end  *)
(* up holding different shares. PayoutRule FALSE pays the whole window, and *)
(* blocks on the main chain pay work deep in a hostile fork.                *)
(*                                                                          *)
(* Abstractions: every bitcoin block and every share has equal work, so     *)
(* chainwork and share chain weight are heights, and payouts are modelled   *)
(* as the set of shares paid, not amounts. Header proof of work and         *)
(* timestamps are not modelled: every existing header is valid. Shares      *)
(* reach every node at once; a node accepts them when it can.               *)
(****************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Honest,         \* Honest nodes, each with its own bitcoind
    Attackers,      \* Nodes that mine shares on any btc_prev
    MaxBlocks,      \* Bound on bitcoin blocks, including the root
    MaxShares,      \* Bound on shares, including the genesis share
    MaxUncles,      \* MAX_UNCLES
    MaxUnclesDepth, \* MAX_UNCLES_DEPTH
    PplnsWindow,    \* Shares in the window, counted back from the parent
    CarryHeaders,   \* TRUE: share messages carry bitcoin headers
    PayoutRule      \* TRUE: pay only eligible shares (the design)

Root == 1          \* The bitcoin block every node starts from
Fake == 0          \* A btc_prev with no block behind it
GenesisShare == 1
NoShare == 0

VARIABLES
    blockCount,     \* Bitcoin blocks created so far, numbered 1..blockCount
    btcParent,      \* Bitcoin block -> its parent block
    hasBody,        \* Bitcoin block -> FALSE if no honest bitcoind accepts
                    \* it: header-only, or on a hostile fork
    foundBy,        \* Bitcoin block -> the share it was mined from, if any
    headers,        \* Honest node -> bitcoin headers it knows
    btcTip,         \* Honest node -> its bitcoind's active tip
    shareCount,     \* Shares mined so far, numbered 1..shareCount
    shareParent,    \* Share -> its share chain parent
    shareUncles,    \* Share -> the uncles it includes
    shareBtcPrev,   \* Share -> its btc_prev
    shareMiner,     \* Share -> the node that mined it
    accepted        \* Honest node -> shares in its store

vars == <<blockCount, btcParent, hasBody, foundBy, headers, btcTip,
          shareCount, shareParent, shareUncles, shareBtcPrev, shareMiner,
          accepted>>

BlockVars == <<blockCount, btcParent, hasBody, foundBy>>
ShareVars == <<shareCount, shareParent, shareUncles, shareBtcPrev, shareMiner>>

Blocks == 1..blockCount
Shares == 1..shareCount

(****************************************************************************)
(* Bitcoin chain                                                            *)
(****************************************************************************)
RECURSIVE BtcHeight(_), BtcAncestors(_)
BtcHeight(block) == IF block = Root THEN 1 ELSE 1 + BtcHeight(btcParent[block])
BtcAncestors(block) ==
    IF block = Root THEN {Root} ELSE {block} \cup BtcAncestors(btcParent[block])

\* Every block back to the root has a body honest bitcoinds accept.
FullChain(block) == \A ancestor \in BtcAncestors(block) : hasBody[ancestor]

\* How many blocks at the end of block's chain no honest bitcoind accepts:
\* how deep block is into a header-only branch or a hostile fork.
UnacceptedDepth(block) ==
    LET full == {ancestor \in BtcAncestors(block) : FullChain(ancestor)}
        deepest == CHOOSE ancestor \in full :
                    \A other \in full : BtcHeight(other) <= BtcHeight(ancestor)
    IN BtcHeight(block) - BtcHeight(deepest)

(****************************************************************************)
(* Share chain                                                              *)
(****************************************************************************)
RECURSIVE ShareHeight(_), ShareAncestors(_)
ShareHeight(share) ==
    IF share = GenesisShare THEN 1 ELSE 1 + ShareHeight(shareParent[share])
ShareAncestors(share) ==
    IF share = GenesisShare THEN {GenesisShare}
    ELSE {share} \cup ShareAncestors(shareParent[share])

\* Uncle position rules of the share chain, as in validate_uncle_positions.
UnclePositionOk(uncle, parent) ==
    /\ uncle \notin ShareAncestors(parent)
    /\ ShareHeight(uncle) <= ShareHeight(parent)
    /\ ShareHeight(parent) + 1 - ShareHeight(uncle) <= MaxUnclesDepth

(****************************************************************************)
(* PPLNS window and the payout rule                                         *)
(****************************************************************************)
\* The window of a share mined on parent: the last PplnsWindow shares of the
\* parent's history, eligible or not, so ineligible shares keep their slots.
WindowEntries(parent) ==
    {ancestor \in ShareAncestors(parent) \ {GenesisShare} :
        ShareHeight(parent) - ShareHeight(ancestor) < PplnsWindow}

\* Uncles of the window entries, which use no slots.
WindowUncles(parent) ==
    UNION {shareUncles[entry] : entry \in WindowEntries(parent)}
        \ {GenesisShare}

\* A window share is eligible for a paying share with btc_prev payingPrev if
\* its btc_prev is on the chain ending at payingPrev, or one block off it.
Eligible(payingPrev, share) ==
    LET prev == shareBtcPrev[share]
        payingChain == BtcAncestors(payingPrev)
    IN /\ prev # Fake
       /\ prev \in payingChain \/ btcParent[prev] \in payingChain

\* Shares paid by a share mined on parent with btc_prev payingPrev.
PaidShares(parent, payingPrev) ==
    LET candidates == WindowEntries(parent) \cup WindowUncles(parent)
    IN IF PayoutRule
       THEN {share \in candidates : Eligible(payingPrev, share)}
       ELSE candidates

\* The window holds shares, but none of them would be paid.
NothingEligible(parent, payingPrev) ==
    /\ WindowEntries(parent) # {}
    /\ PaidShares(parent, payingPrev) = {}

(****************************************************************************)
(* Acceptance: parent and uncles first, and the btc_prev header known once  *)
(* the share's carried headers are checked. The headers can come from any   *)
(* honest node that accepted the share, or from the attacker that mined it. *)
(* A share whose window holds shares but none eligible is invalid.          *)
(****************************************************************************)
HeadersSupplied(share) ==
    /\ CarryHeaders
    /\ shareBtcPrev[share] # Fake
    /\ \/ \E other \in Honest : share \in accepted[other]
       \/ shareMiner[share] \in Attackers

HeadersAfterCheck(node, share) ==
    IF HeadersSupplied(share)
    THEN headers[node] \cup BtcAncestors(shareBtcPrev[share])
    ELSE headers[node]

CanAccept(node, share) ==
    /\ share \notin accepted[node]
    /\ shareParent[share] \in accepted[node]
    /\ shareUncles[share] \subseteq accepted[node]
    /\ shareBtcPrev[share] \in HeadersAfterCheck(node, share)
    /\ ~NothingEligible(shareParent[share], shareBtcPrev[share])

(****************************************************************************)
(* Job builder: unchanged. The parent is the highest accepted share;        *)
(* uncles are accepted shares in an uncle position, not already an uncle of *)
(* the parent's ancestry, as many as MaxUncles allows.                      *)
(****************************************************************************)
JobParents(node) ==
    {share \in accepted[node] :
        \A other \in accepted[node] : ShareHeight(other) <= ShareHeight(share)}

CandidateUncles(node, parent) ==
    {uncle \in accepted[node] :
        /\ UnclePositionOk(uncle, parent)
        /\ \A ancestor \in ShareAncestors(parent) :
                uncle \notin shareUncles[ancestor]}

JobUncles(node, parent) ==
    LET candidates == CandidateUncles(node, parent)
        count == IF Cardinality(candidates) < MaxUncles
                 THEN Cardinality(candidates) ELSE MaxUncles
    IN {uncles \in SUBSET candidates : Cardinality(uncles) = count}

(****************************************************************************)
(* Actions                                                                  *)
(****************************************************************************)
Init ==
    /\ blockCount = 1
    /\ btcParent = [block \in 1..MaxBlocks |-> Root]
    /\ hasBody = [block \in 1..MaxBlocks |-> TRUE]
    /\ foundBy = [block \in 1..MaxBlocks |-> NoShare]
    /\ headers = [node \in Honest |-> {Root}]
    /\ btcTip = [node \in Honest |-> Root]
    /\ shareCount = 1
    /\ shareParent = [share \in 1..MaxShares |-> GenesisShare]
    /\ shareUncles = [share \in 1..MaxShares |-> {}]
    /\ shareBtcPrev = [share \in 1..MaxShares |-> Root]
    /\ shareMiner = [share \in 1..MaxShares |-> CHOOSE node \in Honest : TRUE]
    /\ accepted = [node \in Honest |-> {GenesisShare}]

\* A new bitcoin block on parent, mined from share or from outside the pool.
AddBlock(parent, withBody, share) ==
    /\ blockCount < MaxBlocks
    /\ blockCount' = blockCount + 1
    /\ btcParent' = [btcParent EXCEPT ![blockCount + 1] = parent]
    /\ hasBody' = [hasBody EXCEPT ![blockCount + 1] = withBody]
    /\ foundBy' = [foundBy EXCEPT ![blockCount + 1] = share]

\* A new share; if found, it also meets bitcoin difficulty.
AddShare(miner, parent, uncles, btcPrev, found) ==
    /\ shareCount < MaxShares
    /\ shareCount' = shareCount + 1
    /\ shareParent' = [shareParent EXCEPT ![shareCount + 1] = parent]
    /\ shareUncles' = [shareUncles EXCEPT ![shareCount + 1] = uncles]
    /\ shareBtcPrev' = [shareBtcPrev EXCEPT ![shareCount + 1] = btcPrev]
    /\ shareMiner' = [shareMiner EXCEPT ![shareCount + 1] = miner]
    /\ IF found THEN AddBlock(btcPrev, hasBody[btcPrev], shareCount + 1)
       ELSE UNCHANGED BlockVars

\* The bitcoin network finds a block outside the pool.
MineBitcoinBlock(parent) ==
    /\ hasBody[parent]
    /\ AddBlock(parent, TRUE, NoShare)
    /\ UNCHANGED <<headers, btcTip, ShareVars, accepted>>

\* An attacker publishes a block honest bitcoinds never accept: a header
\* without a body, or a block on a hostile fork.
MineUnacceptedBlock(parent) ==
    /\ Attackers # {}
    /\ AddBlock(parent, FALSE, NoShare)
    /\ UNCHANGED <<headers, btcTip, ShareVars, accepted>>

\* A block with more work than the tip, and bodies all the way down, reaches
\* a bitcoind, which moves its tip. Equal or less work never becomes the tip.
DeliverBitcoinBlock(node, block) ==
    /\ FullChain(block)
    /\ BtcHeight(block) > BtcHeight(btcTip[node])
    /\ btcTip' = [btcTip EXCEPT ![node] = block]
    /\ headers' = [headers EXCEPT ![node] = @ \cup BtcAncestors(block)]
    /\ UNCHANGED <<BlockVars, ShareVars, accepted>>

\* A peer on the bitcoin network announces a header, including a losing
\* sibling or an unaccepted block. It may never happen for a given block.
DeliverHeader(node, block) ==
    /\ block \notin headers[node]
    /\ btcParent[block] \in headers[node]
    /\ headers' = [headers EXCEPT ![node] = @ \cup {block}]
    /\ UNCHANGED <<BlockVars, btcTip, ShareVars, accepted>>

\* A node accepts a share it can accept. A share it cannot accept is
\* dropped, which changes nothing, so it is not an action; accepting it
\* later stands for the missing-parent header request fetching it again.
AcceptShare(node, share) ==
    /\ CanAccept(node, share)
    /\ headers' = [headers EXCEPT ![node] = HeadersAfterCheck(node, share)]
    /\ accepted' = [accepted EXCEPT ![node] = @ \cup {share}]
    /\ UNCHANGED <<BlockVars, btcTip, ShareVars>>

\* An honest node mines on its bitcoind tip with a parent and uncles from
\* its job builder, unless nothing in the window would be paid, in which case
\* it stops. A block it finds goes straight into its own bitcoind.
MineHonestShare(node, parent, uncles, found) ==
    /\ ~NothingEligible(parent, btcTip[node])
    /\ AddShare(node, parent, uncles, btcTip[node], found)
    /\ accepted' = [accepted EXCEPT ![node] = @ \cup {shareCount + 1}]
    /\ IF found
       THEN /\ btcTip' = [btcTip EXCEPT ![node] = blockCount + 1]
            /\ headers' = [headers EXCEPT ![node] = @ \cup {blockCount + 1}]
       ELSE UNCHANGED <<headers, btcTip>>

\* An attacker mines on any btc_prev, including Fake, unaccepted and old
\* blocks, with any parent and at most one uncle in a valid position. Its
\* coinbase follows the payout rule, or every node rejects the share, so
\* only rule-following attacker shares are modelled.
MineAttackerShare(attacker, parent, uncles, btcPrev, found) ==
    /\ \A uncle \in uncles : UnclePositionOk(uncle, parent)
    /\ found => btcPrev # Fake
    /\ AddShare(attacker, parent, uncles, btcPrev, found)
    /\ UNCHANGED <<headers, btcTip, accepted>>

Next ==
    \/ \E parent \in Blocks : MineBitcoinBlock(parent)
    \/ \E parent \in Blocks : MineUnacceptedBlock(parent)
    \/ \E node \in Honest, block \in Blocks : DeliverBitcoinBlock(node, block)
    \/ \E node \in Honest, block \in Blocks : DeliverHeader(node, block)
    \/ \E node \in Honest, share \in Shares : AcceptShare(node, share)
    \/ \E node \in Honest :
        \E parent \in JobParents(node) :
            \E uncles \in JobUncles(node, parent), found \in BOOLEAN :
                MineHonestShare(node, parent, uncles, found)
    \/ \E attacker \in Attackers, parent \in Shares,
          uncles \in {{}} \cup {{uncle} : uncle \in Shares},
          btcPrev \in Blocks \cup {Fake}, found \in BOOLEAN :
            MineAttackerShare(attacker, parent, uncles, btcPrev, found)

Spec == Init /\ [][Next]_vars

HonestSymmetry == Permutations(Honest)

(****************************************************************************)
(* Properties                                                               *)
(****************************************************************************)
\* A pool block that counts: found by an honest miner, or by an attacker
\* share some honest node accepted, and on a chain honest bitcoinds accept.
CountingPoolBlocks ==
    {block \in Blocks :
        /\ foundBy[block] # NoShare
        /\ FullChain(block)
        /\ \/ shareMiner[foundBy[block]] \in Honest
           \/ \E node \in Honest : foundBy[block] \in accepted[node]}

\* The goal: such a block never pays work on a Fake btc_prev, and never pays
\* work more than one block into a branch honest bitcoinds do not accept.
PoolBlocksPayOnlyWorkNearTheirChain ==
    \A block \in CountingPoolBlocks :
        \A paid \in PaidShares(shareParent[foundBy[block]],
                               shareBtcPrev[foundBy[block]]) :
            /\ shareBtcPrev[paid] # Fake
            /\ UnacceptedDepth(shareBtcPrev[paid]) <= 1

\* Every accepted share's parent and uncles are accepted, its btc_prev
\* header is known, and its window has something eligible.
StoreHoldsValidHistory ==
    \A node \in Honest :
        \A share \in accepted[node] \ {GenesisShare} :
            /\ shareParent[share] \in accepted[node]
            /\ shareUncles[share] \subseteq accepted[node]
            /\ shareBtcPrev[share] \in headers[node]
            /\ ~NothingEligible(shareParent[share], shareBtcPrev[share])

\* Settled: every bitcoind is on the same tip and no node can accept any
\* more shares. Headers the bitcoin network never delivered may be missing.
Settled ==
    /\ \A nodeA, nodeB \in Honest : btcTip[nodeA] = btcTip[nodeB]
    /\ \A node \in Honest, share \in Shares : ~CanAccept(node, share)

\* Convergence: once settled, honest nodes hold the same shares.
AcceptAgreement ==
    Settled => \A nodeA, nodeB \in Honest : accepted[nodeA] = accepted[nodeB]

\* Honest work, including work on orphans, stays paid: once settled, a
\* share mined now on the common tip would pay every honest share in its
\* window, including uncles.
HonestWorkPaidWhenSettled ==
    Settled =>
        \A node \in Honest :
            \A parent \in JobParents(node) :
                \A share \in WindowEntries(parent) \cup WindowUncles(parent) :
                    shareMiner[share] \in Honest =>
                        share \in PaidShares(parent, btcTip[node])

====
