# Atomic Swap Between P2Pool Shares and Lightning Network Bitcoin

This document describes an atomic swap protocol where a miner (Alice) exchanges P2Pool shares for Bitcoin with a market maker (Bob) using HTLCs and the Lightning Network.

## Scenario

- **Alice** is a miner who holds P2Pool shares.
- **Bob** is a market maker who wants to buy P2Pool shares with Bitcoin.

Alice wants to sell **10,000 P2Pool shares** to Bob in exchange for **0.0001 BTC (10,000 sats)**.

## Swap Flow

### Step 1: Alice Creates a Lightning Invoice

Alice generates a random **32-byte secret value (preimage `R`)** and computes its **SHA256 hash (`payment_hash`)**.

She then creates a **Lightning Network invoice** for 10,000 sats using any LN node or wallet. This invoice can follow:

- [BOLT11](https://github.com/lightning/bolts/blob/master/11-payment-encoding.md)
- Or [BOLT12 offers](https://github.com/lightning/bolts/blob/master/12-offer-encoding.md) if supported.

The invoice includes the **payment hash (`payment_hash`)**, which will serve as a cryptographic lock in both chains. The preimage `R` remains secret, known only to Alice, until payment.

---

### Step 2: Alice Locks Shares in a P2Pool HTLC

Alice creates a **P2Pool HTLC** locking 10,000 shares using the same `payment_hash` from the Lightning invoice. This ensures that the P2Pool shares are only claimable by providing the corresponding **preimage `R`** — the same secret she generated when creating the invoice.

![p2pool initiateing](/p2pool-v2/docs/atomic-swap/minner2marketmaker.png)

---

### Step 3: Bob Verifies Alice's Commitments

Before proceeding, Bob performs the following verifications:

- Checks the **validity and finality** of Alice’s on-chain P2Pool HTLC.
- Validates the **details of the Lightning invoice** (amount, expiry, etc.).
- Ensures that the `payment_hash` in both the P2Pool HTLC and Lightning invoice match exactly.

If any of these checks fail, Bob can abort the swap or request corrections.

---

### Step 4: Bob Pays the Lightning Invoice

If satisfied, Bob pays the Lightning invoice for 10,000 sats.
Upon payment, **Alice reveals the preimage `R`** as part of fulfilling the invoice. This act of revealing `R` upon receiving payment ensures that the secret required to claim the P2Pool shares becomes available to Bob immediately after he pays.

---

### Step 5: Bob Redeems the P2Pool Shares

With the revealed preimage `R`, Bob constructs and broadcasts a **redeem transaction** on the P2Pool chain to claim the 10,000 shares from the HTLC. Since the P2Pool HTLC was locked with `payment_hash = SHA256(R)`, providing the correct preimage `R` unlocks it, allowing Bob to take ownership of the shares.

![p2pool redeem](/p2pool-v2/docs/atomic-swap/minner2marketmaker_redeem.png)

### Fallbacks and Refunds

If Bob is **not satisfied** with the verification step:

- He can **choose not to pay** the Lightning invoice.
- Optionally, Bob can refund Alice instantly by signing instant refund path in htlc.
- Otherwise, Alice will need to wait until the **HTLC timeout** expires. After this, she can reclaim the locked shares using a refund path.

---

## Security Guarantees

- **Atomicity**: The use of the same `payment_hash` in both chains ensures atomic behavior — either both transfers succeed, or neither does.
- **Trust-Minimized**: Neither party needs to trust the other if both follow the protocol honestly.
- **Timeout Safety**: HTLC timeouts prevent funds from being locked indefinitely.

---

## Notes

- The timelock details and conditions have yet to be specified.
- If BOLT12 is used, offer/accept flow can further improve privacy and UX.
