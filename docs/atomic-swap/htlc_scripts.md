# 📜 HTLC Script Collection

This repository contains Bitcoin scripts for atomic swap contracts using:

- **P2WSH (Pay-to-Witness-Script-Hash)** with address and pubkey based spending.
- **P2TR (Pay-to-Taproot)** with multiple spending paths.

---

### ✅ Spending Paths Summary

| Path                      | Condition                               | Who Can Spend                 | When                |
| :------------------------ | :-------------------------------------- | :---------------------------- | :------------------ |
| **Success path**          | Redeemer provides secret + signature.   | Redeemer                      | Anytime with secret |
| **Mutual instant refund** | Both sign transaction (2-of-2 multisig) | Initiator & Redeemer together | Instantly           |
| **Initiator refund**      | Waits `<waitTime>` blocks.              | Initiator                     | After `<waitTime>`  |

---

## 📦 P2WSH (with Addresses and 2 Spending Paths)

This P2WSH setup uses addresses for spending keys, hashed into the redeem script.

---

### 📝 Script Template

```plaintext
OP_IF
    OP_SHA256
    <secretHash>
    OP_EQUALVERIFY

    OP_DUP
    OP_HASH160
    <redeemerAddress>
OP_ELSE
    <waitTime>
    OP_CHECKSEQUENCEVERIFY
    OP_DROP

    OP_DUP
    OP_HASH160
    <initiatorAddress>
OP_ENDIF

OP_EQUALVERIFY
OP_CHECKSIG
```

---

### 📖 Explanation

| Opcode / Path                                                  | Description                         |
| :------------------------------------------------------------- | :---------------------------------- |
| `OP_IF`                                                        | Start the **success path**.         |
| `OP_SHA256`, `<secretHash>`, `OP_EQUALVERIFY`                  | Validate the secret hash.           |
| `OP_DUP`, `OP_HASH160`, `<redeemerAddress>`, `OP_EQUALVERIFY`  | Verify redeemer’s public key hash.  |
| `OP_CHECKSIG`                                                  | Check redeemer’s signature.         |
| `OP_ELSE`                                                      | Start the **refund path**.          |
| `<waitTime>`, `OP_CHECKSEQUENCEVERIFY`, `OP_DROP`              | Enforce locktime before refund.     |
| `OP_DUP`, `OP_HASH160`, `<initiatorAddress>`, `OP_EQUALVERIFY` | Verify initiator’s public key hash. |
| `OP_CHECKSIG`                                                  | Check initiator’s signature.        |
| `OP_ENDIF`                                                     | End the conditional block.          |

---

## 📦 P2WSH (with Public Keys Only and 3-Spending-Path)

This HTLC script offers **three spending paths**, with **instant mutual refund prioritized before initiator refund**:

---

### 📝 Script Layout

```plaintext
OP_IF
    OP_SHA256
    <secretHash>
    OP_EQUALVERIFY

    <redeemerPubKey>
    OP_CHECKSIG
OP_ELSE
    OP_IF
        2
        <initiatorPubKey>
        <redeemerPubKey>
        2
        OP_CHECKMULTISIG
    OP_ELSE
        <waitTime>
        OP_CHECKSEQUENCEVERIFY
        OP_DROP

        <initiatorPubKey>
        OP_CHECKSIG
    OP_ENDIF
OP_ENDIF
```

---

### 📖 Explanation

| Opcode / Path                                             | Description                               |
| :-------------------------------------------------------- | :---------------------------------------- |
| `OP_IF`                                                   | Start **success path**.                   |
| `OP_SHA256`, `<secretHash>`, `OP_EQUALVERIFY`             | Validate the secret hash.                 |
| `<redeemerPubKey>`, `OP_CHECKSIG`                         | Check redeemer’s signature.               |
| `OP_ELSE`                                                 | Start **refund logic**.                   |
| `OP_IF`                                                   | Start **instant mutual refund path**.     |
| `2 <initiatorPubKey> <redeemerPubKey> 2 OP_CHECKMULTISIG` | Require both signatures for refund.       |
| `OP_ELSE`                                                 | Start **initiator refund after timeout**. |
| `<waitTime>`, `OP_CHECKSEQUENCEVERIFY`, `OP_DROP`         | Enforce locktime.                         |
| `<initiatorPubKey>`, `OP_CHECKSIG`                        | Check initiator’s signature.              |
| `OP_ENDIF` (×2)                                           | Close conditional branches.               |

---

# 📦 P2TR (with 3 Spending Paths in a Taproot Tree)

This HTLC setup uses **Pay-to-Taproot (P2TR)**, leveraging a **Merkle tree of spending conditions**. It supports **three spending paths** with different conditions, elegantly structured in a binary tree:

---

## 📝 Script Layout

```plaintext
# Happypath (Redeem)
OP_SHA256
<secretHash>
OP_EQUALVERIFY
<redeemerPubKey>
OP_CHECKSIG

# Mutual Instant Refund
<initiatorPubKey>
OP_CHECKSIG
<redeemerPubKey>
OP_CHECKSIGADD
2
OP_NUMEQUAL

# Initiator Refund (Timeout)
<waitTime>
OP_CSV
OP_DROP
<initiatorPubKey>
OP_CHECKSIG
```

---

## 📖 Explanation

| Spending Path                                 | Script / Condition Description                               |
| :-------------------------------------------- | :----------------------------------------------------------- |
| **Happypath (Redeem)**                        | Redeemer reveals the secret and signs to claim funds.        |
| `OP_SHA256`, `<secretHash>`, `OP_EQUALVERIFY` | Validate the provided secret matches the known hash.         |
| `<redeemerPubKey>`, `OP_CHECKSIG`             | Check redeemer’s signature.                                  |
| **Mutual Instant Refund**                     | Both parties must sign for an immediate refund, no timelock. |
| `<initiatorPubKey> OP_CHECKSIG`               | Validate initiator’s signature.                              |
| `<redeemerPubKey> OP_CHECKSIGADD`             | Add redeemer’s signature (value 1 if valid) to total.        |
| `2 OP_NUMEQUAL`                               | Ensure the total signature count equals 2 (both signed).     |
| **Initiator Refund (Timeout)**                | Initiator can refund alone after a relative timelock.        |
| `<waitTime> OP_CSV OP_DROP`                   | Enforce relative locktime.                                   |
| `<initiatorPubKey> OP_CHECKSIG`               | Validate initiator’s signature.                              |

---

## 🌳 Taproot Tree Structure

```
          ┌──────────────┐
          │   Taproot    │
          │   Key Path   │
          └─────┬────────┘
                │
        ┌───────┴────────┐
        │                │
  Happypath         ┌────┴────┐
                    │         │
             Mutual Refund  Timeout Refund
```

- **Key Path Spend :** Set to a Nothing Up My Sleeve (NUMS) point — a public key with no known private key — to make key path spending impossible.
- **Script Path Spend:** Merkle branches containing the three condition scripts.

---

## 📌 Notes

- **`<secretHash>`** — SHA-256 hash of a secret string revealed by the redeemer.

- **`<waitTime>`** — Relative locktime value (in blocks) for refund eligibility.

- **`<initiatorPubKey>`, `<redeemerPubKey>`** —

  - In **P2WSH**, these are **33-byte compressed public keys** (`x, y` coordinates compressed to one byte + 32-byte `x` value).
  - In **P2TR**, only the **32-byte x-only public keys** are used (since Taproot key spends and script spends via Schnorr signatures only require the `x` coordinate).

- In P2WSH, an address-based check (OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY) can be replaced with a direct public key check (<pubkey> OP_CHECKSIG) by removing the hash ops and using the raw public key. Both validate ownership through different methods — one via the pubkey hash, the other via the pubkey itself.

- **Key Path Spend (in P2TR)** — Should be set to a **Nothing Up My Sleeve (NUMS) point** (a public key with no known private key) to disable key path spending entirely, forcing all spends to go through script paths.

---
