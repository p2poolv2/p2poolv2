// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Check that a bitcoind block template leaves enough block weight for the
//! P2Poolv2 coinbase built for it.
//!
//! bitcoind fills a template up to `blockmaxweight`, counting a fixed
//! `blockreservedweight` (Bitcoin Core 29.0 and newer, default 8,000 WU) for
//! the block header, transaction count and coinbase. The P2Poolv2 coinbase
//! carries one output per payee, so if it is heavier than the space bitcoind
//! left, a found block goes over the block weight limit and bitcoind rejects
//! it.
//!
//! bitcoind does not report `blockreservedweight`, so the check works from the
//! template itself: its `weightlimit` minus the weights of its transactions is
//! the space left, whatever bitcoind's configuration. A template with a light
//! mempool always passes; a full template shows the effective reservation,
//! including any slack from a lowered `blockmaxweight`.

use super::block_template::BlockTemplate;
use super::error::WorkError;
use bitcoin::{Transaction, Weight};

/// Oldest Bitcoin Core version with `-blockreservedweight`, as `getnetworkinfo`
/// reports it.
pub const MINIMUM_BITCOIND_VERSION: u64 = 290_000;

/// The `blockreservedweight` P2Poolv2 asks operators to set: room for the
/// largest coinbase with 500 payees, so a node does not stop again as soon as
/// the PPLNS window gains a payee. The README and the bundled bitcoin.conf
/// files set the same value; a test rebuilds that coinbase and checks this.
///
/// Derived from the largest coinbase P2Poolv2 builds, every part at its
/// largest size, in bytes:
///
/// - version 4, input count 1, prevout 36, script length 1
/// - coinbase script 46: BIP34 height push 5 (the largest height a coinbase
///   lock time can carry, 499,999,999), coinbaseaux flags 2, extranonce 13,
///   nsecs 9, pool signature at its maximum length 17
/// - sequence 4, output count 3 (505 outputs)
/// - 502 payout outputs, 500 payees plus the donation and fee cuts, of 51
///   each (amount 8, script length 1, a 42-byte script paying a 40-byte
///   witness program, the largest BIP141 allows): 25,602
/// - witness commitment output 47
/// - commitment padding output 48, padding the 25,792 bytes before the share
///   commitment output to whole SHA256 blocks
/// - share commitment output 43 (`OP_RETURN` with the 32-byte share
///   commitment hash)
/// - lock time 4
///
/// That coinbase is 25,839 bytes with no witness, so 103,356 WU. A block
/// needs on top of it the 80-byte header (320 WU), a 3-byte transaction count
/// (12 WU) and the 36 witness bytes bitcoind adds on submit (36 WU), for
/// 103,724 WU in all, rounded up to a multiple of 1,000.
pub const RECOMMENDED_RESERVED_WEIGHT: u64 = 104_000;

/// Size of a serialized block header in bytes.
const BLOCK_HEADER_SIZE: u64 = 80;

/// Size of the largest transaction count varint in bytes. A transaction is at
/// least 60 bytes, so a 4,000,000 WU block holds fewer than 65,536
/// transactions and the count fits a 3-byte varint.
const MAX_TRANSACTION_COUNT_SIZE: u64 = 3;

/// Witness bytes bitcoind's `submitblock` adds to a coinbase that has no
/// witness when the block carries a BIP141 witness commitment: the segwit
/// marker and flag (2), the witness stack item count (1), the item length (1)
/// and the 32-byte witness reserved value.
const WITNESS_RESERVED_VALUE_SIZE: u64 = 2 + 1 + 1 + 32;

/// Block weight a block built around `coinbase` needs beyond the template's
/// transactions: the header, the largest transaction count, and the coinbase
/// with the witness reserved value bitcoind adds on submit.
fn required_reserved_weight(coinbase: &Transaction) -> Weight {
    Weight::from_non_witness_data_size(BLOCK_HEADER_SIZE + MAX_TRANSACTION_COUNT_SIZE)
        + coinbase.weight()
        + Weight::from_witness_data_size(WITNESS_RESERVED_VALUE_SIZE)
}

/// Sum of the weights bitcoind reports for the template's transactions.
fn template_transactions_weight(template: &BlockTemplate) -> Weight {
    Weight::from_wu(
        template
            .transactions
            .iter()
            .map(|transaction| u64::from(transaction.weight))
            .sum(),
    )
}

/// The `blockreservedweight` to suggest when a coinbase needing
/// `required_weight` did not fit: the larger of that weight, rounded up to a
/// multiple of 1,000, and `RECOMMENDED_RESERVED_WEIGHT`.
fn suggested_reserved_weight(required_weight: u64) -> u64 {
    (required_weight.div_ceil(1_000) * 1_000).max(RECOMMENDED_RESERVED_WEIGHT)
}

/// Check that `template` leaves enough block weight for `coinbase`, the
/// coinbase P2Poolv2 builds for it.
///
/// The space left is the template's `weightlimit` minus the weights bitcoind
/// reports for its transactions. It must cover the header, the largest
/// transaction count and the coinbase. Every miner's coinbase on a template
/// has the same weight, because the per-miner parts are fixed size.
///
/// Returns an error asking for `blockreservedweight` to be set in bitcoin.conf
/// when the template leaves too little. The caller stops the node on it.
pub(crate) fn check_coinbase_fits(
    template: &BlockTemplate,
    coinbase: &Transaction,
) -> Result<(), WorkError> {
    //* A template heavier than the limit leaves no room at all.
    let available_weight = u64::from(template.weightlimit)
        .saturating_sub(template_transactions_weight(template).to_wu());
    let required_weight = required_reserved_weight(coinbase).to_wu();
    if available_weight >= required_weight {
        return Ok(());
    }
    let suggested_weight = suggested_reserved_weight(required_weight);
    Err(WorkError {
        message: format!(
            "bitcoind block template at height {} leaves {available_weight} WU of block weight \
             for the coinbase, but the P2Poolv2 coinbase needs {required_weight} WU, so a found \
             block would be rejected. Set blockreservedweight={suggested_weight} in bitcoin.conf \
             and restart bitcoind.",
            template.height
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounting::OutputPair;
    use crate::shares::witness_commitment::{WITNESS_COMMITMENT_LENGTH, WitnessCommitment};
    use crate::stratum::work::block_template::parse_flags;
    use crate::stratum::work::coinbase::build_bitcoin_coinbase_transaction;
    use bitcoin::absolute::LOCK_TIME_THRESHOLD;
    use bitcoin::hashes::{Hash, sha256};
    use bitcoin::script::PushBytesBuf;
    use bitcoin::transaction::Version;
    use bitcoin::{Address, Amount, Network, WitnessProgram, WitnessVersion};
    use p2poolv2_config::MAX_POOL_SIGNATURE_LENGTH;

    /// Payees `RECOMMENDED_RESERVED_WEIGHT` leaves room for.
    const MAX_COINBASE_PAYEES: usize = 500;

    /// Outputs for the donation and fee cuts, paid on top of the payees.
    const CUT_OUTPUTS: usize = 2;

    /// Largest witness program allowed by BIP141. A payout address of segwit
    /// version 1 or higher can carry one, giving a 51-byte output.
    const MAX_WITNESS_PROGRAM_SIZE: usize = 40;

    /// Largest height the coinbase lock time can carry: lock times from
    /// `LOCK_TIME_THRESHOLD` up are timestamps. Its BIP34 push is the longest a
    /// block will carry, 5 bytes.
    const LARGEST_HEIGHT: i64 = LOCK_TIME_THRESHOLD as i64 - 1;

    /// Build the largest coinbase P2Poolv2 produces for `template` with
    /// `MAX_COINBASE_PAYEES` payees, used to suggest a `blockreservedweight`.
    fn largest_coinbase(template: &BlockTemplate) -> Result<Transaction, WorkError> {
        largest_coinbase_at_height(
            template.height as i64,
            parse_flags(template.coinbaseaux.get("flags").cloned())?,
        )
    }

    /// Build the largest coinbase P2Poolv2 produces at `height` with `aux_flags`
    /// and `MAX_COINBASE_PAYEES` payees.
    ///
    /// Each part of the coinbase is set to its largest size:
    ///
    /// - Every payee and cut output is 51 bytes. Payout addresses can be any
    ///   segwit version from 1 upwards, with a witness program of up to 40 bytes,
    ///   so the largest output pays a 40-byte program.
    /// - The pool signature is at its configured maximum length.
    /// - The witness commitment, share commitment and extranonce are all present.
    ///
    /// Output amounts serialize to 8 bytes whatever their value, so the coinbase
    /// value does not change the size.
    ///
    /// The commitment padding output only rounds the coinbase prefix up to a
    /// SHA256 block boundary, so it cannot make a smaller coinbase come out
    /// larger than this one.
    fn largest_coinbase_at_height(
        height: i64,
        aux_flags: PushBytesBuf,
    ) -> Result<Transaction, WorkError> {
        let output_count = MAX_COINBASE_PAYEES + CUT_OUTPUTS;
        //* Every version opcode is one byte, so the version does not change the
        //* output size; version 0 only allows 20 or 32-byte programs.
        let largest_program =
            WitnessProgram::new(WitnessVersion::V1, &[0u8; MAX_WITNESS_PROGRAM_SIZE]).map_err(
                |error| WorkError {
                    message: format!("Failed to build the largest witness program: {error}"),
                },
            )?;
        let largest_output = OutputPair {
            address: Address::from_witness_program(largest_program, Network::Bitcoin),
            amount: Amount::MAX_MONEY / output_count as u64,
        };
        let witness_commitment = WitnessCommitment::new([0u8; WITNESS_COMMITMENT_LENGTH]);
        build_bitcoin_coinbase_transaction(
            Version::TWO,
            &vec![largest_output; output_count],
            height,
            aux_flags,
            Some(&witness_commitment),
            &[0u8; MAX_POOL_SIGNATURE_LENGTH],
            Some(sha256::Hash::all_zeros()),
            0,
            None,
        )
    }

    #[test]
    fn test_required_reserved_weight_covers_500_payees() {
        //* The one-txn fixture is at height 505 with no coinbaseaux flags.
        //* The coinbase is 25,839 bytes (103,356 WU): version 4, input count 1,
        //* prevout 36, script length 1, script 44 (height 3, flags 2,
        //* extranonce 13, nsecs 9, signature 17), sequence 4, output count 3,
        //* 502 payee and cut outputs of 51 (a 40-byte witness program),
        //* witness commitment output 47, padding output 9 + 41 (pads the
        //* 25,792-byte prefix to a multiple of 64), share commitment output 43,
        //* locktime 4.
        //* The reservation adds header 320 WU, a 3-byte count 12 WU and the
        //* witness reserved value 36 WU.
        let template: BlockTemplate = serde_json::from_str(include_str!(
            "../../../../p2poolv2_tests/test_data/gbt/regtest/ckpool/one-txn/gbt.json"
        ))
        .unwrap();

        let coinbase = largest_coinbase(&template).unwrap();
        let weight = required_reserved_weight(&coinbase);

        assert_eq!(coinbase.output[0].script_pubkey.len(), 42);
        assert_eq!(coinbase.weight().to_wu(), 103_356);
        assert_eq!(weight.to_wu(), 320 + 12 + 103_356 + 36);
    }

    #[test]
    fn test_template_transactions_weight_sums_reported_weights() {
        let mut template: BlockTemplate = serde_json::from_str(include_str!(
            "../../../../p2poolv2_tests/test_data/gbt/regtest/ckpool/one-txn/gbt.json"
        ))
        .unwrap();
        let mut second_transaction = template.transactions[0].clone();
        second_transaction.weight = 1_000;
        template.transactions.push(second_transaction);

        assert_eq!(template.transactions[0].weight, 561);
        assert_eq!(template_transactions_weight(&template).to_wu(), 561 + 1_000);
    }

    #[test]
    fn test_suggested_reserved_weight_covers_500_payees_for_a_small_coinbase() {
        //* A coinbase needing 2,000 WU did not fit; the suggestion still
        //* leaves room for 500 payees.
        assert_eq!(suggested_reserved_weight(2_000), 104_000);
    }

    #[test]
    fn test_suggested_reserved_weight_covers_a_coinbase_larger_than_500_payees() {
        assert_eq!(suggested_reserved_weight(150_001), 151_000);
    }

    #[test]
    fn test_recommended_reserved_weight_covers_largest_coinbase() {
        //* The largest coinbase at the height with the longest BIP34 push and
        //* without coinbaseaux flags needs 103,724 WU, which rounds up to the
        //* constant.
        let coinbase =
            largest_coinbase_at_height(LARGEST_HEIGHT, parse_flags(None).unwrap()).unwrap();
        let weight = required_reserved_weight(&coinbase).to_wu();

        assert_eq!(weight.div_ceil(1_000) * 1_000, RECOMMENDED_RESERVED_WEIGHT);
    }

    #[test]
    fn test_check_accepts_largest_coinbase_in_light_template() {
        //* One 561 WU transaction leaves nearly the whole block for the
        //* coinbase, whatever bitcoind's blockreservedweight.
        let template: BlockTemplate = serde_json::from_str(include_str!(
            "../../../../p2poolv2_tests/test_data/gbt/regtest/ckpool/one-txn/gbt.json"
        ))
        .unwrap();
        let coinbase = largest_coinbase(&template).unwrap();

        let result = check_coinbase_fits(&template, &coinbase);

        assert!(result.is_ok(), "unexpected error: {:?}", result.err());
    }

    #[test]
    fn test_check_rejects_largest_coinbase_in_template_filled_to_default_reservation() {
        //* A full template from bitcoind with the default 8,000 WU
        //* reservation: its transactions weigh 4,000,000 - 8,000 WU.
        let mut template: BlockTemplate = serde_json::from_str(include_str!(
            "../../../../p2poolv2_tests/test_data/gbt/regtest/ckpool/one-txn/gbt.json"
        ))
        .unwrap();
        template.transactions[0].weight = 4_000_000 - 8_000;
        let coinbase = largest_coinbase(&template).unwrap();

        let result = check_coinbase_fits(&template, &coinbase);

        let Err(error) = result else {
            panic!("a template leaving 8,000 WU should be rejected");
        };
        assert_eq!(
            error.message,
            "bitcoind block template at height 505 leaves 8000 WU of block weight for the \
             coinbase, but the P2Poolv2 coinbase needs 103724 WU, so a found block would be \
             rejected. Set blockreservedweight=104000 in bitcoin.conf and restart bitcoind."
        );
    }

    #[test]
    fn test_check_rejects_coinbase_one_weight_unit_short() {
        let mut template: BlockTemplate = serde_json::from_str(include_str!(
            "../../../../p2poolv2_tests/test_data/gbt/regtest/ckpool/one-txn/gbt.json"
        ))
        .unwrap();
        template.transactions[0].weight = 4_000_000 - 103_723;
        let coinbase = largest_coinbase(&template).unwrap();

        let result = check_coinbase_fits(&template, &coinbase);

        assert!(result.is_err(), "a template 1 WU short should be rejected");
    }

    #[test]
    fn test_check_accepts_template_leaving_exactly_required() {
        let mut template: BlockTemplate = serde_json::from_str(include_str!(
            "../../../../p2poolv2_tests/test_data/gbt/regtest/ckpool/one-txn/gbt.json"
        ))
        .unwrap();
        template.transactions[0].weight = 4_000_000 - 103_724;
        let coinbase = largest_coinbase(&template).unwrap();

        let result = check_coinbase_fits(&template, &coinbase);

        assert!(result.is_ok(), "unexpected error: {:?}", result.err());
    }

    #[test]
    fn test_check_measures_room_against_template_weightlimit() {
        //* The same transactions that leave exactly enough under a 4,000,000
        //* WU limit leave 1 WU too little under a limit 1 WU lower.
        let mut template: BlockTemplate = serde_json::from_str(include_str!(
            "../../../../p2poolv2_tests/test_data/gbt/regtest/ckpool/one-txn/gbt.json"
        ))
        .unwrap();
        template.transactions[0].weight = 4_000_000 - 103_724;
        template.weightlimit = 4_000_000 - 1;
        let coinbase = largest_coinbase(&template).unwrap();

        let result = check_coinbase_fits(&template, &coinbase);

        assert!(
            result.is_err(),
            "the check should use the template's weightlimit"
        );
    }

    #[test]
    fn test_check_rejects_template_over_block_weight_limit() {
        //* Transactions heavier than the limit leave no room.
        let mut template: BlockTemplate = serde_json::from_str(include_str!(
            "../../../../p2poolv2_tests/test_data/gbt/regtest/ckpool/one-txn/gbt.json"
        ))
        .unwrap();
        template.transactions[0].weight = 4_000_001;
        let coinbase = largest_coinbase(&template).unwrap();

        let result = check_coinbase_fits(&template, &coinbase);

        let Err(error) = result else {
            panic!("a template over the block weight limit should be rejected");
        };
        assert!(
            error.message.contains("leaves 0 WU of block weight"),
            "unexpected error: {}",
            error.message
        );
    }
}
