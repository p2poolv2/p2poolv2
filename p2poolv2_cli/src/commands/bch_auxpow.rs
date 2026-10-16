// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Offline construction and verification of public BCH auxiliary work proofs.

use bitcoin::Target;
use bitcoin::hashes::sha256d;
use clap::Subcommand;
use p2poolv2_lib::shares::auxpow::{AuxPowProof, AuxiliaryTree, AuxiliaryWork};
use serde::Deserialize;
use serde_json::json;
use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

const MAX_JSON_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Subcommand)]
pub enum AuxpowCommand {
    /// Build one coinbase commitment and proofs from {"nonce":0,"work":[...]} JSON
    Build { file: PathBuf },
    /// Verify a proof against independently supplied token work and target
    Verify {
        file: PathBuf,
        #[arg(long)]
        chain_id: u32,
        /// Work hash in Bitcoin display order
        #[arg(long)]
        work_hash: sha256d::Hash,
        /// Full 256-bit target, 64 hexadecimal digits in big-endian order
        #[arg(long)]
        target: String,
    },
}

#[derive(Deserialize)]
struct WorkSelection {
    nonce: u32,
    work: Vec<AuxiliaryWork>,
}

/// Run a public-data-only command; no node, wallet, keys or config are needed.
pub fn execute(command: &AuxpowCommand) -> Result<(), Box<dyn Error>> {
    let file = match command {
        AuxpowCommand::Build { file } | AuxpowCommand::Verify { file, .. } => file,
    };
    let bytes = read_bounded(File::open(file)?)?;
    let output = match command {
        AuxpowCommand::Build { .. } => {
            let selection: WorkSelection = serde_json::from_slice(&bytes)?;
            serde_json::to_value(AuxiliaryTree::build(&selection.work, selection.nonce)?)?
        }
        AuxpowCommand::Verify {
            chain_id,
            work_hash,
            target,
            ..
        } => {
            let proof: AuxPowProof = serde_json::from_slice(&bytes)?;
            let target: [u8; 32] = hex::decode(target)?
                .try_into()
                .map_err(|_| "target must contain exactly 32 bytes")?;
            proof.verify(
                AuxiliaryWork {
                    chain_id: *chain_id,
                    hash: *work_hash,
                },
                Target::from_be_bytes(target),
            )?;
            json!({"valid_auxpow": true, "parent_hash": proof.parent_header.block_hash().to_string()})
        }
    };
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn read_bounded(reader: impl Read) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = Vec::with_capacity(4096);
    reader.take(MAX_JSON_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_JSON_BYTES {
        return Err("auxiliary work/proof JSON exceeds 1 MiB".into());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::{Cli, Commands};
    use clap::Parser;
    use std::io::Cursor;

    #[test]
    fn build_command_needs_no_config() {
        let cli =
            Cli::try_parse_from(["p2poolv2_cli", "bch-auxpow", "build", "work.json"]).unwrap();
        assert!(cli.config.is_none());
        assert!(matches!(
            cli.command,
            Some(Commands::BchAuxpow {
                command: AuxpowCommand::Build { .. }
            })
        ));
    }

    #[test]
    fn verify_command_requires_independent_work_and_target() {
        assert!(
            Cli::try_parse_from(["p2poolv2_cli", "bch-auxpow", "verify", "proof.json"]).is_err()
        );
    }

    #[test]
    fn bounded_read_accepts_the_limit_and_rejects_one_more_byte() {
        let exact = vec![b' '; MAX_JSON_BYTES as usize];
        assert_eq!(
            read_bounded(Cursor::new(&exact)).unwrap().len(),
            exact.len()
        );
        let excessive = vec![b' '; MAX_JSON_BYTES as usize + 1];
        assert!(read_bounded(Cursor::new(excessive)).is_err());
    }
}
