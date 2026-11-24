// SPDX-FileCopyrightText: 2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Descriptor wallet commands.
//!
//! Each wallet is a SQLite file at `<datadir>/<network>/<name>.sqlite`. The
//! default wallet is saved with its network in `<datadir>/wallet.toml`.

use crate::commands::{WalletCommands, WalletDefaultCommands};
use clap::{Args, ValueHint};
use p2poolv2_lib::config::Chain;
use p2poolv2_wallet::expected_hrp;
use serde::{Deserialize, Serialize};
use std::env;
use std::error::Error;
use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

/// Network used when none is given.
const DEFAULT_CHAIN: Chain = Chain::Testnet5;

/// Data directory under the home directory, used when none is given.
const DEFAULT_DATADIR_NAME: &str = ".p2poolv2_wallet";

/// Settings file in the data directory that holds the default wallet.
const WALLET_SETTINGS_FILE_NAME: &str = "wallet.toml";

/// A wallet in a data directory, named by its name and network.
#[derive(Debug, PartialEq, Eq)]
pub struct WalletSelection {
    /// Name of the wallet, its database file name without `.sqlite`.
    pub name: String,
    /// Chain the wallet belongs to, also the name of its directory under the
    /// data directory.
    pub chain: Chain,
}

impl WalletSelection {
    /// The wallet database path, `<datadir>/<network>/<name>.sqlite`.
    fn path(&self, datadir: &Path) -> PathBuf {
        datadir
            .join(self.chain.as_str())
            .join(format!("{}.sqlite", self.name))
    }
}

/// Layout of `wallet.toml`. Unknown keys are refused, so a typo is reported
/// instead of being ignored.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WalletSettingsFile {
    default_wallet: String,
    default_network: String,
}

/// The wallet data directory option, shared by every wallet command.
#[derive(Args, Debug)]
pub struct DatadirArgs {
    /// Wallet data directory (default: ~/.p2poolv2_wallet)
    #[arg(short, long, value_hint = ValueHint::DirPath)]
    pub datadir: Option<PathBuf>,
}

impl DatadirArgs {
    /// The data directory given, else `~/.p2poolv2_wallet`.
    fn resolve(&self) -> Result<PathBuf, Box<dyn Error>> {
        match &self.datadir {
            Some(datadir) => Ok(datadir.clone()),
            None => Ok(env::home_dir()
                .ok_or("home directory is unavailable. Pass --datadir.")?
                .join(DEFAULT_DATADIR_NAME)),
        }
    }
}

/// Options naming an existing wallet.
#[derive(Args, Debug)]
pub struct SelectWalletArgs {
    #[command(flatten)]
    pub datadir_args: DatadirArgs,
    /// Wallet to use
    #[arg(short, long, value_parser = parse_wallet_name)]
    pub wallet: String,
    /// Network of the wallet: main, testnet4, testnet5, signet or regtest
    /// (default: testnet5)
    #[arg(short, long, value_parser = parse_wallet_chain)]
    pub network: Option<Chain>,
}

impl SelectWalletArgs {
    /// The data directory and the wallet these options name.
    fn resolve(&self) -> Result<(PathBuf, WalletSelection), Box<dyn Error>> {
        let datadir = self.datadir_args.resolve()?;
        let selection = WalletSelection {
            name: self.wallet.clone(),
            chain: self.network.unwrap_or(DEFAULT_CHAIN),
        };
        Ok((datadir, selection))
    }
}

/// Execute a wallet command.
pub fn execute(command: &WalletCommands) -> Result<(), Box<dyn Error>> {
    match command {
        WalletCommands::Default { command } => match command {
            WalletDefaultCommands::Set(arguments) => execute_default_set(arguments),
            WalletDefaultCommands::Show(datadir_args) => execute_default_show(datadir_args),
        },
    }
}

/// Save the selected wallet as the default in `<datadir>/wallet.toml`.
///
/// Only checks that the wallet file exists. A command that opens the wallet
/// reports a file that is not a wallet.
fn execute_default_set(arguments: &SelectWalletArgs) -> Result<(), Box<dyn Error>> {
    let (datadir, selection) = arguments.resolve()?;
    let path = selection.path(&datadir);
    if !path.is_file() {
        return Err(format!("no wallet file at {}", path.display()).into());
    }
    write_default_wallet(&datadir, &selection)?;
    println!(
        "Default wallet set to {} ({}) at {}",
        selection.name,
        selection.chain,
        path.display()
    );
    Ok(())
}

/// Print the default wallet saved in `<datadir>/wallet.toml`.
fn execute_default_show(datadir_args: &DatadirArgs) -> Result<(), Box<dyn Error>> {
    let datadir = datadir_args.resolve()?;
    match read_default_wallet(&datadir)? {
        Some(default_wallet) => println!(
            "{} ({}) at {}",
            default_wallet.name,
            default_wallet.chain,
            default_wallet.path(&datadir).display()
        ),
        None => println!(
            "No default wallet. Set one with: p2poolv2_cli wallet default set --wallet <name>"
        ),
    }
    Ok(())
}

/// Read the default wallet from `<datadir>/wallet.toml`, or `None` if the file
/// does not exist.
///
/// A file that cannot be read, is not valid TOML, or holds a wallet name or
/// network the command line would refuse, is an error naming the file. The
/// file is never changed or replaced here.
fn read_default_wallet(datadir: &Path) -> Result<Option<WalletSelection>, Box<dyn Error>> {
    let path = datadir.join(WALLET_SETTINGS_FILE_NAME);
    let contents = match fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("cannot read {}: {error}", path.display()).into()),
    };
    let settings: WalletSettingsFile = toml::from_str(&contents)
        .map_err(|error| format!("{} is not valid: {error}", path.display()))?;
    let name = parse_wallet_name(&settings.default_wallet)
        .map_err(|error| format!("{}: default_wallet: {error}", path.display()))?;
    let chain = parse_wallet_chain(&settings.default_network)
        .map_err(|error| format!("{}: default_network: {error}", path.display()))?;
    Ok(Some(WalletSelection { name, chain }))
}

/// Save `default_wallet` as the default in `<datadir>/wallet.toml`, replacing
/// any default saved before.
///
/// The new file is written beside the old one and then renamed over it, so a
/// reader never sees a partly written file. `datadir` must exist.
fn write_default_wallet(
    datadir: &Path,
    default_wallet: &WalletSelection,
) -> Result<(), Box<dyn Error>> {
    let settings = WalletSettingsFile {
        default_wallet: default_wallet.name.clone(),
        default_network: default_wallet.chain.as_str().to_owned(),
    };
    let contents = toml::to_string(&settings)?;
    let mut staged = NamedTempFile::new_in(datadir)?;
    staged.write_all(contents.as_bytes())?;
    staged
        .persist(datadir.join(WALLET_SETTINGS_FILE_NAME))
        .map_err(|error| error.error)?;
    Ok(())
}

/// Accept the networks that have a share chain wallet, the ones with a share
/// chain address prefix: main, testnet4, testnet5, signet and regtest.
fn parse_wallet_chain(value: &str) -> Result<Chain, String> {
    value
        .parse::<Chain>()
        .ok()
        .filter(|chain| expected_hrp(chain.bitcoin_network()).is_ok())
        .ok_or_else(|| {
            format!(
                "unknown network '{value}', expected main, testnet4, testnet5, signet or regtest"
            )
        })
}

/// Accept only ASCII letters, digits, hyphens and underscores, so a wallet name
/// cannot point outside the data directory.
fn parse_wallet_name(value: &str) -> Result<String, String> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(
            "wallet names must contain only ASCII letters, digits, hyphens or underscores".into(),
        );
    }
    Ok(value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::Cli;
    use clap::{CommandFactory, Parser, error::ErrorKind};
    use tempfile::tempdir;

    #[test]
    fn wallet_names_and_networks_are_validated() {
        Cli::command().debug_assert();
        let path_name = Cli::try_parse_from([
            "p2poolv2_cli",
            "wallet",
            "default",
            "set",
            "--wallet",
            "../alice",
        ])
        .unwrap_err();
        assert_eq!(path_name.kind(), ErrorKind::ValueValidation);
        let testnet3 = Cli::try_parse_from([
            "p2poolv2_cli",
            "wallet",
            "default",
            "set",
            "--wallet",
            "alice",
            "-n",
            "test",
        ])
        .unwrap_err();
        assert_eq!(testnet3.kind(), ErrorKind::ValueValidation);
    }

    #[test]
    fn wallet_default_set_requires_the_wallet_file_and_saves_it() {
        let datadir = tempdir().unwrap();
        let arguments = SelectWalletArgs {
            datadir_args: DatadirArgs {
                datadir: Some(datadir.path().to_path_buf()),
            },
            wallet: "alice".to_owned(),
            network: Some(Chain::Testnet5),
        };
        //* With no wallet file, nothing is saved.
        assert!(execute_default_set(&arguments).is_err());
        assert_eq!(read_default_wallet(datadir.path()).unwrap(), None);
        //* Once <datadir>/testnet5/alice.sqlite exists it becomes the default.
        let wallet_directory = datadir.path().join("testnet5");
        fs::create_dir_all(&wallet_directory).unwrap();
        fs::write(wallet_directory.join("alice.sqlite"), b"").unwrap();
        execute_default_set(&arguments).unwrap();
        assert_eq!(
            read_default_wallet(datadir.path()).unwrap(),
            Some(WalletSelection {
                name: "alice".to_owned(),
                chain: Chain::Testnet5,
            })
        );
    }

    #[test]
    fn default_wallet_is_none_without_wallet_toml_and_read_from_it() {
        let datadir = tempdir().unwrap();
        //* No file means no default.
        assert_eq!(read_default_wallet(datadir.path()).unwrap(), None);
        //* The name and network are read from wallet.toml, and the wallet is at <datadir>/<network>/<name>.sqlite.
        fs::write(
            datadir.path().join("wallet.toml"),
            "default_wallet = \"alice\"\ndefault_network = \"testnet5\"\n",
        )
        .unwrap();
        let default_wallet = read_default_wallet(datadir.path()).unwrap().unwrap();
        assert_eq!(
            default_wallet,
            WalletSelection {
                name: "alice".to_owned(),
                chain: Chain::Testnet5,
            }
        );
        assert_eq!(
            default_wallet.path(datadir.path()),
            datadir.path().join("testnet5").join("alice.sqlite")
        );
    }

    #[test]
    fn default_wallet_refuses_a_hand_edited_name_outside_the_data_directory() {
        let datadir = tempdir().unwrap();
        fs::write(
            datadir.path().join("wallet.toml"),
            "default_wallet = \"../alice\"\ndefault_network = \"testnet5\"\n",
        )
        .unwrap();
        //* The name is checked like a command line name, so it cannot point outside the data directory.
        assert!(read_default_wallet(datadir.path()).is_err());
    }
}
