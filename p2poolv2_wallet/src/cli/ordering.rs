// SPDX-FileCopyrightText: 2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Option placement normalization.
//!
//! Named options take zero or one value. Repeated options retain their order.
//! `--` ends reordering and option parsing.

use clap::Command;
use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::str;

/// Place option/value pairs after command words, preserving their order.
pub(super) fn normalize(
    definition: &Command,
    arguments: impl Iterator<Item = OsString>,
) -> Vec<OsString> {
    let mut arities = HashMap::with_capacity(64);
    collect_arities(definition, &mut arities);
    let mut arguments = arguments.peekable();
    let mut command_words = Vec::with_capacity(3);
    let mut options = Vec::with_capacity(arguments.size_hint().0);
    let mut trailing = Vec::with_capacity(arguments.size_hint().0);
    command_words.extend(arguments.next());
    while let Some(argument) = arguments.next() {
        if argument == "--" {
            trailing.push(argument);
            trailing.extend(arguments.by_ref());
        } else if argument.as_encoded_bytes().starts_with(b"-") && argument != "-" {
            let following_value = takes_following_value(&argument, &arities);
            options.push(argument);
            if following_value {
                options.extend(arguments.next());
            }
        } else {
            command_words.push(argument);
        }
    }
    command_words.extend(options);
    command_words.extend(trailing);
    command_words
}

/// Collect option names and whether each option takes a value.
///
/// Each name must have the same arity across all commands.
fn collect_arities(command: &Command, arities: &mut HashMap<String, bool>) {
    for argument in command.get_arguments() {
        let takes_value = argument.get_action().takes_values();
        if argument.is_positional() {
            // Only the help command accepts positional arguments.
            assert_eq!(
                command.get_name(),
                "help",
                "data inputs must be named options"
            );
        } else if let Some(range) = argument.get_num_args() {
            assert!(
                range.max_values() <= 1,
                "option ordering requires single-value options"
            );
        }
        if let Some(long) = argument.get_long() {
            register_arity(arities, format!("--{long}"), takes_value);
        }
        if let Some(short) = argument.get_short() {
            register_arity(arities, format!("-{short}"), takes_value);
        }
    }
    for subcommand in command.get_subcommands() {
        collect_arities(subcommand, arities);
    }
}

/// Register an option's arity and reject conflicting definitions.
fn register_arity(arities: &mut HashMap<String, bool>, name: String, takes_value: bool) {
    if let Some(previous) = arities.insert(name.clone(), takes_value) {
        assert_eq!(previous, takes_value, "inconsistent arity for {name}");
    }
}

/// Return whether an option or short-option cluster needs the next argument.
fn takes_following_value(argument: &OsStr, arities: &HashMap<String, bool>) -> bool {
    let bytes = argument.as_encoded_bytes();
    if bytes.starts_with(b"--") {
        !bytes.contains(&b'=')
            && str::from_utf8(bytes)
                .ok()
                .and_then(|name| arities.get(name))
                .copied()
                .unwrap_or(false)
    } else {
        bytes[1..]
            .iter()
            .enumerate()
            .find_map(|(index, short)| {
                let name = [b'-', *short];
                match str::from_utf8(&name)
                    .ok()
                    .and_then(|name| arities.get(name))
                {
                    Some(false) => None,
                    Some(true) => Some(index + 2 == bytes.len()),
                    None => Some(false),
                }
            })
            .unwrap_or(false)
    }
}
