// SPDX-FileCopyrightText: 2024-2026 P2Poolv2 Developers (see AUTHORS)
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use bitcoin::Address;

const INITIAL_SIZE: usize = 1000;

/// We track the keys as indices of a `Vec<Option<T>>`, where each slot
/// holds either a value or `None` if the slot is free.
///
/// `key_for` performs a single linear scan over the vector: it returns the
/// index of an existing value if found, otherwise it reuses the first
/// `None` slot observed, or appends a new slot if none are free. This avoids
/// hashing the values.
///
/// The window interns payout addresses (the default) and share owners, the
/// share chain addresses, each in its own `AddressKeys`.
pub(super) struct AddressKeys<T = Address>(Vec<Option<T>>);

impl<T> Default for AddressKeys<T> {
    fn default() -> Self {
        Self(Vec::with_capacity(INITIAL_SIZE))
    }
}

impl<T: PartialEq> AddressKeys<T> {
    /// Returns the index for the value, inserting it if not present.
    ///
    /// Reuses the first None slot if available, otherwise appends.
    pub(super) fn key_for(&mut self, value: T) -> usize {
        let mut first_none: Option<usize> = None;
        for (index, slot) in self.0.iter().enumerate() {
            match slot {
                Some(existing) if existing == &value => return index,
                None if first_none.is_none() => first_none = Some(index),
                _ => {}
            }
        }
        match first_none {
            Some(index) => {
                self.0[index] = Some(value);
                index
            }
            None => {
                self.0.push(Some(value));
                self.0.len() - 1
            }
        }
    }

    /// Returns the index for the value without inserting it, or `None`
    /// when no cached entry references it.
    pub(super) fn find(&self, value: &T) -> Option<usize> {
        self.0.iter().position(|slot| slot.as_ref() == Some(value))
    }

    /// Return the number of slots in the backing vector.
    pub(super) fn len(&self) -> usize {
        self.0.len()
    }

    /// Get the value at the index
    pub(super) fn value_for(&self, index: usize) -> Option<&T> {
        self.0.get(index)?.as_ref()
    }

    /// Set None at index
    pub(super) fn remove(&mut self, index: usize) {
        self.0[index] = None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::parse_address_from_string;

    #[test]
    fn key_for_assigns_sequential_keys() {
        let mut address_keys = AddressKeys::default();
        let addr_a = parse_address_from_string("bcrt1qe2qaq0e8qlp425pxytrakala7725dynwhknufr");
        let addr_b = parse_address_from_string("bcrt1qlk935ze2fsu86zjp395uvtegztrkaezawxx0wf");

        assert_eq!(address_keys.key_for(addr_a), 0);
        assert_eq!(address_keys.key_for(addr_b), 1);
    }

    #[test]
    fn key_for_returns_same_key_for_same_address() {
        let mut address_keys = AddressKeys::default();
        let addr = parse_address_from_string("bcrt1qe2qaq0e8qlp425pxytrakala7725dynwhknufr");

        let key_first = address_keys.key_for(addr.clone());
        let key_second = address_keys.key_for(addr);

        assert_eq!(key_first, key_second);
    }

    #[test]
    fn value_for_returns_inserted_address() {
        let mut address_keys = AddressKeys::default();
        let addr = parse_address_from_string("bcrt1qe2qaq0e8qlp425pxytrakala7725dynwhknufr");

        let key = address_keys.key_for(addr.clone());

        assert_eq!(address_keys.value_for(key), Some(&addr));
    }

    #[test]
    fn value_for_returns_none_for_out_of_bounds() {
        let address_keys: AddressKeys = AddressKeys::default();

        assert_eq!(address_keys.value_for(0), None);
        assert_eq!(address_keys.value_for(999), None);
    }

    #[test]
    fn remove_frees_slot() {
        let mut address_keys = AddressKeys::default();
        let addr = parse_address_from_string("bcrt1qe2qaq0e8qlp425pxytrakala7725dynwhknufr");

        let key = address_keys.key_for(addr);
        address_keys.remove(key);

        assert_eq!(address_keys.value_for(key), None);
    }

    #[test]
    fn removed_slot_is_reused() {
        let mut address_keys = AddressKeys::default();
        let addr_a = parse_address_from_string("bcrt1qe2qaq0e8qlp425pxytrakala7725dynwhknufr");
        let addr_b = parse_address_from_string("bcrt1qlk935ze2fsu86zjp395uvtegztrkaezawxx0wf");
        let addr_c = parse_address_from_string("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080");

        let key_a = address_keys.key_for(addr_a);
        let _key_b = address_keys.key_for(addr_b);
        address_keys.remove(key_a);

        let key_c = address_keys.key_for(addr_c);
        assert_eq!(key_c, key_a);
    }

    #[test]
    fn find_returns_the_key_without_inserting() {
        let mut address_keys = AddressKeys::default();
        let addr_a = parse_address_from_string("bcrt1qe2qaq0e8qlp425pxytrakala7725dynwhknufr");
        let addr_b = parse_address_from_string("bcrt1qlk935ze2fsu86zjp395uvtegztrkaezawxx0wf");

        let key_a = address_keys.key_for(addr_a.clone());

        assert_eq!(address_keys.find(&addr_a), Some(key_a));
        assert_eq!(address_keys.find(&addr_b), None);
        assert_eq!(address_keys.len(), 1);
    }

    #[test]
    fn find_does_not_return_a_removed_value() {
        let mut address_keys = AddressKeys::default();
        let addr = parse_address_from_string("bcrt1qe2qaq0e8qlp425pxytrakala7725dynwhknufr");

        let key = address_keys.key_for(addr.clone());
        address_keys.remove(key);

        assert_eq!(address_keys.find(&addr), None);
    }

    #[test]
    fn different_addresses_get_different_keys() {
        let mut address_keys = AddressKeys::default();
        let addr_a = parse_address_from_string("bcrt1qe2qaq0e8qlp425pxytrakala7725dynwhknufr");
        let addr_b = parse_address_from_string("bcrt1qlk935ze2fsu86zjp395uvtegztrkaezawxx0wf");

        let key_a = address_keys.key_for(addr_a);
        let key_b = address_keys.key_for(addr_b);

        assert_ne!(key_a, key_b);
    }
}
