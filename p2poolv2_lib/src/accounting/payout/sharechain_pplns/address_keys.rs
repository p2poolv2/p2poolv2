//
// This file is part of P2Poolv2
//
// P2Poolv2 is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// P2Poolv2 is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// P2Poolv2. If not, see <https://www.gnu.org/licenses/>.//
// This file is part of P2Poolv2
//
// P2Poolv2 is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// P2Poolv2 is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// P2Poolv2. If not, see <https://www.gnu.org/licenses/>.

use bitcoin::Address;

const INITIAL_SIZE: usize = 1000;

/// Store mapping from Address string to internal u32 key.
///
/// We track the keys as index of a vec! which contains Option<String>.
///
/// We choose iterate twice over the vector than to do a hash of
/// Address.
pub(super) struct AddressKeys(Vec<Option<Address>>);

impl Default for AddressKeys {
    fn default() -> Self {
        Self(Vec::with_capacity(INITIAL_SIZE))
    }
}

impl AddressKeys {
    /// Returns the index for the address, inserting it if not present.
    ///
    /// Reuses the first None slot if available, otherwise appends.
    pub(super) fn key_for(&mut self, address: Address) -> usize {
        let mut first_none: Option<usize> = None;
        for (index, slot) in self.0.iter().enumerate() {
            match slot {
                Some(addr) if *addr == address => return index,
                None if first_none.is_none() => first_none = Some(index),
                _ => {}
            }
        }
        match first_none {
            Some(index) => {
                self.0[index] = Some(address);
                index
            }
            None => {
                self.0.push(Some(address));
                self.0.len() - 1
            }
        }
    }

    /// Get the address at the index
    pub(super) fn value_for(&self, index: usize) -> Option<&Address> {
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

    fn make_address(addr_str: &str) -> Address {
        addr_str
            .parse::<bitcoin::Address<_>>()
            .unwrap()
            .assume_checked()
    }

    #[test]
    fn key_for_assigns_sequential_keys() {
        let mut address_keys = AddressKeys::default();
        let addr_a = make_address("bcrt1qe2qaq0e8qlp425pxytrakala7725dynwhknufr");
        let addr_b = make_address("bcrt1qlk935ze2fsu86zjp395uvtegztrkaezawxx0wf");

        assert_eq!(address_keys.key_for(addr_a), 0);
        assert_eq!(address_keys.key_for(addr_b), 1);
    }

    #[test]
    fn key_for_returns_same_key_for_same_address() {
        let mut address_keys = AddressKeys::default();
        let addr = make_address("bcrt1qe2qaq0e8qlp425pxytrakala7725dynwhknufr");

        let key_first = address_keys.key_for(addr.clone());
        let key_second = address_keys.key_for(addr);

        assert_eq!(key_first, key_second);
    }

    #[test]
    fn value_for_returns_inserted_address() {
        let mut address_keys = AddressKeys::default();
        let addr = make_address("bcrt1qe2qaq0e8qlp425pxytrakala7725dynwhknufr");

        let key = address_keys.key_for(addr.clone());

        assert_eq!(address_keys.value_for(key), Some(&addr));
    }

    #[test]
    fn value_for_returns_none_for_out_of_bounds() {
        let address_keys = AddressKeys::default();

        assert_eq!(address_keys.value_for(0), None);
        assert_eq!(address_keys.value_for(999), None);
    }

    #[test]
    fn remove_frees_slot() {
        let mut address_keys = AddressKeys::default();
        let addr = make_address("bcrt1qe2qaq0e8qlp425pxytrakala7725dynwhknufr");

        let key = address_keys.key_for(addr);
        address_keys.remove(key);

        assert_eq!(address_keys.value_for(key), None);
    }

    #[test]
    fn removed_slot_is_reused() {
        let mut address_keys = AddressKeys::default();
        let addr_a = make_address("bcrt1qe2qaq0e8qlp425pxytrakala7725dynwhknufr");
        let addr_b = make_address("bcrt1qlk935ze2fsu86zjp395uvtegztrkaezawxx0wf");
        let addr_c = make_address("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080");

        let key_a = address_keys.key_for(addr_a);
        let _key_b = address_keys.key_for(addr_b);
        address_keys.remove(key_a);

        let key_c = address_keys.key_for(addr_c);
        assert_eq!(key_c, key_a);
    }

    #[test]
    fn different_addresses_get_different_keys() {
        let mut address_keys = AddressKeys::default();
        let addr_a = make_address("bcrt1qe2qaq0e8qlp425pxytrakala7725dynwhknufr");
        let addr_b = make_address("bcrt1qlk935ze2fsu86zjp395uvtegztrkaezawxx0wf");

        let key_a = address_keys.key_for(addr_a);
        let key_b = address_keys.key_for(addr_b);

        assert_ne!(key_a, key_b);
    }
}
