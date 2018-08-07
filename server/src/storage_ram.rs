//! A RAM example of the persistent lease storage of the DHCP server.
//! (well, not persistent, eventually)

use std::{collections::HashMap, net::Ipv4Addr};

use lease::Lease;
use storage::{Error, Storage};

pub struct RamStorage {
    /// `IPv4` to `client_id` mapping.
    address_client_map: HashMap<Ipv4Addr, Vec<u8>>,
    /// `client_id` to `Lease` mapping.
    client_lease_map: HashMap<Vec<u8>, Lease>,
    /// `IPv4` addresses reported by `DHCPDECLINE`.
    frozen_addresses: Vec<Ipv4Addr>,
}

impl RamStorage {
    pub fn new() -> Self {
        RamStorage {
            address_client_map: HashMap::new(),
            client_lease_map: HashMap::new(),
            frozen_addresses: Vec::new(),
        }
    }
}

impl Storage for RamStorage {
    fn get_client(&self, address: &Ipv4Addr) -> Result<Option<Vec<u8>>, Error> {
        if let Some(client_id) = self.address_client_map.get(&address) {
            Ok(Some(client_id.to_owned()))
        } else {
            Ok(None)
        }
    }

    fn add_client(&mut self, address: &Ipv4Addr, client_id: &[u8]) -> Result<(), Error> {
        self.address_client_map
            .insert(address.to_owned(), client_id.to_vec());
        Ok(())
    }

    fn delete_client(&mut self, address: &Ipv4Addr) -> Result<(), Error> {
        self.address_client_map.remove(&address);
        Ok(())
    }

    fn get_lease(&self, client_id: &[u8]) -> Result<Option<Lease>, Error> {
        if let Some(lease) = self.client_lease_map.get(client_id) {
            Ok(Some(lease.to_owned()))
        } else {
            Ok(None)
        }
    }

    fn add_lease(&mut self, client_id: &[u8], lease: Lease) -> Result<(), Error> {
        self.client_lease_map.insert(client_id.to_vec(), lease);
        Ok(())
    }

    fn update_lease(
        &mut self,
        client_id: &[u8],
        action: &mut FnMut(&mut Lease) -> (),
    ) -> Result<(), Error> {
        if let Some(ref mut lease) = self.client_lease_map.get_mut(client_id) {
            action(lease);
        }
        Ok(())
    }

    fn check_frozen(&self, address: &Ipv4Addr) -> Result<bool, Error> {
        Ok(self.frozen_addresses.contains(address))
    }

    fn add_frozen(&mut self, address: &Ipv4Addr) -> Result<(), Error> {
        self.frozen_addresses.push(address.to_owned());
        Ok(())
    }
}
