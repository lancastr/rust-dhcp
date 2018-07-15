//! A RAM example of the persistent lease storage of the DHCP server.
//! (well, not persistent, eventually)

use std::{
    collections::HashMap,
};

use storage::{
    Storage,
    Error,
};
use lease::Lease;

pub struct RamStorage {
    /// `IPv4` to `client_id` mapping.
    address_client_map      : HashMap<u32, Vec<u8>>,
    /// `client_id` to `Lease` mapping.
    client_lease_map        : HashMap<Vec<u8>, Lease>,
//    /// `IPv4` addresses reported by `DHCPDECLINE`.
//    frozen_addresses        : Vec<u32>,
}

impl RamStorage {
    pub fn new() -> Self {
        RamStorage {
            address_client_map  : HashMap::new(),
            client_lease_map    : HashMap::new(),
        }
    }
}

impl Storage for RamStorage {
    fn get_client(
        &self,
        address: u32,
    ) -> Result<Option<Vec<u8>>, Error>
    {
        if let Some(client_id) = self.address_client_map.get(&address) {
            Ok(Some(client_id.to_owned()))
        } else {
            Ok(None)
        }
    }

    fn add_client(
        &mut self,
        address: u32,
        client_id: &[u8],
    ) -> Result<(), Error>
    {
        self.address_client_map.insert(address, client_id.to_vec());
        Ok(())
    }

    fn delete_client(
        &mut self,
        address: u32,
    ) -> Result<(), Error>
    {
        self.address_client_map.remove(&address);
        Ok(())
    }

    fn get_lease(
        &self,
        client_id: &[u8],
    ) -> Result<Option<Lease>, Error>
    {
        if let Some(lease) = self.client_lease_map.get(client_id) {
            Ok(Some(lease.to_owned()))
        } else {
            Ok(None)
        }
    }

    fn add_lease(
        &mut self,
        client_id: &[u8],
        lease: Lease,
    ) -> Result<(), Error>
    {
        self.client_lease_map.insert(client_id.to_vec(), lease);
        Ok(())
    }

    fn update_lease(
        &mut self,
        client_id: &[u8],
        action: &mut FnMut(&mut Lease) -> (),
    ) -> Result<Option<Lease>, Error> {
        if let Some(lease) = self.client_lease_map.get_mut(client_id) {
            action(lease);
            Ok(Some(lease.to_owned()))
        } else {
            Ok(None)
        }
    }
}