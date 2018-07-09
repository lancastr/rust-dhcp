use std::{
    ops::Range,
    collections::HashMap,
    net::Ipv4Addr,
};

use lease::Lease;

const DEFAULT_LEASE_TIME: u32 = 86400;

pub struct Storage {
    dynamic_address_range   : Range<u32>,
    address_client_map      : HashMap<u32, u32>, // IPv4 -> client_id
    client_lease_map        : HashMap<u32, Lease>, // client_id -> Lease
}

impl Storage {
    pub fn new(
        dynamic_address_range : Range<Ipv4Addr>,
    ) -> Self {
        let dynamic_address_range = Range{
            start   : u32::from(dynamic_address_range.start),
            end     : u32::from(dynamic_address_range.end),
        };
        let dynamic_address_number = (dynamic_address_range.end - dynamic_address_range.start + 1) as usize;

        Storage {
            dynamic_address_range,
            address_client_map      : HashMap::with_capacity(dynamic_address_number),
            client_lease_map        : HashMap::with_capacity(dynamic_address_number),
        }
    }

    pub fn allocate(
        &mut self,
        client_id           : u32,
        lease_time          : Option<u32>,
        requested_address   : Option<Ipv4Addr>,
    ) -> Result<Ipv4Addr, String> {
        println!("Allocation sequence: started");
        let lease_time = lease_time.unwrap_or(DEFAULT_LEASE_TIME);
        let requested_address = requested_address.map(|address| u32::from(address));

        /*
        RFC 2131 §4.3.1 (step 1)
        The client's current address as recorded in the client's current binding.
        */
        println!("Allocation sequence: checking for a client's current address");
        if let Some(address) = self.client_current_address(client_id) {
            println!("Allocation sequence: the client has already leased an address: {}", Ipv4Addr::from(address));
            self.lease(address, client_id, lease_time);
            return Ok(Ipv4Addr::from(address));
        } else {
            println!("Allocation sequence: the client has no current address");
        }

        /*
        RFC 2131 §4.3.1 (step 2)
        The client's previous address as recorded in the client's (now
        expired or released) binding, if that address is in the server's
        pool of available addresses and not already allocated.
        */
        println!("Allocation sequence: checking for a client's previous address");
        if let Some(address) = self.client_last_address(client_id) {
            println!("Allocation sequence: checking if the address {} is available", Ipv4Addr::from(address));
            if self.is_address_available(address) {
                println!("Allocation sequence: giving the client his previous address {}", Ipv4Addr::from(address));
                self.lease(address, client_id, lease_time);
                return Ok(Ipv4Addr::from(address));
            }
            println!("Allocation sequence: the previous address {} is not available", Ipv4Addr::from(address));
        } else {
            println!("Allocation sequence: the client has never had an address");
        }

        /*
        RFC 2131 §4.3.1 (step 3)
        The address requested in the 'Requested IP Address' option, if that
        address is valid and not already allocated.
        */
        if let Some(address) = requested_address {
            println!("Allocation sequence: checking if the requested address {} is available", Ipv4Addr::from(address));
            if self.is_address_available(address) {
                println!("Allocation sequence: giving the client the requested address: {}", Ipv4Addr::from(address));
                self.lease(address, client_id, lease_time);
                return Ok(Ipv4Addr::from(address));
            }
            println!("Allocation sequence: the requested address {} is not available", Ipv4Addr::from(address));
        } else {
            println!("Allocation sequence: the client does not request an address");
        }

        /*
        RFC 2131 §4.3.1 (step 4)
        A new address allocated from the server's pool of available
        addresses; the address is selected based on the subnet from which
        the message was received (if 'giaddr' is 0) or on the address of
        the relay agent that forwarded the message ('giaddr' when not 0).

        Note: giaddr stuff not implemented
        */
        let address = self.first_available_address().ok_or("None available".to_owned())?;
        println!("Allocation sequence: giving the client the newly allocated address: {}", Ipv4Addr::from(address));
        self.lease(address, client_id, lease_time);
        Ok(Ipv4Addr::from(address))
    }

    pub fn deallocate(
        &mut self,
        address: &Ipv4Addr,
        client_id: u32,
    ) {
        self.release(u32::from(address.to_owned()), client_id);
    }

    fn first_available_address(&self) -> Option<u32> {
        for address in self.dynamic_address_range.start..self.dynamic_address_range.end {
            if self.is_address_available(address) {
                return Some(address);
            }
        }
        None
    }

    fn lease(
        &mut self,
        address: u32,
        client_id: u32,
        lease_time: u32,
    ) {
        self.address_client_map.insert(address, client_id);
        self.client_lease_map.insert(client_id, Lease::new(address, lease_time));
    }

    fn release(
        &mut self,
        address: u32,
        client_id: u32,
    ) {
        self.address_client_map.remove(&address);
        if let Some(ref mut lease) = self.client_lease_map.get_mut(&client_id) {
            lease.release();
        }
    }

    fn client_current_address(&self, client_id: u32) -> Option<u32> {
        if let Some(ref lease) = self.client_lease_map.get(&client_id) {
            if lease.is_active() {
                return Some(lease.address());
            }
        }
        None
    }

    fn client_last_address(&self, client_id: u32) -> Option<u32> {
        if let Some(ref lease) = self.client_lease_map.get(&client_id) {
            return Some(lease.address());
        }
        None
    }

    fn is_in_dynamic_pool(&self, address: u32) -> bool {
        self.dynamic_address_range.start <= address && address < self.dynamic_address_range.end
    }

    fn is_address_available(&self, address: u32) -> bool {
        !self.is_address_leased(address) && self.is_in_dynamic_pool(address)
    }

    fn is_address_leased(&self, address: u32) -> bool {
        if let Some(cid) = self.address_client_map.get(&address).map(|cid| *cid) {
            if let Some(ref lease) = self.client_lease_map.get(&cid) {
                return lease.is_active();
            }
        }
        false
    }

//    fn is_address_leased_by(&self, address: u32, client_id: u32) -> bool {
//        if let Some(cid) = self.address_client_map.get(&address).map(|cid| *cid) {
//            if let Some(ref lease) = self.client_lease_map.get(&cid) {
//                return cid == client_id && lease.is_active();
//            }
//        }
//        false
//    }
//
//    fn had_been_address_leased_by(&self, address: u32, client_id: u32) -> bool {
//        if let Some(cid) = self.address_client_map.get(&address).map(|cid| *cid) {
//            if let Some(ref lease) = self.client_lease_map.get(&cid) {
//                return cid == client_id;
//            }
//        }
//        false
//    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reuses_client_current_address() {
        let mut storage = Storage::new(
            Ipv4Addr::new(192,168,0,101)..Ipv4Addr::new(192,168,0,200),
        );
        let client_id = 1u32;

        let address1 = storage.allocate(
            client_id,
            Some(1000),
            None
        ).unwrap();

        let address2 = storage.allocate(
            client_id,
            Some(1000),
            Some(Ipv4Addr::new(192,168,0,166)),
        ).unwrap();

        assert_eq!(address1, address2);
    }

    #[test]
    fn reuses_client_previous_address() {
        let mut storage = Storage::new(
            Ipv4Addr::new(192,168,0,101)..Ipv4Addr::new(192,168,0,200),
        );
        let client_id = 1u32;

        let address1 = storage.allocate(
            client_id,
            Some(1000),
            None
        ).unwrap();

        storage.deallocate(&address1, client_id);

        let address2 = storage.allocate(
            client_id,
            Some(1000),
            Some(Ipv4Addr::new(192,168,0,166)),
        ).unwrap();

        assert_eq!(address1, address2);
    }

    #[test]
    fn uses_deallocated_address_for_new_client() {
        let mut storage = Storage::new(
            Ipv4Addr::new(192,168,0,101)..Ipv4Addr::new(192,168,0,200),
        );
        let client_id = 1u32;
        let another_client_id = 2u32;

        let current = Ipv4Addr::new(192,168,0,166);

        let address1 = storage.allocate(
            client_id,
            Some(1000),
            Some(current),
        ).unwrap();

        storage.deallocate(&address1, client_id);

        let address2 = storage.allocate(
            another_client_id,
            Some(1000),
            Some(current),
        ).unwrap();

        assert_eq!(address1, address2);
    }

    #[test]
    fn uses_requested_address_if_current_and_previous_are_unavailable() {
        let mut storage = Storage::new(
            Ipv4Addr::new(192,168,0,101)..Ipv4Addr::new(192,168,0,200),
        );
        let client_id = 1u32;
        let another_client_id = 2u32;

        let current = Ipv4Addr::new(192,168,0,166);
        let requested = Ipv4Addr::new(192,168,0,180);

        let address1 = storage.allocate(
            client_id,
            Some(1000),
            Some(current),
        ).unwrap();
        storage.deallocate(&address1, client_id);

        let _ = storage.allocate(
            another_client_id,
            Some(1000),
            Some(current),
        ).unwrap();

        let address3 = storage.allocate(
            client_id,
            Some(1000),
            Some(requested),
        ).unwrap();

        assert_eq!(address3, requested);
    }

    #[test]
    fn uses_new_address_if_current_and_previous_and_requested_are_unavailable() {
        let mut storage = Storage::new(
            Ipv4Addr::new(192,168,0,101)..Ipv4Addr::new(192,168,0,200),
        );
        let client_id = 1u32;
        let another_client_id = 2u32;
        let yet_another_client_id = 3u32;

        let current = Ipv4Addr::new(192,168,0,166);
        let requested = Ipv4Addr::new(192,168,0,180);

        let address1 = storage.allocate(
            client_id,
            Some(1000),
            Some(current),
        ).unwrap();
        storage.deallocate(&address1, client_id);

        let _ = storage.allocate(
            another_client_id,
            Some(1000),
            Some(current),
        ).unwrap();

        let _ = storage.allocate(
            yet_another_client_id,
            Some(1000),
            Some(requested),
        ).unwrap();

        let address3 = storage.allocate(
            client_id,
            Some(1000),
            Some(requested),
        ).unwrap();

        assert_ne!(address3, requested);
    }
}