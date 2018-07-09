use std::{
    cmp,
    ops::Range,
    collections::HashMap,
    net::Ipv4Addr,
};

use lease::Lease;
use offer::Offer;

const DEFAULT_LEASE_TIME: u32       = 60 * 60 * 24; // 24 hours
const MAX_LEASE_TIME: u32           = DEFAULT_LEASE_TIME * 7; // a week

pub struct Storage {
    static_address_range    : Range<u32>,
    dynamic_address_range   : Range<u32>,
    address_client_map      : HashMap<u32, u32>, // IPv4 -> client_id
    client_lease_map        : HashMap<u32, Lease>, // client_id -> Lease
}

impl Storage {
    pub fn new(
        static_address_range    : Range<Ipv4Addr>,
        dynamic_address_range   : Range<Ipv4Addr>,
    ) -> Self {
        let static_address_range = Range{
            start   : u32::from(static_address_range.start),
            end     : u32::from(static_address_range.end),
        };
        let static_address_number = (static_address_range.end - static_address_range.start) as usize;

        let dynamic_address_range = Range{
            start   : u32::from(dynamic_address_range.start),
            end     : u32::from(dynamic_address_range.end),
        };
        let dynamic_address_number = (dynamic_address_range.end - dynamic_address_range.start) as usize;

        Storage {
            static_address_range,
            dynamic_address_range,
            address_client_map      : HashMap::with_capacity(static_address_number + dynamic_address_number),
            client_lease_map        : HashMap::with_capacity(static_address_number + dynamic_address_number),
        }
    }

    ///
    /// Lease time calculation algorithm:
    ///     RFC 2132 §4.3.1
    ///     The server must also choose an expiration time for the lease, as follows:
    ///
    ///     1. IF the client has not requested a specific lease in the
    ///        DHCPDISCOVER message and the client already has an assigned network
    ///        address, the server returns the lease expiration time previously
    ///        assigned to that address (note that the client must explicitly
    ///        request a specific lease to extend the expiration time on a
    ///        previously assigned address), ELSE
    ///
    ///     2. IF the client has not requested a specific lease in the
    ///        DHCPDISCOVER message and the client does not have an assigned
    ///        network address, the server assigns a locally configured default
    ///        lease time, ELSE
    ///
    ///     3. IF the client has requested a specific lease in the DHCPDISCOVER
    ///        message (regardless of whether the client has an assigned network
    ///        address), the server may choose either to return the requested
    ///        lease (if the lease is acceptable to local policy) or select
    ///        another lease.
    ///
    /// Address allocation algorithm:
    ///     RFC 2132 §4.3.1
    ///     If an address is available, the new address SHOULD be chosen as follows:
    ///
    ///     1. The client's current address as recorded in the client's current
    ///        binding, ELSE
    ///
    ///     2. The client's previous address as recorded in the client's (now
    ///        expired or released) binding, if that address is in the server's
    ///        pool of available addresses and not already allocated, ELSE
    ///
    ///     3. The address requested in the 'Requested IP Address' option, if that
    ///        address is valid and not already allocated, ELSE
    ///
    ///     4. A new address allocated from the server's pool of available
    ///        addresses; the address is selected based on the subnet from which
    ///        the message was received (if 'giaddr' is 0) or on the address of
    ///        the relay agent that forwarded the message ('giaddr' when not 0).
    ///
    pub fn allocate(
        &mut self,
        client_id           : u32,
        lease_time_opt      : Option<u32>,
        requested_address   : Option<Ipv4Addr>,
    ) -> Result<Offer, String> {
        println!("Allocation sequence: started");

        // lease time case 2 or 3
        let lease_time = cmp::min(lease_time_opt.unwrap_or(DEFAULT_LEASE_TIME), MAX_LEASE_TIME);

        let requested_address = requested_address.map(|address| u32::from(address));

        // address allocation case 1
        println!("Allocation sequence: checking for a client's current address");
        if let Some(address) = self.client_current_address(client_id) {
            // lease time case 1
            let lease_time = self.offer(address, client_id, lease_time, lease_time_opt.is_none());

            let offer = Offer{
                address: Ipv4Addr::from(address),
                lease_time,
                message: "Offering the client his current address".to_owned(),
            };
            println!("Allocation sequence: offering the client his current address: {:?}", offer);
            return Ok(offer);
        } else {
            println!("Allocation sequence: the client has no current address");
        }

        // address allocation case 2
        println!("Allocation sequence: checking for a client's previous address");
        if let Some(address) = self.client_last_address(client_id) {
            println!("Allocation sequence: checking if the address {} is available", Ipv4Addr::from(address));
            if self.is_address_available(address) {
                let lease_time = self.offer(address, client_id, lease_time, false);

                let offer = Offer{
                    address: Ipv4Addr::from(address),
                    lease_time,
                    message: "Offering the client his previous address".to_owned(),
                };
                println!("Allocation sequence: offering the client his previous address {:?}", offer);
                return Ok(offer);
            }
            println!("Allocation sequence: the previous address {} is not available", Ipv4Addr::from(address));
        } else {
            println!("Allocation sequence: the client has never had an address");
        }

        // address allocation case 3
        if let Some(address) = requested_address {
            println!("Allocation sequence: checking if the requested address {} is available", Ipv4Addr::from(address));
            if self.is_address_available(address) {
                let lease_time = self.offer(address, client_id, lease_time, false);

                let offer = Offer{
                    address: Ipv4Addr::from(address),
                    lease_time,
                    message: "Offering the client the requested address".to_owned(),
                };
                println!("Allocation sequence: offering the client the requested address: {:?}", offer);
                return Ok(offer);
            }
            println!("Allocation sequence: the requested address {} is not available", Ipv4Addr::from(address));
        } else {
            println!("Allocation sequence: the client does not request an address");
        }

        // address allocation case 4
        // giaddr stuff not implemented
        let address = self.get_dynamic_available().ok_or("None available".to_owned())?;
        let lease_time = self.offer(address, client_id, lease_time, false);

        let offer = Offer{
            address: Ipv4Addr::from(address),
            lease_time,
            message: "Offering the client an address from the dynamic pool".to_owned(),
        };
        println!("Allocation sequence: offering the client an address from the dynamic pool: {:?}", offer);
        Ok(offer)
    }

    pub fn release(
        &mut self,
        address: &Ipv4Addr,
        client_id: u32,
    ) {
        let address = u32::from(address.to_owned());
        self.address_client_map.remove(&address);
        if let Some(ref mut lease) = self.client_lease_map.get_mut(&client_id) {
            lease.release();
        }
    }

    fn offer(
        &mut self,
        address: u32,
        client_id: u32,
        lease_time: u32,
        reuse_lease_time: bool,
    ) -> u32 {
        self.address_client_map.insert(address, client_id);
        let mut lease_time = lease_time;
        if reuse_lease_time {
            if let Some(ref lease) = self.client_lease_map.get_mut(&client_id) {
                lease_time = lease.expires_after();
            }
        }

        self.client_lease_map.insert(client_id, Lease::new(address));
        lease_time
    }

    fn get_dynamic_available(&self) -> Option<u32> {
        for address in self.dynamic_address_range.start..self.dynamic_address_range.end {
            if self.is_address_available(address) {
                return Some(address);
            }
        }
        None
    }

    fn client_current_address(&self, client_id: u32) -> Option<u32> {
        if let Some(ref lease) = self.client_lease_map.get(&client_id) {
            if lease.is_allocated() {
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

    fn is_in_static_pool(&self, address: u32) -> bool {
        self.static_address_range.start <= address && address < self.static_address_range.end
    }

    fn is_in_dynamic_pool(&self, address: u32) -> bool {
        self.dynamic_address_range.start <= address && address < self.dynamic_address_range.end
    }

    fn is_address_available(&self, address: u32) -> bool {
        (self.is_in_static_pool(address) || self.is_in_dynamic_pool(address)) && !self.is_address_leased(address)
    }

    fn is_address_leased(&self, address: u32) -> bool {
        if let Some(cid) = self.address_client_map.get(&address).map(|cid| *cid) {
            if let Some(ref lease) = self.client_lease_map.get(&cid) {
                return lease.is_allocated();
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reuses_client_current_address() {
        let mut storage = Storage::new(
            Ipv4Addr::new(192,168,0,2)..Ipv4Addr::new(192,168,0,101),
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
            Ipv4Addr::new(192,168,0,2)..Ipv4Addr::new(192,168,0,101),
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
            Ipv4Addr::new(192,168,0,2)..Ipv4Addr::new(192,168,0,101),
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
            Ipv4Addr::new(192,168,0,2)..Ipv4Addr::new(192,168,0,101),
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
            Ipv4Addr::new(192,168,0,2)..Ipv4Addr::new(192,168,0,101),
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