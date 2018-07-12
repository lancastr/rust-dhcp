use std::{
    cmp,
    ops::Range,
    collections::HashMap,
    net::Ipv4Addr,
};

use lease::Lease;
use message::{
    Offer,
    Ack,
    Error,
};

const DEFAULT_LEASE_TIME: u32       = 60 * 60 * 24; // 24 hours
const MAX_LEASE_TIME: u32           = DEFAULT_LEASE_TIME * 7; // a week

pub struct Storage {
    static_address_range    : Range<u32>,
    dynamic_address_range   : Range<u32>,

    address_client_map      : HashMap<u32, Vec<u8>>, // IPv4 -> client_id
    client_lease_map        : HashMap<Vec<u8>, Lease>, // client_id -> Lease
    frozen_addresses        : Vec<u32>, // reported by DHCPDECLINE
}

#[allow(dead_code)]
impl Storage {
    pub fn new(
        static_address_range    : Range<Ipv4Addr>,
        dynamic_address_range   : Range<Ipv4Addr>,
    ) -> Self {
        let static_address_range = Range{
            start   : u32::from(static_address_range.start),
            end     : u32::from(static_address_range.end),
        };
        let dynamic_address_range = Range{
            start   : u32::from(dynamic_address_range.start),
            end     : u32::from(dynamic_address_range.end),
        };

        let static_address_number = (static_address_range.end - static_address_range.start) as usize;
        let dynamic_address_number = (dynamic_address_range.end - dynamic_address_range.start) as usize;
        let total_address_number = static_address_number + dynamic_address_number;

        Storage {
            static_address_range,
            dynamic_address_range,
            address_client_map      : HashMap::with_capacity(total_address_number),
            client_lease_map        : HashMap::with_capacity(total_address_number * 4),

            frozen_addresses        : Vec::new(),
        }
    }

    //
    // Lease time calculation algorithm:
    //     RFC 2132 §4.3.1
    //     The server must also choose an expiration time for the lease, as follows:
    //
    //     1. IF has not requested a specific lease in the
    //        DHCPDISCOVER message and already has an assigned network
    //        address, the server returns the lease expiration time previously
    //        assigned to that address (note that must explicitly
    //        request a specific lease to extend the expiration time on a
    //        previously assigned address), ELSE
    //
    //     2. IF has not requested a specific lease in the
    //        DHCPDISCOVER message and does not have an assigned
    //        network address, the server assigns a locally configured default
    //        lease time, ELSE
    //
    //     3. IF has requested a specific lease in the DHCPDISCOVER
    //        message (regardless of whether has an assigned network
    //        address), the server may choose either to return the requested
    //        lease (if the lease is acceptable to local policy) or select
    //        another lease.
    //
    // Address allocation algorithm:
    //     RFC 2132 §4.3.1
    //     If an address is available, the new address SHOULD be chosen as follows:
    //
    //     1. The current address as recorded in the current
    //        binding, ELSE
    //
    //     2. The previous address as recorded in the (now
    //        expired or released) binding, if that address is in the server's
    //        pool of available addresses and not already allocated, ELSE
    //
    //     3. The address requested in the 'Requested IP Address' option, if that
    //        address is valid and not already allocated, ELSE
    //
    //     4. A new address allocated from the server's pool of available
    //        addresses; the address is selected based on the subnet from which
    //        the message was received (if 'giaddr' is 0) or on the address of
    //        the relay agent that forwarded the message ('giaddr' when not 0).
    //
    pub fn allocate(
        &mut self,
        client_id           : Option<Vec<u8>>,
        lease_time          : Option<u32>,
        requested_address   : Option<Ipv4Addr>,
    ) -> Result<Offer, Error> {
        let client_id = client_id.ok_or(Error::ClientIdNotSpecified)?;

        // for lease time case 1
        let reuse_lease_time = lease_time.is_none();
        // lease time case 2 or 3
        let lease_time = cmp::min(lease_time.unwrap_or(DEFAULT_LEASE_TIME), MAX_LEASE_TIME);

        let requested_address = requested_address.map(|address| u32::from(address));

        // address allocation case 1
        if let Some(address) = self.client_current_address(&client_id) {
            // lease time case 1
            let lease_time = self.offer(address, &client_id, lease_time, reuse_lease_time);

            let offer = Offer{
                address: Ipv4Addr::from(address),
                lease_time,
                message: "Offering the current address".to_owned(),
            };
            trace!("offering to client {:?} the current address: {:?}", client_id, offer);
            return Ok(offer);
        } else {
            trace!("client {:?} has no current address", client_id);
        }

        // address allocation case 2
        if let Some(address) = self.client_last_address(&client_id) {
            if self.is_address_available(address) {
                let lease_time = self.offer(address, &client_id, lease_time, false);

                let offer = Offer{
                    address: Ipv4Addr::from(address),
                    lease_time,
                    message: "Offering the previous address".to_owned(),
                };
                trace!("offering to client {:?} the previous address {:?}", client_id, offer);
                return Ok(offer);
            }
            trace!("the previous address {} is not available", Ipv4Addr::from(address));
        } else {
            trace!("client {:?} has never had an address", client_id);
        }

        // address allocation case 3
        if let Some(address) = requested_address {
            if self.is_address_available(address) && self.is_address_in_static_pool(address) {
                let lease_time = self.offer(address, &client_id, lease_time, false);

                let offer = Offer{
                    address: Ipv4Addr::from(address),
                    lease_time,
                    message: "Offering the requested address".to_owned(),
                };
                trace!("offering to client {:?} the requested address: {:?}", client_id, offer);
                return Ok(offer);
            }
            trace!("the requested address {} is not available", Ipv4Addr::from(address));
        } else {
            trace!("client {:?} does not request an address", client_id);
        }

        // address allocation case 4
        // giaddr stuff not implemented
        let address = self.get_dynamic_available().ok_or(Error::DynamicPoolExhausted)?;
        let lease_time = self.offer(address, &client_id, lease_time, false);

        let offer = Offer{
            address: Ipv4Addr::from(address),
            lease_time,
            message: "Offering an address from the dynamic pool".to_owned(),
        };
        trace!("offering to client {:?} an address from the dynamic pool: {:?}", client_id, offer);
        Ok(offer)
    }

    pub fn assign(
        &mut self,
        client_id       : Option<Vec<u8>>,
        address         : Option<Ipv4Addr>,
    ) -> Result<Ack, Error> {
        let client_id = client_id.ok_or(Error::ClientIdNotSpecified)?;

        let address = u32::from(address.ok_or(Error::AddressNotSpecified)?.to_owned());

        if let Some(ref mut lease) = self.client_lease_map.get_mut::<Vec<u8>>(client_id.as_ref()) {
            if lease.is_offered() {
                if lease.address() != address {
                    return Err(Error::InvalidAddress);
                }
                lease.assign();
                return Ok(Ack{
                    address     : Ipv4Addr::from(lease.address()),
                    lease_time  : lease.lease_time(),
                    message     : "Successfully assigned".to_owned(),
                });
            } else {
                if lease.is_offer_expired() {
                    return Err(Error::OfferExpired);
                } else {
                    return Err(Error::AddressNotOffered);
                }
            }
        }
        Err(Error::OfferNotFound)
    }

    pub fn renew(
        &mut self,
        client_id       : Option<Vec<u8>>,
        address         : &Ipv4Addr,
        lease_time      : Option<u32>,
    ) -> Result<Ack, Error> {
        let client_id = client_id.ok_or(Error::ClientIdNotSpecified)?;

        let address = u32::from(address.to_owned());
        let lease_time = cmp::min(lease_time.unwrap_or(DEFAULT_LEASE_TIME), MAX_LEASE_TIME);

        if let Some(ref mut lease) = self.client_lease_map.get_mut::<Vec<u8>>(client_id.as_ref()) {
            if lease.address() == address {
                lease.renew(lease_time);
                return Ok(Ack{
                    address     : Ipv4Addr::from(lease.address()),
                    lease_time  : lease.lease_time(),
                    message     : "Your lease has been renewed".to_owned(),
                });
            } else {
                return Err(Error::LeaseHasDifferentAddress);
            }
        }
        Err(Error::LeaseNotFound)
    }

    pub fn deallocate(
        &mut self,
        client_id   : Option<Vec<u8>>,
        address     : Option<Ipv4Addr>,
    ) -> Result<(), Error> {
        let client_id = client_id.ok_or(Error::ClientIdNotSpecified)?;

        let address = u32::from(address.ok_or(Error::AddressNotSpecified)?.to_owned());

        self.address_client_map.remove(&address);
        if let Some(ref mut lease) = self.client_lease_map.get_mut::<Vec<u8>>(client_id.as_ref()) {
            lease.release();
        }
        Ok(())
    }

    pub fn freeze(
        &mut self,
        client_id   : Option<Vec<u8>>,
        address     : Option<Ipv4Addr>,
    ) -> Result<(), Error> {
        let client_id = client_id.ok_or(Error::ClientIdNotSpecified)?;

        let address = u32::from(address.ok_or(Error::AddressNotSpecified)?.to_owned());

        self.address_client_map.remove(&address);
        if let Some(ref mut lease) = self.client_lease_map.get_mut::<Vec<u8>>(client_id.as_ref()) {
            lease.release();
        }
        Ok(())
    }

    pub fn check(
        &self,
        client_id   : Option<Vec<u8>>,
        address     : Option<Ipv4Addr>,
    ) -> Result<Ack, Error> {
        let client_id = client_id.ok_or(Error::ClientIdNotSpecified)?;

        let address = u32::from(address.ok_or(Error::AddressNotSpecified)?.to_owned());

        if let Some(ref lease) = self.client_lease_map.get::<Vec<u8>>(client_id.as_ref()) {
            if lease.address() == address {
                return Ok(Ack{
                    address     : Ipv4Addr::from(lease.address()),
                    lease_time  : lease.lease_time(),
                    message     : "Your lease is active".to_owned(),
                });
            } else {
                return Err(Error::LeaseHasDifferentAddress);
            }
        }
        Err(Error::LeaseNotFound)
    }

    fn offer(
        &mut self,
        address             : u32,
        client_id           : &[u8],
        lease_time          : u32,
        reuse_lease_time    : bool,
    ) -> u32 {
        self.address_client_map.insert(address, client_id.to_owned());
        let mut lease_time = lease_time;
        if reuse_lease_time {
            if let Some(ref lease) = self.client_lease_map.get_mut(client_id) {
                lease_time = lease.expires_after();
            }
        }

        self.client_lease_map.insert(client_id.to_vec(), Lease::new(address, lease_time));
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

    fn client_current_address(&self, client_id: &[u8]) -> Option<u32> {
        if let Some(ref lease) = self.client_lease_map.get(client_id) {
            if lease.is_allocated() {
                return Some(lease.address());
            }
        }
        None
    }

    fn client_last_address(&self, client_id: &[u8]) -> Option<u32> {
        if let Some(ref lease) = self.client_lease_map.get(client_id) {
            return Some(lease.address());
        }
        None
    }

    fn is_address_in_static_pool(&self, address: u32) -> bool {
        self.static_address_range.start <= address && address < self.static_address_range.end
    }

    fn is_address_in_dynamic_pool(&self, address: u32) -> bool {
        self.dynamic_address_range.start <= address && address < self.dynamic_address_range.end
    }

    fn is_address_frozen(&self, address: u32) -> bool {
        self.frozen_addresses.contains(&address)
    }

    fn is_address_available(&self, address: u32) -> bool {
        !self.is_address_allocated(address) && !self.is_address_frozen(address)
    }

    fn is_address_allocated(&self, address: u32) -> bool {
        if let Some(cid) = self.address_client_map.get(&address).map(|cid| cid.to_owned()) {
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
        let client_id = vec![1u8];

        let offer1 = storage.allocate(
            client_id,
            Some(1000),
            None
        ).unwrap();

        let offer2 = storage.allocate(
            client_id,
            Some(1000),
            Some(Ipv4Addr::new(192,168,0,166)),
        ).unwrap();

        assert_eq!(offer1.address, offer2.address);
    }

    #[test]
    fn reuses_client_previous_address() {
        let mut storage = Storage::new(
            Ipv4Addr::new(192,168,0,2)..Ipv4Addr::new(192,168,0,101),
            Ipv4Addr::new(192,168,0,101)..Ipv4Addr::new(192,168,0,200),
        );
        let client_id = vec![1u8];

        let offer1 = storage.allocate(
            client_id,
            Some(1000),
            None
        ).unwrap();

        storage.deallocate(client_id, Some(offer1.address)).unwrap();

        let offer2 = storage.allocate(
            client_id,
            Some(1000),
            Some(Ipv4Addr::new(192,168,0,166)),
        ).unwrap();

        assert_eq!(offer1.address, offer2.address);
    }

    #[test]
    fn uses_deallocated_address_for_new_client() {
        let mut storage = Storage::new(
            Ipv4Addr::new(192,168,0,2)..Ipv4Addr::new(192,168,0,101),
            Ipv4Addr::new(192,168,0,101)..Ipv4Addr::new(192,168,0,200),
        );
        let client_id = vec![1u8];
        let another_client_id = vec![2u8];

        let current = Ipv4Addr::new(192,168,0,166);

        let offer1 = storage.allocate(
            client_id,
            Some(1000),
            Some(current),
        ).unwrap();

        storage.deallocate(client_id, Some(offer1.address)).unwrap();

        let offer2 = storage.allocate(
            another_client_id,
            Some(1000),
            Some(current),
        ).unwrap();

        assert_eq!(offer1.address, offer2.address);
    }

    #[test]
    fn uses_requested_address_if_current_and_previous_are_unavailable() {
        let mut storage = Storage::new(
            Ipv4Addr::new(192,168,0,2)..Ipv4Addr::new(192,168,0,101),
            Ipv4Addr::new(192,168,0,101)..Ipv4Addr::new(192,168,0,200),
        );
        let client_id = vec![1u8];
        let another_client_id = vec![2u8];

        let current = Ipv4Addr::new(192,168,0,66);
        let requested = Ipv4Addr::new(192,168,0,77);

        let offer1 = storage.allocate(
            client_id,
            Some(1000),
            Some(current),
        ).unwrap();

        storage.deallocate(client_id, Some(offer1.address)).unwrap();

        let _ = storage.allocate(
            another_client_id,
            Some(1000),
            Some(current),
        ).unwrap();

        let offer3 = storage.allocate(
            client_id,
            Some(1000),
            Some(requested),
        ).unwrap();

        assert_eq!(offer3.address, requested);
    }

    #[test]
    fn uses_new_address_if_current_and_previous_and_requested_are_unavailable() {
        let mut storage = Storage::new(
            Ipv4Addr::new(192,168,0,2)..Ipv4Addr::new(192,168,0,101),
            Ipv4Addr::new(192,168,0,101)..Ipv4Addr::new(192,168,0,200),
        );
        let client_id = vec![1u8];
        let another_client_id = vec![2u8];
        let yet_another_client_id = vec![3u8];

        let current = Ipv4Addr::new(192,168,0,66);
        let requested = Ipv4Addr::new(192,168,0,77);

        let offer1 = storage.allocate(
            client_id,
            Some(1000),
            Some(current),
        ).unwrap();

        storage.deallocate(client_id, Some(offer1.address)).unwrap();

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

        let offer3 = storage.allocate(
            client_id,
            Some(1000),
            Some(requested),
        ).unwrap();

        assert_ne!(offer3.address, requested);
    }
}