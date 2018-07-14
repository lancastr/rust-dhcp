//! Storage module

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

/// T1 RFC 2131 suggestion.
const RENEWAL_TIME_FACTOR: f64      = 0.5;
/// T2 RFC 2131 suggestion.
const REBINDING_TIME_FACTOR: f64    = 0.875;
/// 24 hours.
const DEFAULT_LEASE_TIME: u32       = 60 * 60 * 24;
/// 1 week.
const MAX_LEASE_TIME: u32           = 60 * 60 * 24 * 7;

/// DHCP persistent lease database.
///
/// `Ipv4Addr` is represented as `u32` for better usability and performance.
pub struct Storage {
    /// Non-inclusive static address range.
    static_address_range    : Range<u32>,
    /// Non-inclusive dynamic address range.
    dynamic_address_range   : Range<u32>,
    /// `IPv4` to `client_id` mapping.
    address_client_map      : HashMap<u32, Vec<u8>>,
    /// `client_id` to `Lease` mapping.
    client_lease_map        : HashMap<Vec<u8>, Lease>,
    /// `IPv4` addresses reported by `DHCPDECLINE`.
    frozen_addresses        : Vec<u32>,
}

#[allow(dead_code)]
impl Storage {
    /// Creates a new storage with specified static and dynamic address pools.
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

    /// Allocates an address.
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
    pub fn allocate(
        &mut self,
        client_id           : &[u8],
        lease_time          : Option<u32>,
        requested_address   : Option<Ipv4Addr>,
    ) -> Result<Offer, Error> {
        // for lease time case 1
        let reuse_lease_time = lease_time.is_none();
        // lease time case 2 or 3
        let lease_time = cmp::min(lease_time.unwrap_or(DEFAULT_LEASE_TIME), MAX_LEASE_TIME);

        let requested_address = requested_address.map(|address| u32::from(address));

        // address allocation case 1
        if let Some(address) = self.client_current_address(client_id) {
            if self.is_address_allocated_by(address, client_id) {
                // lease time case 1
                let lease_time = self.offer(address, client_id, lease_time, reuse_lease_time);

                let offer = Offer {
                    address: Ipv4Addr::from(address),
                    lease_time,
                    message: "Offering the current address".to_owned(),
                };
                trace!("Offering to client {:?} the current address: {:?}", client_id, offer);
                return Ok(offer);
            }
            trace!("The current address {} is not available", Ipv4Addr::from(address));
        } else {
            trace!("Client {:?} has no current address", client_id);
        }

        // address allocation case 2
        if let Some(address) = self.client_last_address(client_id) {
            if self.is_address_available(address) {
                let lease_time = self.offer(address, client_id, lease_time, false);

                let offer = Offer{
                    address: Ipv4Addr::from(address),
                    lease_time,
                    message: "Offering the previous address".to_owned(),
                };
                trace!("Offering to client {:?} the previous address {:?}", client_id, offer);
                return Ok(offer);
            }
            trace!("The previous address {} is not available", Ipv4Addr::from(address));
        } else {
            trace!("Client {:?} has never had an address", client_id);
        }

        // address allocation case 3
        if let Some(address) = requested_address {
            if self.is_address_available(address) && self.is_address_in_static_pool(address) {
                let lease_time = self.offer(address, client_id, lease_time, false);

                let offer = Offer{
                    address: Ipv4Addr::from(address),
                    lease_time,
                    message: "Offering the requested address".to_owned(),
                };
                trace!("Offering to client {:?} the requested address: {:?}", client_id, offer);
                return Ok(offer);
            }
            trace!("The requested address {} is not available", Ipv4Addr::from(address));
        } else {
            trace!("Client {:?} does not request an address", client_id);
        }

        // address allocation case 4
        // giaddr stuff not implemented
        let address = self.get_dynamic_available().ok_or(Error::DynamicPoolExhausted)?;
        let lease_time = self.offer(address, client_id, lease_time, false);

        let offer = Offer{
            address: Ipv4Addr::from(address),
            lease_time,
            message: "Offering an address from the dynamic pool".to_owned(),
        };
        trace!("Offering to client {:?} an address from the dynamic pool: {:?}", client_id, offer);
        Ok(offer)
    }

    /// Assigns a previously offered address.
    pub fn assign(
        &mut self,
        client_id           : &[u8],
        lease_time          : Option<u32>,
        requested_address   : Option<Ipv4Addr>,
    ) -> Result<Ack, Error> {
        let requested_address = u32::from(requested_address.ok_or(Error::AddressNotSpecified)?.to_owned());

        if let Some(ref mut lease) = self.client_lease_map.get_mut(client_id) {
            if lease.is_offered() {
                if lease.address() != requested_address {
                    return Err(Error::InvalidAddress);
                }
                let lease_time = cmp::min(lease_time.unwrap_or(lease.lease_time()), lease.lease_time());
                lease.assign(lease_time);
                return Ok(Ack{
                    address         : Ipv4Addr::from(lease.address()),
                    lease_time      : lease.lease_time(),
                    renewal_time    : ((lease.lease_time() as f64) * RENEWAL_TIME_FACTOR) as u32,
                    rebinding_time  : ((lease.lease_time() as f64) * REBINDING_TIME_FACTOR) as u32,
                    message         : "Successfully assigned".to_owned(),
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

    /// Renewes a previously assigned address.
    pub fn renew(
        &mut self,
        client_id           : &[u8],
        address             : &Ipv4Addr,
        lease_time          : Option<u32>,
    ) -> Result<Ack, Error> {
        let address = u32::from(address.to_owned());
        let lease_time = cmp::min(lease_time.unwrap_or(DEFAULT_LEASE_TIME), MAX_LEASE_TIME);

        if let Some(ref mut lease) = self.client_lease_map.get_mut(client_id) {
            if lease.address() == address {
                lease.renew(lease_time);
                return Ok(Ack{
                    address         : Ipv4Addr::from(lease.address()),
                    lease_time      : lease.lease_time(),
                    renewal_time    : ((lease.lease_time() as f64) * RENEWAL_TIME_FACTOR) as u32,
                    rebinding_time  : ((lease.lease_time() as f64) * REBINDING_TIME_FACTOR) as u32,
                    message         : "Your lease has been renewed".to_owned(),
                });
            } else {
                return Err(Error::LeaseHasDifferentAddress);
            }
        }
        Err(Error::LeaseNotFound)
    }

    /// Deallocates a previously offered or assigned address.
    pub fn deallocate(
        &mut self,
        client_id           : &[u8],
        address             : Option<Ipv4Addr>,
    ) -> Result<(), Error> {
        let address = u32::from(address.ok_or(Error::AddressNotSpecified)?.to_owned());

        self.address_client_map.remove(&address);
        if let Some(ref mut lease) = self.client_lease_map.get_mut(client_id) {
            lease.release();
        }
        Ok(())
    }

    /// Freezes an address as a response to a `DHCPDECLINE` message.
    pub fn freeze(
        &mut self,
        client_id           : &[u8],
        address             : Option<Ipv4Addr>,
    ) -> Result<(), Error> {
        let address = u32::from(address.ok_or(Error::AddressNotSpecified)?.to_owned());

        self.address_client_map.remove(&address);
        if let Some(ref mut lease) = self.client_lease_map.get_mut(client_id) {
            lease.release();
        }
        Ok(())
    }

    /// Checks the address of a client in `INIT-REBOOT` state.
    pub fn check(
        &self,
        client_id           : &[u8],
        address             : Option<Ipv4Addr>,
    ) -> Result<Ack, Error> {
        let address = u32::from(address.ok_or(Error::AddressNotSpecified)?.to_owned());

        if let Some(ref lease) = self.client_lease_map.get(client_id) {
            if lease.address() == address {
                return Ok(Ack{
                    address         : Ipv4Addr::from(lease.address()),
                    lease_time      : lease.lease_time(),
                    renewal_time    : ((lease.lease_time() as f64) * RENEWAL_TIME_FACTOR) as u32,
                    rebinding_time  : ((lease.lease_time() as f64) * REBINDING_TIME_FACTOR) as u32,
                    message         : "Your lease is active".to_owned(),
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
        self.address_client_map.insert(address, client_id.to_vec());
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

    fn is_address_allocated_by(&self, address: u32, client_id: &[u8]) -> bool {
        if let Some(cid) = self.address_client_map.get(&address).map(|cid| cid.to_owned()) {
            if cid == client_id {
                if let Some(ref lease) = self.client_lease_map.get(&cid) {
                    return lease.is_allocated();
                }
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
            client_id.as_ref(),
            Some(1000),
            Some(Ipv4Addr::new(192,168,0,11)),
        ).unwrap();
        let ack1 = storage.assign(
            client_id.as_ref(),
            Some(offer1.lease_time),
            Some(offer1.address),
        ).unwrap();

        let offer2 = storage.allocate(
            client_id.as_ref(),
            Some(1000),
            Some(Ipv4Addr::new(192,168,0,12)),
        ).unwrap();
        let ack2 = storage.assign(
            client_id.as_ref(),
            Some(offer2.lease_time),
            Some(offer2.address),
        ).unwrap();

        assert_eq!(ack1.address, ack2.address);
    }

    #[test]
    fn reuses_client_previous_address() {
        let mut storage = Storage::new(
            Ipv4Addr::new(192,168,0,2)..Ipv4Addr::new(192,168,0,101),
            Ipv4Addr::new(192,168,0,101)..Ipv4Addr::new(192,168,0,200),
        );
        let client_id = vec![1u8];

        let offer1 = storage.allocate(
            client_id.as_ref(),
            Some(1000),
            None,
        ).unwrap();
        let ack1 = storage.assign(
            client_id.as_ref(),
            Some(offer1.lease_time),
            Some(offer1.address),
        ).unwrap();
        storage.deallocate(client_id.as_ref(), Some(ack1.address)).unwrap();

        let offer2 = storage.allocate(
            client_id.as_ref(),
            Some(1000),
            Some(Ipv4Addr::new(192,168,0,166)),
        ).unwrap();
        let ack2 = storage.assign(
            client_id.as_ref(),
            Some(offer2.lease_time),
            Some(offer2.address),
        ).unwrap();

        assert_eq!(ack1.address, ack2.address);
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
            client_id.as_ref(),
            Some(1000),
            Some(current),
        ).unwrap();
        let ack1 = storage.assign(
            client_id.as_ref(),
            Some(offer1.lease_time),
            Some(offer1.address),
        ).unwrap();
        storage.deallocate(client_id.as_ref(), Some(ack1.address)).unwrap();

        let offer2 = storage.allocate(
            another_client_id.as_ref(),
            Some(1000),
            Some(current),
        ).unwrap();
        let ack2 = storage.assign(
            another_client_id.as_ref(),
            Some(offer2.lease_time),
            Some(offer2.address),
        ).unwrap();

        assert_eq!(ack1.address, ack2.address);
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
            client_id.as_ref(),
            Some(1000),
            Some(current),
        ).unwrap();
        let ack1 = storage.assign(
            client_id.as_ref(),
            Some(offer1.lease_time),
            Some(offer1.address),
        ).unwrap();
        storage.deallocate(client_id.as_ref(), Some(ack1.address)).unwrap();

        let offer2 = storage.allocate(
            another_client_id.as_ref(),
            Some(1000),
            Some(current),
        ).unwrap();
        let _ack2 = storage.assign(
            another_client_id.as_ref(),
            Some(offer2.lease_time),
            Some(offer2.address),
        ).unwrap();

        let offer3 = storage.allocate(
            client_id.as_ref(),
            Some(1000),
            Some(requested),
        ).unwrap();
        let ack3 = storage.assign(
            client_id.as_ref(),
            Some(offer3.lease_time),
            Some(offer3.address),
        ).unwrap();

        assert_eq!(ack3.address, requested);
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
            client_id.as_ref(),
            Some(1000),
            Some(current),
        ).unwrap();
        let ack1 = storage.assign(
            client_id.as_ref(),
            Some(offer1.lease_time),
            Some(offer1.address),
        ).unwrap();
        storage.deallocate(client_id.as_ref(), Some(ack1.address)).unwrap();

        let offer2 = storage.allocate(
            another_client_id.as_ref(),
            Some(1000),
            Some(current),
        ).unwrap();
        let _ack2 = storage.assign(
            another_client_id.as_ref(),
            Some(offer2.lease_time),
            Some(offer2.address),
        ).unwrap();

        let offer3 = storage.allocate(
            yet_another_client_id.as_ref(),
            Some(1000),
            Some(requested),
        ).unwrap();
        let _ack3 = storage.assign(
            yet_another_client_id.as_ref(),
            Some(offer3.lease_time),
            Some(offer3.address),
        ).unwrap();

        let offer4 = storage.allocate(
            client_id.as_ref(),
            Some(1000),
            Some(requested),
        ).unwrap();
        let ack4 = storage.assign(
            client_id.as_ref(),
            Some(offer4.lease_time),
            Some(offer4.address),
        ).unwrap();

        assert_ne!(ack4.address, requested);
    }
}