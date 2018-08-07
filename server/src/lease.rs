//! Address lease implementation.

use std::net::Ipv4Addr;

use chrono::prelude::*;

/// The state of the `Lease`.
#[derive(Clone)]
enum State {
    Offered,
    Assigned,
    Released,
}

/// A client has only `OFFER_TIMEOUT` seconds to accept a `DHCPOFFER`.
const OFFER_TIMEOUT: u32 = 60;

/// A lease record of the DHCP server lease database.
#[derive(Clone)]
pub struct Lease {
    address: Ipv4Addr,
    state: State,
    lease_time: u32,
    offered_at: u32,
    assigned_at: u32,
    renewed_at: u32,
    released_at: u32,
    expires_at: u32,
}

#[allow(dead_code)]
impl Lease {
    /// Creates a new `Lease` in `Offered` state.
    pub fn new(address: Ipv4Addr, lease_time: u32) -> Self {
        let offered_at = Utc::now().timestamp() as u32;

        Lease {
            address,
            state: State::Offered,
            lease_time,
            offered_at,
            assigned_at: 0,
            renewed_at: 0,
            released_at: 0,
            expires_at: 0,
        }
    }

    /// `IPv4` lease address.
    pub fn address(&self) -> Ipv4Addr {
        self.address.to_owned()
    }

    /// How long the address is leased for in seconds.
    pub fn lease_time(&self) -> u32 {
        self.lease_time
    }

    /// Moves the lease from `Offered` to the `Assigned` state.
    ///
    /// Records the assignment time and calculates the expiration time.
    pub fn assign(&mut self, lease_time: u32) {
        self.state = State::Assigned;
        self.assigned_at = Utc::now().timestamp() as u32;
        self.lease_time = lease_time;
        self.expires_at = self.assigned_at + self.lease_time;
    }

    /// Renewes the expiration time if the lease is in the `Assigned` state.
    ///
    /// Records the renewal time and calculates the expiration time.
    pub fn renew(&mut self, lease_time: u32) {
        self.lease_time = lease_time;
        self.renewed_at = Utc::now().timestamp() as u32;
        self.expires_at = self.renewed_at + self.lease_time;
    }

    /// Releases the address and moves the lease to `Released` state.
    pub fn release(&mut self) {
        self.state = State::Released;
        self.released_at = Utc::now().timestamp() as u32;
    }

    /// The timestamp when the lease is expired in milliseconds.
    pub fn expires_at(&self) -> u32 {
        self.expires_at
    }

    /// The number of seconds before the lease is expired in milliseconds.
    ///
    /// Returns 0 if the lease has already expired.
    pub fn expires_after(&self) -> u32 {
        if self.is_expired() {
            return 0;
        }
        self.expires_at - (Utc::now().timestamp() as u32)
    }

    /// Check whether the address of the lease is active (assigned and not expired or released).
    pub fn is_active(&self) -> bool {
        self.is_assigned() && !self.is_expired()
    }

    /// Check whether the address of the lease is still allocated (offered or assigned and not expired or released).
    pub fn is_allocated(&self) -> bool {
        (self.is_offered() && !self.is_offer_expired()) || self.is_active()
    }

    /// Check whether the address of the lease is available (the offer or assignment expired or released).
    pub fn is_available(&self) -> bool {
        !self.is_allocated()
    }

    /// Check whether the lease is in `Offered` state.
    ///
    /// Does not check for expiration.
    pub fn is_offered(&self) -> bool {
        if let State::Offered = self.state {
            true
        } else {
            false
        }
    }

    /// Check whether the lease is in `Assigned` state.
    ///
    /// Does not check for expiration.
    pub fn is_assigned(&self) -> bool {
        if let State::Assigned = self.state {
            true
        } else {
            false
        }
    }

    /// Check whether the lease is in `Released` state.
    ///
    /// The lease can be only manually released.
    pub fn is_released(&self) -> bool {
        if let State::Released = self.state {
            true
        } else {
            false
        }
    }

    /// Check whether the lease's offer is expired.
    pub fn is_offer_expired(&self) -> bool {
        if self.offered_at == 0 {
            return false;
        }
        (Utc::now().timestamp() as u32) >= self.offered_at + OFFER_TIMEOUT
    }

    /// Check whether the lease is expired.
    pub fn is_expired(&self) -> bool {
        if self.expires_at == 0 {
            return false;
        }
        (Utc::now().timestamp() as u32) >= self.expires_at
    }
}
