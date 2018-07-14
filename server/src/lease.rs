use chrono::prelude::*;

enum State {
    Offered,
    Assigned,
    Released,
}

const OFFER_TIMEOUT: u32 = 10;

pub struct Lease {
    address             : u32,
    lease_time          : u32,

    state               : State,
    offered_at          : u32,
    assigned_at         : u32,
    renewed_at          : u32,
    released_at         : u32,
    expires_at          : u32,
}

#[allow(dead_code)]
impl Lease {
    //
    // Created in Offered state
    //
    pub fn new(address: u32, lease_time: u32) -> Self {
        let offered_at = Utc::now().timestamp() as u32;

        Lease {
            address,
            lease_time,

            state               : State::Offered,
            offered_at,
            assigned_at         : 0,
            renewed_at          : 0,
            released_at         : 0,
            expires_at          : 0,
        }
    }

    pub fn address(&self) -> u32 {
        self.address
    }

    pub fn lease_time(&self) -> u32 {
        self.lease_time
    }

    pub fn assign(&mut self, lease_time: u32) {
        // possible only in Offered state
        if !self.is_offered() {
            return;
        }

        self.state = State::Assigned;
        self.assigned_at = Utc::now().timestamp() as u32;
        self.lease_time = lease_time;
        self.expires_at = self.assigned_at + self.lease_time;
    }

    pub fn renew(&mut self, lease_time: u32) {
        // possible only in Assigned state
        if !self.is_assigned() {
            return;
        }

        self.lease_time = lease_time;
        self.renewed_at = Utc::now().timestamp() as u32;
        self.expires_at = self.renewed_at + self.lease_time;
    }

    pub fn release(&mut self) {
        // may be released only once
        if !self.is_released() {
            return;
        }

        self.state = State::Released;
        self.released_at = Utc::now().timestamp() as u32;
    }

    pub fn expires_at(&self) -> u32 {
        self.expires_at
    }

    pub fn expires_after(&self) -> u32 {
        let current = Utc::now().timestamp() as u32;
        if current > self.expires_at {
            return 0;
        }
        self.expires_at - current
    }

    pub fn is_allocated(&self) -> bool {
        (self.is_offered() && !self.is_offer_expired()) || (self.is_assigned() && !self.is_expired())
    }

    pub fn is_available(&self) -> bool {
        !self.is_allocated()
    }

    pub fn is_offered(&self) -> bool {
        if let State::Offered = self.state { true } else { false }
    }

    pub fn is_assigned(&self) -> bool {
        if let State::Assigned = self.state { true } else { false }
    }

    pub fn is_released(&self) -> bool {
        if let State::Released = self.state { true } else { false }
    }

    pub fn is_offer_expired(&self) -> bool {
        if !self.is_offered() {
            return true;
        }
        if self.offered_at == 0 {
            return false;
        }
        (Utc::now().timestamp() as u32) >= self.offered_at + OFFER_TIMEOUT
    }

    pub fn is_expired(&self) -> bool {
        if self.expires_at == 0 {
            return false;
        }
        (Utc::now().timestamp() as u32) >= self.expires_at
    }
}