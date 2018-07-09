use chrono::prelude::*;

enum State {
    Offered,
    Assigned,
    Released,
}

const OFFER_TIMEOUT: u32 = 60;

pub struct Lease {
    address             : u32,
    state               : State,
    offered_at          : u32,
    assigned_at         : u32,
    released_at         : u32,

    offer_expires_at    : u32,
    expires_at          : u32,
}

impl Lease {
    pub fn new(address: u32) -> Self {
        let offered_at = Utc::now().timestamp() as u32;

        Lease {
            address,
            state               : State::Offered,
            offered_at,
            assigned_at         : 0,
            released_at         : 0,

            offer_expires_at    : offered_at + OFFER_TIMEOUT,
            expires_at          : 0,
        }
    }

    pub fn address(&self) -> u32 {
        self.address
    }

    pub fn assign(&mut self, lease_time: u32) {
        match self.state {
            State::Offered => {
                self.state = State::Assigned;
                self.assigned_at = Utc::now().timestamp() as u32;

                self.offer_expires_at = 0;
                self.expires_at = self.assigned_at + lease_time;
            },
            _ => {},
        }
    }

    pub fn release(&mut self) {
        self.state = State::Released;
        self.released_at = Utc::now().timestamp() as u32;
    }

    pub fn expires_at(&self) -> u32 {
        self.expires_at
    }

    pub fn expires_after(&self) -> u32 {
        self.expires_at - (Utc::now().timestamp() as u32)
    }

    pub fn is_allocated(&self) -> bool {
        (self.is_offered() && !self.is_offer_expired()) || (self.is_assigned() && !self.is_expired())
    }

    pub fn is_available(&self) -> bool {
        !self.is_allocated()
    }

    pub fn is_offered(&self) -> bool {
        match self.state {
            State::Offered => !self.is_offer_expired(),
            _ => false,
        }
    }

    pub fn is_assigned(&self) -> bool {
        match self.state {
            State::Assigned => !self.is_expired(),
            _ => false,
        }
    }

    pub fn is_released(&self) -> bool {
        match self.state {
            State::Released => true,
            _ => false,
        }
    }

    pub fn is_offer_expired(&self) -> bool {
        if self.offer_expires_at == 0 {
            return false;
        }
        (Utc::now().timestamp() as u32) >= self.offer_expires_at
    }

    pub fn is_expired(&self) -> bool {
        if self.expires_at == 0 {
            return false;
        }
        (Utc::now().timestamp() as u32) >= self.expires_at
    }
}