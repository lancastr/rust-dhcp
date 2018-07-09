use chrono::prelude::*;

pub struct Lease {
    address     : u32,
    leased_at   : u32,
    expired_at  : u32,
    released    : bool,
}

impl Lease {
    pub fn new(
        address     : u32,
        lease_time  : u32
    ) -> Self {
        let leased_at = Utc::now().timestamp() as u32;
        let expired_at = leased_at + lease_time;

        Lease {
            address,
            leased_at,
            expired_at,
            released: false,
        }
    }

    pub fn address(&self) -> u32 {
        self.address
    }

    pub fn release(&mut self) {
        self.released = true;
    }

    pub fn is_active(&self) -> bool {
        !self.is_released() && !self.is_expired()
    }

    fn is_released(&self) -> bool {
        self.released
    }

    fn is_expired(&self) -> bool {
        (Utc::now().timestamp() as u32) >= self.expired_at
    }
}