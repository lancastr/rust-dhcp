//! The Binary Exponential Forthon™ module.
//! 
//! In both RENEWING and REBINDING states, if the client receives no
//! response to its DHCPREQUEST message, the client SHOULD wait one-half
//! of the remaining time until T2 (in RENEWING state) and one-half of
//! the remaining lease time (in REBINDING state), down to a minimum of
//! 60 seconds, before retransmitting the DHCPREQUEST message.

use std::{
    time::{
        Instant,
        Duration,
    },
};

use futures::{
    Async,
    Future,
    Poll,
    Stream,
};
use tokio::{
    timer::{
        Delay,
        Error,
    },
};

/// Binary exponential Forthon™ algorithm implemented as a `Stream`.
///
/// Yields and eats a half of `left` after each timeout.
pub struct Forthon {
    /// Left until deadline.
    left: Duration,
    /// Last sleep duration.
    sleep: Duration,
    /// The timeout is defaulted to it if `left` is less than `minimal`.
    minimal: Duration,
    /// The timer himself.
    timeout: Delay,
    /// The expiration flag.
    expired: bool,
}

impl Forthon {
    /// Constructs a timer and starts it.
    ///
    /// * `deadline`
    /// The duration until expiration.
    ///
    /// * `minimal`
    /// The duration to be slept if `left` is less than it. The last timeout before expiration.
    pub fn new(deadline: Duration, minimal: Duration) -> Forthon {
        let (sleep, expired) = if deadline < minimal * 2 {
            (deadline, true)
        } else {
            (deadline / 2, false)
        };

        Forthon {
            left: deadline - sleep,
            sleep,
            minimal,
            timeout: Delay::new(Instant::now() + sleep),
            expired,
        }
    }

    fn next(&mut self) -> Duration {
        self.sleep = if self.left < self.minimal * 2 {
            self.expired = true;
            self.left
        } else {
            self.left / 2
        };
        self.left -= self.sleep;
        self.sleep
    }
}

impl Stream for Forthon {
    type Item = (u64, bool);
    type Error = Error;

    /// Yields seconds slept and the expiration flag.
    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        try_ready!(self.timeout.poll());
        let seconds = self.sleep.as_secs();
        if self.expired {
            return Ok(Async::Ready(Some((seconds, true))))
        }
        self.timeout = Delay::new(Instant::now() + self.next());
        Ok(Async::Ready(Some((seconds, false))))
    }
}