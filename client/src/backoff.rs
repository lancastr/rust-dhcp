//! The Binary Exponential Backoff module.

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
    self,
    timer::Delay,
};

/// Binary exponential backoff algorithm implemented as a `Stream`.
///
/// Yields a value after each timeout.
pub struct Backoff {
    current: Duration,
    maximal: Duration,
    timeout: Delay,
}

impl Backoff {
    pub fn new(base: Duration, max: Duration) -> Backoff {
        Backoff {
            current: base,
            maximal: max,
            timeout: Delay::new(Instant::now() + base),
        }
    }
}

impl Stream for Backoff {
    type Item = ();
    type Error = tokio::timer::Error;

    /// Returns `Some(())` if has got beyond maximal timeout and `None` if has not.
    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        try_ready!(self.timeout.poll());
        self.current *= 2;
        if self.current > self.maximal {
            return Ok(Async::Ready(Some(())));
        }
        self.timeout = Delay::new(Instant::now() + self.current);
        Ok(Async::Ready(None))
    }
}