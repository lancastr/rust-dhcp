//! The Binary Exponential Backoff module.

use std::{
    time::{
        Instant,
        Duration,
    },
    ops::{
        AddAssign,
        SubAssign,
    }
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
use rand::{
    self,
    Rng,
};

/// Binary exponential backoff algorithm implemented as a `Stream`.
///
/// Yields after each timeout.
pub struct Backoff {
    minimal: Duration,
    current: Duration,
    maximal: Duration,
    timeout: Delay,
}

impl Backoff {
    /// Constructs a timer and starts it.
    ///
    /// * `minimal`
    /// The initial timeout duration.
    ///
    /// * `maximal`
    /// The maximal timeout duration, inclusively.
    pub fn new(minimal: Duration, maximal: Duration) -> Backoff {
        Backoff {
            minimal,
            current: minimal,
            maximal,
            timeout: Delay::new(Instant::now() + minimal),
        }
    }

    /// Construct a duration with -1/0/+1 second random offset.
    fn randomize(duration: &Duration) -> Duration {
        let offset = rand::thread_rng().gen_range::<i32>(-1, 2);
        let mut duration = Duration::from(duration.to_owned());
        if offset > 0 {
            duration.add_assign(Duration::from_secs(offset as u64));
        }
        if offset < 0 {
            duration.sub_assign(Duration::from_secs((-offset) as u64));
        }
        duration
    }
}

impl Stream for Backoff {
    type Item = ();
    type Error = Error;

    /// Returns `Some(())` if has got beyond maximal timeout and `None` if has not.
    ///
    /// Resets to its minimal timeout after reaching the maximum.
    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        try_ready!(self.timeout.poll());
        self.current *= 2;
        if self.current > self.maximal {
            self.current = self.minimal;
            self.timeout = Delay::new(Instant::now() + Self::randomize(&self.current));
            return Ok(Async::Ready(Some(())));
        }
        self.timeout = Delay::new(Instant::now() + Self::randomize(&self.current));
        Ok(Async::Ready(None))
    }
}