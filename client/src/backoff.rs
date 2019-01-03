//! The Binary Exponential Backoff module.
//!
//! DHCP clients are responsible for all message retransmission.  The
//! client MUST adopt a retransmission strategy that incorporates a
//! randomized exponential backoff algorithm to determine the delay
//! between retransmissions.  The delay between retransmissions SHOULD be
//! chosen to allow sufficient time for replies from the server to be
//! delivered based on the characteristics of the internetwork between
//! the client and the server.  For example, in a 10Mb/sec Ethernet
//! internetwork, the delay before the first retransmission SHOULD be 4
//! seconds randomized by the value of a uniform random number chosen
//! from the range -1 to +1.  Clients with clocks that provide resolution
//! granularity of less than one second may choose a non-integer
//! randomization value.  The delay before the next retransmission SHOULD
//! be 8 seconds randomized by the value of a uniform number chosen from
//! the range -1 to +1.  The retransmission delay SHOULD be doubled with
//! subsequent retransmissions up to a maximum of 64 seconds.  The client
//! MAY provide an indication of retransmission attempts to the user as
//! an indication of the progress of the configuration process.

use std::time::{Duration, Instant};

use futures::{Async, Future, Poll, Stream};
use rand::{self, Rng};
use tokio::timer::{Delay, Error};

/// This `value`, this `-value` or `0` is added to each timeout in seconds.
const AMPLITUDE: i32 = 1;

/// Binary exponential backoff algorithm implemented as a `Stream`.
///
/// Yields after each timeout.
pub struct Backoff {
    /// The current timeout without randomization.
    current: Duration,
    /// The current timeout with randomization.
    with_rand: Duration,
    /// The timeout after which the timer is expired.
    maximal: Duration,
    /// The timer himself.
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
        let with_rand = Self::randomize(&minimal);

        Backoff {
            current: minimal,
            with_rand,
            maximal,
            timeout: Delay::new(Instant::now() + with_rand),
        }
    }

    /// Construct a duration with -1/0/+1 second random offset.
    fn randomize(duration: &Duration) -> Duration {
        let offset: i32 = rand::thread_rng().gen_range(-AMPLITUDE, AMPLITUDE + 1);
        let mut duration = Duration::from(duration.to_owned());
        if offset > 0 {
            duration += Duration::from_secs(offset as u64);
        }
        if offset < 0 {
            duration -= Duration::from_secs((-offset) as u64);
        }
        duration
    }
}

impl Stream for Backoff {
    type Item = (u64, bool);
    type Error = Error;

    /// Yields seconds slept and the expiration flag.
    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        try_ready!(self.timeout.poll());
        let seconds = self.with_rand.as_secs();
        self.current *= 2;
        self.with_rand = Self::randomize(&self.current);
        self.timeout = Delay::new(Instant::now() + self.with_rand);
        Ok(Async::Ready(Some((seconds, self.current > self.maximal))))
    }
}
