/// A rate limit state for a destination endpoint ID.
#[derive(Drop, Serde, Default, starknet::Store, PartialEq, Debug)]
pub struct RateLimit {
    /// An amount in flight.
    pub amount_in_flight: u256,
    /// A timestamp from which we calculate decays.
    pub last_updated: u64,
    /// An amount limit of the rate.
    pub limit: u256,
    /// A time window of the rate.
    pub window: u64,
}

/// A rate limit configuration.
#[derive(Clone, Drop, Serde, Default, starknet::Store, PartialEq, Debug)]
pub struct RateLimitConfig {
    /// A destination endpoint ID.
    pub dst_eid: u32,
    /// An amount limit of the rate.
    pub limit: u256,
    /// A time window of the rate.
    pub window: u64,
}

/// A sendable amount.
#[derive(Drop, Serde, starknet::Store, PartialEq, Debug)]
pub struct SendableAmount {
    /// The current amount that is sent.
    pub amount_in_flight: u256,
    /// An amount that can be sent.
    pub sendable_amount: u256,
}
