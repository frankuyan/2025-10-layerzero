use crate::oapps::common::rate_limiter::structs::RateLimitConfig;

/// An event when rate limits are changed.
#[derive(Debug, Drop, starknet::Event)]
pub struct RateLimitsChanged {
    /// Rate limit configurations.
    pub configs: Array<RateLimitConfig>,
}
