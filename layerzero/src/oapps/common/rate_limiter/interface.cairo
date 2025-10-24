use crate::oapps::common::rate_limiter::structs::{RateLimit, SendableAmount};

/// An interface for a rate limiter component.
#[starknet::interface]
pub trait IRateLimiter<TContractState> {
    /// Gets the current amount that can be sent to the destination endpoint ID for the given rate
    /// limit window.
    ///
    /// # Arguments
    /// * `dst_eid` - The destination endpoint ID.
    ///
    /// # Returns
    /// * `SendableAmount` - The sendable amount.
    fn get_sendable_amount(self: @TContractState, dst_eid: u32) -> SendableAmount;

    /// Gets the current rate limit for the destination endpoint ID.
    ///
    /// # Arguments
    /// * `dst_eid` - The destination endpoint ID.
    ///
    /// # Returns
    /// * `RateLimit` - The rate limit state.
    fn get_rate_limit(self: @TContractState, dst_eid: u32) -> RateLimit;
}
