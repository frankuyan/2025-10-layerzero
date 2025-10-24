//! RateLimiter component implementation

/// The rate limiter component.
///
/// It implements rate limiting functionality. This component provides a basic framework for rate
/// limiting how often a function can be executed.
/// It is designed to be embedded into other contracts requiring rate limiting capabilities to
/// protect resources or services from excessive use.
///
/// The ordering of transactions within a given block (timestamp) affects the consumed capacity.
/// Carefully consider the minimum window duration for the given blockchain. For example, on
/// Starknet, the minimum window duration should be at least 6 seconds as of September 1,
/// 2025. If a window less than the time is configured, then the rate limit will effectively
/// reset with each block, rendering rate limiting ineffective.
///
/// Carefully consider the proportion of the limit to the window. If the limit is much smaller
/// than the window, the decay function is lossy. Consider using a limit that is greater than or
/// equal to the window to avoid this. This is especially important for blockchains with short
/// average block times.
///
/// Example 1: Max rate limit reached at beginning of window. As time continues the amount of in
/// flights comes down.
///
/// Rate Limit Config:
///   limit: 100 units
///   window: 60 seconds
///
///                              Amount in Flight (units) vs. Time Graph (seconds)
///
///      100 | * - (Max limit reached at beginning of window)
///          |   *
///          |     *
///          |       *
///       50 |         * (After 30 seconds only 50 units in flight)
///          |           *
///          |             *
///          |               *
///       0  +-|---|---|---|---|--> (After 60 seconds 0 units are in flight)
///            0  15  30  45  60 (seconds)
///
/// Example 2: Max rate limit reached at beginning of window. As time continues the amount of in
/// flights comes down allowing for more to be sent. At the 90 second mark, more in flights come in.
///
/// Rate Limit Config:
///   limit: 100 units
///   window: 60 seconds
///
///                              Amount in Flight (units) vs. Time Graph (seconds)
///
///      100 | * - (Max limit reached at beginning of window)
///          |   *
///          |     *
///       50 |       *           * (50 inflight)
///          |         *           *
///          |           *           *
///          |             *           *
///        0 +-|--|--|--|--|--|--|--|--|--> Time
///            0 15 30 45 60 75 90 105 120 (seconds)
///
/// Example 3: Max rate limit reached at beginning of window. At the 30 second mark, the window gets
/// updated to 60 seconds and the limit gets updated to 50 units. This scenario shows the direct
/// depiction of "in flight" from the previous window affecting the current window.
///
/// Initial Rate Limit Config: For first 30 seconds
///   limit: 100 units
///   window: 60 seconds
///
/// Updated Rate Limit Config: Updated at 30 second mark
///   limit: 50 units
///   window: 60 seconds
///
///                              Amount in Flight (units) vs. Time Graph (seconds)
///
///      100 | * - (Max limit reached at beginning of window)
///          |   *
///          |     *
///       75 |       *
///          |         *
///          |           *
///          |             *
///       50 |               *
///          |                 . *
///          |                   .   *
///          |                     .     *
///       25 |                       .       *
///          |                         .         *
///          |                           .           *
///          |                             .             *
///        0 +-|-------------|-------------|-------------|---------> Time
///            0            30            60            90    (seconds)
///            [      original window      ]
///                          [       updated window      ]
#[starknet::component]
pub mod RateLimiterComponent {
    use core::cmp::max;
    use core::num::traits::SaturatingSub;
    use starknet::get_block_timestamp;
    use starknet::storage::{
        Map, StorageMapReadAccess, StoragePathEntry, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starkware_utils::errors::assert_with_byte_array;
    use crate::oapps::common::rate_limiter::errors::err_rate_limit_exceeded;
    use crate::oapps::common::rate_limiter::events::RateLimitsChanged;
    use crate::oapps::common::rate_limiter::interface::IRateLimiter;
    use crate::oapps::common::rate_limiter::structs::{RateLimit, RateLimitConfig, SendableAmount};

    #[storage]
    pub struct Storage {
        /// A map from endpoint IDs to their rate limit configurations and states.
        pub RateLimiter_rate_limits: Map<u32, RateLimit>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        RateLimitsChanged: RateLimitsChanged,
    }

    pub trait RateLimiterHooks<TContractState, +HasComponent<TContractState>> {
        fn _get_sendable_amount(
            self: @ComponentState<TContractState>, limit: @RateLimit,
        ) -> SendableAmount {
            let RateLimit { amount_in_flight, last_updated, limit, window } = limit;

            // Prevent division by zero.
            let window = max(*window, 1);
            let duration = get_block_timestamp() - *last_updated;

            // Presume linear decay.
            let amount_in_flight = amount_in_flight
                .saturating_sub(*limit * duration.into() / window.into());

            SendableAmount {
                // Although the amount in flight should never be above the limit, we double-check
                // that with saturating subtraction.
                amount_in_flight, sendable_amount: limit.saturating_sub(amount_in_flight),
            }
        }

        /// Increases the amount in flight by the given amount.
        ///
        /// It verifies whether the specified amount falls within the rate limit constraints
        /// for the destination endpoint ID. On successful verification, it updates the
        /// amount in flight and the last-updated timestamp. If the amount exceeds the rate limit,
        /// the operation reverts.
        ///
        /// * `dst_eid` The destination endpoint ID.
        /// * `amount` The amount to outflow.
        fn _outflow(
            ref self: ComponentState<TContractState>, dst_eid: u32, amount: u256,
        ) {
            let entry = self.RateLimiter_rate_limits.entry(dst_eid);
            let rate_limit = entry.read();

            let SendableAmount {
                amount_in_flight, sendable_amount,
            } = Self::_get_sendable_amount(@self, @rate_limit);

            assert_with_byte_array(amount <= sendable_amount, err_rate_limit_exceeded());

            entry
                .write(
                    RateLimit {
                        amount_in_flight: amount_in_flight + amount,
                        last_updated: get_block_timestamp(),
                        ..rate_limit,
                    },
                )
        }

        /// Decreases the amount in flight by the given amount.
        ///
        /// To be used when you want to calculate your rate limits as a function of net
        /// outbound AND inbound. i.e. If you move 150 out, and 100 in, you effective inflight
        /// should be 50. / It does not need to update decay values, as the inflow is effective
        /// immediately.
        ///
        /// # Arguments
        /// * `src_eid` - The source endpoint ID.
        /// * `amount` - The amount to inflow back.
        fn _inflow(
            ref self: ComponentState<TContractState>, src_eid: u32, amount: u256,
        ) {
            let entry = self.RateLimiter_rate_limits.entry(src_eid);
            let rate_limit = entry.read();

            entry
                .write(
                    RateLimit {
                        amount_in_flight: rate_limit.amount_in_flight.saturating_sub(amount),
                        ..rate_limit,
                    },
                );
        }

        /// Sets the rate limits.
        ///
        /// # Arguments
        /// * `configs` - Rate limit configurations.
        fn _set_rate_limits(
            ref self: ComponentState<TContractState>, configs: Array<RateLimitConfig>,
        ) {
            for config in @configs {
                // We checkpoint the rate limit state with the old rate.
                Self::_outflow(ref self, *config.dst_eid, 0);

                let entry = self.RateLimiter_rate_limits.entry(*config.dst_eid);
                // Do NOT reset the `amount_in_flight` or `last_updated` of the existing
                // rate limit.
                entry
                    .write(
                        RateLimit { limit: *config.limit, window: *config.window, ..entry.read() },
                    );
            }

            self.emit(RateLimitsChanged { configs });
        }
    }

    #[embeddable_as(RateLimiterImpl)]
    impl RateLimiter<
        TContractState, +HasComponent<TContractState>, +RateLimiterHooks<TContractState>,
    > of IRateLimiter<ComponentState<TContractState>> {
        fn get_sendable_amount(
            self: @ComponentState<TContractState>, dst_eid: u32,
        ) -> SendableAmount {
            self._get_sendable_amount(@self.RateLimiter_rate_limits.read(dst_eid))
        }

        fn get_rate_limit(self: @ComponentState<TContractState>, dst_eid: u32) -> RateLimit {
            self.RateLimiter_rate_limits.read(dst_eid)
        }
    }
}

pub impl RateLimiterHooksDefaultImpl<
    TContractState, +RateLimiterComponent::HasComponent<TContractState>,
> of RateLimiterComponent::RateLimiterHooks<TContractState> {}
