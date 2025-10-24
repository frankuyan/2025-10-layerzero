//! LayerZero rate limiter tests

use core::cmp::min;
use core::num::traits::{SaturatingAdd, SaturatingSub};
use layerzero::oapps::common::rate_limiter::errors::err_rate_limit_exceeded;
use layerzero::oapps::common::rate_limiter::events::RateLimitsChanged;
use layerzero::oapps::common::rate_limiter::interface::{
    IRateLimiterDispatcher, IRateLimiterDispatcherTrait,
};
use layerzero::oapps::common::rate_limiter::rate_limiter::RateLimiterComponent;
use layerzero::oapps::common::rate_limiter::structs::{RateLimit, RateLimitConfig, SendableAmount};
use snforge_std::{
    CheatSpan, ContractClassTrait, DeclareResultTrait, EventSpyAssertionsTrait,
    cheat_block_timestamp, declare, spy_events,
};
use starknet::ContractAddress;
use starkware_utils_testing::test_utils::assert_panic_with_error;
use crate::constants::assert_eq;
use crate::fuzzable::contract_address::FuzzableContractAddress;
use crate::mocks::rate_limiter::interface::{
    IMockRateLimiterDispatcher, IMockRateLimiterDispatcherTrait, IMockRateLimiterSafeDispatcher,
    IMockRateLimiterSafeDispatcherTrait,
};

#[derive(Drop)]
struct RateLimiterHelper {
    address: ContractAddress,
    rate_limiter: IRateLimiterDispatcher,
    mock_rate_limiter: IMockRateLimiterDispatcher,
    safe_mock_rate_limiter: IMockRateLimiterSafeDispatcher,
}

fn deploy_mock_rate_limiter() -> RateLimiterHelper {
    let contract = declare("MockRateLimiter").unwrap().contract_class();
    let (address, _) = contract.deploy(@array![]).unwrap();

    RateLimiterHelper {
        address,
        rate_limiter: IRateLimiterDispatcher { contract_address: address },
        mock_rate_limiter: IMockRateLimiterDispatcher { contract_address: address },
        safe_mock_rate_limiter: IMockRateLimiterSafeDispatcher { contract_address: address },
    }
}

#[test]
fn test_deploy() {
    deploy_mock_rate_limiter();
}

#[test]
#[fuzzer(runs: 10)]
fn test_set_rate_limit(dst_eid: u32, limit: u256, window: u64) {
    let limiter = deploy_mock_rate_limiter();
    let mut spy = spy_events();
    let configs = array![RateLimitConfig { dst_eid, limit, window }];

    limiter.mock_rate_limiter.set_rate_limits(configs.clone());

    spy
        .assert_emitted(
            @array![
                (
                    limiter.address,
                    RateLimiterComponent::Event::RateLimitsChanged(RateLimitsChanged { configs }),
                ),
            ],
        );
}

#[test]
#[fuzzer(runs: 10)]
fn test_set_rate_limits(
    dst_eid_1: u32, limit_1: u256, window_1: u64, dst_eid_2: u32, limit_2: u256, window_2: u64,
) {
    if dst_eid_1 == dst_eid_2 {
        return;
    }

    let limiter = deploy_mock_rate_limiter();
    let mut spy = spy_events();
    let configs = array![
        RateLimitConfig { dst_eid: dst_eid_1, limit: limit_1, window: window_1 },
        RateLimitConfig { dst_eid: dst_eid_2, limit: limit_2, window: window_2 },
    ];

    limiter.mock_rate_limiter.set_rate_limits(configs.clone());

    spy
        .assert_emitted(
            @array![
                (
                    limiter.address,
                    RateLimiterComponent::Event::RateLimitsChanged(RateLimitsChanged { configs }),
                ),
            ],
        );
}


#[test]
#[fuzzer(runs: 10)]
fn test_set_rate_limit_with_state_checkpoint(
    dst_eid: u32,
    limit_1: u128,
    window_1: u16,
    limit_2: u128,
    window_2: u16,
    amount: u256,
    duration: u16,
) {
    let limit_1 = limit_1.into();
    let window_1 = window_1.into();
    let limit_2 = limit_2.into();
    let window_2 = window_2.into();
    let duration = duration.into() + 1;
    let limiter = deploy_mock_rate_limiter();

    limiter
        .mock_rate_limiter
        .set_rate_limits(array![RateLimitConfig { dst_eid, limit: limit_1, window: window_1 }]);
    // Hit the rate limit.
    limiter.mock_rate_limiter.outflow(dst_eid, limit_1);

    assert_eq(
        limiter.rate_limiter.get_rate_limit(dst_eid),
        RateLimit { amount_in_flight: limit_1, last_updated: 0, limit: limit_1, window: window_1 },
    );

    cheat_block_timestamp(limiter.address, duration, CheatSpan::Indefinite);
    limiter
        .mock_rate_limiter
        .set_rate_limits(array![RateLimitConfig { dst_eid, limit: limit_2, window: window_2 }]);

    assert_eq(
        limiter.rate_limiter.get_rate_limit(dst_eid),
        RateLimit {
            amount_in_flight: limit_1.saturating_sub(limit_1 * duration.into() / window_1.into()),
            last_updated: duration,
            limit: limit_2,
            window: window_2,
        },
    );
}

#[test]
#[fuzzer(runs: 10)]
fn test_get_rate_limit(dst_eid: u32, limit: u256, window: u64) {
    let limiter = deploy_mock_rate_limiter();

    limiter.mock_rate_limiter.set_rate_limits(array![RateLimitConfig { dst_eid, limit, window }]);

    assert_eq(
        limiter.rate_limiter.get_rate_limit(dst_eid),
        RateLimit { amount_in_flight: 0, last_updated: 0, limit, window },
    );
}

#[test]
#[fuzzer(runs: 10)]
fn test_get_rate_limits(
    dst_eid_1: u32, limit_1: u256, window_1: u64, dst_eid_2: u32, limit_2: u256, window_2: u64,
) {
    if dst_eid_1 == dst_eid_2 {
        return;
    }

    let limiter = deploy_mock_rate_limiter();

    limiter
        .mock_rate_limiter
        .set_rate_limits(
            array![
                RateLimitConfig { dst_eid: dst_eid_1, limit: limit_1, window: window_1 },
                RateLimitConfig { dst_eid: dst_eid_2, limit: limit_2, window: window_2 },
            ],
        );

    assert_eq(
        limiter.rate_limiter.get_rate_limit(dst_eid_1),
        RateLimit { amount_in_flight: 0, last_updated: 0, limit: limit_1, window: window_1 },
    );
    assert_eq(
        limiter.rate_limiter.get_rate_limit(dst_eid_2),
        RateLimit { amount_in_flight: 0, last_updated: 0, limit: limit_2, window: window_2 },
    );
}

#[test]
#[fuzzer(runs: 10)]
fn test_get_sendable_amount(dst_eid: u32, limit: u256, window: u64) {
    let limiter = deploy_mock_rate_limiter();

    limiter.mock_rate_limiter.set_rate_limits(array![RateLimitConfig { dst_eid, limit, window }]);

    assert_eq(
        limiter.rate_limiter.get_sendable_amount(dst_eid),
        SendableAmount { amount_in_flight: 0, sendable_amount: limit },
    );
}

#[test]
#[fuzzer(runs: 10)]
fn test_get_sendable_amount_before_full_window(
    dst_eid: u32, limit: u128, window: u16, amount: u256, duration: u16,
) {
    let limit = limit.into();
    let window = window.saturating_add(1);
    let duration = duration % window; // in [0, window)
    let limiter = deploy_mock_rate_limiter();

    limiter
        .mock_rate_limiter
        .set_rate_limits(array![RateLimitConfig { dst_eid, limit, window: window.into() }]);
    // Hit the rate limit.
    limiter.mock_rate_limiter.outflow(dst_eid, limit);

    assert_eq(
        limiter.rate_limiter.get_sendable_amount(dst_eid),
        SendableAmount { amount_in_flight: limit, sendable_amount: 0 },
    );

    cheat_block_timestamp(limiter.address, duration.into(), CheatSpan::Indefinite);
    let SendableAmount {
        amount_in_flight, sendable_amount,
    } = limiter.rate_limiter.get_sendable_amount(dst_eid);

    assert_eq(sendable_amount, limit * duration.into() / window.into());
    assert_eq(amount_in_flight, limit - sendable_amount);
}

// Although this case is covered by `test_get_sendable_amount_after_duration` already, we add it so
// that it is tested on every run of the test suite.
#[test]
#[fuzzer(runs: 10)]
fn test_get_sendable_amount_after_full_window(
    dst_eid: u32, limit: u128, window: u16, amount: u256, delta: u8,
) {
    let limit = limit.into();
    let delta = delta.into();
    let limiter = deploy_mock_rate_limiter();

    limiter
        .mock_rate_limiter
        .set_rate_limits(array![RateLimitConfig { dst_eid, limit, window: window.into() }]);
    // Hit the rate limit.
    limiter.mock_rate_limiter.outflow(dst_eid, limit);

    assert_eq(
        limiter.rate_limiter.get_sendable_amount(dst_eid),
        SendableAmount { amount_in_flight: limit, sendable_amount: 0 },
    );

    // We reach exactly to or go over the full window.
    cheat_block_timestamp(limiter.address, window.into() + delta, CheatSpan::Indefinite);
    let SendableAmount {
        amount_in_flight, sendable_amount,
    } = limiter.rate_limiter.get_sendable_amount(dst_eid);

    assert_eq(sendable_amount, limit);
    assert_eq(amount_in_flight, 0);
}

#[test]
#[fuzzer(runs: 10)]
fn test_get_sendable_amount_without_configuration(dst_eid: u32) {
    let limiter = deploy_mock_rate_limiter();

    assert_eq(
        limiter.rate_limiter.get_sendable_amount(dst_eid),
        SendableAmount { amount_in_flight: 0, sendable_amount: 0 },
    );
}

#[test]
#[fuzzer(runs: 10)]
fn test_outflow_by_zero(dst_eid: u32, limit: u256, window: u64) {
    let limiter = deploy_mock_rate_limiter();

    limiter.mock_rate_limiter.set_rate_limits(array![RateLimitConfig { dst_eid, limit, window }]);
    limiter.mock_rate_limiter.outflow(dst_eid, 0);

    assert_eq(
        limiter.rate_limiter.get_rate_limit(dst_eid),
        RateLimit { amount_in_flight: 0, last_updated: 0, limit, window },
    );
    assert_eq(
        limiter.rate_limiter.get_sendable_amount(dst_eid),
        SendableAmount { amount_in_flight: 0, sendable_amount: limit },
    );
}

#[test]
#[fuzzer(runs: 10)]
fn test_outflow(dst_eid: u32, limit: u256, window: u64, amount: u256) {
    let limiter = deploy_mock_rate_limiter();

    limiter.mock_rate_limiter.set_rate_limits(array![RateLimitConfig { dst_eid, limit, window }]);

    let amount = min(amount, limit);
    limiter.mock_rate_limiter.outflow(dst_eid, amount);

    assert_eq(
        limiter.rate_limiter.get_rate_limit(dst_eid),
        RateLimit { amount_in_flight: amount, last_updated: 0, limit, window },
    );
    assert_eq(
        limiter.rate_limiter.get_sendable_amount(dst_eid),
        SendableAmount { amount_in_flight: amount, sendable_amount: limit - amount },
    );
}

#[test]
#[fuzzer(runs: 10)]
fn test_outflow_before_full_window(
    dst_eid: u32, limit: u128, window: u16, amount: u256, duration: u16,
) {
    let limit = limit.into();
    let window = window.saturating_add(1);
    let duration = (duration % window).into();
    let window = window.into();
    let limiter = deploy_mock_rate_limiter();

    limiter.mock_rate_limiter.set_rate_limits(array![RateLimitConfig { dst_eid, limit, window }]);
    // Hit the rate limit.
    limiter.mock_rate_limiter.outflow(dst_eid, limit);

    assert_eq(
        limiter.rate_limiter.get_sendable_amount(dst_eid),
        SendableAmount { amount_in_flight: limit, sendable_amount: 0 },
    );

    cheat_block_timestamp(limiter.address, duration, CheatSpan::Indefinite);
    let sendable_amount = limiter.rate_limiter.get_sendable_amount(dst_eid);
    limiter.mock_rate_limiter.outflow(dst_eid, sendable_amount.sendable_amount);

    assert_eq(
        limiter.rate_limiter.get_sendable_amount(dst_eid),
        SendableAmount { amount_in_flight: limit, sendable_amount: 0 },
    );
    assert_eq(
        limiter.rate_limiter.get_rate_limit(dst_eid),
        RateLimit { amount_in_flight: limit, last_updated: duration, limit, window },
    );
}

#[test]
#[fuzzer(runs: 10)]
fn test_outflow_after_full_window(dst_eid: u32, limit: u128, window: u16, amount: u256) {
    let limit = limit.into();
    let window = window.into();
    let limiter = deploy_mock_rate_limiter();

    limiter
        .mock_rate_limiter
        .set_rate_limits(array![RateLimitConfig { dst_eid, limit, window: window.into() }]);
    // Hit the rate limit.
    limiter.mock_rate_limiter.outflow(dst_eid, limit);

    assert_eq(
        limiter.rate_limiter.get_sendable_amount(dst_eid),
        SendableAmount { amount_in_flight: limit, sendable_amount: 0 },
    );

    cheat_block_timestamp(limiter.address, window, CheatSpan::Indefinite);
    // Hit the rate limit again.
    limiter.mock_rate_limiter.outflow(dst_eid, limit);

    assert_eq(
        limiter.rate_limiter.get_sendable_amount(dst_eid),
        SendableAmount { amount_in_flight: limit, sendable_amount: 0 },
    );
    assert_eq(
        limiter.rate_limiter.get_rate_limit(dst_eid),
        RateLimit {
            amount_in_flight: limit, last_updated: window.into(), limit, window: window.into(),
        },
    );
}

#[test]
#[fuzzer(runs: 10)]
fn test_outflow_with_exceeded_limit(dst_eid: u32, limit: u256, window: u64, amount: u256) {
    let limiter = deploy_mock_rate_limiter();
    limiter.mock_rate_limiter.set_rate_limits(array![RateLimitConfig { dst_eid, limit, window }]);

    let result = limiter.safe_mock_rate_limiter.outflow(dst_eid, limit + 1);
    assert_panic_with_error(result, err_rate_limit_exceeded());
}

#[test]
#[fuzzer(runs: 10)]
fn test_outflow_by_zero_without_configuration(dst_eid: u32) {
    let limiter = deploy_mock_rate_limiter();
    limiter.mock_rate_limiter.outflow(dst_eid, 0);

    assert_eq(
        limiter.rate_limiter.get_rate_limit(dst_eid),
        RateLimit { amount_in_flight: 0, last_updated: 0, limit: 0, window: 0 },
    );
}

#[test]
#[fuzzer(runs: 10)]
fn test_outflow_by_one_without_configuration(dst_eid: u32) {
    let limiter = deploy_mock_rate_limiter();
    let result = limiter.safe_mock_rate_limiter.outflow(dst_eid, 1);
    assert_panic_with_error(result, err_rate_limit_exceeded());
}

#[test]
#[fuzzer(runs: 10)]
fn test_inflow(
    dst_eid: u32, limit: u256, window: u16, out_amount: u256, in_amount: u256, duration: u16,
) {
    let window = window.into();
    let out_amount = min(out_amount, limit);
    let limiter = deploy_mock_rate_limiter();

    limiter.mock_rate_limiter.set_rate_limits(array![RateLimitConfig { dst_eid, limit, window }]);
    limiter.mock_rate_limiter.outflow(dst_eid, out_amount);
    assert_eq(limiter.rate_limiter.get_rate_limit(dst_eid).amount_in_flight, out_amount);

    cheat_block_timestamp(limiter.address, duration.into(), CheatSpan::Indefinite);
    limiter.mock_rate_limiter.inflow(dst_eid, in_amount);

    // We do NOT update the last-updated timestamp.
    assert_eq(
        limiter.rate_limiter.get_rate_limit(dst_eid),
        RateLimit {
            amount_in_flight: out_amount.saturating_sub(in_amount), last_updated: 0, limit, window,
        },
    );
}

#[test]
#[fuzzer(runs: 10)]
fn test_inflow_below_zero(dst_eid: u32, limit: u256, window: u16, amount: u256, duration: u16) {
    let window = window.into();
    let amount = min(amount, limit);
    let limiter = deploy_mock_rate_limiter();

    limiter.mock_rate_limiter.set_rate_limits(array![RateLimitConfig { dst_eid, limit, window }]);
    limiter.mock_rate_limiter.outflow(dst_eid, amount);
    assert_eq(limiter.rate_limiter.get_rate_limit(dst_eid).amount_in_flight, amount);

    // Inflow back the same amount after a while.
    cheat_block_timestamp(limiter.address, duration.into(), CheatSpan::Indefinite);
    limiter.mock_rate_limiter.inflow(dst_eid, amount);

    assert_eq(
        limiter.rate_limiter.get_rate_limit(dst_eid),
        RateLimit { amount_in_flight: 0, last_updated: 0, limit, window },
    );
}

#[test]
#[fuzzer(runs: 10)]
fn test_inflow_without_configuration(dst_eid: u32, amount: u256) {
    let limiter = deploy_mock_rate_limiter();
    limiter.mock_rate_limiter.inflow(dst_eid, amount);
    assert_eq(
        limiter.rate_limiter.get_rate_limit(dst_eid),
        RateLimit { amount_in_flight: 0, last_updated: 0, limit: 0, window: 0 },
    );
}
