use layerzero::oapps::common::rate_limiter::structs::RateLimitConfig;

#[starknet::interface]
pub trait IMockRateLimiter<TContractState> {
    fn set_rate_limits(ref self: TContractState, configs: Array<RateLimitConfig>);
    fn outflow(ref self: TContractState, dst_eid: u32, amount: u256);
    fn inflow(ref self: TContractState, src_eid: u32, amount: u256);
}
