use starknet::ContractAddress;
use crate::common::structs::messaging::{MessageReceipt, MessagingFee};

#[starknet::interface]
pub trait IOmniCounter<TContractState> {
    /// Get the counter value for a specific remote EID.
    fn get_counter(self: @TContractState, remote_eid: u32) -> u256;

    /// Quote an increment.
    fn quote(
        self: @TContractState,
        dst_eid: u32,
        increment_type: u8,
        options: ByteArray,
        pay_in_lz_token: bool,
    ) -> MessagingFee;

    /// Send an increment message to another chain.
    fn increment(
        ref self: TContractState,
        dst_eid: u32,
        increment_type: u8,
        options: ByteArray,
        fee: MessagingFee,
        refund_address: ContractAddress,
    ) -> MessageReceipt;
}
