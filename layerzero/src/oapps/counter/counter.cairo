#[starknet::contract]
pub mod OmniCounter {
    use alexandria_bytes::byte_array_ext::ByteArrayTraitExt;
    use lz_utils::bytes::Bytes32;
    use openzeppelin::access::ownable::OwnableComponent;
    use starknet::storage::{
        Map, StoragePathEntry, StoragePointerReadAccess, StoragePointerWriteAccess,
    };
    use starknet::{ContractAddress, get_caller_address};
    use crate::common::structs::messaging::{MessageReceipt, MessagingFee};
    use crate::common::structs::packet::Origin;
    use crate::oapps::counter::constants::{INCREMENT_TYPE_A_B, INCREMENT_TYPE_A_B_A};
    use crate::oapps::counter::interface::IOmniCounter;
    use crate::oapps::counter::structs::{IncrementReceived, IncrementSent};
    use crate::oapps::oapp::oapp_core::OAppCoreComponent;

    component!(path: OAppCoreComponent, storage: oapp_core, event: OAppCoreEvent);
    component!(path: OwnableComponent, storage: ownable, event: OwnableEvent);

    // OAppCore Mixin - now with built-in ownership control
    #[abi(embed_v0)]
    impl OAppCoreImpl = OAppCoreComponent::OAppCoreImpl<ContractState>;
    impl OAppCoreInternalImpl = OAppCoreComponent::InternalImpl<ContractState>;
    impl OAppCoreSenderImpl = OAppCoreComponent::OAppSenderImpl<ContractState>;

    #[abi(embed_v0)]
    impl OAppCoreReceiverImpl = OAppCoreComponent::OAppReceiverImpl<ContractState>;

    #[abi(embed_v0)]
    impl ILayerZeroReceiverImpl =
        OAppCoreComponent::LayerZeroReceiverImpl<ContractState>;

    // Ownable Mixin
    #[abi(embed_v0)]
    impl OwnableImpl = OwnableComponent::OwnableImpl<ContractState>;
    impl OwnableInternalImpl = OwnableComponent::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        // Map from remoteEid to counter value
        counters: Map<u32, u256>,
        #[substorage(v0)]
        oapp_core: OAppCoreComponent::Storage,
        #[substorage(v0)]
        ownable: OwnableComponent::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        #[flat]
        OAppCoreEvent: OAppCoreComponent::Event,
        #[flat]
        OwnableEvent: OwnableComponent::Event,
        IncrementSent: IncrementSent,
        IncrementReceived: IncrementReceived,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        endpoint: ContractAddress,
        owner: ContractAddress,
        native_token: ContractAddress,
    ) {
        self.oapp_core.initializer(endpoint, owner, native_token);
        self.ownable.initializer(owner);
    }


    #[abi(embed_v0)]
    impl OmniCounterImpl of IOmniCounter<ContractState> {
        fn get_counter(self: @ContractState, remote_eid: u32) -> u256 {
            self.counters.entry(remote_eid).read()
        }

        fn quote(
            self: @ContractState,
            dst_eid: u32,
            increment_type: u8,
            options: ByteArray,
            pay_in_lz_token: bool,
        ) -> MessagingFee {
            self
                .oapp_core
                ._quote(
                    dst_eid,
                    self._encode_increment_message(increment_type),
                    options,
                    pay_in_lz_token,
                )
        }

        fn increment(
            ref self: ContractState,
            dst_eid: u32,
            increment_type: u8,
            options: ByteArray,
            fee: MessagingFee,
            refund_address: ContractAddress,
        ) -> MessageReceipt {
            let caller = get_caller_address();
            let message = self._encode_increment_message(increment_type);

            self.emit(IncrementSent { sender: caller, dst_eid, increment_type });

            // Call the underlying OAppCore send function
            self.oapp_core._lz_send(dst_eid, message, options, fee, refund_address)
        }
    }

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        /// Encode increment message for cross-chain communication
        fn _encode_increment_message(self: @ContractState, increment_type: u8) -> ByteArray {
            let mut message: ByteArray = "";

            // Message Format:
            // 1 byte: Increment type (AB=0x01, ABA=0x02)
            message.append_byte(increment_type);

            message
        }

        /// Send a response increment back to the original sender (for ABA type)
        fn _send_response(ref self: ContractState, dst_eid: u32) {
            // Use default options and fee for response (in real implementation, these should be
            // configurable)
            let options: ByteArray = "";
            let fee = MessagingFee { native_fee: 0, lz_token_fee: 0 };
            let refund_address = get_caller_address();

            self.increment(dst_eid, INCREMENT_TYPE_A_B, options, fee, refund_address);
        }
    }

    // Implement OAppHooks to provide the required _lz_receive implementation
    impl OAppHooks of OAppCoreComponent::OAppHooks<ContractState> {
        fn _lz_receive(
            ref self: OAppCoreComponent::ComponentState<ContractState>,
            origin: Origin,
            guid: Bytes32,
            message: ByteArray,
            executor: ContractAddress,
            value: u256,
            extra_data: ByteArray,
        ) {
            // Parse the message
            let (_, increment_type) = message.read_u8(0);

            // Get the source EID
            let src_eid = origin.src_eid;

            // Increment the counter for this remote EID
            let mut contract = self.get_contract_mut();
            let counter_entry = contract.counters.entry(src_eid);
            let old_value = counter_entry.read();
            let new_value = old_value + 1;
            counter_entry.write(new_value);

            contract
                .emit(IncrementReceived { src_eid, old_value, new_value, increment_type, value });

            // If this is an ABA type increment, send a response back
            if increment_type == INCREMENT_TYPE_A_B_A {
                contract._send_response(src_eid);
            }
        }
    }
}
