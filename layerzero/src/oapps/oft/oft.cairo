/// OFT (Omnichain Fungible Token) Contract
/// Standard ERC20 token with cross-chain transfer capabilities
#[starknet::contract]
pub mod OFT {
    use layerzero::oapps::common::oapp_options_type_3::oapp_options_type_3::OAppOptionsType3Component;
    use layerzero::oapps::oapp::oapp_core::OAppCoreComponent;
    use layerzero::oapps::oft::oft_core::default_oapp_hooks::OFTCoreOAppHooksDefaultImpl;
    use layerzero::oapps::oft::oft_core::default_oft_hooks::OFTCoreOFTHooksDefaultImpl;
    use layerzero::oapps::oft::oft_core::oft_core::OFTCoreComponent;
    use openzeppelin::access::ownable::OwnableComponent;
    use openzeppelin::token::erc20::{ERC20Component, ERC20HooksEmptyImpl};
    use starknet::ContractAddress;

    // Component declarations
    component!(path: ERC20Component, storage: erc20, event: ERC20Event);
    component!(path: OwnableComponent, storage: ownable, event: OwnableEvent);
    component!(path: OAppCoreComponent, storage: oapp_core, event: OAppCoreEvent);
    component!(path: OFTCoreComponent, storage: oft_core, event: OFTCoreEvent);
    component!(
        path: OAppOptionsType3Component, storage: oapp_options_type_3, event: OAppOptionsType3Event,
    );

    // ERC20 Mixin
    #[abi(embed_v0)]
    impl ERC20MixinImpl = ERC20Component::ERC20MixinImpl<ContractState>;
    impl ERC20InternalImpl = ERC20Component::InternalImpl<ContractState>;

    // ERC20 immutable configuration
    impl ERC20ImmutableConfig of ERC20Component::ImmutableConfig {
        const DECIMALS: u8 = 18;
    }

    // Ownable Mixin
    #[abi(embed_v0)]
    impl OwnableMixinImpl = OwnableComponent::OwnableMixinImpl<ContractState>;
    impl OwnableInternalImpl = OwnableComponent::InternalImpl<ContractState>;

    // OApp Core
    #[abi(embed_v0)]
    impl OAppCoreImpl = OAppCoreComponent::OAppCoreImpl<ContractState>;
    impl OAppCoreInternalImpl = OAppCoreComponent::InternalImpl<ContractState>;

    // OApp Receiver
    #[abi(embed_v0)]
    impl IOAppReceiverImpl = OAppCoreComponent::OAppReceiverImpl<ContractState>;

    // LayerZero Receiver from OApp Core
    #[abi(embed_v0)]
    impl ILayerZeroReceiverImpl =
        OAppCoreComponent::LayerZeroReceiverImpl<ContractState>;

    // OFT Core - embed the implementation
    #[abi(embed_v0)]
    impl OFTCoreImpl = OFTCoreComponent::OFTCoreImpl<ContractState>;
    impl OFTCoreInternalImpl = OFTCoreComponent::InternalImpl<ContractState>;

    impl OFTCoreImmutableConfig of OFTCoreComponent::ImmutableConfig {
        const SHARED_DECIMALS: u8 = 6;
    }

    // OApp Options Type 3
    #[abi(embed_v0)]
    impl OAppOptionsType3Impl =
        OAppOptionsType3Component::OAppOptionsType3Impl<ContractState>;
    impl OAppOptionsType3InternalImpl = OAppOptionsType3Component::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        #[substorage(v0)]
        erc20: ERC20Component::Storage,
        #[substorage(v0)]
        ownable: OwnableComponent::Storage,
        #[substorage(v0)]
        oapp_core: OAppCoreComponent::Storage,
        #[substorage(v0)]
        oft_core: OFTCoreComponent::Storage,
        #[substorage(v0)]
        oapp_options_type_3: OAppOptionsType3Component::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        ERC20Event: ERC20Component::Event,
        #[flat]
        OwnableEvent: OwnableComponent::Event,
        #[flat]
        OAppCoreEvent: OAppCoreComponent::Event,
        #[flat]
        OFTCoreEvent: OFTCoreComponent::Event,
        #[flat]
        OAppOptionsType3Event: OAppOptionsType3Component::Event,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        name: ByteArray,
        symbol: ByteArray,
        lz_endpoint: ContractAddress,
        owner: ContractAddress,
        native_token: ContractAddress,
    ) {
        // Initialize ERC20
        self.erc20.initializer(name, symbol);

        // Initialize Ownable
        self.ownable.initializer(owner);

        // Initialize OApp Core
        self.oapp_core.initializer(lz_endpoint, owner, native_token);

        // Initialize OFT Core with local decimals
        let local_decimals = self.erc20.decimals();
        self.oft_core.initializer(local_decimals);
    }
}
