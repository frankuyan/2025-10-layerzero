use snforge_std::{ContractClassTrait, DeclareResultTrait, declare};
use starknet::ContractAddress;

pub fn deploy_mock_lz_token_fee_lib(fee: u256) -> ContractAddress {
    let contract = declare("MockLzTokenFeeLib").unwrap().contract_class();
    let (address, _) = contract.deploy(@array![fee.low.into(), fee.high.into()]).unwrap();
    address
}
