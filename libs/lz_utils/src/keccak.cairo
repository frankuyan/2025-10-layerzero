use core::integer::u128_byte_reverse;
use core::keccak::compute_keccak_byte_array;
use crate::bytes::Bytes32;

/// Computes the keccak256 hash of a byte array and returns it as a u256 value
///
/// # Arguments
/// * `arr` - A reference to a byte array to be hashed
///
/// # Returns
/// * `Bytes32` - The keccak256 hash of the input as a u256
pub fn keccak256(arr: @ByteArray) -> Bytes32 {
    u256_reverse_endian(compute_keccak_byte_array(arr))
}

/// Reverses the endianness of a u256 value
/// This is necessary when working with hashes between Cairo and EVM environments
///
/// # Arguments
/// * `input` - The u256 value to reverse
///
/// # Returns
/// * `Bytes32` - The input with byte order reversed
pub fn u256_reverse_endian(input: u256) -> Bytes32 {
    let low = u128_byte_reverse(input.high);
    let high = u128_byte_reverse(input.low);
    Bytes32 { value: u256 { low, high } }
}
